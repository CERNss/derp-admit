package service

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type dAccessSnapshot struct {
	Roles      []model.Role
	Relays     []model.Relay
	Rules      []model.CasbinRule
	Version    int64
	AuditCount int64
}

func dNewAccessTestService(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()

	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "access.db")
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := gormDB.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("seed builtins: %v", err)
	}
	engine, err := policy.NewEngine(gormDB, true)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	svc := New(gormDB, engine, "test-pepper", 5*time.Second, NewVerifyCache(0), zap.NewNop())
	return svc, gormDB
}

func dAdminCtx(tier actor.Tier, action, targetType, targetID string) context.Context {
	keyID := uuid.New()
	ctx := actor.With(context.Background(), actor.Actor{
		KeyID: &keyID,
		Name:  "track-d-actor",
		Tier:  tier,
		IP:    "127.0.0.1",
	})
	return actor.WithOp(ctx, &actor.Op{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
	})
}

func dTakeAccessSnapshot(t *testing.T, gormDB *gorm.DB) dAccessSnapshot {
	t.Helper()

	var snap dAccessSnapshot
	if err := gormDB.Order("name asc").Find(&snap.Roles).Error; err != nil {
		t.Fatalf("snapshot roles: %v", err)
	}
	if err := gormDB.Order("name asc").Find(&snap.Relays).Error; err != nil {
		t.Fatalf("snapshot relays: %v", err)
	}
	if err := gormDB.Order("id asc").Find(&snap.Rules).Error; err != nil {
		t.Fatalf("snapshot casbin_rule: %v", err)
	}
	v, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("snapshot version: %v", err)
	}
	snap.Version = v
	if err := gormDB.Model(&model.AdminAuditLog{}).Count(&snap.AuditCount).Error; err != nil {
		t.Fatalf("snapshot audit count: %v", err)
	}
	return snap
}

func TestAccessMutationsAreAtomic(t *testing.T) {
	forcedErr := errors.New("forced admin audit failure")

	cases := []struct {
		name string
		run  func(t *testing.T, svc *Service, userID uuid.UUID) error
	}{
		{
			name: "create_relay",
			run: func(t *testing.T, svc *Service, _ uuid.UUID) error {
				_, err := svc.CreateRelay(dAdminCtx(actor.TierAdmin, "relay.create", "relay", ""), CreateRelayInput{
					Name:        "ap-1",
					Description: "Asia Pacific",
				})
				return err
			},
		},
		{
			name: "delete_relay",
			run: func(t *testing.T, svc *Service, _ uuid.UUID) error {
				return svc.DeleteRelay(dAdminCtx(actor.TierAdmin, "relay.delete", "relay", "eu-1"), "eu-1")
			},
		},
		{
			name: "create_role",
			run: func(t *testing.T, svc *Service, _ uuid.UUID) error {
				_, err := svc.CreateRole(dAdminCtx(actor.TierAdmin, "role.create", "role", ""), CreateRoleInput{
					Name:        "eng",
					Description: "Engineering",
					Relays:      []string{"default", "eu-1"},
				})
				return err
			},
		},
		{
			name: "set_role_relays",
			run: func(t *testing.T, svc *Service, _ uuid.UUID) error {
				_, err := svc.SetRoleRelays(dAdminCtx(actor.TierAdmin, "role.grants.set", "role", "ops"), "ops", []string{"*"})
				return err
			},
		},
		{
			name: "delete_role",
			run: func(t *testing.T, svc *Service, _ uuid.UUID) error {
				_, err := svc.DeleteRole(dAdminCtx(actor.TierAdmin, "role.delete", "role", "ops"), "ops")
				return err
			},
		},
		{
			name: "set_user_roles",
			run: func(t *testing.T, svc *Service, userID uuid.UUID) error {
				_, err := svc.SetUserRoles(dAdminCtx(actor.TierOperator, "user.roles.set", "user", userID.String()), userID, []string{"standard"})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, gormDB := dNewAccessTestService(t)

			// Seed baseline state: relay eu-1, role ops granted eu-1, user bound to ops.
			if _, err := svc.CreateRelay(context.Background(), CreateRelayInput{Name: "eu-1", Description: "Europe"}); err != nil {
				t.Fatalf("seed relay eu-1: %v", err)
			}
			if _, err := svc.CreateRole(context.Background(), CreateRoleInput{
				Name:   "ops",
				Relays: []string{"eu-1"},
			}); err != nil {
				t.Fatalf("seed role ops: %v", err)
			}
			user, err := svc.CreateUser(context.Background(), CreateUserInput{
				Username: "atomic-user",
				Roles:    &[]string{"ops"},
			})
			if err != nil {
				t.Fatalf("seed user: %v", err)
			}

			before := dTakeAccessSnapshot(t, gormDB)

			cbName := "d_fail_admin_audit_" + tc.name
			if err := gormDB.Callback().Create().Before("gorm:create").Register(cbName, func(tx *gorm.DB) {
				if tx.Statement != nil && tx.Statement.Table == "admin_audit_logs" {
					_ = tx.AddError(forcedErr)
				}
			}); err != nil {
				t.Fatalf("register callback: %v", err)
			}
			defer func() {
				_ = gormDB.Callback().Create().Remove(cbName)
			}()

			err = tc.run(t, svc, user.ID)
			if !errors.Is(err, forcedErr) {
				t.Fatalf("%s err=%v want %v", tc.name, err, forcedErr)
			}

			after := dTakeAccessSnapshot(t, gormDB)
			if !reflect.DeepEqual(before.Roles, after.Roles) {
				t.Fatalf("roles changed on rollback:\nbefore=%+v\nafter=%+v", before.Roles, after.Roles)
			}
			if !reflect.DeepEqual(before.Relays, after.Relays) {
				t.Fatalf("relays changed on rollback:\nbefore=%+v\nafter=%+v", before.Relays, after.Relays)
			}
			if !reflect.DeepEqual(before.Rules, after.Rules) {
				t.Fatalf("casbin_rule changed on rollback:\nbefore=%+v\nafter=%+v", before.Rules, after.Rules)
			}
			if before.Version != after.Version {
				t.Fatalf("policy version changed on rollback: before=%d after=%d", before.Version, after.Version)
			}
			if before.AuditCount != after.AuditCount {
				t.Fatalf("audit count changed on rollback: before=%d after=%d", before.AuditCount, after.AuditCount)
			}
		})
	}
}

func TestAccessIdempotentNoopAuditsWithoutVersionBump(t *testing.T) {
	svc, gormDB := dNewAccessTestService(t)

	if _, err := svc.CreateRelay(context.Background(), CreateRelayInput{Name: "eu-1"}); err != nil {
		t.Fatalf("create relay eu-1: %v", err)
	}
	if _, err := svc.CreateRole(context.Background(), CreateRoleInput{
		Name:   "ops",
		Relays: []string{"default", "eu-1"},
	}); err != nil {
		t.Fatalf("create role ops: %v", err)
	}
	if _, err := svc.CreateRole(context.Background(), CreateRoleInput{
		Name:   "all-access",
		Relays: []string{"*"},
	}); err != nil {
		t.Fatalf("create role all-access: %v", err)
	}
	if _, err := svc.CreateRole(context.Background(), CreateRoleInput{
		Name: "empty-role",
	}); err != nil {
		t.Fatalf("create role empty-role: %v", err)
	}
	user, err := svc.CreateUser(context.Background(), CreateUserInput{
		Username: "noop-user",
		Roles:    &[]string{"ops", "standard"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	v0, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v0: %v", err)
	}

	// 1. SetRoleRelays with identical named grants (reordered + duplicate) is a no-op.
	gotRelays, err := svc.SetRoleRelays(dAdminCtx(actor.TierAdmin, "role.grants.set", "role", "ops"), "ops", []string{"eu-1", "default", "eu-1"})
	if err != nil {
		t.Fatalf("noop SetRoleRelays named: %v", err)
	}
	if !reflect.DeepEqual(gotRelays, []string{"default", "eu-1"}) {
		t.Fatalf("gotRelays=%v want=[default eu-1]", gotRelays)
	}

	// 2. SetRoleRelays with identical wildcard ["*"] is a no-op.
	gotWild, err := svc.SetRoleRelays(dAdminCtx(actor.TierAdmin, "role.grants.set", "role", "all-access"), "all-access", []string{"*"})
	if err != nil {
		t.Fatalf("noop SetRoleRelays wildcard: %v", err)
	}
	if !reflect.DeepEqual(gotWild, []string{"*"}) {
		t.Fatalf("gotWild=%v want=[*]", gotWild)
	}

	// 3. SetRoleRelays with identical empty [] is a no-op.
	gotEmpty, err := svc.SetRoleRelays(dAdminCtx(actor.TierAdmin, "role.grants.set", "role", "empty-role"), "empty-role", []string{})
	if err != nil {
		t.Fatalf("noop SetRoleRelays empty: %v", err)
	}
	if len(gotEmpty) != 0 {
		t.Fatalf("gotEmpty=%v want=[]", gotEmpty)
	}

	// 4. SetUserRoles with identical roles (reordered + duplicate) is a no-op.
	gotRoles, err := svc.SetUserRoles(dAdminCtx(actor.TierOperator, "user.roles.set", "user", user.ID.String()), user.ID, []string{"standard", "ops", "standard"})
	if err != nil {
		t.Fatalf("noop SetUserRoles: %v", err)
	}
	if !reflect.DeepEqual(gotRoles, []string{"ops", "standard"}) {
		t.Fatalf("gotRoles=%v want=[ops standard]", gotRoles)
	}

	v1, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v1: %v", err)
	}
	if v1 != v0 {
		t.Fatalf("policy version bumped on idempotent no-ops: got=%d want=%d", v1, v0)
	}

	var audits []model.AdminAuditLog
	if err := gormDB.Order("id asc").Find(&audits).Error; err != nil {
		t.Fatalf("query admin_audit_logs: %v", err)
	}
	if len(audits) != 4 {
		t.Fatalf("audit row count=%d want=4 (one per no-op call)", len(audits))
	}
	for _, row := range audits {
		if row.Outcome != AuditOutcomeSuccess {
			t.Fatalf("noop audit outcome=%q want=%q", row.Outcome, AuditOutcomeSuccess)
		}
		var summary map[string]any
		if err := json.Unmarshal([]byte(row.Summary), &summary); err != nil {
			t.Fatalf("unmarshal audit summary %q: %v", row.Summary, err)
		}
		if len(summary) == 0 {
			t.Fatalf("expected non-empty summary for action %q", row.Action)
		}
	}

	// A real change bumps the version by 1.
	if _, err := svc.SetRoleRelays(dAdminCtx(actor.TierAdmin, "role.grants.set", "role", "ops"), "ops", []string{"eu-1"}); err != nil {
		t.Fatalf("real SetRoleRelays: %v", err)
	}
	v2, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v2: %v", err)
	}
	if v2 != v0+1 {
		t.Fatalf("policy version after real change=%d want=%d", v2, v0+1)
	}
}

func TestAccessListRolesGrantsBatch(t *testing.T) {
	svc, _ := dNewAccessTestService(t)

	if _, err := svc.CreateRelay(context.Background(), CreateRelayInput{Name: "eu-1"}); err != nil {
		t.Fatalf("create relay eu-1: %v", err)
	}
	if _, err := svc.CreateRole(context.Background(), CreateRoleInput{Name: "r-empty"}); err != nil {
		t.Fatalf("create r-empty: %v", err)
	}
	if _, err := svc.CreateRole(context.Background(), CreateRoleInput{Name: "r-named", Relays: []string{"eu-1", "default"}}); err != nil {
		t.Fatalf("create r-named: %v", err)
	}
	if _, err := svc.CreateRole(context.Background(), CreateRoleInput{Name: "r-wild", Relays: []string{"*"}}); err != nil {
		t.Fatalf("create r-wild: %v", err)
	}

	req, err := page.Parse("roles", "", "")
	if err != nil {
		t.Fatalf("page.Parse: %v", err)
	}
	roles, nextCursor, err := svc.ListRoles(context.Background(), req)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if nextCursor != nil {
		t.Fatalf("expected nil nextCursor, got %q", *nextCursor)
	}

	got := make(map[string][]string, len(roles))
	for _, r := range roles {
		got[r.Role.Name] = r.Relays
	}
	want := map[string][]string{
		"standard": {"default"},
		"r-empty":  {},
		"r-named":  {"default", "eu-1"},
		"r-wild":   {"*"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListRoles grants=%v want=%v", got, want)
	}
}
