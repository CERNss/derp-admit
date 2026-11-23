package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func newMutationTestService(t *testing.T, cacheTTL time.Duration) (*Service, *gorm.DB) {
	t.Helper()

	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "mutation.db")
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
	svc := New(gormDB, engine, "test-pepper", 5*time.Second, NewVerifyCache(cacheTTL), zap.NewNop())
	return svc, gormDB
}

func testAdminCtx(action, targetType, targetID string) context.Context {
	keyID := uuid.New()
	ctx := actor.With(context.Background(), actor.Actor{
		KeyID: &keyID,
		Name:  "test-operator",
		Tier:  actor.TierOperator,
		IP:    "127.0.0.1",
	})
	return actor.WithOp(ctx, &actor.Op{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
	})
}

func TestMutateAtomicRollback(t *testing.T) {
	svc, gormDB := newMutationTestService(t, 0)

	forcedErr := errors.New("forced admin audit failure")
	if err := gormDB.Callback().Create().Before("gorm:create").Register("test_fail_admin_audit", func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "admin_audit_logs" {
			_ = tx.AddError(forcedErr)
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	defer func() {
		_ = gormDB.Callback().Create().Remove("test_fail_admin_audit")
	}()

	ctx := testAdminCtx("user.create", "user", "")
	if _, err := svc.CreateUser(ctx, CreateUserInput{Username: "rollback-user"}); !errors.Is(err, forcedErr) {
		t.Fatalf("CreateUser err=%v want %v", err, forcedErr)
	}

	var userCount int64
	if err := gormDB.Model(&model.User{}).Where("username = ?", "rollback-user").Count(&userCount).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 0 {
		t.Fatalf("user count=%d want=0 (change must roll back when audit insert fails)", userCount)
	}

	var auditCount int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Count(&auditCount).Error; err != nil {
		t.Fatalf("count admin audit rows: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("admin audit count=%d want=0", auditCount)
	}
}

func TestMutateNoopAuditsWithoutBump(t *testing.T) {
	svc, gormDB := newMutationTestService(t, 0)

	user, err := svc.CreateUser(testAdminCtx("user.create", "user", ""), CreateUserInput{Username: "noop-user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	v0, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v0: %v", err)
	}

	// Enabling an already-enabled user is an idempotent no-op: writes an audit
	// row, does not bump the policy version.
	if err := svc.SetUserDisabled(testAdminCtx("user.enable", "user", user.ID.String()), user.ID, false); err != nil {
		t.Fatalf("noop enable user: %v", err)
	}

	v1, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v1: %v", err)
	}
	if v1 != v0 {
		t.Fatalf("version bumped on noop: got=%d want=%d", v1, v0)
	}

	var auditCount int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Where("action = ?", "user.enable").Count(&auditCount).Error; err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("noop audit count=%d want=1", auditCount)
	}

	// Disabling the user actually changes state and bumps the version.
	if err := svc.SetUserDisabled(testAdminCtx("user.disable", "user", user.ID.String()), user.ID, true); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	v2, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v2: %v", err)
	}
	if v2 != v0+1 {
		t.Fatalf("version after real change: got=%d want=%d", v2, v0+1)
	}
}

func TestPolicyVersionUnchangedOnRollback(t *testing.T) {
	svc, gormDB := newMutationTestService(t, 0)

	user, err := svc.CreateUser(context.Background(), CreateUserInput{Username: "v-rollback-user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	v0, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v0: %v", err)
	}

	forcedErr := errors.New("audit insert failed")
	if err := gormDB.Callback().Create().Before("gorm:create").Register("test_fail_audit_version", func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "admin_audit_logs" {
			_ = tx.AddError(forcedErr)
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	defer func() {
		_ = gormDB.Callback().Create().Remove("test_fail_audit_version")
	}()

	// Case 1: Mutate with a non-EffectNone effect executes BumpVersion inside the
	// transaction, then fails on the admin audit insert and rolls back.
	if err := svc.Mutate(testAdminCtx("test.effect", "user", user.ID.String()), EffectCache, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		ch.Changed = true
		return nil
	}); !errors.Is(err, forcedErr) {
		t.Fatalf("Mutate err=%v want %v", err, forcedErr)
	}

	v1, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v1: %v", err)
	}
	if v1 != v0 {
		t.Fatalf("version changed after post-bump audit rollback: got=%d want=%d", v1, v0)
	}

	// Case 2: real admin mutation (SetUserDisabled, EffectCache) bumps version inside
	// tx, then fails on the admin audit insert and rolls back both the update and version.
	if err := svc.SetUserDisabled(testAdminCtx("user.disable", "user", user.ID.String()), user.ID, true); !errors.Is(err, forcedErr) {
		t.Fatalf("SetUserDisabled err=%v want %v", err, forcedErr)
	}

	v2, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v2: %v", err)
	}
	if v2 != v0 {
		t.Fatalf("version changed after SetUserDisabled rollback: got=%d want=%d", v2, v0)
	}
	var reloaded model.User
	if err := gormDB.First(&reloaded, "id = ?", user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.DisabledAt != nil {
		t.Fatalf("expected user.DisabledAt to remain nil after rollback")
	}
}

func TestMutateConcurrentWithVerifySQLite(t *testing.T) {
	svc, gormDB := newMutationTestService(t, time.Minute)

	user, err := svc.CreateUser(context.Background(), CreateUserInput{Username: "race-verify-user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	nodePub := key.NewNode().Public()
	body, err := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: nodePub})
	if err != nil {
		t.Fatalf("marshal verify request: %v", err)
	}

	device := model.Device{
		ID:      uuid.New(),
		UserID:  user.ID,
		NodeKey: nodePub.String(),
	}
	if err := gormDB.Create(&device).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	const iterations = 25
	var wg sync.WaitGroup
	errCh := make(chan error, 4*iterations)

	// Mutator 1: toggle device revocation.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			ctx := testAdminCtx("device.toggle", "device", device.ID.String())
			if err := svc.SetDeviceRevoked(ctx, device.ID, i%2 == 0); err != nil {
				errCh <- err
			}
		}
	}()

	// Mutator 2: toggle user disabled state.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			ctx := testAdminCtx("user.toggle", "user", user.ID.String())
			if err := svc.SetUserDisabled(ctx, user.ID, i%2 == 0); err != nil {
				errCh <- err
			}
		}
	}()

	// Concurrent verifiers reading DB and writing audit logs.
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, reason := svc.Verify(context.Background(), "default", body)
				if reason == DenyReasonInternal {
					errCh <- errors.New("verify returned internal error under sqlite contention")
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent mutate/verify error: %v", err)
	}

	// After all mutations complete, no cached decision may contradict final DB state.
	var finalUser model.User
	if err := gormDB.First(&finalUser, "id = ?", user.ID).Error; err != nil {
		t.Fatalf("load final user: %v", err)
	}
	var finalDevice model.Device
	if err := gormDB.First(&finalDevice, "id = ?", device.ID).Error; err != nil {
		t.Fatalf("load final device: %v", err)
	}

	wantAllow := true
	wantReason := ""
	switch {
	case finalDevice.RevokedAt != nil:
		wantAllow = false
		wantReason = DenyReasonRevoked
	case finalUser.DisabledAt != nil:
		wantAllow = false
		wantReason = DenyReasonUserDisabled
	}

	allow, reason := svc.Verify(context.Background(), "default", body)
	if allow != wantAllow || reason != wantReason {
		t.Fatalf("post-race verify=(%v, %q) contradicts final DB state (revoked=%v disabled=%v) want=(%v, %q)",
			allow, reason, finalDevice.RevokedAt != nil, finalUser.DisabledAt != nil, wantAllow, wantReason)
	}
}
