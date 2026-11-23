package policy_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestSeedBuiltinsIdempotent(t *testing.T) {
	dbConn := openPolicyTestDB(t)

	var created1, created2 bool
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		var err error
		created1, err = policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("SeedBuiltins #1: %v", err)
	}
	if !created1 {
		t.Fatalf("expected created=true on first seed")
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		var err error
		created2, err = policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("SeedBuiltins #2: %v", err)
	}
	if created2 {
		t.Fatalf("expected created=false on second seed")
	}

	var relayCount, roleCount, grantCount int64
	if err := dbConn.Model(&model.Relay{}).Where("name = ?", policy.BuiltinRelay).Count(&relayCount).Error; err != nil {
		t.Fatalf("count default relay: %v", err)
	}
	if err := dbConn.Model(&model.Role{}).Where("name = ?", policy.BuiltinRole).Count(&roleCount).Error; err != nil {
		t.Fatalf("count standard role: %v", err)
	}
	if err := dbConn.Model(&model.CasbinRule{}).
		Where("ptype = ? AND v0 = ? AND v1 = ? AND v2 = ?", "p", "role:standard", "derp:default", "connect").
		Count(&grantCount).Error; err != nil {
		t.Fatalf("count standard grant: %v", err)
	}
	if relayCount != 1 || roleCount != 1 || grantCount != 1 {
		t.Fatalf("counts relay=%d role=%d grant=%d want 1,1,1", relayCount, roleCount, grantCount)
	}
}

func TestSeedKeepsEditedStandardGrants(t *testing.T) {
	dbConn := openPolicyTestDB(t)

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("SeedBuiltins #1: %v", err)
	}

	if err := dbConn.Create(&model.Relay{Name: "eu-1"}).Error; err != nil {
		t.Fatalf("create relay eu-1: %v", err)
	}
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, policy.BuiltinRole, []string{"eu-1"})
	}); err != nil {
		t.Fatalf("SetRoleGrants standard -> [eu-1]: %v", err)
	}

	// Re-seeding on restart must not restore default onto standard.
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("SeedBuiltins #2: %v", err)
	}

	grants, err := policy.RoleGrants(context.Background(), dbConn, []string{policy.BuiltinRole})
	if err != nil {
		t.Fatalf("RoleGrants: %v", err)
	}
	if !reflect.DeepEqual(grants[policy.BuiltinRole], []string{"eu-1"}) {
		t.Fatalf("standard grants=%v want=[eu-1]", grants[policy.BuiltinRole])
	}
}

func TestEnforceRoleGrantOnRelay(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Relay{Name: "eu-1"}).Error; err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := dbConn.Create(&model.Role{Name: "ops"}).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}

	userID := uuid.New()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		if err := policy.SetRoleGrants(tx, "ops", []string{"eu-1"}); err != nil {
			return err
		}
		return policy.SetUserRoles(tx, userID, []string{"ops"})
	}); err != nil {
		t.Fatalf("setup grants/bindings: %v", err)
	}

	// Verify NewEngine ignores enabled=false and always enforces.
	engine, err := policy.NewEngine(dbConn, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	allowed, err := engine.Enforce(policy.Request{UserID: userID, Relay: "eu-1"})
	if err != nil || !allowed {
		t.Fatalf("enforce eu-1: allowed=%v err=%v want true, nil", allowed, err)
	}
	allowed, err = engine.Enforce(policy.Request{UserID: userID, Relay: "default"})
	if err != nil || allowed {
		t.Fatalf("enforce default: allowed=%v err=%v want false, nil", allowed, err)
	}
}

func TestEnforceWildcardGrant(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Role{Name: "global"}).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}
	userID := uuid.New()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		if err := policy.SetRoleGrants(tx, "global", []string{"*"}); err != nil {
			return err
		}
		return policy.SetUserRoles(tx, userID, []string{"global"})
	}); err != nil {
		t.Fatalf("set wildcard grant: %v", err)
	}

	engine, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Add a new relay AFTER the role was created and granted "*".
	if err := dbConn.Create(&model.Relay{Name: "ap-1"}).Error; err != nil {
		t.Fatalf("create relay ap-1: %v", err)
	}
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	for _, relay := range []string{"default", "ap-1"} {
		allowed, err := engine.Enforce(policy.Request{UserID: userID, Relay: relay})
		if err != nil || !allowed {
			t.Fatalf("enforce %s: allowed=%v err=%v want true, nil", relay, allowed, err)
		}
	}
	// An unregistered relay must still be denied.
	allowed, err := engine.Enforce(policy.Request{UserID: userID, Relay: "unknown-1"})
	if err != nil || allowed {
		t.Fatalf("enforce unregistered relay: allowed=%v err=%v want false, nil", allowed, err)
	}
}

func TestEnforceUserWithoutRoleDenied(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	engine, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	allowed, err := engine.Enforce(policy.Request{UserID: uuid.New(), Relay: "default"})
	if err != nil || allowed {
		t.Fatalf("unbound user enforce: allowed=%v err=%v want false, nil", allowed, err)
	}
}

func TestEnforceIgnoresDirectAndDeviceRules(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Role{Name: "role-a"}).Error; err != nil {
		t.Fatalf("create role-a: %v", err)
	}
	if err := dbConn.Create(&model.Role{Name: "role-b"}).Error; err != nil {
		t.Fatalf("create role-b: %v", err)
	}

	userDirect := uuid.New()
	userInherited := uuid.New()
	userWrongAct := uuid.New()
	nodeKey := "nodekey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Insert unmanaged rules directly into casbin_rule:
	unmanaged := []model.CasbinRule{
		// Direct p on user subject.
		{Ptype: "p", V0: policy.UserSubject(userDirect), V1: "derp:default", V2: "connect"},
		// Direct p on device subject + legacy device grouping.
		{Ptype: "p", V0: "device:" + nodeKey, V1: "derp:default", V2: "connect"},
		{Ptype: "g", V0: "device:" + nodeKey, V1: policy.UserSubject(userDirect)},
		// Role-to-role inheritance (role-a -> standard which has default).
		{Ptype: "g", V0: "role:role-a", V1: "role:standard"},
		{Ptype: "g", V0: policy.UserSubject(userInherited), V1: "role:role-a"},
		// Non-connect action on role-b.
		{Ptype: "p", V0: "role:role-b", V1: "derp:default", V2: "admin"},
		{Ptype: "g", V0: policy.UserSubject(userWrongAct), V1: "role:role-b"},
	}
	if err := dbConn.Create(&unmanaged).Error; err != nil {
		t.Fatalf("insert unmanaged rules: %v", err)
	}

	engine, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	for name, req := range map[string]policy.Request{
		"direct_user_and_device": {UserID: userDirect, NodeKey: nodeKey, Relay: "default"},
		"role_to_role_inherit":   {UserID: userInherited, Relay: "default"},
		"other_action":           {UserID: userWrongAct, Relay: "default"},
	} {
		allowed, err := engine.Enforce(req)
		if err != nil || allowed {
			t.Fatalf("%s: allowed=%v err=%v want false, nil", name, allowed, err)
		}
	}

	// All unmanaged rows remain untouched in casbin_rule.
	var count int64
	if err := dbConn.Model(&model.CasbinRule{}).Count(&count).Error; err != nil {
		t.Fatalf("count casbin_rule: %v", err)
	}
	if count != int64(len(unmanaged)+1) { // +1 for standard -> default seed
		t.Fatalf("casbin_rule count=%d want=%d", count, len(unmanaged)+1)
	}
}

func TestEnforceIgnoresStoredWildcardRule(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Role{Name: "legacy-wild", AllRelays: false}).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}
	userID := uuid.New()
	if err := dbConn.Create(&model.CasbinRule{
		Ptype: "p", V0: "role:legacy-wild", V1: "derp:*", V2: "connect",
	}).Error; err != nil {
		t.Fatalf("insert stored wildcard rule: %v", err)
	}
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetUserRoles(tx, userID, []string{"legacy-wild"})
	}); err != nil {
		t.Fatalf("bind user: %v", err)
	}

	engine, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	allowed, err := engine.Enforce(policy.Request{UserID: userID, Relay: "default"})
	if err != nil || allowed {
		t.Fatalf("stored derp:* rule allowed=%v err=%v want false, nil", allowed, err)
	}
}

func TestRuleFunctions(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	for _, r := range []string{"eu-1", "us-1"} {
		if err := dbConn.Create(&model.Relay{Name: r}).Error; err != nil {
			t.Fatalf("create relay %s: %v", r, err)
		}
	}
	for _, r := range []string{"ops", "eng"} {
		if err := dbConn.Create(&model.Role{Name: r}).Error; err != nil {
			t.Fatalf("create role %s: %v", r, err)
		}
	}

	// SetRoleGrants: named relays, wildcard alone, wildcard mixed, unknown relay.
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "ops", []string{"us-1", "eu-1", "eu-1"})
	}); err != nil {
		t.Fatalf("SetRoleGrants named: %v", err)
	}
	grants, err := policy.RoleGrants(context.Background(), dbConn, []string{"ops"})
	if err != nil {
		t.Fatalf("RoleGrants named: %v", err)
	}
	if !reflect.DeepEqual(grants["ops"], []string{"eu-1", "us-1"}) {
		t.Fatalf("ops grants=%v want=[eu-1 us-1]", grants["ops"])
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "ops", []string{"*", "eu-1"})
	}); !errors.Is(err, policy.ErrInvalidGrant) {
		t.Fatalf("mixed wildcard err=%v want ErrInvalidGrant", err)
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "ops", []string{"no-such-relay"})
	}); !errors.Is(err, policy.ErrUnknownRelay) {
		t.Fatalf("unknown relay err=%v want ErrUnknownRelay", err)
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "ops", []string{"*"})
	}); err != nil {
		t.Fatalf("SetRoleGrants wildcard: %v", err)
	}
	grants, err = policy.RoleGrants(context.Background(), dbConn, []string{"ops"})
	if err != nil {
		t.Fatalf("RoleGrants wildcard: %v", err)
	}
	if !reflect.DeepEqual(grants["ops"], []string{"*"}) {
		t.Fatalf("ops wildcard grants=%v want=[*]", grants["ops"])
	}

	// Switch back to named grants for DeleteRelayGrants check.
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "ops", []string{"eu-1", "us-1"})
	}); err != nil {
		t.Fatalf("SetRoleGrants switch back: %v", err)
	}

	// SetUserRoles & UserRoles (including unknown role error).
	u1, u2 := uuid.New(), uuid.New()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetUserRoles(tx, u1, []string{"no-such-role"})
	}); !errors.Is(err, policy.ErrUnknownRole) {
		t.Fatalf("SetUserRoles unknown err=%v want ErrUnknownRole", err)
	}
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		if err := policy.SetUserRoles(tx, u1, []string{"ops", "eng"}); err != nil {
			return err
		}
		return policy.SetUserRoles(tx, u2, []string{"ops"})
	}); err != nil {
		t.Fatalf("SetUserRoles valid: %v", err)
	}
	rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{u1, u2})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[u1], []string{"eng", "ops"}) || !reflect.DeepEqual(rolesMap[u2], []string{"ops"}) {
		t.Fatalf("UserRoles got=%v", rolesMap)
	}

	// DeleteRelayGrants refuses builtin and deletes named relay grants.
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.DeleteRelayGrants(tx, policy.BuiltinRelay)
	}); !errors.Is(err, policy.ErrBuiltin) {
		t.Fatalf("DeleteRelayGrants builtin err=%v want ErrBuiltin", err)
	}
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.DeleteRelayGrants(tx, "eu-1")
	}); err != nil {
		t.Fatalf("DeleteRelayGrants eu-1: %v", err)
	}
	grants, err = policy.RoleGrants(context.Background(), dbConn, []string{"ops"})
	if err != nil {
		t.Fatalf("RoleGrants after DeleteRelayGrants: %v", err)
	}
	if !reflect.DeepEqual(grants["ops"], []string{"us-1"}) {
		t.Fatalf("ops grants after eu-1 delete=%v want=[us-1]", grants["ops"])
	}

	// DeleteRoleRules refuses builtin and returns binding count (2 users bound to ops).
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		_, err := policy.DeleteRoleRules(tx, policy.BuiltinRole)
		return err
	}); !errors.Is(err, policy.ErrBuiltin) {
		t.Fatalf("DeleteRoleRules builtin err=%v want ErrBuiltin", err)
	}
	var removed int64
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		var err error
		removed, err = policy.DeleteRoleRules(tx, "ops")
		return err
	}); err != nil {
		t.Fatalf("DeleteRoleRules ops: %v", err)
	}
	if removed != 2 {
		t.Fatalf("DeleteRoleRules removed=%d want=2", removed)
	}

	// DeleteLegacyDeviceRule & DeleteUserRules.
	nk1 := "nodekey:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	nk2 := "nodekey:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := dbConn.Create(&[]model.CasbinRule{
		{Ptype: "g", V0: "device:" + nk1, V1: policy.UserSubject(u1)},
		{Ptype: "g", V0: "device:" + nk2, V1: policy.UserSubject(u1)},
	}).Error; err != nil {
		t.Fatalf("seed legacy device rules: %v", err)
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.DeleteLegacyDeviceRule(tx, nk1, u1)
	}); err != nil {
		t.Fatalf("DeleteLegacyDeviceRule: %v", err)
	}
	var legacyCount int64
	if err := dbConn.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ?", "g", "device:"+nk1).Count(&legacyCount).Error; err != nil {
		t.Fatalf("count legacy nk1: %v", err)
	}
	if legacyCount != 0 {
		t.Fatalf("legacy rule nk1 still exists")
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.DeleteUserRules(tx, u1, []string{nk2})
	}); err != nil {
		t.Fatalf("DeleteUserRules: %v", err)
	}
	if err := dbConn.Model(&model.CasbinRule{}).
		Where("v0 = ? OR v0 = ?", policy.UserSubject(u1), "device:"+nk2).
		Count(&legacyCount).Error; err != nil {
		t.Fatalf("count remaining u1 rules: %v", err)
	}
	if legacyCount != 0 {
		t.Fatalf("remaining u1 rules=%d want=0", legacyCount)
	}
}

func seedBuiltins(t *testing.T, dbConn *gorm.DB) {
	t.Helper()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("seed builtins: %v", err)
	}
}

func openPolicyTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "policy.db")
	dbURL := "sqlite://" + dbPath

	conn, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), conn, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	return conn
}
