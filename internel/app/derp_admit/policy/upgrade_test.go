package policy_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/casbin/casbin/v3"
	casbinmodel "github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
)

const aOldCasbinModelText = `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

func aOpenDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "upgrade.db")
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return gormDB
}

func aSeedBuiltins(t *testing.T, dbConn *gorm.DB) {
	t.Helper()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("SeedBuiltins: %v", err)
	}
}

func aNewObservedLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zap.WarnLevel)
	return zap.New(core), logs
}

func aCreateUser(t *testing.T, dbConn *gorm.DB, username string, disabled bool) model.User {
	t.Helper()
	var disabledAt *time.Time
	if disabled {
		now := time.Now().UTC()
		disabledAt = &now
	}
	u := model.User{
		ID:         uuid.New(),
		Username:   username,
		DisabledAt: disabledAt,
	}
	if err := dbConn.Create(&u).Error; err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return u
}

func aCreateDevice(t *testing.T, dbConn *gorm.DB, userID uuid.UUID, nodeKey string, revoked bool) model.Device {
	t.Helper()
	var revokedAt *time.Time
	if revoked {
		now := time.Now().UTC()
		revokedAt = &now
	}
	d := model.Device{
		ID:        uuid.New(),
		UserID:    userID,
		NodeKey:   nodeKey,
		RevokedAt: revokedAt,
	}
	if err := dbConn.Create(&d).Error; err != nil {
		t.Fatalf("create device %s: %v", nodeKey, err)
	}
	return d
}

func aInsertRules(t *testing.T, dbConn *gorm.DB, rules ...model.CasbinRule) {
	t.Helper()
	if len(rules) == 0 {
		return
	}
	if err := dbConn.Create(&rules).Error; err != nil {
		t.Fatalf("insert casbin rules: %v", err)
	}
}

func aBuildOldEnforcer(t *testing.T, dbConn *gorm.DB) *casbin.Enforcer {
	t.Helper()

	m, err := casbinmodel.NewModelFromString(aOldCasbinModelText)
	if err != nil {
		t.Fatalf("build old casbin model: %v", err)
	}

	var rows []model.CasbinRule
	if err := dbConn.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("read raw casbin_rule rows: %v", err)
	}
	for _, r := range rows {
		parts := []string{r.Ptype, r.V0, r.V1, r.V2, r.V3, r.V4, r.V5}
		end := len(parts)
		for end > 1 && parts[end-1] == "" {
			end--
		}
		line := strings.Join(parts[:end], ", ")
		if err := persist.LoadPolicyLine(line, m); err != nil {
			// Skip malformed lines that gorm-adapter/Casbin could not load.
			continue
		}
	}

	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("new old casbin enforcer: %v", err)
	}
	enforcer.EnableAutoSave(false)
	if err := enforcer.BuildRoleLinks(); err != nil {
		t.Fatalf("build old casbin role links: %v", err)
	}
	return enforcer
}

func aEvalOldVerify(t *testing.T, oldEnf *casbin.Enforcer, casbinWasDisabled bool, u model.User, d model.Device) bool {
	t.Helper()
	if d.RevokedAt != nil || u.DisabledAt != nil {
		return false
	}
	if casbinWasDisabled {
		return true
	}
	allowed, err := oldEnf.Enforce("device:"+d.NodeKey, "derp:default", "connect")
	if err != nil {
		t.Fatalf("old enforce device %s: %v", d.NodeKey, err)
	}
	return allowed
}

func aEvalNewVerify(t *testing.T, dbConn *gorm.DB, eng *policy.Engine, deviceID uuid.UUID) bool {
	t.Helper()
	var d model.Device
	if err := dbConn.First(&d, "id = ?", deviceID).Error; err != nil {
		t.Fatalf("reload device %s: %v", deviceID, err)
	}
	if d.RevokedAt != nil {
		return false
	}
	var u model.User
	if err := dbConn.First(&u, "id = ?", d.UserID).Error; err != nil {
		t.Fatalf("reload user %s: %v", d.UserID, err)
	}
	if u.DisabledAt != nil {
		return false
	}
	allowed, err := eng.Enforce(policy.Request{
		UserID:  d.UserID,
		NodeKey: d.NodeKey,
		Relay:   policy.BuiltinRelay,
	})
	if err != nil {
		t.Fatalf("new enforce device %s: %v", d.NodeKey, err)
	}
	return allowed
}

func aCountRules(t *testing.T, dbConn *gorm.DB) int64 {
	t.Helper()
	var count int64
	if err := dbConn.Model(&model.CasbinRule{}).Count(&count).Error; err != nil {
		t.Fatalf("count casbin_rule: %v", err)
	}
	return count
}

func TestUpgradeKeepsDeviceUserRoleRules(t *testing.T) {
	dbConn := aOpenDB(t)
	u := aCreateUser(t, dbConn, "alice", false)
	nk := "nodekey:alice-1"
	d := aCreateDevice(t, dbConn, u.ID, nk, false)

	aInsertRules(t, dbConn,
		model.CasbinRule{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
		model.CasbinRule{Ptype: "g", V0: "device:" + nk, V1: policy.UserSubject(u.ID)},
		model.CasbinRule{Ptype: "g", V0: policy.UserSubject(u.ID), V1: "role:standard"},
	)

	aSeedBuiltins(t, dbConn)
	logger, _ := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, false, logger); err != nil {
		t.Fatalf("RunUpgrade: %v", err)
	}

	// All three rules must still exist unchanged.
	if got := aCountRules(t, dbConn); got != 3 {
		t.Fatalf("casbin_rule count=%d want=3", got)
	}
	var legacyCount int64
	if err := dbConn.Model(&model.CasbinRule{}).
		Where("ptype = ? AND v0 = ? AND v1 = ?", "g", "device:"+nk, policy.UserSubject(u.ID)).
		Count(&legacyCount).Error; err != nil {
		t.Fatalf("count legacy rule: %v", err)
	}
	if legacyCount != 1 {
		t.Fatalf("legacy rule count=%d want=1", legacyCount)
	}

	eng, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if !aEvalNewVerify(t, dbConn, eng, d.ID) {
		t.Fatalf("expected device to stay allowed after upgrade")
	}
}

func TestUpgradeCasbinDisabledBindsAllUnbound(t *testing.T) {
	dbConn := aOpenDB(t)
	uWithDev := aCreateUser(t, dbConn, "bob", false)
	uNoDev := aCreateUser(t, dbConn, "carol", false)
	d := aCreateDevice(t, dbConn, uWithDev.ID, "nodekey:bob-1", false)

	aSeedBuiltins(t, dbConn)
	logger, _ := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, true, logger); err != nil {
		t.Fatalf("RunUpgrade: %v", err)
	}

	rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{uWithDev.ID, uNoDev.ID})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	for _, id := range []uuid.UUID{uWithDev.ID, uNoDev.ID} {
		if !reflect.DeepEqual(rolesMap[id], []string{policy.BuiltinRole}) {
			t.Fatalf("user %s roles=%v want=[standard]", id, rolesMap[id])
		}
	}

	eng, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if !aEvalNewVerify(t, dbConn, eng, d.ID) {
		t.Fatalf("expected bob's device to be allowed after disabled-mode upgrade")
	}
}

func TestUpgradeCasbinDisabledBindsUserWithRoleLackingDefaultGrant(t *testing.T) {
	dbConn := aOpenDB(t)
	u := aCreateUser(t, dbConn, "dave", false)
	d := aCreateDevice(t, dbConn, u.ID, "nodekey:dave-1", false)

	aInsertRules(t, dbConn,
		model.CasbinRule{Ptype: "p", V0: "role:eu-only", V1: "derp:eu-1", V2: "connect"},
		model.CasbinRule{Ptype: "g", V0: policy.UserSubject(u.ID), V1: "role:eu-only"},
	)

	aSeedBuiltins(t, dbConn)
	logger, _ := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, true, logger); err != nil {
		t.Fatalf("RunUpgrade: %v", err)
	}

	rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{u.ID})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[u.ID], []string{"eu-only", policy.BuiltinRole}) {
		t.Fatalf("dave roles=%v want=[eu-only standard]", rolesMap[u.ID])
	}

	eng, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if !aEvalNewVerify(t, dbConn, eng, d.ID) {
		t.Fatalf("expected dave's device to be allowed on default")
	}
}

func TestUpgradeEnforcedBindsUnboundUserWithoutDevices(t *testing.T) {
	dbConn := aOpenDB(t)
	u := aCreateUser(t, dbConn, "eve", false)

	aSeedBuiltins(t, dbConn)
	logger, logs := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, false, logger); err != nil {
		t.Fatalf("RunUpgrade: %v", err)
	}

	rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{u.ID})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[u.ID], []string{policy.BuiltinRole}) {
		t.Fatalf("eve roles=%v want=[standard]", rolesMap[u.ID])
	}
	if logs.Len() != 0 {
		t.Fatalf("expected no warning logs, got %d", logs.Len())
	}
}

func TestUpgradeEnforcedLeavesUnboundUserWithDevices(t *testing.T) {
	dbConn := aOpenDB(t)
	u := aCreateUser(t, dbConn, "frank", false)
	d := aCreateDevice(t, dbConn, u.ID, "nodekey:frank-1", false)

	aSeedBuiltins(t, dbConn)
	logger, logs := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, false, logger); err != nil {
		t.Fatalf("RunUpgrade: %v", err)
	}

	rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{u.ID})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if len(rolesMap[u.ID]) != 0 {
		t.Fatalf("frank roles=%v want=[]", rolesMap[u.ID])
	}

	// Device stays unrevoked, but verify is denied by policy.
	var reloaded model.Device
	if err := dbConn.First(&reloaded, "id = ?", d.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if reloaded.RevokedAt != nil {
		t.Fatalf("expected uncovered user's device not to be revoked")
	}

	eng, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if aEvalNewVerify(t, dbConn, eng, d.ID) {
		t.Fatalf("expected frank's device to be policy denied")
	}

	if logs.Len() != 1 {
		t.Fatalf("warning log count=%d want=1", logs.Len())
	}
	ctxMap := logs.All()[0].ContextMap()
	if ctxMap["uncovered_user_count"] != int64(1) {
		t.Fatalf("uncovered_user_count=%v want=1", ctxMap["uncovered_user_count"])
	}
	gotIDs, _ := ctxMap["uncovered_user_ids"].([]any)
	if len(gotIDs) != 1 || gotIDs[0] != u.ID.String() {
		t.Fatalf("uncovered_user_ids=%v want=[%s]", ctxMap["uncovered_user_ids"], u.ID)
	}
}

func TestUpgradeEnforcedLeavesUserWithRoleLackingDefaultGrant(t *testing.T) {
	dbConn := aOpenDB(t)
	u := aCreateUser(t, dbConn, "grace", false)
	d := aCreateDevice(t, dbConn, u.ID, "nodekey:grace-1", false)

	aInsertRules(t, dbConn,
		model.CasbinRule{Ptype: "p", V0: "role:eu-only", V1: "derp:eu-1", V2: "connect"},
		model.CasbinRule{Ptype: "g", V0: policy.UserSubject(u.ID), V1: "role:eu-only"},
		model.CasbinRule{Ptype: "g", V0: "device:" + d.NodeKey, V1: policy.UserSubject(u.ID)},
	)

	aSeedBuiltins(t, dbConn)
	logger, logs := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, false, logger); err != nil {
		t.Fatalf("RunUpgrade: %v", err)
	}

	rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{u.ID})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[u.ID], []string{"eu-only"}) {
		t.Fatalf("grace roles=%v want=[eu-only]", rolesMap[u.ID])
	}

	eng, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if aEvalNewVerify(t, dbConn, eng, d.ID) {
		t.Fatalf("expected grace's device to be denied on default")
	}

	if logs.Len() != 1 {
		t.Fatalf("warning log count=%d want=1", logs.Len())
	}
	ctxMap := logs.All()[0].ContextMap()
	if ctxMap["uncovered_user_count"] != int64(1) {
		t.Fatalf("uncovered_user_count=%v want=1", ctxMap["uncovered_user_count"])
	}
}

func TestUpgradeEnforcedRevokesDeviceWithoutLegacyRule(t *testing.T) {
	dbConn := aOpenDB(t)
	u := aCreateUser(t, dbConn, "heidi", false)
	dGood := aCreateDevice(t, dbConn, u.ID, "nodekey:heidi-good", false)
	dMissing := aCreateDevice(t, dbConn, u.ID, "nodekey:heidi-missing", false)

	aInsertRules(t, dbConn,
		model.CasbinRule{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
		model.CasbinRule{Ptype: "g", V0: policy.UserSubject(u.ID), V1: "role:standard"},
		model.CasbinRule{Ptype: "g", V0: "device:" + dGood.NodeKey, V1: policy.UserSubject(u.ID)},
	)

	aSeedBuiltins(t, dbConn)
	logger, logs := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, false, logger); err != nil {
		t.Fatalf("RunUpgrade: %v", err)
	}

	var goodReloaded, missingReloaded model.Device
	if err := dbConn.First(&goodReloaded, "id = ?", dGood.ID).Error; err != nil {
		t.Fatalf("reload dGood: %v", err)
	}
	if err := dbConn.First(&missingReloaded, "id = ?", dMissing.ID).Error; err != nil {
		t.Fatalf("reload dMissing: %v", err)
	}
	if goodReloaded.RevokedAt != nil {
		t.Fatalf("dGood should not be revoked")
	}
	if missingReloaded.RevokedAt == nil {
		t.Fatalf("dMissing should be revoked")
	}

	// Verify system admin audit row.
	var audits []model.AdminAuditLog
	if err := dbConn.Find(&audits).Error; err != nil {
		t.Fatalf("query admin_audit_logs: %v", err)
	}
	if len(audits) != 1 {
		t.Fatalf("audit rows=%d want=1", len(audits))
	}
	row := audits[0]
	if row.ActorKeyID != nil || row.ActorName != actor.System.Name || row.ActorTier != actor.System.Tier.String() {
		t.Fatalf("unexpected actor: keyID=%v name=%q tier=%q", row.ActorKeyID, row.ActorName, row.ActorTier)
	}
	if row.Action != "device.revoke" || row.TargetType != "device" || row.TargetID != dMissing.ID.String() {
		t.Fatalf("unexpected audit target: action=%q type=%q id=%q", row.Action, row.TargetType, row.TargetID)
	}
	if row.Outcome != "success" || row.HTTPStatus != nil {
		t.Fatalf("unexpected audit outcome=%q status=%v", row.Outcome, row.HTTPStatus)
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(row.Summary), &summary); err != nil {
		t.Fatalf("unmarshal summary %q: %v", row.Summary, err)
	}
	if summary["source"] != "policy_upgrade" {
		t.Fatalf("summary=%v want source=policy_upgrade", summary)
	}

	// Verify warning log lists the revoked device id.
	if logs.Len() != 1 {
		t.Fatalf("warning log count=%d want=1", logs.Len())
	}
	ctxMap := logs.All()[0].ContextMap()
	if ctxMap["revoked_device_count"] != int64(1) {
		t.Fatalf("revoked_device_count=%v want=1", ctxMap["revoked_device_count"])
	}
	gotRevoked, _ := ctxMap["revoked_device_ids"].([]any)
	if len(gotRevoked) != 1 || gotRevoked[0] != dMissing.ID.String() {
		t.Fatalf("revoked_device_ids=%v want=[%s]", ctxMap["revoked_device_ids"], dMissing.ID)
	}

	eng, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if !aEvalNewVerify(t, dbConn, eng, dGood.ID) {
		t.Fatalf("expected dGood to be allowed")
	}
	if aEvalNewVerify(t, dbConn, eng, dMissing.ID) {
		t.Fatalf("expected dMissing to be denied while revoked")
	}

	// Clearing revoked_at (as admin re-enable does) makes dMissing allowed.
	if err := dbConn.Model(&model.Device{}).Where("id = ?", dMissing.ID).Update("revoked_at", nil).Error; err != nil {
		t.Fatalf("re-enable dMissing: %v", err)
	}
	if !aEvalNewVerify(t, dbConn, eng, dMissing.ID) {
		t.Fatalf("expected dMissing to be allowed after clearing revoked_at")
	}
}

func TestUpgradeImportsRolesAndRelays(t *testing.T) {
	dbConn := aOpenDB(t)
	u := aCreateUser(t, dbConn, "ivan", false)
	d := aCreateDevice(t, dbConn, u.ID, "nodekey:ivan-1", false)

	aInsertRules(t, dbConn,
		model.CasbinRule{Ptype: "g", V0: "device:" + d.NodeKey, V1: policy.UserSubject(u.ID)},
		model.CasbinRule{Ptype: "g", V0: policy.UserSubject(u.ID), V1: "role:ops"},
		model.CasbinRule{Ptype: "g", V0: policy.UserSubject(u.ID), V1: "role:viewer-only"},
		model.CasbinRule{Ptype: "p", V0: "role:ops", V1: "derp:default", V2: "connect"},
		model.CasbinRule{Ptype: "p", V0: "role:ops", V1: "derp:eu-1", V2: "connect"},
		model.CasbinRule{Ptype: "p", V0: "role:ops", V1: "derp:*", V2: "connect"},
		model.CasbinRule{Ptype: "p", V0: "role:BAD_ROLE", V1: "derp:us-1", V2: "connect"},
	)

	aSeedBuiltins(t, dbConn)
	logger, _ := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, false, logger); err != nil {
		t.Fatalf("RunUpgrade: %v", err)
	}

	var roleNames []string
	if err := dbConn.Model(&model.Role{}).Order("name asc").Pluck("name", &roleNames).Error; err != nil {
		t.Fatalf("pluck roles: %v", err)
	}
	if !reflect.DeepEqual(roleNames, []string{"ops", "standard", "viewer-only"}) {
		t.Fatalf("roles=%v want=[ops standard viewer-only]", roleNames)
	}

	var relayNames []string
	if err := dbConn.Model(&model.Relay{}).Order("name asc").Pluck("name", &relayNames).Error; err != nil {
		t.Fatalf("pluck relays: %v", err)
	}
	if !reflect.DeepEqual(relayNames, []string{"default", "eu-1"}) {
		t.Fatalf("relays=%v want=[default eu-1]", relayNames)
	}

	grants, err := policy.RoleGrants(context.Background(), dbConn, []string{"ops"})
	if err != nil {
		t.Fatalf("RoleGrants: %v", err)
	}
	if !reflect.DeepEqual(grants["ops"], []string{"default", "eu-1"}) {
		t.Fatalf("ops grants=%v want=[default eu-1]", grants["ops"])
	}

	eng, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	for _, relay := range []string{"default", "eu-1"} {
		ok, err := eng.Enforce(policy.Request{UserID: u.ID, NodeKey: d.NodeKey, Relay: relay})
		if err != nil || !ok {
			t.Fatalf("enforce %s: ok=%v err=%v want true, nil", relay, ok, err)
		}
	}
}

func TestUpgradeUnmanagedRulesGrantNothing(t *testing.T) {
	dbConn := aOpenDB(t)
	uDirect := aCreateUser(t, dbConn, "u-direct", false)
	dDirect := aCreateDevice(t, dbConn, uDirect.ID, "nodekey:direct-1", false)

	uWild := aCreateUser(t, dbConn, "u-wild", false)
	dWild := aCreateDevice(t, dbConn, uWild.ID, "nodekey:wild-1", false)

	uInherit := aCreateUser(t, dbConn, "u-inherit", false)
	dInherit := aCreateDevice(t, dbConn, uInherit.ID, "nodekey:inherit-1", false)

	aInsertRules(t, dbConn,
		// 1. Direct p on device:
		model.CasbinRule{Ptype: "p", V0: "device:" + dDirect.NodeKey, V1: "derp:default", V2: "connect"},
		// 2. Pre-existing derp:* rule:
		model.CasbinRule{Ptype: "g", V0: policy.UserSubject(uWild.ID), V1: "role:wild"},
		model.CasbinRule{Ptype: "p", V0: "role:wild", V1: "derp:*", V2: "connect"},
		// 3. Role-to-role inheritance g, role:a, role:b:
		model.CasbinRule{Ptype: "g", V0: policy.UserSubject(uInherit.ID), V1: "role:a"},
		model.CasbinRule{Ptype: "g", V0: "role:a", V1: "role:b"},
		model.CasbinRule{Ptype: "p", V0: "role:b", V1: "derp:default", V2: "connect"},
	)

	aSeedBuiltins(t, dbConn)
	beforeRules := aCountRules(t, dbConn)

	logger, logs := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, false, logger); err != nil {
		t.Fatalf("RunUpgrade: %v", err)
	}

	// All rules (including the 3 unmanaged ones) must stay in casbin_rule.
	if afterRules := aCountRules(t, dbConn); afterRules != beforeRules {
		t.Fatalf("casbin_rule count changed: before=%d after=%d", beforeRules, afterRules)
	}

	// None of the three devices may be allowed.
	eng, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	for name, dev := range map[string]model.Device{
		"direct_device": dDirect,
		"stored_wild":   dWild,
		"role_inherit":  dInherit,
	} {
		if aEvalNewVerify(t, dbConn, eng, dev.ID) {
			t.Fatalf("%s was unexpectedly allowed after upgrade", name)
		}
	}

	// One warning log counting the 3 unmanaged rules; none of these devices is revoked/listed.
	if logs.Len() != 1 {
		t.Fatalf("warning log count=%d want=1", logs.Len())
	}
	ctxMap := logs.All()[0].ContextMap()
	if ctxMap["unmanaged_rule_count"] != int64(3) {
		t.Fatalf("unmanaged_rule_count=%v want=3", ctxMap["unmanaged_rule_count"])
	}
	if ctxMap["revoked_device_count"] != int64(0) {
		t.Fatalf("revoked_device_count=%v want=0", ctxMap["revoked_device_count"])
	}
	var auditCount int64
	if err := dbConn.Model(&model.AdminAuditLog{}).Count(&auditCount).Error; err != nil {
		t.Fatalf("count admin_audit_logs: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("admin_audit_logs count=%d want=0", auditCount)
	}
}

func TestUpgradeRunsOnlyOnce(t *testing.T) {
	dbConn := aOpenDB(t)
	aSeedBuiltins(t, dbConn)

	logger1, _ := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, false, logger1); err != nil {
		t.Fatalf("RunUpgrade #1: %v", err)
	}

	// After the upgrade: insert a new user by SQL with no role, and a covered
	// user with a device lacking any legacy rule. Neither may be touched on restart.
	uSQL := aCreateUser(t, dbConn, "post-upgrade-sql-user", false)
	uCovered := aCreateUser(t, dbConn, "post-upgrade-covered", false)
	dNew := aCreateDevice(t, dbConn, uCovered.ID, "nodekey:post-1", false)
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetUserRoles(tx, uCovered.ID, []string{policy.BuiltinRole})
	}); err != nil {
		t.Fatalf("bind uCovered: %v", err)
	}

	verBefore, err := policy.ReadVersion(context.Background(), dbConn)
	if err != nil {
		t.Fatalf("ReadVersion before #2: %v", err)
	}

	logger2, logs2 := aNewObservedLogger()
	if err := policy.RunUpgrade(context.Background(), dbConn, true, logger2); err != nil {
		t.Fatalf("RunUpgrade #2: %v", err)
	}

	rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{uSQL.ID})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if len(rolesMap[uSQL.ID]) != 0 {
		t.Fatalf("post-upgrade SQL user was unexpectedly bound: %v", rolesMap[uSQL.ID])
	}

	var devReloaded model.Device
	if err := dbConn.First(&devReloaded, "id = ?", dNew.ID).Error; err != nil {
		t.Fatalf("reload dNew: %v", err)
	}
	if devReloaded.RevokedAt != nil {
		t.Fatalf("post-upgrade device was unexpectedly revoked")
	}

	verAfter, err := policy.ReadVersion(context.Background(), dbConn)
	if err != nil {
		t.Fatalf("ReadVersion after #2: %v", err)
	}
	if verAfter != verBefore {
		t.Fatalf("version bumped on second RunUpgrade: before=%d after=%d", verBefore, verAfter)
	}
	if logs2.Len() != 0 {
		t.Fatalf("second RunUpgrade logged %d warnings, want 0", logs2.Len())
	}
}

func TestUpgradeBumpsVersionOnlyWhenChanged(t *testing.T) {
	t.Run("no_changes_does_not_bump", func(t *testing.T) {
		dbConn := aOpenDB(t)
		u := aCreateUser(t, dbConn, "already-good", false)
		d := aCreateDevice(t, dbConn, u.ID, "nodekey:already-good-1", false)
		aInsertRules(t, dbConn,
			model.CasbinRule{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
			model.CasbinRule{Ptype: "g", V0: policy.UserSubject(u.ID), V1: "role:standard"},
			model.CasbinRule{Ptype: "g", V0: "device:" + d.NodeKey, V1: policy.UserSubject(u.ID)},
		)
		aSeedBuiltins(t, dbConn)

		verBefore, err := policy.ReadVersion(context.Background(), dbConn)
		if err != nil {
			t.Fatalf("ReadVersion before: %v", err)
		}
		if err := policy.RunUpgrade(context.Background(), dbConn, false, zap.NewNop()); err != nil {
			t.Fatalf("RunUpgrade: %v", err)
		}
		verAfter, err := policy.ReadVersion(context.Background(), dbConn)
		if err != nil {
			t.Fatalf("ReadVersion after: %v", err)
		}
		if verAfter != verBefore {
			t.Fatalf("version changed on no-op upgrade: before=%d after=%d", verBefore, verAfter)
		}
		var state model.PolicyState
		if err := dbConn.First(&state, "id = ?", model.PolicyStateRowID).Error; err != nil {
			t.Fatalf("read policy_state: %v", err)
		}
		if state.UpgradedAt == nil {
			t.Fatalf("expected upgraded_at to be set even when nothing changed")
		}
	})

	t.Run("change_bumps_once", func(t *testing.T) {
		dbConn := aOpenDB(t)
		_ = aCreateUser(t, dbConn, "unbound-no-dev", false)
		aSeedBuiltins(t, dbConn)

		verBefore, err := policy.ReadVersion(context.Background(), dbConn)
		if err != nil {
			t.Fatalf("ReadVersion before: %v", err)
		}
		if err := policy.RunUpgrade(context.Background(), dbConn, false, zap.NewNop()); err != nil {
			t.Fatalf("RunUpgrade: %v", err)
		}
		verAfter, err := policy.ReadVersion(context.Background(), dbConn)
		if err != nil {
			t.Fatalf("ReadVersion after: %v", err)
		}
		if verAfter != verBefore+1 {
			t.Fatalf("version=%d want=%d", verAfter, verBefore+1)
		}
	})
}

func TestUpgradeNeverLoosens(t *testing.T) {
	type deviceSpec struct {
		user    string
		key     string
		revoked bool
	}
	type userSpec struct {
		name     string
		disabled bool
	}
	type stateCase struct {
		name  string
		users []userSpec
		devs  []deviceSpec
		// buildRules receives user name -> user.ID so rules can reference exact UUIDs.
		buildRules func(uIDs map[string]uuid.UUID) []model.CasbinRule
	}

	states := []stateCase{
		{
			name:  "covered_standard_with_and_without_legacy",
			users: []userSpec{{name: "u1"}},
			devs: []deviceSpec{
				{user: "u1", key: "nodekey:c1-with-legacy"},
				{user: "u1", key: "nodekey:c1-no-legacy"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["u1"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:nodekey:c1-with-legacy", V1: policy.UserSubject(u["u1"])},
				}
			},
		},
		{
			name:  "covered_legacy_points_to_wrong_owner",
			users: []userSpec{{name: "owner"}, {name: "other"}},
			devs: []deviceSpec{
				{user: "owner", key: "nodekey:wrong-owner"},
				{user: "other", key: "nodekey:other-ok"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["owner"]), V1: "role:standard"},
					{Ptype: "g", V0: policy.UserSubject(u["other"]), V1: "role:standard"},
					// Points to "other" instead of "owner" (owner is covered, so if other were uncovered
					// old Casbin denied it; upgrade MUST revoke owner's device).
					{Ptype: "g", V0: "device:nodekey:wrong-owner", V1: policy.UserSubject(u["other"])},
					{Ptype: "g", V0: "device:nodekey:other-ok", V1: policy.UserSubject(u["other"])},
				}
			},
		},
		{
			name:  "covered_legacy_points_to_uncovered_other",
			users: []userSpec{{name: "covered"}, {name: "uncovered"}},
			devs: []deviceSpec{
				{user: "covered", key: "nodekey:wrong-uncovered"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["covered"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:nodekey:wrong-uncovered", V1: policy.UserSubject(u["uncovered"])},
				}
			},
		},
		{
			name:  "unbound_user_with_devices_and_unbound_without_devices",
			users: []userSpec{{name: "with-dev"}, {name: "no-dev"}},
			devs: []deviceSpec{
				{user: "with-dev", key: "nodekey:unbound-1"},
				{user: "with-dev", key: "nodekey:unbound-2", revoked: true},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: "device:nodekey:unbound-1", V1: policy.UserSubject(u["with-dev"])},
				}
			},
		},
		{
			name:  "unbound_user_with_only_revoked_device",
			users: []userSpec{{name: "only-revoked"}},
			devs: []deviceSpec{
				{user: "only-revoked", key: "nodekey:revoked-only", revoked: true},
			},
			buildRules: func(_ map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
				}
			},
		},
		{
			name:  "role_lacking_default_grant_eu_only",
			users: []userSpec{{name: "eu-user"}},
			devs: []deviceSpec{
				{user: "eu-user", key: "nodekey:eu-1"},
				{user: "eu-user", key: "nodekey:eu-2"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:eu-only", V1: "derp:eu-1", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["eu-user"]), V1: "role:eu-only"},
					{Ptype: "g", V0: "device:nodekey:eu-1", V1: policy.UserSubject(u["eu-user"])},
				}
			},
		},
		{
			name:  "role_with_no_grants",
			users: []userSpec{{name: "empty-role-user"}},
			devs: []deviceSpec{
				{user: "empty-role-user", key: "nodekey:empty-role-1"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["empty-role-user"]), V1: "role:empty"},
					{Ptype: "g", V0: "device:nodekey:empty-role-1", V1: policy.UserSubject(u["empty-role-user"])},
				}
			},
		},
		{
			name:  "custom_role_with_default_grant",
			users: []userSpec{{name: "ops-user"}},
			devs: []deviceSpec{
				{user: "ops-user", key: "nodekey:ops-with-legacy"},
				{user: "ops-user", key: "nodekey:ops-no-legacy"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:ops", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["ops-user"]), V1: "role:ops"},
					{Ptype: "g", V0: "device:nodekey:ops-with-legacy", V1: policy.UserSubject(u["ops-user"])},
				}
			},
		},
		{
			name:  "disabled_users_and_revoked_devices",
			users: []userSpec{{name: "dis-cov", disabled: true}, {name: "dis-uncov", disabled: true}, {name: "en-cov"}},
			devs: []deviceSpec{
				{user: "dis-cov", key: "nodekey:dis-cov-legacy"},
				{user: "dis-cov", key: "nodekey:dis-cov-nolegacy"},
				{user: "dis-uncov", key: "nodekey:dis-uncov-1"},
				{user: "en-cov", key: "nodekey:en-cov-revoked-legacy", revoked: true},
				{user: "en-cov", key: "nodekey:en-cov-revoked-nolegacy", revoked: true},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["dis-cov"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:nodekey:dis-cov-legacy", V1: policy.UserSubject(u["dis-cov"])},
					{Ptype: "g", V0: policy.UserSubject(u["en-cov"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:nodekey:en-cov-revoked-legacy", V1: policy.UserSubject(u["en-cov"])},
				}
			},
		},
		{
			name:  "direct_device_and_user_rules_and_direct_device_to_role",
			users: []userSpec{{name: "u-dir-dev"}, {name: "u-dir-user"}, {name: "u-dev-role"}},
			devs: []deviceSpec{
				{user: "u-dir-dev", key: "nodekey:dir-dev"},
				{user: "u-dir-user", key: "nodekey:dir-user"},
				{user: "u-dev-role", key: "nodekey:dev-role"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "device:nodekey:dir-dev", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: "device:nodekey:dir-user", V1: policy.UserSubject(u["u-dir-user"])},
					{Ptype: "p", V0: policy.UserSubject(u["u-dir-user"]), V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: "device:nodekey:dev-role", V1: "role:standard"},
				}
			},
		},
		{
			name:  "stored_wildcard_role_inherit_wrong_action_noncanonical_uuid",
			users: []userSpec{{name: "u-wild"}, {name: "u-inh"}, {name: "u-act"}, {name: "u-upper"}},
			devs: []deviceSpec{
				{user: "u-wild", key: "nodekey:wild-d"},
				{user: "u-inh", key: "nodekey:inh-d"},
				{user: "u-act", key: "nodekey:act-d"},
				{user: "u-upper", key: "nodekey:upper-d"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: "device:nodekey:wild-d", V1: policy.UserSubject(u["u-wild"])},
					{Ptype: "g", V0: policy.UserSubject(u["u-wild"]), V1: "role:wild"},
					{Ptype: "p", V0: "role:wild", V1: "derp:*", V2: "connect"},

					{Ptype: "g", V0: "device:nodekey:inh-d", V1: policy.UserSubject(u["u-inh"])},
					{Ptype: "g", V0: policy.UserSubject(u["u-inh"]), V1: "role:a"},
					{Ptype: "g", V0: "role:a", V1: "role:b"},
					{Ptype: "p", V0: "role:b", V1: "derp:default", V2: "connect"},

					{Ptype: "g", V0: "device:nodekey:act-d", V1: policy.UserSubject(u["u-act"])},
					{Ptype: "g", V0: policy.UserSubject(u["u-act"]), V1: "role:otheract"},
					{Ptype: "p", V0: "role:otheract", V1: "derp:default", V2: "admin"},

					{Ptype: "g", V0: "device:nodekey:upper-d", V1: "user:" + strings.ToUpper(u["u-upper"].String())},
					{Ptype: "g", V0: "user:" + strings.ToUpper(u["u-upper"].String()), V1: "role:standard"},
				}
			},
		},
		{
			name:  "extra_v2_on_legacy_device_rule_does_not_bypass_revocation",
			users: []userSpec{{name: "u-extra"}},
			devs: []deviceSpec{
				{user: "u-extra", key: "nodekey:extra-v2"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["u-extra"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:nodekey:extra-v2", V1: policy.UserSubject(u["u-extra"]), V2: "extra"},
				}
			},
		},
		{
			name: "combined_mixed_population",
			users: []userSpec{
				{name: "normal"},
				{name: "partial-legacy"},
				{name: "unbound-with-dev"},
				{name: "unbound-no-dev"},
				{name: "eu-only"},
				{name: "ops-default"},
				{name: "disabled-covered", disabled: true},
				{name: "wild-unmanaged"},
			},
			devs: []deviceSpec{
				{user: "normal", key: "nodekey:mix-normal-1"},
				{user: "normal", key: "nodekey:mix-normal-2"},
				{user: "partial-legacy", key: "nodekey:mix-part-ok"},
				{user: "partial-legacy", key: "nodekey:mix-part-missing"},
				{user: "partial-legacy", key: "nodekey:mix-part-revoked", revoked: true},
				{user: "unbound-with-dev", key: "nodekey:mix-unbound-1"},
				{user: "eu-only", key: "nodekey:mix-eu-1"},
				{user: "ops-default", key: "nodekey:mix-ops-ok"},
				{user: "ops-default", key: "nodekey:mix-ops-missing"},
				{user: "disabled-covered", key: "nodekey:mix-dis-ok"},
				{user: "disabled-covered", key: "nodekey:mix-dis-missing"},
				{user: "wild-unmanaged", key: "nodekey:mix-wild-1"},
			},
			buildRules: func(u map[string]uuid.UUID) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:eu-only", V1: "derp:eu-1", V2: "connect"},
					{Ptype: "p", V0: "role:ops", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:wild", V1: "derp:*", V2: "connect"},

					{Ptype: "g", V0: policy.UserSubject(u["normal"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:nodekey:mix-normal-1", V1: policy.UserSubject(u["normal"])},
					{Ptype: "g", V0: "device:nodekey:mix-normal-2", V1: policy.UserSubject(u["normal"])},

					{Ptype: "g", V0: policy.UserSubject(u["partial-legacy"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:nodekey:mix-part-ok", V1: policy.UserSubject(u["partial-legacy"])},

					{Ptype: "g", V0: "device:nodekey:mix-unbound-1", V1: policy.UserSubject(u["unbound-with-dev"])},

					{Ptype: "g", V0: policy.UserSubject(u["eu-only"]), V1: "role:eu-only"},
					{Ptype: "g", V0: "device:nodekey:mix-eu-1", V1: policy.UserSubject(u["eu-only"])},

					{Ptype: "g", V0: policy.UserSubject(u["ops-default"]), V1: "role:ops"},
					{Ptype: "g", V0: "device:nodekey:mix-ops-ok", V1: policy.UserSubject(u["ops-default"])},

					{Ptype: "g", V0: policy.UserSubject(u["disabled-covered"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:nodekey:mix-dis-ok", V1: policy.UserSubject(u["disabled-covered"])},

					{Ptype: "g", V0: policy.UserSubject(u["wild-unmanaged"]), V1: "role:wild"},
					{Ptype: "g", V0: "device:nodekey:mix-wild-1", V1: policy.UserSubject(u["wild-unmanaged"])},
				}
			},
		},
	}

	modes := []struct {
		name              string
		casbinWasDisabled bool
	}{
		{name: "enforced", casbinWasDisabled: false},
		{name: "casbin_disabled", casbinWasDisabled: true},
	}

	for _, mode := range modes {
		beforeAllowedTotal := 0
		beforeDeniedTotal := 0
		for _, tc := range states {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				dbConn := aOpenDB(t)

				usersByName := make(map[string]model.User, len(tc.users))
				userIDs := make(map[string]uuid.UUID, len(tc.users))
				for _, us := range tc.users {
					u := aCreateUser(t, dbConn, us.name, us.disabled)
					usersByName[us.name] = u
					userIDs[us.name] = u.ID
				}

				devs := make([]model.Device, 0, len(tc.devs))
				for _, ds := range tc.devs {
					d := aCreateDevice(t, dbConn, userIDs[ds.user], ds.key, ds.revoked)
					devs = append(devs, d)
				}

				rules := tc.buildRules(userIDs)
				aInsertRules(t, dbConn, rules...)

				// Compute BEFORE decisions using the REAL OLD Casbin model over raw casbin_rule rows.
				oldEnf := aBuildOldEnforcer(t, dbConn)
				before := make(map[uuid.UUID]bool, len(devs))
				for _, d := range devs {
					var owner model.User
					for _, u := range usersByName {
						if u.ID == d.UserID {
							owner = u
							break
						}
					}
					b := aEvalOldVerify(t, oldEnf, mode.casbinWasDisabled, owner, d)
					before[d.ID] = b
					if b {
						beforeAllowedTotal++
					} else {
						beforeDeniedTotal++
					}
				}

				// Run startup sequence: SeedBuiltins -> RunUpgrade -> NewEngine/Reload.
				aSeedBuiltins(t, dbConn)
				if err := policy.RunUpgrade(context.Background(), dbConn, mode.casbinWasDisabled, zap.NewNop()); err != nil {
					t.Fatalf("RunUpgrade: %v", err)
				}
				eng, err := policy.NewEngine(dbConn, true)
				if err != nil {
					t.Fatalf("NewEngine: %v", err)
				}

				// Compare AFTER decision for every device: must NEVER loosen (false -> true).
				for _, d := range devs {
					after := aEvalNewVerify(t, dbConn, eng, d.ID)
					if !before[d.ID] && after {
						t.Errorf("upgrade loosened access for device %s (key=%s): before=DENY after=ALLOW", d.ID, d.NodeKey)
					}
					// In casbin_disabled mode, every device allowed before must remain allowed after.
					if mode.casbinWasDisabled && before[d.ID] && !after {
						t.Errorf("casbin_disabled upgrade unexpectedly denied device %s (key=%s): before=ALLOW after=DENY", d.ID, d.NodeKey)
					}
				}
			})
		}
		if beforeAllowedTotal == 0 || beforeDeniedTotal == 0 {
			t.Fatalf("mode %s sanity check failed: beforeAllowed=%d beforeDenied=%d (both must be > 0)",
				mode.name, beforeAllowedTotal, beforeDeniedTotal)
		}
	}

	// Sanity check: confirm sorted state names are unique.
	names := make([]string, 0, len(states))
	for _, s := range states {
		names = append(names, s.name)
	}
	sort.Strings(names)
	for i := 1; i < len(names); i++ {
		if names[i] == names[i-1] {
			t.Fatalf("duplicate state name: %s", names[i])
		}
	}
}
