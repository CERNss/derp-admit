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

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/casbin/casbin/v3"
	casbinmodel "github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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

func aBuildOldEnforcer(t *testing.T, dbConn *gorm.DB, casbinWasDisabled bool) *casbin.Enforcer {
	t.Helper()

	m, err := casbinmodel.NewModelFromString(aOldCasbinModelText)
	if err != nil {
		t.Fatalf("build old casbin model: %v", err)
	}

	var rows []model.CasbinRule
	if err := dbConn.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("read raw casbin_rule rows: %v", err)
	}
	hasDefaultStandardGrant := false
	for _, r := range rows {
		if r.Ptype == "p" && r.V0 == "role:standard" && r.V1 == "derp:default" && r.V2 == "connect" &&
			r.V3 == "" && r.V4 == "" && r.V5 == "" {
			hasDefaultStandardGrant = true
		}
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

	// In enforced mode, the previous version's startup Bootstrap re-added
	// `p, role:standard, derp:default, connect` on every start, so a database
	// where that row had been deleted still allowed legacy standard devices
	// on plain /verify before the upgrade.
	if !casbinWasDisabled && !hasDefaultStandardGrant {
		if err := persist.LoadPolicyLine("p, role:standard, derp:default, connect", m); err != nil {
			t.Fatalf("seed old Bootstrap baseline grant: %v", err)
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

func aNewRealNodeKey(t *testing.T) string {
	t.Helper()
	pub := key.NewNode().Public()
	raw, err := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: pub})
	if err != nil {
		t.Fatalf("marshal node key: %v", err)
	}
	_, parsed, err := derp.ParseRequest(raw)
	if err != nil {
		t.Fatalf("parse node key: %v", err)
	}
	return parsed
}

func aBuildVerifyBody(t *testing.T, nodeKey string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"NodePublic": nodeKey, "Source": ""})
	if err != nil {
		t.Fatalf("marshal verify body: %v", err)
	}
	return raw
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

	eng, err := policy.NewEngine(dbConn)
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

	eng, err := policy.NewEngine(dbConn)
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

	eng, err := policy.NewEngine(dbConn)
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

	eng, err := policy.NewEngine(dbConn)
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

	eng, err := policy.NewEngine(dbConn)
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

	eng, err := policy.NewEngine(dbConn)
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

	eng, err := policy.NewEngine(dbConn)
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
	eng, err := policy.NewEngine(dbConn)
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

func TestUpgradeEnforcedRevokesDeviceWithoutLegacyRuleOnOtherRelay(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "upgrade-other-relay.db")
	dbURL := "sqlite://" + dbPath
	dbConn, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := dbConn.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.ApplyMigrations(context.Background(), dbConn, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	u := aCreateUser(t, dbConn, "eu-only-owner", false)
	nkWithLegacy := aNewRealNodeKey(t)
	nkNoLegacy := aNewRealNodeKey(t)
	dWithLegacy := aCreateDevice(t, dbConn, u.ID, nkWithLegacy, false)
	dNoLegacy := aCreateDevice(t, dbConn, u.ID, nkNoLegacy, false)

	// User is NOT covered on default, only bound to role:eu-only granted on eu-1.
	aInsertRules(t, dbConn,
		model.CasbinRule{Ptype: "p", V0: "role:eu-only", V1: "derp:eu-1", V2: "connect"},
		model.CasbinRule{Ptype: "g", V0: policy.UserSubject(u.ID), V1: "role:eu-only"},
		model.CasbinRule{Ptype: "g", V0: "device:" + nkWithLegacy, V1: policy.UserSubject(u.ID)},
	)

	logger, logs := aNewObservedLogger()
	application, err := app.Build(context.Background(), dbConn, config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "upgrade-pepper",
		DBTimeout:            5 * time.Second,
		PolicySyncInterval:   2 * time.Second,
		VerifyRateLimitRPS:   1000,
		VerifyRateBurst:      1000,
		RegisterRateLimitRPS: 1000,
		RegisterRateBurst:    1000,
		AdminRateLimitRPS:    1000,
		AdminRateBurst:       1000,
	}, logger)
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	t.Cleanup(application.Close)

	// Device without legacy rule MUST be revoked, audited as system, and denied on eu-1 and default.
	var reloadedMissing, reloadedLegacy model.Device
	if err := dbConn.First(&reloadedMissing, "id = ?", dNoLegacy.ID).Error; err != nil {
		t.Fatalf("reload dNoLegacy: %v", err)
	}
	if err := dbConn.First(&reloadedLegacy, "id = ?", dWithLegacy.ID).Error; err != nil {
		t.Fatalf("reload dWithLegacy: %v", err)
	}
	if reloadedMissing.RevokedAt == nil {
		t.Fatalf("expected device without legacy rule on non-default relay to be revoked")
	}
	if reloadedLegacy.RevokedAt != nil {
		t.Fatalf("device with legacy rule should not be revoked")
	}

	for _, relay := range []string{"default", "eu-1"} {
		allow, reason := application.Service.Verify(context.Background(), relay, aBuildVerifyBody(t, nkNoLegacy))
		if allow || reason != service.DenyReasonRevoked {
			t.Fatalf("verify missing-legacy device on %s = (%v, %q) want (false, %q)", relay, allow, reason, service.DenyReasonRevoked)
		}
	}

	// Device with legacy rule stays allowed on eu-1 and policy-denied on default.
	if allow, reason := application.Service.Verify(context.Background(), "eu-1", aBuildVerifyBody(t, nkWithLegacy)); !allow {
		t.Fatalf("verify legacy device on eu-1 = (false, %q) want allow", reason)
	}
	if allow, reason := application.Service.Verify(context.Background(), "default", aBuildVerifyBody(t, nkWithLegacy)); allow || reason != service.DenyReasonPolicyDenied {
		t.Fatalf("verify legacy device on default = (%v, %q) want (false, %q)", allow, reason, service.DenyReasonPolicyDenied)
	}

	// System audit row recorded the revocation.
	var audits []model.AdminAuditLog
	if err := dbConn.Where("actor_key_id IS NULL AND actor_name = ? AND target_id = ?", actor.System.Name, dNoLegacy.ID.String()).Find(&audits).Error; err != nil {
		t.Fatalf("query system audit: %v", err)
	}
	if len(audits) != 1 || audits[0].Action != "device.revoke" {
		t.Fatalf("expected 1 system device.revoke audit row, got %+v", audits)
	}

	// Warning log reports both the uncovered user and the revoked device.
	if logs.Len() < 1 {
		t.Fatalf("expected upgrade warning log")
	}
	foundWarning := false
	for _, entry := range logs.All() {
		ctxMap := entry.ContextMap()
		if ctxMap["revoked_device_count"] == int64(1) && ctxMap["uncovered_user_count"] == int64(1) {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("expected warning with revoked_device_count=1 and uncovered_user_count=1, got %v", logs.All())
	}
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
		name       string
		users      []userSpec
		devs       []deviceSpec
		preRoles   []model.Role
		preRelays  []model.Relay
		buildRules func(uIDs map[string]uuid.UUID, devKeys map[string]string) []model.CasbinRule
	}

	states := []stateCase{
		{
			name:  "empty_casbin_rule_empty_db",
			users: nil,
			devs:  nil,
			buildRules: func(map[string]uuid.UUID, map[string]string) []model.CasbinRule {
				return nil
			},
		},
		{
			name:  "data_written_while_casbin_disabled_no_rules",
			users: []userSpec{{name: "u1"}, {name: "u2", disabled: true}},
			devs: []deviceSpec{
				{user: "u1", key: "d1"},
				{user: "u1", key: "d2", revoked: true},
				{user: "u2", key: "d3"},
			},
			buildRules: func(map[string]uuid.UUID, map[string]string) []model.CasbinRule {
				return nil
			},
		},
		{
			name:  "standard_default_grant_row_deleted",
			users: []userSpec{{name: "u-std"}},
			devs: []deviceSpec{
				{user: "u-std", key: "std-with-legacy"},
				{user: "u-std", key: "std-no-legacy"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				// Intentionally omit `p, role:standard, derp:default, connect`.
				return []model.CasbinRule{
					{Ptype: "g", V0: policy.UserSubject(u["u-std"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["std-with-legacy"], V1: policy.UserSubject(u["u-std"])},
				}
			},
		},
		{
			name:  "invalid_role_name_with_default_grant",
			users: []userSpec{{name: "u-badrole"}},
			devs: []deviceSpec{
				{user: "u-badrole", key: "badrole-with-legacy"},
				{user: "u-badrole", key: "badrole-no-legacy"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:Admin", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["u-badrole"]), V1: "role:Admin"},
					{Ptype: "g", V0: "device:" + dk["badrole-with-legacy"], V1: policy.UserSubject(u["u-badrole"])},
				}
			},
		},
		{
			name: "preexisting_roles_and_relays_with_all_relays",
			preRelays: []model.Relay{
				{Name: "pre-eu"},
			},
			preRoles: []model.Role{
				{Name: "pre-all", AllRelays: true},
				{Name: "pre-empty", AllRelays: false},
			},
			users: []userSpec{{name: "u-all-with-p"}, {name: "u-all-nolegacy"}, {name: "u-pre-empty"}},
			devs: []deviceSpec{
				{user: "u-all-with-p", key: "all-ok"},
				{user: "u-all-with-p", key: "all-missing"},
				{user: "u-all-nolegacy", key: "all-only-missing"},
				{user: "u-pre-empty", key: "empty-d1"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:pre-all", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["u-all-with-p"]), V1: "role:pre-all"},
					{Ptype: "g", V0: "device:" + dk["all-ok"], V1: policy.UserSubject(u["u-all-with-p"])},
					{Ptype: "g", V0: policy.UserSubject(u["u-all-nolegacy"]), V1: "role:pre-all"},
					{Ptype: "g", V0: policy.UserSubject(u["u-pre-empty"]), V1: "role:pre-empty"},
				}
			},
		},
		{
			name:  "disabled_user_without_devices",
			users: []userSpec{{name: "dis-nodev", disabled: true}, {name: "en-withdev"}},
			devs: []deviceSpec{
				{user: "en-withdev", key: "en-d1"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["en-withdev"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["en-d1"], V1: policy.UserSubject(u["en-withdev"])},
				}
			},
		},
		{
			name:  "noncanonical_legacy_device_rule_with_canonical_role_binding",
			users: []userSpec{{name: "u-canon"}},
			devs: []deviceSpec{
				{user: "u-canon", key: "canon-upper-legacy"},
				{user: "u-canon", key: "canon-valid-legacy"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["u-canon"]), V1: "role:standard"},
					// Non-canonical uppercase UUID in legacy device rule; canonical role binding above.
					{Ptype: "g", V0: "device:" + dk["canon-upper-legacy"], V1: "user:" + strings.ToUpper(u["u-canon"].String())},
					{Ptype: "g", V0: "device:" + dk["canon-valid-legacy"], V1: policy.UserSubject(u["u-canon"])},
				}
			},
		},
		{
			name:  "covered_standard_with_and_without_legacy",
			users: []userSpec{{name: "u1"}},
			devs: []deviceSpec{
				{user: "u1", key: "c1-with-legacy"},
				{user: "u1", key: "c1-no-legacy"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["u1"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["c1-with-legacy"], V1: policy.UserSubject(u["u1"])},
				}
			},
		},
		{
			name:  "covered_legacy_points_to_wrong_owner",
			users: []userSpec{{name: "owner"}, {name: "other"}},
			devs: []deviceSpec{
				{user: "owner", key: "wrong-owner"},
				{user: "other", key: "other-ok"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["owner"]), V1: "role:standard"},
					{Ptype: "g", V0: policy.UserSubject(u["other"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["wrong-owner"], V1: policy.UserSubject(u["other"])},
					{Ptype: "g", V0: "device:" + dk["other-ok"], V1: policy.UserSubject(u["other"])},
				}
			},
		},
		{
			name:  "covered_legacy_points_to_uncovered_other",
			users: []userSpec{{name: "covered"}, {name: "uncovered"}},
			devs: []deviceSpec{
				{user: "covered", key: "wrong-uncovered"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["covered"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["wrong-uncovered"], V1: policy.UserSubject(u["uncovered"])},
				}
			},
		},
		{
			name:  "unbound_user_with_devices_and_unbound_without_devices",
			users: []userSpec{{name: "with-dev"}, {name: "no-dev"}},
			devs: []deviceSpec{
				{user: "with-dev", key: "unbound-1"},
				{user: "with-dev", key: "unbound-2", revoked: true},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: "device:" + dk["unbound-1"], V1: policy.UserSubject(u["with-dev"])},
				}
			},
		},
		{
			name:  "unbound_user_with_only_revoked_device",
			users: []userSpec{{name: "only-revoked"}},
			devs: []deviceSpec{
				{user: "only-revoked", key: "revoked-only", revoked: true},
			},
			buildRules: func(_ map[string]uuid.UUID, _ map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
				}
			},
		},
		{
			name:  "role_lacking_default_grant_eu_only",
			users: []userSpec{{name: "eu-user"}},
			devs: []deviceSpec{
				{user: "eu-user", key: "eu-1"},
				{user: "eu-user", key: "eu-2"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:eu-only", V1: "derp:eu-1", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["eu-user"]), V1: "role:eu-only"},
					{Ptype: "g", V0: "device:" + dk["eu-1"], V1: policy.UserSubject(u["eu-user"])},
				}
			},
		},
		{
			name:  "role_with_no_grants",
			users: []userSpec{{name: "empty-role-user"}},
			devs: []deviceSpec{
				{user: "empty-role-user", key: "empty-role-1"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["empty-role-user"]), V1: "role:empty"},
					{Ptype: "g", V0: "device:" + dk["empty-role-1"], V1: policy.UserSubject(u["empty-role-user"])},
				}
			},
		},
		{
			name:  "custom_role_with_default_grant",
			users: []userSpec{{name: "ops-user"}},
			devs: []deviceSpec{
				{user: "ops-user", key: "ops-with-legacy"},
				{user: "ops-user", key: "ops-no-legacy"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:ops", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["ops-user"]), V1: "role:ops"},
					{Ptype: "g", V0: "device:" + dk["ops-with-legacy"], V1: policy.UserSubject(u["ops-user"])},
				}
			},
		},
		{
			name:  "disabled_users_and_revoked_devices",
			users: []userSpec{{name: "dis-cov", disabled: true}, {name: "dis-uncov", disabled: true}, {name: "en-cov"}},
			devs: []deviceSpec{
				{user: "dis-cov", key: "dis-cov-legacy"},
				{user: "dis-cov", key: "dis-cov-nolegacy"},
				{user: "dis-uncov", key: "dis-uncov-1"},
				{user: "en-cov", key: "en-cov-revoked-legacy", revoked: true},
				{user: "en-cov", key: "en-cov-revoked-nolegacy", revoked: true},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["dis-cov"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["dis-cov-legacy"], V1: policy.UserSubject(u["dis-cov"])},
					{Ptype: "g", V0: policy.UserSubject(u["en-cov"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["en-cov-revoked-legacy"], V1: policy.UserSubject(u["en-cov"])},
				}
			},
		},
		{
			name:  "direct_device_and_user_rules_and_direct_device_to_role",
			users: []userSpec{{name: "u-dir-dev"}, {name: "u-dir-user"}, {name: "u-dev-role"}},
			devs: []deviceSpec{
				{user: "u-dir-dev", key: "dir-dev"},
				{user: "u-dir-user", key: "dir-user"},
				{user: "u-dev-role", key: "dev-role"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "device:" + dk["dir-dev"], V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: "device:" + dk["dir-user"], V1: policy.UserSubject(u["u-dir-user"])},
					{Ptype: "p", V0: policy.UserSubject(u["u-dir-user"]), V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: "device:" + dk["dev-role"], V1: "role:standard"},
				}
			},
		},
		{
			name:  "stored_wildcard_role_inherit_wrong_action_noncanonical_uuid",
			users: []userSpec{{name: "u-wild"}, {name: "u-inh"}, {name: "u-act"}, {name: "u-upper"}},
			devs: []deviceSpec{
				{user: "u-wild", key: "wild-d"},
				{user: "u-inh", key: "inh-d"},
				{user: "u-act", key: "act-d"},
				{user: "u-upper", key: "upper-d"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: "device:" + dk["wild-d"], V1: policy.UserSubject(u["u-wild"])},
					{Ptype: "g", V0: policy.UserSubject(u["u-wild"]), V1: "role:wild"},
					{Ptype: "p", V0: "role:wild", V1: "derp:*", V2: "connect"},

					{Ptype: "g", V0: "device:" + dk["inh-d"], V1: policy.UserSubject(u["u-inh"])},
					{Ptype: "g", V0: policy.UserSubject(u["u-inh"]), V1: "role:a"},
					{Ptype: "g", V0: "role:a", V1: "role:b"},
					{Ptype: "p", V0: "role:b", V1: "derp:default", V2: "connect"},

					{Ptype: "g", V0: "device:" + dk["act-d"], V1: policy.UserSubject(u["u-act"])},
					{Ptype: "g", V0: policy.UserSubject(u["u-act"]), V1: "role:otheract"},
					{Ptype: "p", V0: "role:otheract", V1: "derp:default", V2: "admin"},

					{Ptype: "g", V0: "device:" + dk["upper-d"], V1: "user:" + strings.ToUpper(u["u-upper"].String())},
					{Ptype: "g", V0: "user:" + strings.ToUpper(u["u-upper"].String()), V1: "role:standard"},
				}
			},
		},
		{
			name:  "extra_v2_on_legacy_device_rule_does_not_bypass_revocation",
			users: []userSpec{{name: "u-extra"}},
			devs: []deviceSpec{
				{user: "u-extra", key: "extra-v2"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "g", V0: policy.UserSubject(u["u-extra"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["extra-v2"], V1: policy.UserSubject(u["u-extra"]), V2: "extra"},
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
				{user: "normal", key: "mix-normal-1"},
				{user: "normal", key: "mix-normal-2"},
				{user: "partial-legacy", key: "mix-part-ok"},
				{user: "partial-legacy", key: "mix-part-missing"},
				{user: "partial-legacy", key: "mix-part-revoked", revoked: true},
				{user: "unbound-with-dev", key: "mix-unbound-1"},
				{user: "eu-only", key: "mix-eu-1"},
				{user: "eu-only", key: "mix-eu-missing"},
				{user: "ops-default", key: "mix-ops-ok"},
				{user: "ops-default", key: "mix-ops-missing"},
				{user: "disabled-covered", key: "mix-dis-ok"},
				{user: "disabled-covered", key: "mix-dis-missing"},
				{user: "wild-unmanaged", key: "mix-wild-1"},
			},
			buildRules: func(u map[string]uuid.UUID, dk map[string]string) []model.CasbinRule {
				return []model.CasbinRule{
					{Ptype: "p", V0: "role:standard", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:eu-only", V1: "derp:eu-1", V2: "connect"},
					{Ptype: "p", V0: "role:ops", V1: "derp:default", V2: "connect"},
					{Ptype: "p", V0: "role:wild", V1: "derp:*", V2: "connect"},

					{Ptype: "g", V0: policy.UserSubject(u["normal"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["mix-normal-1"], V1: policy.UserSubject(u["normal"])},
					{Ptype: "g", V0: "device:" + dk["mix-normal-2"], V1: policy.UserSubject(u["normal"])},

					{Ptype: "g", V0: policy.UserSubject(u["partial-legacy"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["mix-part-ok"], V1: policy.UserSubject(u["partial-legacy"])},

					{Ptype: "g", V0: "device:" + dk["mix-unbound-1"], V1: policy.UserSubject(u["unbound-with-dev"])},

					{Ptype: "g", V0: policy.UserSubject(u["eu-only"]), V1: "role:eu-only"},
					{Ptype: "g", V0: "device:" + dk["mix-eu-1"], V1: policy.UserSubject(u["eu-only"])},

					{Ptype: "g", V0: policy.UserSubject(u["ops-default"]), V1: "role:ops"},
					{Ptype: "g", V0: "device:" + dk["mix-ops-ok"], V1: policy.UserSubject(u["ops-default"])},

					{Ptype: "g", V0: policy.UserSubject(u["disabled-covered"]), V1: "role:standard"},
					{Ptype: "g", V0: "device:" + dk["mix-dis-ok"], V1: policy.UserSubject(u["disabled-covered"])},

					{Ptype: "g", V0: policy.UserSubject(u["wild-unmanaged"]), V1: "role:wild"},
					{Ptype: "g", V0: "device:" + dk["mix-wild-1"], V1: policy.UserSubject(u["wild-unmanaged"])},
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
				dbURL := "sqlite://" + filepath.Join(t.TempDir(), "upgrade.db")
				dbConn, err := db.OpenDatabase(dbURL)
				if err != nil {
					t.Fatalf("open db: %v", err)
				}
				t.Cleanup(func() {
					if sqlDB, err := dbConn.DB(); err == nil {
						_ = sqlDB.Close()
					}
				})
				if err := db.ApplyMigrations(context.Background(), dbConn, dbURL); err != nil {
					t.Fatalf("apply migrations: %v", err)
				}

				for _, r := range tc.preRelays {
					if err := dbConn.Create(&r).Error; err != nil {
						t.Fatalf("seed pre-relay %s: %v", r.Name, err)
					}
				}
				for _, r := range tc.preRoles {
					if err := dbConn.Create(&r).Error; err != nil {
						t.Fatalf("seed pre-role %s: %v", r.Name, err)
					}
				}

				usersByName := make(map[string]model.User, len(tc.users))
				userIDs := make(map[string]uuid.UUID, len(tc.users))
				for _, us := range tc.users {
					u := aCreateUser(t, dbConn, us.name, us.disabled)
					usersByName[us.name] = u
					userIDs[us.name] = u.ID
				}

				devKeys := make(map[string]string, len(tc.devs))
				devs := make([]model.Device, 0, len(tc.devs))
				for _, ds := range tc.devs {
					realNK := aNewRealNodeKey(t)
					devKeys[ds.key] = realNK
					d := aCreateDevice(t, dbConn, userIDs[ds.user], realNK, ds.revoked)
					devs = append(devs, d)
				}

				rules := tc.buildRules(userIDs, devKeys)
				aInsertRules(t, dbConn, rules...)

				hasCanonicalLegacyRule := make(map[uuid.UUID]bool, len(devs))
				for _, d := range devs {
					wantV0 := "device:" + d.NodeKey
					wantV1 := policy.UserSubject(d.UserID)
					for _, r := range rules {
						if r.Ptype == "g" && r.V0 == wantV0 && r.V1 == wantV1 &&
							r.V2 == "" && r.V3 == "" && r.V4 == "" && r.V5 == "" {
							hasCanonicalLegacyRule[d.ID] = true
							break
						}
					}
				}

				// Compute BEFORE decisions using the REAL OLD Casbin model over raw casbin_rule rows.
				oldEnf := aBuildOldEnforcer(t, dbConn, mode.casbinWasDisabled)
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

				// Run the real application startup (migrations -> SeedBuiltins -> RunUpgrade -> Reload)
				// and evaluate AFTER decisions through real Service.Verify.
				application, err := app.Build(context.Background(), dbConn, config.Config{
					DatabaseURL:          dbURL,
					TokenPepper:          "upgrade-test-pepper",
					LegacyCasbinDisabled: mode.casbinWasDisabled,
					DBTimeout:            5 * time.Second,
					PolicySyncInterval:   2 * time.Second,
					VerifyRateLimitRPS:   1000,
					VerifyRateBurst:      1000,
					RegisterRateLimitRPS: 1000,
					RegisterRateBurst:    1000,
					AdminRateLimitRPS:    1000,
					AdminRateBurst:       1000,
				}, zap.NewNop())
				if err != nil {
					t.Fatalf("app.Build: %v", err)
				}
				t.Cleanup(application.Close)

				var registeredRelays []model.Relay
				if err := dbConn.Order("name asc").Find(&registeredRelays).Error; err != nil {
					t.Fatalf("list registered relays: %v", err)
				}

				// Compare AFTER decision for every device via Service.Verify: must NEVER loosen (false -> true).
				for _, d := range devs {
					body := aBuildVerifyBody(t, d.NodeKey)
					afterDefault, _ := application.Service.Verify(context.Background(), policy.BuiltinRelay, body)
					if !before[d.ID] && afterDefault {
						t.Errorf("upgrade loosened access for device %s (key=%s): before=DENY after=ALLOW", d.ID, d.NodeKey)
					}
					// In casbin_disabled mode, every device allowed before must remain allowed after on default.
					if mode.casbinWasDisabled && before[d.ID] && !afterDefault {
						t.Errorf("casbin_disabled upgrade unexpectedly denied device %s (key=%s): before=ALLOW after=DENY", d.ID, d.NodeKey)
					}
					// A2: in enforced mode, every device denied before because it had no canonical legacy rule
					// must stay denied on EVERY registered relay after the upgrade.
					if !mode.casbinWasDisabled && !before[d.ID] && !hasCanonicalLegacyRule[d.ID] {
						for _, relay := range registeredRelays {
							afterRelay, _ := application.Service.Verify(context.Background(), relay.Name, body)
							if afterRelay {
								t.Errorf("device %s without legacy rule was allowed on relay %q after enforced upgrade", d.ID, relay.Name)
							}
						}
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
