package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func eInsertLegacyDeviceRule(t *testing.T, dbConn *gorm.DB, nodeKey string, userID uuid.UUID) {
	t.Helper()
	rule := model.CasbinRule{
		Ptype: "g",
		V0:    "device:" + nodeKey,
		V1:    policy.UserSubject(userID),
	}
	if err := dbConn.Create(&rule).Error; err != nil {
		t.Fatalf("insert legacy device rule: %v", err)
	}
}

func eCountLegacyDeviceRules(t *testing.T, dbConn *gorm.DB, nodeKey string, userID uuid.UUID) int64 {
	t.Helper()
	var count int64
	if err := dbConn.Model(&model.CasbinRule{}).
		Where("ptype = ? AND v0 = ? AND v1 = ?", "g", "device:"+nodeKey, policy.UserSubject(userID)).
		Count(&count).Error; err != nil {
		t.Fatalf("count legacy device rules: %v", err)
	}
	return count
}

func eToStringSlice(t *testing.T, raw any) []string {
	t.Helper()
	arr, ok := raw.([]any)
	if !ok {
		t.Fatalf("expected []any, got %T (%v)", raw, raw)
	}
	out := make([]string, len(arr))
	for i, v := range arr {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("element %d expected string, got %T", i, v)
		}
		out[i] = s
	}
	return out
}

func eMakeCursor(list string, ts time.Time, k string) string {
	raw, _ := json.Marshal(page.Cursor{L: list, T: ts.UTC(), K: k})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestAdminDeleteUserRemovesTokensDevicesBindings(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
	})

	// Provision target user with token, device, legacy device rule, and warm verify cache.
	userIDStr, token := provisionUserAndToken(t, router, "del-target")
	userID := uuid.MustParse(userIDStr)
	nodeKey := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
	}); status != http.StatusOK {
		t.Fatalf("register target status=%d want=%d", status, http.StatusOK)
	}
	eInsertLegacyDeviceRule(t, gormDB, nodeKey, userID)

	// Warm the live verify cache with an allow decision.
	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
		t.Fatalf("pre-delete verify expected allow, got deny=%q", denyReason(payload))
	}

	// Provision a bystander user to ensure deletes are scoped strictly to the target user.
	otherIDStr, otherToken := provisionUserAndToken(t, router, "del-bystander")
	otherID := uuid.MustParse(otherIDStr)
	otherNodeKey := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   otherToken,
		"nodeKey": otherNodeKey,
	}); status != http.StatusOK {
		t.Fatalf("register bystander status=%d want=%d", status, http.StatusOK)
	}
	eInsertLegacyDeviceRule(t, gormDB, otherNodeKey, otherID)

	vBefore, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version before: %v", err)
	}

	status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/users/"+userIDStr, testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("DELETE /admin/users/:id status=%d want=%d", status, http.StatusOK)
	}

	vAfter, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version after: %v", err)
	}
	if vAfter != vBefore+1 {
		t.Fatalf("policy version=%d want=%d", vAfter, vBefore+1)
	}

	// Target user, tokens, devices, role bindings, and legacy device rules are gone.
	var count int64
	if err := gormDB.Model(&model.User{}).Where("id = ?", userID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("target user remaining=%d err=%v", count, err)
	}
	if err := gormDB.Model(&model.EnrollToken{}).Where("user_id = ?", userID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("target tokens remaining=%d err=%v", count, err)
	}
	if err := gormDB.Model(&model.Device{}).Where("user_id = ?", userID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("target devices remaining=%d err=%v", count, err)
	}
	if err := gormDB.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ?", "g", policy.UserSubject(userID)).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("target role bindings remaining=%d err=%v", count, err)
	}
	if got := eCountLegacyDeviceRules(t, gormDB, nodeKey, userID); got != 0 {
		t.Fatalf("target legacy device rules remaining=%d want=0", got)
	}

	// Verify immediately denies as not registered (cache invalidated).
	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if allow, _ := payload["Allow"].(bool); allow {
		t.Fatalf("deleted user's device expected deny, got allow")
	}
	if reason := denyReason(payload); reason != service.DenyReasonNotRegistered {
		t.Fatalf("deleted user's device reason=%q want=%q", reason, service.DenyReasonNotRegistered)
	}

	// Bystander user, token, device, role binding, and legacy rule are untouched.
	if err := gormDB.Model(&model.User{}).Where("id = ?", otherID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("bystander user count=%d err=%v", count, err)
	}
	if err := gormDB.Model(&model.EnrollToken{}).Where("user_id = ?", otherID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("bystander token count=%d err=%v", count, err)
	}
	if err := gormDB.Model(&model.Device{}).Where("user_id = ?", otherID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("bystander device count=%d err=%v", count, err)
	}
	if got := eCountLegacyDeviceRules(t, gormDB, otherNodeKey, otherID); got != 1 {
		t.Fatalf("bystander legacy device rules=%d want=1", got)
	}
	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, otherNodeKey)); payload["Allow"] != true {
		t.Fatalf("bystander verify expected allow, got deny=%q", denyReason(payload))
	}
}

func TestAdminDeleteDeviceAllowsReEnrol(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
	})

	userID, token := provisionUserAndToken(t, router, "del-dev-reenrol")
	nodeKey := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
		"label":   "first",
	}); status != http.StatusOK {
		t.Fatalf("initial register status=%d want=%d", status, http.StatusOK)
	}

	// Warm verify cache.
	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
		t.Fatalf("pre-delete verify expected allow, got deny=%q", denyReason(payload))
	}

	status, body := doAdminRequest(t, router, http.MethodGet, "/admin/devices?userId="+userID, testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list devices status=%d want=%d", status, http.StatusOK)
	}
	firstDeviceID := body["devices"].([]any)[0].(map[string]any)["id"].(string)

	vBefore, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version before: %v", err)
	}

	// Delete the device.
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/devices/"+firstDeviceID, testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("DELETE /admin/devices/:id status=%d want=%d", status, http.StatusOK)
	}

	vAfter, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version after: %v", err)
	}
	if vAfter != vBefore+1 {
		t.Fatalf("policy version=%d want=%d", vAfter, vBefore+1)
	}

	// Verify immediately reports not registered.
	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if reason := denyReason(payload); reason != service.DenyReasonNotRegistered {
		t.Fatalf("post-delete verify reason=%q want=%q", reason, service.DenyReasonNotRegistered)
	}

	// Node key can enrol again with a valid token.
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
		"label":   "second",
	}); status != http.StatusOK {
		t.Fatalf("re-enrol after delete status=%d want=%d", status, http.StatusOK)
	}

	var dev model.Device
	if err := gormDB.Where("node_key = ?", nodeKey).First(&dev).Error; err != nil {
		t.Fatalf("load re-enrolled device: %v", err)
	}
	if dev.ID.String() == firstDeviceID {
		t.Fatalf("expected a new device row id after delete and re-enrol")
	}
	if dev.Label != "second" {
		t.Fatalf("re-enrolled label=%q want=%q", dev.Label, "second")
	}
	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
		t.Fatalf("post-re-enrol verify expected allow, got deny=%q", denyReason(payload))
	}
}

func TestAdminDeleteTokenKeepsDevices(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	userID, token := provisionUserAndToken(t, router, "del-tok-user")
	nodeKey := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
		"label":   "kept-device",
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}

	status, body := doAdminRequest(t, router, http.MethodGet, "/admin/tokens", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list tokens status=%d want=%d", status, http.StatusOK)
	}
	tokenID := body["tokens"].([]any)[0].(map[string]any)["id"].(string)

	var beforeDevice model.Device
	if err := gormDB.Where("node_key = ?", nodeKey).First(&beforeDevice).Error; err != nil {
		t.Fatalf("load device before token delete: %v", err)
	}

	vBefore, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version before: %v", err)
	}

	// Delete the token.
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/tokens/"+tokenID, testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("DELETE /admin/tokens/:id status=%d want=%d", status, http.StatusOK)
	}

	// EffectNone: policy version must NOT bump.
	vAfter, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version after: %v", err)
	}
	if vAfter != vBefore {
		t.Fatalf("policy version bumped on token delete: got=%d want=%d", vAfter, vBefore)
	}

	// Token is gone and can no longer be used for registration.
	var tokCount int64
	if err := gormDB.Model(&model.EnrollToken{}).Where("id = ?", uuid.MustParse(tokenID)).Count(&tokCount).Error; err != nil || tokCount != 0 {
		t.Fatalf("token remaining=%d err=%v", tokCount, err)
	}
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": newNodeKey(t),
	}); status != http.StatusUnauthorized {
		t.Fatalf("register with deleted token status=%d want=%d", status, http.StatusUnauthorized)
	}

	// Device row is unchanged and still verified.
	var afterDevice model.Device
	if err := gormDB.Where("node_key = ?", nodeKey).First(&afterDevice).Error; err != nil {
		t.Fatalf("load device after token delete: %v", err)
	}
	if afterDevice.ID != beforeDevice.ID || afterDevice.UserID != uuid.MustParse(userID) || afterDevice.Label != beforeDevice.Label {
		t.Fatalf("device changed after token delete: before=%+v after=%+v", beforeDevice, afterDevice)
	}
	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
		t.Fatalf("verify after token delete expected allow, got deny=%q", denyReason(payload))
	}

	// Admin audit row for token.delete contains no plaintext token or hash.
	var auditRow model.AdminAuditLog
	if err := gormDB.Where("action = ?", "token.delete").Order("id desc").First(&auditRow).Error; err != nil {
		t.Fatalf("load token.delete audit row: %v", err)
	}
	tokenHash := hashToken(token, "test-pepper")
	if strings.Contains(auditRow.Summary, token) || strings.Contains(auditRow.Summary, tokenHash) {
		t.Fatalf("token.delete audit summary leaked secret: %q", auditRow.Summary)
	}
}

func TestAdminDeleteKeepsVerifyAuditSQLite(t *testing.T) {
	t.Run("delete_device", func(t *testing.T) {
		router, gormDB := newTestRouter(t, adminKeyOpt)

		userIDStr, token := provisionUserAndToken(t, router, "audit-keep-dev")
		nodeKey := newNodeKey(t)
		if status, _ := doJSONRequest(t, router, "/register", map[string]any{
			"token":   token,
			"nodeKey": nodeKey,
		}); status != http.StatusOK {
			t.Fatalf("register status=%d want=%d", status, http.StatusOK)
		}

		var dev model.Device
		if err := gormDB.Where("node_key = ?", nodeKey).First(&dev).Error; err != nil {
			t.Fatalf("load device: %v", err)
		}

		// Insert a verify audit row with explicit relay + fields, and also trigger a live /verify.
		relay := "eu-1"
		ts := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
		seeded := model.AuditLog{
			DeviceID: &dev.ID,
			NodeKey:  nodeKey,
			Relay:    &relay,
			Allowed:  true,
			Reason:   "",
			TS:       ts,
		}
		if err := gormDB.Create(&seeded).Error; err != nil {
			t.Fatalf("seed audit row: %v", err)
		}
		if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
			t.Fatalf("verify expected allow, got deny=%q", denyReason(payload))
		}
		_ = userIDStr

		if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/devices/"+dev.ID.String(), testAdminKey, nil); status != http.StatusOK {
			t.Fatalf("delete device status=%d want=%d", status, http.StatusOK)
		}

		var rows []model.AuditLog
		if err := gormDB.Where("node_key = ?", nodeKey).Order("id asc").Find(&rows).Error; err != nil {
			t.Fatalf("query audit_logs: %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("audit row count=%d want=2", len(rows))
		}
		for i, row := range rows {
			if row.DeviceID != nil {
				t.Fatalf("row %d device_id=%v want=nil", i, row.DeviceID)
			}
			if row.NodeKey != nodeKey {
				t.Fatalf("row %d node_key=%q want=%q", i, row.NodeKey, nodeKey)
			}
		}
		if rows[0].Relay == nil || *rows[0].Relay != relay || !rows[0].Allowed || !rows[0].TS.Equal(ts) {
			t.Fatalf("seeded audit row altered: %+v", rows[0])
		}
	})

	t.Run("delete_user", func(t *testing.T) {
		router, gormDB := newTestRouter(t, adminKeyOpt)

		userIDStr, token := provisionUserAndToken(t, router, "audit-keep-user")
		nodeKey := newNodeKey(t)
		if status, _ := doJSONRequest(t, router, "/register", map[string]any{
			"token":   token,
			"nodeKey": nodeKey,
		}); status != http.StatusOK {
			t.Fatalf("register status=%d want=%d", status, http.StatusOK)
		}

		var dev model.Device
		if err := gormDB.Where("node_key = ?", nodeKey).First(&dev).Error; err != nil {
			t.Fatalf("load device: %v", err)
		}

		relay := "us-west"
		ts := time.Date(2026, 11, 21, 15, 30, 0, 0, time.UTC)
		seeded := model.AuditLog{
			DeviceID: &dev.ID,
			NodeKey:  nodeKey,
			Relay:    &relay,
			Allowed:  false,
			Reason:   service.DenyReasonPolicyDenied,
			TS:       ts,
		}
		if err := gormDB.Create(&seeded).Error; err != nil {
			t.Fatalf("seed audit row: %v", err)
		}

		if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/users/"+userIDStr, testAdminKey, nil); status != http.StatusOK {
			t.Fatalf("delete user status=%d want=%d", status, http.StatusOK)
		}

		var got model.AuditLog
		if err := gormDB.First(&got, seeded.ID).Error; err != nil {
			t.Fatalf("load audit row after user delete: %v", err)
		}
		if got.DeviceID != nil {
			t.Fatalf("device_id=%v want=nil", got.DeviceID)
		}
		if got.NodeKey != nodeKey || got.Allowed != false || got.Reason != service.DenyReasonPolicyDenied ||
			got.Relay == nil || *got.Relay != relay || !got.TS.Equal(ts) {
			t.Fatalf("audit row fields altered after user delete: %+v", got)
		}
	})
}

func TestAdminDeleteRemovesLegacyDeviceRules(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// User 1 with two devices: delete one device directly, then delete the user (removing the second).
	u1Str, _ := provisionUserAndToken(t, router, "legacy-u1")
	u1 := uuid.MustParse(u1Str)
	nk1 := newNodeKey(t)
	nk2 := newNodeKey(t)
	d1 := createDevice(t, gormDB, u1, nk1, "d1", nil)
	createDevice(t, gormDB, u1, nk2, "d2", nil)
	eInsertLegacyDeviceRule(t, gormDB, nk1, u1)
	eInsertLegacyDeviceRule(t, gormDB, nk2, u1)

	// User 2 with one device: must stay untouched throughout.
	u2Str, _ := provisionUserAndToken(t, router, "legacy-u2")
	u2 := uuid.MustParse(u2Str)
	nk3 := newNodeKey(t)
	createDevice(t, gormDB, u2, nk3, "d3", nil)
	eInsertLegacyDeviceRule(t, gormDB, nk3, u2)

	// Delete d1 directly -> removes only nk1's legacy rule.
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/devices/"+d1.ID.String(), testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("delete device d1 status=%d want=%d", status, http.StatusOK)
	}
	if got := eCountLegacyDeviceRules(t, gormDB, nk1, u1); got != 0 {
		t.Fatalf("nk1 legacy rules=%d want=0", got)
	}
	if got := eCountLegacyDeviceRules(t, gormDB, nk2, u1); got != 1 {
		t.Fatalf("nk2 legacy rules=%d want=1", got)
	}
	if got := eCountLegacyDeviceRules(t, gormDB, nk3, u2); got != 1 {
		t.Fatalf("nk3 legacy rules=%d want=1", got)
	}

	// Delete u1 -> removes nk2's legacy rule; u2's nk3 rule still stays.
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/users/"+u1Str, testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("delete user u1 status=%d want=%d", status, http.StatusOK)
	}
	if got := eCountLegacyDeviceRules(t, gormDB, nk2, u1); got != 0 {
		t.Fatalf("nk2 legacy rules after user delete=%d want=0", got)
	}
	if got := eCountLegacyDeviceRules(t, gormDB, nk3, u2); got != 1 {
		t.Fatalf("nk3 legacy rules after u1 delete=%d want=1", got)
	}
}

func TestAdminRevokeKeepsLegacyDeviceRule(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	uStr, _ := provisionUserAndToken(t, router, "revoke-keeps-legacy")
	uid := uuid.MustParse(uStr)
	nk := newNodeKey(t)
	dev := createDevice(t, gormDB, uid, nk, "dev", nil)
	eInsertLegacyDeviceRule(t, gormDB, nk, uid)

	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+dev.ID.String()+"/revoke", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("revoke device status=%d want=%d", status, http.StatusOK)
	}

	if got := eCountLegacyDeviceRules(t, gormDB, nk, uid); got != 1 {
		t.Fatalf("legacy device rule count after revoke=%d want=1", got)
	}
	var reloaded model.Device
	if err := gormDB.First(&reloaded, "id = ?", dev.ID).Error; err != nil {
		t.Fatalf("load revoked device: %v", err)
	}
	if reloaded.RevokedAt == nil {
		t.Fatalf("expected device revoked_at to be set")
	}
}

func TestAdminRevokedDeviceCannotReEnrol(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	_, token := provisionUserAndToken(t, router, "revoke-ban-user")
	nk := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nk,
		"label":   "orig",
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}

	var dev model.Device
	if err := gormDB.Where("node_key = ?", nk).First(&dev).Error; err != nil {
		t.Fatalf("load device: %v", err)
	}

	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+dev.ID.String()+"/revoke", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("revoke status=%d want=%d", status, http.StatusOK)
	}

	// Re-enrolling a revoked node key returns 403 and leaves it revoked.
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nk,
		"label":   "attempt",
	}); status != http.StatusForbidden {
		t.Fatalf("re-register revoked device status=%d want=%d", status, http.StatusForbidden)
	}

	var after model.Device
	if err := gormDB.First(&after, "id = ?", dev.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if after.RevokedAt == nil || after.Label != "orig" {
		t.Fatalf("revoked device modified on failed re-enrol: %+v", after)
	}
}

func TestAdminDeleteUnknownAndMalformedIDs(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Seed one of each resource to verify failed deletes remove nothing.
	uStr, _ := provisionUserAndToken(t, router, "del-err-check")
	uid := uuid.MustParse(uStr)
	createDevice(t, gormDB, uid, newNodeKey(t), "d", nil)

	cases := []struct {
		name       string
		path       string
		wantStatus int
		wantAction string
	}{
		{"user_malformed", "/admin/users/not-a-uuid", http.StatusBadRequest, "user.delete"},
		{"user_unknown", "/admin/users/" + uuid.New().String(), http.StatusNotFound, "user.delete"},
		{"token_malformed", "/admin/tokens/not-a-uuid", http.StatusBadRequest, "token.delete"},
		{"token_unknown", "/admin/tokens/" + uuid.New().String(), http.StatusNotFound, "token.delete"},
		{"device_malformed", "/admin/devices/not-a-uuid", http.StatusBadRequest, "device.delete"},
		{"device_unknown", "/admin/devices/" + uuid.New().String(), http.StatusNotFound, "device.delete"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := doAdminRequest(t, router, http.MethodDelete, tc.path, testAdminKey, nil)
			if status != tc.wantStatus {
				t.Fatalf("DELETE %s status=%d want=%d", tc.path, status, tc.wantStatus)
			}
			var last model.AdminAuditLog
			if err := gormDB.Order("id desc").First(&last).Error; err != nil {
				t.Fatalf("load audit row: %v", err)
			}
			if last.Action != tc.wantAction || last.Outcome != service.AuditOutcomeFailure ||
				last.HTTPStatus == nil || *last.HTTPStatus != tc.wantStatus {
				t.Fatalf("unexpected audit row for %s: %+v", tc.name, last)
			}
		})
	}

	var uCnt, tCnt, dCnt int64
	_ = gormDB.Model(&model.User{}).Count(&uCnt)
	_ = gormDB.Model(&model.EnrollToken{}).Count(&tCnt)
	_ = gormDB.Model(&model.Device{}).Count(&dCnt)
	if uCnt != 1 || tCnt != 1 || dCnt != 1 {
		t.Fatalf("failed deletes removed data: users=%d tokens=%d devices=%d", uCnt, tCnt, dCnt)
	}
}

func TestAdminDeleteRoutesRequireOperator(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	viewerKey := insertAdminKey(t, gormDB, "e-viewer-del", actor.TierViewer)
	opKey := insertAdminKey(t, gormDB, "e-operator-del", actor.TierOperator)

	uStr, _ := provisionUserAndToken(t, router, "tier-del-user")
	uid := uuid.MustParse(uStr)
	dev := createDevice(t, gormDB, uid, newNodeKey(t), "dev", nil)

	var tok model.EnrollToken
	if err := gormDB.Where("user_id = ?", uid).First(&tok).Error; err != nil {
		t.Fatalf("load token: %v", err)
	}

	// Viewer receives 403 on all three delete routes and deletes nothing.
	for _, path := range []string{
		"/admin/devices/" + dev.ID.String(),
		"/admin/tokens/" + tok.ID.String(),
		"/admin/users/" + uStr,
	} {
		status, _ := doAdminRequest(t, router, http.MethodDelete, path, viewerKey, nil)
		if status != http.StatusForbidden {
			t.Fatalf("viewer DELETE %s status=%d want=%d", path, status, http.StatusForbidden)
		}
	}

	var forbiddenCount int64
	if err := gormDB.Model(&model.AdminAuditLog{}).
		Where("actor_name = ? AND outcome = ? AND http_status = ?", "e-viewer-del", service.AuditOutcomeFailure, http.StatusForbidden).
		Count(&forbiddenCount).Error; err != nil {
		t.Fatalf("count forbidden audit rows: %v", err)
	}
	if forbiddenCount != 3 {
		t.Fatalf("forbidden audit rows=%d want=3", forbiddenCount)
	}

	// Operator succeeds on all three delete routes.
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/devices/"+dev.ID.String(), opKey, nil); status != http.StatusOK {
		t.Fatalf("operator DELETE device status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/tokens/"+tok.ID.String(), opKey, nil); status != http.StatusOK {
		t.Fatalf("operator DELETE token status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/users/"+uStr, opKey, nil); status != http.StatusOK {
		t.Fatalf("operator DELETE user status=%d want=%d", status, http.StatusOK)
	}
}

func TestAdminUserViewsCarryRoles(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Create two extra roles to test sorting and deduplication.
	for _, name := range []string{"zeta", "alpha"} {
		if err := gormDB.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("create role %s: %v", name, err)
		}
	}

	// 1. Omitted roles -> ["standard"]
	status, body := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "roles-default",
	})
	if status != http.StatusCreated {
		t.Fatalf("create default user status=%d want=%d", status, http.StatusCreated)
	}
	uDefault := body["user"].(map[string]any)
	if got := eToStringSlice(t, uDefault["roles"]); !reflect.DeepEqual(got, []string{"standard"}) {
		t.Fatalf("create default roles=%v want=[standard]", got)
	}

	// 2. Explicit unsorted + duplicate roles -> sorted, deduplicated ["alpha", "zeta"]
	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "roles-multi",
		"roles":    []string{"zeta", "alpha", "zeta"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create multi-role user status=%d want=%d", status, http.StatusCreated)
	}
	uMulti := body["user"].(map[string]any)
	if got := eToStringSlice(t, uMulti["roles"]); !reflect.DeepEqual(got, []string{"alpha", "zeta"}) {
		t.Fatalf("create multi roles=%v want=[alpha zeta]", got)
	}

	// 3. Explicit empty roles -> [] (non-null empty JSON array)
	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "roles-empty",
		"roles":    []string{},
	})
	if status != http.StatusCreated {
		t.Fatalf("create empty-role user status=%d want=%d", status, http.StatusCreated)
	}
	uEmpty := body["user"].(map[string]any)
	if got := eToStringSlice(t, uEmpty["roles"]); len(got) != 0 {
		t.Fatalf("create empty roles=%v want=[]", got)
	}

	// 4. List returns every user with its sorted roles.
	status, body = doAdminRequest(t, router, http.MethodGet, "/admin/users", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list users status=%d want=%d", status, http.StatusOK)
	}
	users := body["users"].([]any)
	if len(users) != 3 {
		t.Fatalf("user count=%d want=3", len(users))
	}
	gotByName := make(map[string][]string, len(users))
	for _, raw := range users {
		u := raw.(map[string]any)
		gotByName[u["username"].(string)] = eToStringSlice(t, u["roles"])
	}
	wantByName := map[string][]string{
		"roles-default": {"standard"},
		"roles-multi":   {"alpha", "zeta"},
		"roles-empty":   {},
	}
	for name, want := range wantByName {
		if !reflect.DeepEqual(gotByName[name], want) {
			t.Fatalf("list user %s roles=%v want=%v", name, gotByName[name], want)
		}
	}
}

func TestAdminListPaginationLifecycle(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Seed 55 users, 55 tokens, and 55 devices (with groups sharing identical
	// created_at timestamps to exercise the id tie-breaker).
	const total = 55
	baseTime := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	type rowMeta struct {
		id string
		ts time.Time
	}
	userMetas := make([]rowMeta, 0, total)
	tokenMetas := make([]rowMeta, 0, total)
	deviceMetas := make([]rowMeta, 0, total)

	var firstUserID uuid.UUID
	firstUserDeviceIDs := make([]rowMeta, 0, 10)

	for i := 0; i < total; i++ {
		// Every 5 rows share the same timestamp so the tie-break is heavily exercised.
		ts := baseTime.Add(time.Duration(i/5) * time.Second)
		u := model.User{
			ID:        uuid.New(),
			Username:  fmt.Sprintf("page-user-%03d", i),
			CreatedAt: ts,
		}
		if err := gormDB.Create(&u).Error; err != nil {
			t.Fatalf("create user %d: %v", i, err)
		}
		if i == 0 {
			firstUserID = u.ID
		}
		userMetas = append(userMetas, rowMeta{id: u.ID.String(), ts: ts})

		tok := model.EnrollToken{
			ID:         uuid.New(),
			UserID:     u.ID,
			TokenHash:  hashToken(fmt.Sprintf("tok-seed-%03d", i), "test-pepper"),
			MaxDevices: 1,
			CreatedAt:  ts,
		}
		if err := gormDB.Create(&tok).Error; err != nil {
			t.Fatalf("create token %d: %v", i, err)
		}
		tokenMetas = append(tokenMetas, rowMeta{id: tok.ID.String(), ts: ts})

		ownerID := u.ID
		if i < 10 {
			ownerID = firstUserID
		}
		dev := model.Device{
			ID:        uuid.New(),
			UserID:    ownerID,
			NodeKey:   newNodeKey(t),
			Label:     fmt.Sprintf("dev-%03d", i),
			CreatedAt: ts,
		}
		if err := gormDB.Create(&dev).Error; err != nil {
			t.Fatalf("create device %d: %v", i, err)
		}
		deviceMetas = append(deviceMetas, rowMeta{id: dev.ID.String(), ts: ts})
		if ownerID == firstUserID {
			firstUserDeviceIDs = append(firstUserDeviceIDs, rowMeta{id: dev.ID.String(), ts: ts})
		}
	}

	sortAsc := func(metas []rowMeta) []string {
		cp := append([]rowMeta(nil), metas...)
		sort.Slice(cp, func(i, j int) bool {
			if !cp[i].ts.Equal(cp[j].ts) {
				return cp[i].ts.Before(cp[j].ts)
			}
			return cp[i].id < cp[j].id
		})
		out := make([]string, len(cp))
		for i, m := range cp {
			out[i] = m.id
		}
		return out
	}

	wantUsers := sortAsc(userMetas)
	wantTokens := sortAsc(tokenMetas)
	wantDevices := sortAsc(deviceMetas)
	wantFirstUserDevices := sortAsc(firstUserDeviceIDs)

	endpoints := []struct {
		name      string
		path      string
		listName  string
		itemsKey  string
		wantOrder []string
	}{
		{"users", "/admin/users", "users", "users", wantUsers},
		{"tokens", "/admin/tokens", "tokens", "tokens", wantTokens},
		{"devices", "/admin/devices", "devices", "devices", wantDevices},
	}

	// Capture one real cursor per endpoint to test cross-list cursor rejection.
	sampleCursors := make(map[string]string, len(endpoints))

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			// 1. Default page size is 50 -> 50 items + non-null nextCursor; second page has 5 + null nextCursor.
			status, body := doAdminRequest(t, router, http.MethodGet, ep.path, testAdminKey, nil)
			if status != http.StatusOK {
				t.Fatalf("default page status=%d want=%d", status, http.StatusOK)
			}
			items := body[ep.itemsKey].([]any)
			if len(items) != page.DefaultLimit {
				t.Fatalf("default page len=%d want=%d", len(items), page.DefaultLimit)
			}
			nextCursor, ok := body["nextCursor"].(string)
			if !ok || nextCursor == "" {
				t.Fatalf("expected non-empty nextCursor on first default page, got %#v", body["nextCursor"])
			}
			sampleCursors[ep.name] = nextCursor

			status, body = doAdminRequest(t, router, http.MethodGet, ep.path+"?cursor="+url.QueryEscape(nextCursor), testAdminKey, nil)
			if status != http.StatusOK {
				t.Fatalf("second default page status=%d want=%d", status, http.StatusOK)
			}
			items2 := body[ep.itemsKey].([]any)
			if len(items2) != total-page.DefaultLimit {
				t.Fatalf("second default page len=%d want=%d", len(items2), total-page.DefaultLimit)
			}
			if body["nextCursor"] != nil {
				t.Fatalf("expected nil nextCursor on last page, got %#v", body["nextCursor"])
			}

			// 2. limit=1 and limit=200 are accepted.
			status, body = doAdminRequest(t, router, http.MethodGet, ep.path+"?limit=1", testAdminKey, nil)
			if status != http.StatusOK || len(body[ep.itemsKey].([]any)) != 1 || body["nextCursor"] == nil {
				t.Fatalf("limit=1 failed: status=%d body=%v", status, body)
			}
			status, body = doAdminRequest(t, router, http.MethodGet, ep.path+"?limit=200", testAdminKey, nil)
			if status != http.StatusOK || len(body[ep.itemsKey].([]any)) != total || body["nextCursor"] != nil {
				t.Fatalf("limit=200 failed: status=%d len=%d next=%v", status, len(body[ep.itemsKey].([]any)), body["nextCursor"])
			}

			// 3. Invalid limits rejected with 400.
			for _, bad := range []string{"0", "-1", "201", "abc"} {
				if status, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?limit="+bad, testAdminKey, nil); status != http.StatusBadRequest {
					t.Fatalf("limit=%s status=%d want=%d", bad, status, http.StatusBadRequest)
				}
			}

			// 4. Invalid cursors rejected with 400 (including forged non-UUID key).
			for _, bad := range []string{
				"not-valid-base64!!!",
				"e30",
				eMakeCursor(ep.listName, baseTime, "not-a-uuid"),
			} {
				if status, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?cursor="+url.QueryEscape(bad), testAdminKey, nil); status != http.StatusBadRequest {
					t.Fatalf("bad cursor %q status=%d want=%d", bad, status, http.StatusBadRequest)
				}
			}

			// 5. Full walk with limit=7: no row repeated or skipped, exact order, equal timestamps tie-broken by id.
			var gotIDs []string
			cur := ""
			for {
				q := ep.path + "?limit=7"
				if cur != "" {
					q += "&cursor=" + url.QueryEscape(cur)
				}
				status, body := doAdminRequest(t, router, http.MethodGet, q, testAdminKey, nil)
				if status != http.StatusOK {
					t.Fatalf("walk %s status=%d want=%d", q, status, http.StatusOK)
				}
				for _, raw := range body[ep.itemsKey].([]any) {
					gotIDs = append(gotIDs, raw.(map[string]any)["id"].(string))
				}
				if body["nextCursor"] == nil {
					break
				}
				cur = body["nextCursor"].(string)
			}
			if !reflect.DeepEqual(gotIDs, ep.wantOrder) {
				t.Fatalf("%s walked %d items, mismatch with expected order", ep.name, len(gotIDs))
			}
		})
	}

	// Cross-list cursor rejection: cursor from one list fails on every other list with 400.
	for _, ep := range endpoints {
		for otherName, otherCursor := range sampleCursors {
			if otherName == ep.name {
				continue
			}
			if status, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?cursor="+url.QueryEscape(otherCursor), testAdminKey, nil); status != http.StatusBadRequest {
				t.Fatalf("%s accepted cursor from %s: status=%d want=%d", ep.name, otherName, status, http.StatusBadRequest)
			}
		}
	}

	// Devices filtered by userId also paginate cleanly.
	var filteredIDs []string
	cur := ""
	for {
		q := "/admin/devices?userId=" + firstUserID.String() + "&limit=3"
		if cur != "" {
			q += "&cursor=" + url.QueryEscape(cur)
		}
		status, body := doAdminRequest(t, router, http.MethodGet, q, testAdminKey, nil)
		if status != http.StatusOK {
			t.Fatalf("filtered devices status=%d want=%d", status, http.StatusOK)
		}
		for _, raw := range body["devices"].([]any) {
			filteredIDs = append(filteredIDs, raw.(map[string]any)["id"].(string))
		}
		if body["nextCursor"] == nil {
			break
		}
		cur = body["nextCursor"].(string)
	}
	if !reflect.DeepEqual(filteredIDs, wantFirstUserDevices) {
		t.Fatalf("filtered devices=%v want=%v", filteredIDs, wantFirstUserDevices)
	}
}
