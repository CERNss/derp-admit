package server_test

import (
	"net/http"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/service"
)

func TestRegisterInvalidToken(t *testing.T) {
	router, _ := newTestRouter(t)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "invalid",
		"nodeKey": newNodeKey(t),
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d want=%d", status, http.StatusUnauthorized)
	}
}

func TestRegisterRateLimited(t *testing.T) {
	router, testDB := newTestRouter(t, func(c *config.Config) {
		c.RegisterRateLimitRPS = 1
		c.RegisterRateBurst = 1
	})
	user := createUser(t, testDB, "u-ratelimit")
	createEnrollToken(t, testDB, user.ID, "test-pepper", "token-rl", nil, nil, 0)

	// First request consumes the single burst token and succeeds.
	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-rl",
		"nodeKey": newNodeKey(t),
	})
	if status != http.StatusOK {
		t.Fatalf("first register status=%d want=%d", status, http.StatusOK)
	}

	// Second immediate request is throttled.
	status, _ = doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-rl",
		"nodeKey": newNodeKey(t),
	})
	if status != http.StatusTooManyRequests {
		t.Fatalf("second register status=%d want=%d", status, http.StatusTooManyRequests)
	}
}

func TestRegisterInvalidNodeKey(t *testing.T) {
	router, testDB := newTestRouter(t)
	user := createUser(t, testDB, "u-badkey")
	createEnrollToken(t, testDB, user.ID, "test-pepper", "token-badkey", nil, nil, 0)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-badkey",
		"nodeKey": "not-a-real-node-key",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d", status, http.StatusBadRequest)
	}
}

func TestRegisterTokenExpiredOrRevoked(t *testing.T) {
	router, testDB := newTestRouter(t)
	pepper := "test-pepper"

	user := createUser(t, testDB, "u-expired")
	expired := time.Now().UTC().Add(-time.Minute)
	createEnrollToken(t, testDB, user.ID, pepper, "expired-token", &expired, nil, 0)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "expired-token",
		"nodeKey": newNodeKey(t),
	})
	if status != http.StatusForbidden {
		t.Fatalf("expired status=%d want=%d", status, http.StatusForbidden)
	}

	revokedAt := time.Now().UTC()
	createEnrollToken(t, testDB, user.ID, pepper, "revoked-token", nil, &revokedAt, 0)
	status, _ = doJSONRequest(t, router, "/register", map[string]any{
		"token":   "revoked-token",
		"nodeKey": newNodeKey(t),
	})
	if status != http.StatusForbidden {
		t.Fatalf("revoked status=%d want=%d", status, http.StatusForbidden)
	}
}

func TestRegisterNodeKeyConflictAcrossUsers(t *testing.T) {
	router, testDB := newTestRouter(t)
	pepper := "test-pepper"

	userA := createUser(t, testDB, "u-a")
	userB := createUser(t, testDB, "u-b")
	createEnrollToken(t, testDB, userA.ID, pepper, "token-a", nil, nil, 0)
	sharedKey := newNodeKey(t)
	createDevice(t, testDB, userB.ID, sharedKey, "", nil)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-a",
		"nodeKey": sharedKey,
	})
	if status != http.StatusConflict {
		t.Fatalf("status=%d want=%d", status, http.StatusConflict)
	}
}

func TestRegisterMaxDevicesLimit(t *testing.T) {
	router, testDB := newTestRouter(t)
	pepper := "test-pepper"

	user := createUser(t, testDB, "u-limit")
	createEnrollToken(t, testDB, user.ID, pepper, "token-limit", nil, nil, 1)
	createDevice(t, testDB, user.ID, newNodeKey(t), "", nil)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-limit",
		"nodeKey": newNodeKey(t),
	})
	if status != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", status, http.StatusForbidden)
	}
}

func TestRegisterRevokedDeviceRefused(t *testing.T) {
	router, testDB := newTestRouter(t)
	pepper := "test-pepper"

	user := createUser(t, testDB, "u-revoked-refused")
	createEnrollToken(t, testDB, user.ID, pepper, "token-revoked-refused", nil, nil, 0)

	nodeKey := newNodeKey(t)
	revokedAt := time.Now().UTC().Add(-10 * time.Minute)
	device := createDevice(t, testDB, user.ID, nodeKey, "original-label", &revokedAt)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-revoked-refused",
		"nodeKey": nodeKey,
		"label":   "updated-label",
	})
	if status != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", status, http.StatusForbidden)
	}

	var updated model.Device
	if err := testDB.Where("id = ?", device.ID).First(&updated).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if updated.RevokedAt == nil || !updated.RevokedAt.Equal(revokedAt) {
		t.Fatalf("revoked_at=%v want=%v", updated.RevokedAt, revokedAt)
	}
	if updated.Label != "original-label" {
		t.Fatalf("label=%q want=%q", updated.Label, "original-label")
	}

	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if allow, _ := payload["Allow"].(bool); allow {
		t.Fatalf("expected deny response after refused re-register")
	}
	if reason := denyReason(payload); reason != service.DenyReasonRevoked {
		t.Fatalf("reason=%q want=%q", reason, service.DenyReasonRevoked)
	}
}

func TestRegisterRevokedDeviceOfOtherUserConflicts(t *testing.T) {
	router, testDB := newTestRouter(t)
	pepper := "test-pepper"

	userA := createUser(t, testDB, "u-conflict-a")
	userB := createUser(t, testDB, "u-conflict-b")
	createEnrollToken(t, testDB, userA.ID, pepper, "token-conflict-a", nil, nil, 0)

	sharedKey := newNodeKey(t)
	revokedAt := time.Now().UTC().Add(-5 * time.Minute)
	device := createDevice(t, testDB, userB.ID, sharedKey, "user-b-label", &revokedAt)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-conflict-a",
		"nodeKey": sharedKey,
		"label":   "user-a-label",
	})
	if status != http.StatusConflict {
		t.Fatalf("status=%d want=%d", status, http.StatusConflict)
	}

	var updated model.Device
	if err := testDB.Where("id = ?", device.ID).First(&updated).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if updated.UserID != userB.ID {
		t.Fatalf("user_id=%v want=%v", updated.UserID, userB.ID)
	}
	if updated.RevokedAt == nil || !updated.RevokedAt.Equal(revokedAt) {
		t.Fatalf("revoked_at=%v want=%v", updated.RevokedAt, revokedAt)
	}
}

func TestVerifyNotRegistered(t *testing.T) {
	router, testDB := newTestRouter(t)
	nodeKey := newNodeKey(t)

	body := buildVerifyBody(t, nodeKey)
	_, payload := doRawRequest(t, router, "/verify", body)

	if allow, _ := payload["Allow"].(bool); allow {
		t.Fatalf("expected deny response")
	}
	if reason := denyReason(payload); reason != service.DenyReasonNotRegistered {
		t.Fatalf("reason=%q want=%q", reason, service.DenyReasonNotRegistered)
	}

	var logRow model.AuditLog
	if err := testDB.Order("id desc").First(&logRow).Error; err != nil {
		t.Fatalf("load audit log: %v", err)
	}
	if logRow.Allowed {
		t.Fatalf("expected deny audit row")
	}
	if logRow.Reason != service.DenyReasonNotRegistered {
		t.Fatalf("audit reason=%q want=%q", logRow.Reason, service.DenyReasonNotRegistered)
	}
	if logRow.DeviceID != nil {
		t.Fatalf("expected nil device_id for unknown node")
	}
}

func TestVerifyRevokedDeviceDenied(t *testing.T) {
	router, testDB := newTestRouter(t)
	user := createUser(t, testDB, "u-revoked")
	now := time.Now().UTC()
	nodeKey := newNodeKey(t)
	createDevice(t, testDB, user.ID, nodeKey, "", &now)

	body := buildVerifyBody(t, nodeKey)
	_, payload := doRawRequest(t, router, "/verify", body)
	if reason := denyReason(payload); reason != service.DenyReasonRevoked {
		t.Fatalf("reason=%q want=%q", reason, service.DenyReasonRevoked)
	}
}

func TestVerifyUserDisabledDenied(t *testing.T) {
	router, testDB := newTestRouter(t)
	user := createUser(t, testDB, "u-disabled")
	now := time.Now().UTC()
	user.DisabledAt = &now
	if err := testDB.Save(&user).Error; err != nil {
		t.Fatalf("disable user: %v", err)
	}
	nodeKey := newNodeKey(t)
	createDevice(t, testDB, user.ID, nodeKey, "", nil)

	body := buildVerifyBody(t, nodeKey)
	_, payload := doRawRequest(t, router, "/verify", body)
	if reason := denyReason(payload); reason != service.DenyReasonUserDisabled {
		t.Fatalf("reason=%q want=%q", reason, service.DenyReasonUserDisabled)
	}
}

func TestVerifyPolicyDenied(t *testing.T) {
	router, testDB := newTestRouter(t)
	user := createUser(t, testDB, "u-policy-denied")
	nodeKey := newNodeKey(t)
	createDevice(t, testDB, user.ID, nodeKey, "", nil)

	body := buildVerifyBody(t, nodeKey)
	_, payload := doRawRequest(t, router, "/verify", body)
	if reason := denyReason(payload); reason != service.DenyReasonPolicyDenied {
		t.Fatalf("reason=%q want=%q", reason, service.DenyReasonPolicyDenied)
	}
}

func TestVerifyAllowUpdatesLastSeenAndAudit(t *testing.T) {
	router, testDB := newTestRouter(t)
	pepper := "test-pepper"
	nodeKey := newNodeKey(t)

	user := createUser(t, testDB, "u-allow")
	createEnrollToken(t, testDB, user.ID, pepper, "token-allow", nil, nil, 0)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-allow",
		"nodeKey": nodeKey,
		"label":   "Laptop",
	})
	if status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}

	var device model.Device
	if err := testDB.Where("node_key = ?", nodeKey).First(&device).Error; err != nil {
		t.Fatalf("load device: %v", err)
	}
	if device.LastSeenAt != nil {
		t.Fatalf("expected last_seen_at to be nil before verify")
	}

	body := buildVerifyBody(t, nodeKey)
	_, payload := doRawRequest(t, router, "/verify", body)
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("expected allow response, got deny reason=%q", denyReason(payload))
	}

	if err := testDB.Where("id = ?", device.ID).First(&device).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if device.LastSeenAt == nil {
		t.Fatalf("expected last_seen_at to be updated")
	}

	var logRow model.AuditLog
	if err := testDB.Order("id desc").First(&logRow).Error; err != nil {
		t.Fatalf("load audit row: %v", err)
	}
	if !logRow.Allowed {
		t.Fatalf("expected allow audit row")
	}
	if logRow.DeviceID == nil || *logRow.DeviceID != device.ID {
		t.Fatalf("unexpected audit device id")
	}
}

func TestVerifyDenyDoesNotUpdateLastSeen(t *testing.T) {
	router, testDB := newTestRouter(t)
	user := createUser(t, testDB, "u-deny-last-seen")
	nodeKey := newNodeKey(t)
	lastSeen := time.Now().UTC().Add(-10 * time.Minute)
	revokedAt := time.Now().UTC()
	device := createDevice(t, testDB, user.ID, nodeKey, "", &revokedAt)
	if err := testDB.Model(&model.Device{}).Where("id = ?", device.ID).Update("last_seen_at", lastSeen).Error; err != nil {
		t.Fatalf("seed last_seen_at: %v", err)
	}

	body := buildVerifyBody(t, nodeKey)
	_, payload := doRawRequest(t, router, "/verify", body)
	if reason := denyReason(payload); reason != service.DenyReasonRevoked {
		t.Fatalf("reason=%q want=%q", reason, service.DenyReasonRevoked)
	}

	var updated model.Device
	if err := testDB.Where("id = ?", device.ID).First(&updated).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if updated.LastSeenAt == nil {
		t.Fatalf("expected last_seen_at to remain set")
	}
	if !updated.LastSeenAt.Equal(lastSeen) {
		t.Fatalf("last_seen_at changed on deny: got=%v want=%v", updated.LastSeenAt, lastSeen)
	}
}
