package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/server"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestRegisterInvalidToken(t *testing.T) {
	router, _ := newTestRouter(t)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "invalid",
		"nodeKey": "node-A",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d want=%d", status, http.StatusUnauthorized)
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
		"nodeKey": "node-expired",
	})
	if status != http.StatusForbidden {
		t.Fatalf("expired status=%d want=%d", status, http.StatusForbidden)
	}

	revokedAt := time.Now().UTC()
	createEnrollToken(t, testDB, user.ID, pepper, "revoked-token", nil, &revokedAt, 0)
	status, _ = doJSONRequest(t, router, "/register", map[string]any{
		"token":   "revoked-token",
		"nodeKey": "node-revoked",
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
	createDevice(t, testDB, userB.ID, "node-shared", "", nil)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-a",
		"nodeKey": "node-shared",
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
	createDevice(t, testDB, user.ID, "node-existing", "", nil)

	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   "token-limit",
		"nodeKey": "node-new",
	})
	if status != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", status, http.StatusForbidden)
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

func newTestRouter(t *testing.T) (http.Handler, *gorm.DB) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	dbURL := "sqlite://" + dbPath

	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	policyEngine, err := policy.NewEngine(gormDB, true)
	if err != nil {
		t.Fatalf("new policy: %v", err)
	}
	if err := policyEngine.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap policy: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(gormDB, policyEngine, "test-pepper", 2*time.Second, service.NewVerifyCache(0), logger)
	cfg := config.Config{
		DBTimeout:          2 * time.Second,
		VerifyRateLimitRPS: 1000,
		VerifyRateBurst:    1000,
	}
	router := server.NewRouter(svc, cfg, logger)

	return router, gormDB
}

func createUser(t *testing.T, dbConn *gorm.DB, username string) model.User {
	t.Helper()
	user := model.User{ID: uuid.New(), Username: username}
	if err := dbConn.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func createEnrollToken(t *testing.T, dbConn *gorm.DB, userID uuid.UUID, pepper, token string, expiresAt, revokedAt *time.Time, maxDevices int) model.EnrollToken {
	t.Helper()
	entry := model.EnrollToken{
		ID:         uuid.New(),
		UserID:     userID,
		TokenHash:  hashToken(token, pepper),
		ExpiresAt:  expiresAt,
		RevokedAt:  revokedAt,
		MaxDevices: maxDevices,
	}
	if err := dbConn.Create(&entry).Error; err != nil {
		t.Fatalf("create token: %v", err)
	}
	return entry
}

func createDevice(t *testing.T, dbConn *gorm.DB, userID uuid.UUID, nodeKey, label string, revokedAt *time.Time) model.Device {
	t.Helper()
	device := model.Device{
		ID:        uuid.New(),
		UserID:    userID,
		NodeKey:   nodeKey,
		Label:     label,
		RevokedAt: revokedAt,
	}
	if err := dbConn.Create(&device).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	return device
}

func doJSONRequest(t *testing.T, handler http.Handler, path string, payload map[string]any) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return doRawRequest(t, handler, path, body)
}

func doRawRequest(t *testing.T, handler http.Handler, path string, body []byte) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var payload map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)
	return rec.Code, payload
}

func hashToken(token, pepper string) string {
	sum := sha256.Sum256([]byte(token + ":" + pepper))
	return hex.EncodeToString(sum[:])
}

func denyReason(payload map[string]any) string {
	if value, ok := payload["DenyReason"].(string); ok && value != "" {
		return value
	}
	if value, ok := payload["Reason"].(string); ok && value != "" {
		return value
	}
	return ""
}

func buildVerifyBody(t *testing.T, nodeKey string) []byte {
	t.Helper()
	payload := map[string]any{
		"NodePublic": nodeKey,
		"Source":     "",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal verify body: %v", err)
	}
	if _, _, err := derp.ParseRequest(body); err != nil {
		t.Fatalf("verify body parse failed: %v", err)
	}
	return body
}

func newNodeKey(t *testing.T) string {
	t.Helper()
	priv := key.NewNode()
	pub := priv.Public()
	body, err := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: pub})
	if err != nil {
		t.Fatalf("marshal key request: %v", err)
	}
	_, parsedNode, err := derp.ParseRequest(body)
	if err != nil {
		t.Fatalf("parse generated key: %v", err)
	}
	return parsedNode
}
