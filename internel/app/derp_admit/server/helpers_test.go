package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const testAdminKey = "test-admin-key-0123456789"

var testEngines sync.Map // *gorm.DB -> *policy.Engine

func adminKeyOpt(c *config.Config) { c.AdminAPIKey = testAdminKey }

func newTestRouter(t *testing.T, opts ...func(*config.Config)) (http.Handler, *gorm.DB) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	dbURL := "sqlite://" + dbPath

	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	logger := zap.NewNop()
	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "test-pepper",
		MetricsEnabled:       true,
		DBTimeout:            2 * time.Second,
		PolicySyncInterval:   2 * time.Second,
		VerifyRateLimitRPS:   1000,
		VerifyRateBurst:      1000,
		RegisterRateLimitRPS: 1000,
		RegisterRateBurst:    1000,
		AdminRateLimitRPS:    1000,
		AdminRateBurst:       1000,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	application, err := app.Build(context.Background(), gormDB, cfg, logger)
	if err != nil {
		t.Fatalf("build app: %v", err)
	}
	testEngines.Store(gormDB, application.Policy)
	t.Cleanup(func() {
		testEngines.Delete(gormDB)
		application.Close()
	})

	return application.Router, gormDB
}

func bindStandardRole(t *testing.T, dbConn *gorm.DB, userID uuid.UUID) {
	t.Helper()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetUserRoles(tx, userID, []string{policy.BuiltinRole})
	}); err != nil {
		t.Fatalf("bind standard role: %v", err)
	}
	if v, ok := testEngines.Load(dbConn); ok {
		if err := v.(*policy.Engine).Reload(context.Background()); err != nil {
			t.Fatalf("reload policy engine: %v", err)
		}
	}
}

func insertAdminKey(t *testing.T, dbConn *gorm.DB, name string, tier actor.Tier) string {
	t.Helper()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generate admin key: %v", err)
	}
	plain := "dak_" + base64.RawURLEncoding.EncodeToString(raw)

	entry := model.AdminKey{
		ID:      uuid.New(),
		Name:    name,
		Tier:    tier.String(),
		KeyHash: hashToken(plain, "test-pepper"),
	}
	if err := dbConn.Create(&entry).Error; err != nil {
		t.Fatalf("insert admin key: %v", err)
	}
	return plain
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

// provisionUserAndToken creates a user and mints an enroll token through the
// admin API, returning the user id and the one-time plaintext token.
func provisionUserAndToken(t *testing.T, handler http.Handler, username string) (string, string) {
	t.Helper()

	status, body := doAdminRequest(t, handler, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": username,
	})
	if status != http.StatusCreated {
		t.Fatalf("create user status=%d want=%d", status, http.StatusCreated)
	}
	userID := body["user"].(map[string]any)["id"].(string)

	status, body = doAdminRequest(t, handler, http.MethodPost, "/admin/tokens", testAdminKey, map[string]any{
		"userId": userID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create token status=%d want=%d", status, http.StatusCreated)
	}
	token, _ := body["token"].(string)
	if token == "" {
		t.Fatalf("expected a plaintext token in response")
	}
	return userID, token
}

func doAdminRequest(t *testing.T, handler http.Handler, method, path, apiKey string, payload any) (int, map[string]any) {
	t.Helper()

	var reader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, reader)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func doAdminRequestFrom(t *testing.T, handler http.Handler, method, path, apiKey, remoteAddr string, payload any) (int, map[string]any) {
	t.Helper()

	var reader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = remoteAddr
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}
