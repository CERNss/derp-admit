package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
)

const testAdminKey = "test-admin-key-0123456789"

func adminKeyOpt(c *config.Config) { c.AdminAPIKey = testAdminKey }

func TestAdminRequiresAuth(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt)

	// No Authorization header.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/users", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("missing key status=%d want=%d", status, http.StatusUnauthorized)
	}
	// Wrong key.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/users", "wrong-key", nil); status != http.StatusUnauthorized {
		t.Fatalf("wrong key status=%d want=%d", status, http.StatusUnauthorized)
	}
	// Correct key.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/users", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("valid key status=%d want=%d", status, http.StatusOK)
	}
}

func TestAdminDisabledWhenNoKey(t *testing.T) {
	router, _ := newTestRouter(t) // default: no admin key

	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/users", testAdminKey, nil); status != http.StatusNotFound {
		t.Fatalf("admin route should be absent, status=%d want=%d", status, http.StatusNotFound)
	}
}

func TestAdminCreateTokenUnknownUser(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt)

	status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/tokens", testAdminKey, map[string]any{
		"userId": uuid.New().String(),
	})
	if status != http.StatusNotFound {
		t.Fatalf("status=%d want=%d", status, http.StatusNotFound)
	}
}

// TestAdminLifecycleEndToEnd exercises the full provisioning path through the
// admin API: create user -> mint token -> register device -> verify allow ->
// revoke device -> verify deny.
func TestAdminLifecycleEndToEnd(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt)

	// Create user.
	status, body := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "alice",
	})
	if status != http.StatusCreated {
		t.Fatalf("create user status=%d want=%d", status, http.StatusCreated)
	}
	userID := body["user"].(map[string]any)["id"].(string)

	// Mint an enroll token; plaintext is returned exactly once.
	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/tokens", testAdminKey, map[string]any{
		"userId": userID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create token status=%d want=%d", status, http.StatusCreated)
	}
	token, _ := body["token"].(string)
	if token == "" {
		t.Fatalf("expected a plaintext token in response")
	}

	// Register a device with that token.
	nodeKey := newNodeKey(t)
	status, _ = doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
	})
	if status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}

	// Verify allows the freshly registered device.
	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("expected allow, got deny reason=%q", denyReason(payload))
	}

	// Find the device id via the admin API.
	status, body = doAdminRequest(t, router, http.MethodGet, "/admin/devices", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list devices status=%d want=%d", status, http.StatusOK)
	}
	devices := body["devices"].([]any)
	if len(devices) != 1 {
		t.Fatalf("device count=%d want=1", len(devices))
	}
	deviceID := devices[0].(map[string]any)["id"].(string)

	// Revoke the device.
	status, _ = doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+deviceID+"/revoke", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke device status=%d want=%d", status, http.StatusOK)
	}

	// Verify now denies with the revoked reason.
	_, payload = doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if reason := denyReason(payload); reason != service.DenyReasonRevoked {
		t.Fatalf("reason=%q want=%q", reason, service.DenyReasonRevoked)
	}
}

func TestAdminDisableUserDeniesVerify(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt)

	// Provision user + token + device.
	_, body := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "bob",
	})
	userID := body["user"].(map[string]any)["id"].(string)

	_, body = doAdminRequest(t, router, http.MethodPost, "/admin/tokens", testAdminKey, map[string]any{
		"userId": userID,
	})
	token := body["token"].(string)

	nodeKey := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}

	// Disable the user.
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users/"+userID+"/disable", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("disable user status=%d want=%d", status, http.StatusOK)
	}

	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if reason := denyReason(payload); reason != service.DenyReasonUserDisabled {
		t.Fatalf("reason=%q want=%q", reason, service.DenyReasonUserDisabled)
	}
}

// TestAdminRevokeDeviceInvalidatesLiveCache runs the revoke flow with a live
// verify cache (TTL > 0): without working cache invalidation the pre-revoke
// allow decision would keep being served from cache and the final verify
// would not report the revocation.
func TestAdminRevokeDeviceInvalidatesLiveCache(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
	})

	userID, token := provisionUserAndToken(t, router, "cache-revoke")
	nodeKey := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}

	// Two verifies: the first fills the cache, the second is served from it.
	for i := 0; i < 2; i++ {
		_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
		if allow, _ := payload["Allow"].(bool); !allow {
			t.Fatalf("verify %d: expected allow, got deny reason=%q", i, denyReason(payload))
		}
	}

	status, body := doAdminRequest(t, router, http.MethodGet, "/admin/devices?userId="+userID, testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list devices status=%d want=%d", status, http.StatusOK)
	}
	deviceID := body["devices"].([]any)[0].(map[string]any)["id"].(string)

	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+deviceID+"/revoke", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("revoke device status=%d want=%d", status, http.StatusOK)
	}

	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if reason := denyReason(payload); reason != service.DenyReasonRevoked {
		t.Fatalf("reason=%q want=%q (stale cached allow?)", reason, service.DenyReasonRevoked)
	}
}

// TestAdminDisableUserInvalidatesLiveCache is the user-disable variant of the
// live-cache invalidation test.
func TestAdminDisableUserInvalidatesLiveCache(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
	})

	userID, token := provisionUserAndToken(t, router, "cache-disable")
	nodeKey := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}

	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
		t.Fatalf("expected allow before disable, got deny reason=%q", denyReason(payload))
	}

	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users/"+userID+"/disable", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("disable user status=%d", status)
	}

	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if reason := denyReason(payload); reason != service.DenyReasonUserDisabled {
		t.Fatalf("reason=%q want=%q (stale cached allow?)", reason, service.DenyReasonUserDisabled)
	}
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
