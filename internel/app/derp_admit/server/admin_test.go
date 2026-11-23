package server_test

import (
	"net/http"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
)

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

func TestAdminRateLimitPerClientIP(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt, func(c *config.Config) {
		c.AdminRateLimitRPS = 0.01
		c.AdminRateBurst = 1
	})

	// First IP consumes its single burst token and succeeds.
	if status, _ := doAdminRequestFrom(t, router, http.MethodGet, "/admin/users", testAdminKey, "192.0.2.1:10001", nil); status != http.StatusOK {
		t.Fatalf("client 1 first request status=%d want=%d", status, http.StatusOK)
	}

	// First IP's second request (different ephemeral port, same client IP) is throttled.
	if status, _ := doAdminRequestFrom(t, router, http.MethodGet, "/admin/users", testAdminKey, "192.0.2.1:10002", nil); status != http.StatusTooManyRequests {
		t.Fatalf("client 1 second request status=%d want=%d", status, http.StatusTooManyRequests)
	}

	// Second IP has an independent bucket and is still served.
	if status, _ := doAdminRequestFrom(t, router, http.MethodGet, "/admin/users", testAdminKey, "198.51.100.2:20001", nil); status != http.StatusOK {
		t.Fatalf("client 2 request status=%d want=%d", status, http.StatusOK)
	}
}

func TestAdminRateLimitBeforeAuth(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt, func(c *config.Config) {
		c.AdminRateLimitRPS = 0.01
		c.AdminRateBurst = 1
	})

	// Exhaust this client IP's bucket with an unauthenticated request (401).
	if status, _ := doAdminRequestFrom(t, router, http.MethodGet, "/admin/users", "", "192.0.2.10:30001", nil); status != http.StatusUnauthorized {
		t.Fatalf("first unauthenticated request status=%d want=%d", status, http.StatusUnauthorized)
	}

	// Now that the bucket is empty, a request without a key must get 429, not 401.
	if status, _ := doAdminRequestFrom(t, router, http.MethodGet, "/admin/users", "", "192.0.2.10:30002", nil); status != http.StatusTooManyRequests {
		t.Fatalf("rate-limited unauthenticated request status=%d want=%d", status, http.StatusTooManyRequests)
	}
}
