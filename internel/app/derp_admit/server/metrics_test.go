package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
)

func bScrapeMetrics(t *testing.T, handler http.Handler) (int, string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Code, rec.Header().Get("Content-Type"), rec.Body.String()
}

func TestMetricsEndpointEnabledAndDisabled(t *testing.T) {
	// Enabled (default in newTestRouter / config).
	enabledRouter, _ := newTestRouter(t)
	code, contentType, body := bScrapeMetrics(t, enabledRouter)
	if code != http.StatusOK {
		t.Fatalf("enabled GET /metrics status=%d want=200", code)
	}
	if !strings.Contains(contentType, "text/plain") {
		t.Fatalf("enabled GET /metrics content-type=%q want text/plain", contentType)
	}
	if !strings.Contains(body, "# HELP derp_admit_") || !strings.Contains(body, "# TYPE derp_admit_") {
		t.Fatalf("enabled GET /metrics does not look like Prometheus exposition:\n%s", body)
	}

	// Disabled when METRICS_ENABLED=false.
	disabledRouter, _ := newTestRouter(t, func(c *config.Config) {
		c.MetricsEnabled = false
	})
	code, _, _ = bScrapeMetrics(t, disabledRouter)
	if code != http.StatusNotFound {
		t.Fatalf("disabled GET /metrics status=%d want=404", code)
	}
}

func TestMetricsVerifyDecisionLabels(t *testing.T) {
	application := bBuildSingleApp(t, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
		c.RegisterRateLimitRPS = 0.01
		c.RegisterRateBurst = 1
	})
	bAddRelayAndRole(t, application, "eu-1", "eu-role", []string{"eu-1"})

	// Active device allowed on default & eu-1.
	user := createUser(t, application.DB, "metrics-user")
	bBindUserRoles(t, application, user.ID, []string{policy.BuiltinRole, "eu-role"})
	activeKey := newNodeKey(t)
	createDevice(t, application.DB, user.ID, activeKey, "active", nil)

	// Revoked device on default.
	now := time.Now().UTC()
	revokedKey := newNodeKey(t)
	createDevice(t, application.DB, user.ID, revokedKey, "revoked", &now)

	// 1. Plain /verify (counts as relay="default") twice -> 1 cache miss, 1 cache hit, 2 allow decisions.
	for i := 0; i < 2; i++ {
		_, payload := doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, activeKey))
		if allow, _ := payload["Allow"].(bool); !allow {
			t.Fatalf("plain /verify %d expected allow, got %+v", i, payload)
		}
	}

	// 2. Named /verify/default for revoked device -> relay="default", allowed="false", reason="revoked".
	_, payload := doRawRequest(t, application.Router, "/verify/default", buildVerifyBody(t, revokedKey))
	if reason := denyReason(payload); reason != service.DenyReasonRevoked {
		t.Fatalf("revoked verify reason=%q want=%q", reason, service.DenyReasonRevoked)
	}

	// 3. Named /verify/eu-1 for active device -> relay="eu-1", allowed="true", reason="".
	_, payload = doRawRequest(t, application.Router, "/verify/eu-1", buildVerifyBody(t, activeKey))
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("/verify/eu-1 expected allow, got %+v", payload)
	}

	// 4. Register rate-limit rejection -> rate_limited_total{endpoint="register"} = 1.
	createEnrollToken(t, application.DB, user.ID, "test-pepper", "metrics-tok", nil, nil, 0)
	if status, _ := doJSONRequest(t, application.Router, "/register", map[string]any{
		"token":   "metrics-tok",
		"nodeKey": newNodeKey(t),
	}); status != http.StatusOK {
		t.Fatalf("first register status=%d want=200", status)
	}
	if status, _ := doJSONRequest(t, application.Router, "/register", map[string]any{
		"token":   "metrics-tok",
		"nodeKey": newNodeKey(t),
	}); status != http.StatusTooManyRequests {
		t.Fatalf("second register status=%d want=429", status)
	}

	// 5. Unauthenticated /admin request -> tier="none", status_class="4xx".
	if status, _ := doAdminRequest(t, application.Router, http.MethodGet, "/admin/users", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("unauth admin status=%d want=401", status)
	}

	code, _, body := bScrapeMetrics(t, application.Router)
	if code != http.StatusOK {
		t.Fatalf("scrape status=%d want=200", code)
	}

	expected := []string{
		`derp_admit_verify_decisions_total{allowed="true",reason="",relay="default"} 2`,
		`derp_admit_verify_decisions_total{allowed="false",reason="revoked",relay="default"} 1`,
		`derp_admit_verify_decisions_total{allowed="true",reason="",relay="eu-1"} 1`,
		`derp_admit_verify_cache_lookups_total{result="hit"} 1`,
		`derp_admit_verify_cache_lookups_total{result="miss"} 3`,
		`derp_admit_register_requests_total{status="200"} 1`,
		`derp_admit_register_requests_total{status="429"} 1`,
		`derp_admit_rate_limited_total{endpoint="register"} 1`,
		`derp_admit_admin_requests_total{status_class="4xx",tier="none"} 1`,
		`derp_admit_policy_version `,
		`derp_admit_policy_sync_last_success_timestamp_seconds `,
		`derp_admit_policy_reloads_total{result="ok"} `,
	}
	for _, want := range expected {
		if !strings.Contains(body, want) {
			t.Errorf("metrics scrape missing %q\nfull output:\n%s", want, body)
		}
	}
}

func TestMetricsUnknownRelayLabel(t *testing.T) {
	application := bBuildSingleApp(t)
	nk := newNodeKey(t)

	// Unregistered well-formed relay and malformed relay must both be labelled "unknown".
	for _, path := range []string{"/verify/does-not-exist", "/verify/Bad_Name"} {
		_, payload := doRawRequest(t, application.Router, path, buildVerifyBody(t, nk))
		if reason := denyReason(payload); reason != service.DenyReasonUnknownRelay {
			t.Fatalf("%s reason=%q want=%q", path, reason, service.DenyReasonUnknownRelay)
		}
	}

	code, _, body := bScrapeMetrics(t, application.Router)
	if code != http.StatusOK {
		t.Fatalf("scrape status=%d want=200", code)
	}

	wantSeries := `derp_admit_verify_decisions_total{allowed="false",reason="unknown relay",relay="unknown"} 2`
	if !strings.Contains(body, wantSeries) {
		t.Fatalf("missing unknown relay series %q\nfull output:\n%s", wantSeries, body)
	}
	for _, forbidden := range []string{"does-not-exist", "Bad_Name"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics output leaked unregistered/malformed relay name %q:\n%s", forbidden, body)
		}
	}
}

func TestMetricsScrapeContainsNoIdentities(t *testing.T) {
	application := bBuildSingleApp(t, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
	})

	const keyName = "ops-secret-key-name-789"
	const username = "alice-identity-check"
	namedKey := insertAdminKey(t, application.DB, keyName, actor.TierOperator)

	var keyRow model.AdminKey
	if err := application.DB.Where("name = ?", keyName).First(&keyRow).Error; err != nil {
		t.Fatalf("load admin key row: %v", err)
	}

	// Admin traffic using the named stored key.
	status, resp := doAdminRequest(t, application.Router, http.MethodPost, "/admin/users", namedKey, map[string]any{
		"username": username,
	})
	if status != http.StatusCreated {
		t.Fatalf("create user status=%d want=201", status)
	}
	userID := resp["user"].(map[string]any)["id"].(string)

	status, resp = doAdminRequest(t, application.Router, http.MethodPost, "/admin/tokens", namedKey, map[string]any{
		"userId": userID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create token status=%d want=201", status)
	}
	enrollToken := resp["token"].(string)

	// Register traffic.
	nk := newNodeKey(t)
	if status, _ := doJSONRequest(t, application.Router, "/register", map[string]any{
		"token":   enrollToken,
		"nodeKey": nk,
		"label":   "secret-laptop-label",
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=200", status)
	}

	var devRow model.Device
	if err := application.DB.Where("node_key = ?", nk).First(&devRow).Error; err != nil {
		t.Fatalf("load device row: %v", err)
	}

	// Verify traffic (allow, cache hit, unknown relay, malformed JSON).
	for i := 0; i < 2; i++ {
		_, payload := doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, nk))
		if allow, _ := payload["Allow"].(bool); !allow {
			t.Fatalf("verify %d expected allow, got %+v", i, payload)
		}
	}
	doRawRequest(t, application.Router, "/verify/not-a-relay", buildVerifyBody(t, nk))
	doRawRequest(t, application.Router, "/verify", []byte("bad-json"))

	// Unauthenticated admin traffic as well.
	doAdminRequest(t, application.Router, http.MethodGet, "/admin/users", "bad-secret-bearer", nil)

	code, _, body := bScrapeMetrics(t, application.Router)
	if code != http.StatusOK {
		t.Fatalf("scrape status=%d want=200", code)
	}

	forbidden := []string{
		nk,
		userID,
		devRow.ID.String(),
		keyRow.ID.String(),
		keyName,
		username,
		namedKey,
		enrollToken,
		testAdminKey,
		"bad-secret-bearer",
		"secret-laptop-label",
		"not-a-relay",
		uuid.Nil.String(),
	}
	for _, s := range forbidden {
		if strings.Contains(body, s) {
			t.Errorf("metrics scrape must not contain %q\nfull output:\n%s", s, body)
		}
	}
}
