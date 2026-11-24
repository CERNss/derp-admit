package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"gorm.io/gorm"
)

func alPrefixes(items ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(items))
	for _, s := range items {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func alVerifyCIDRs(items ...string) func(*config.Config) {
	return func(c *config.Config) { c.VerifyAllowedCIDRs = alPrefixes(items...) }
}

func alMetricsCIDRs(items ...string) func(*config.Config) {
	return func(c *config.Config) { c.MetricsAllowedCIDRs = alPrefixes(items...) }
}

// alDo sends a request from remoteAddr with optional extra headers and returns
// the status and the raw body.
func alDo(t *testing.T, handler http.Handler, method, path, remoteAddr string, body []byte, headers map[string]string) (int, string) {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// alEvaluated reports whether a /verify response is a normal admit response
// (HTTP 200 with a DERPAdmitClientResponse) that was not rate limited.
func alEvaluated(t *testing.T, status int, body string) bool {
	t.Helper()
	if status != http.StatusOK {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode verify body %q: %v", body, err)
	}
	if _, ok := payload["Allow"]; !ok {
		return false
	}
	return denyReason(payload) != "rate limited"
}

func alAssertForbidden(t *testing.T, what string, status int, body string) {
	t.Helper()
	if status != http.StatusForbidden {
		t.Fatalf("%s: status=%d want=403 body=%s", what, status, body)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("%s: 403 body is not JSON: %q", what, body)
	}
	if _, ok := payload["Allow"]; ok {
		t.Fatalf("%s: 403 body must not be an admit response: %s", what, body)
	}
}

func alCountAudit(t *testing.T, dbConn *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := dbConn.Model(&model.AuditLog{}).Count(&n).Error; err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

func alScrape(t *testing.T, handler http.Handler, remoteAddr string) string {
	t.Helper()
	status, body := alDo(t, handler, http.MethodGet, "/metrics", remoteAddr, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("scrape from %s status=%d want=200", remoteAddr, status)
	}
	return body
}

func TestVerifyAllowlistAllowsAndRejects(t *testing.T) {
	router, gormDB := newTestRouter(t, alVerifyCIDRs("10.0.0.0/8", "2001:db8::/32"))

	user := createUser(t, gormDB, "allowlist-user")
	bindStandardRole(t, gormDB, user.ID)
	nodeKey := newNodeKey(t)
	createDevice(t, gormDB, user.ID, nodeKey, "laptop", nil)
	body := buildVerifyBody(t, nodeKey)

	for _, path := range []string{"/verify", "/verify/default"} {
		for _, peer := range []string{"10.1.2.3:41641", "[2001:db8::7]:41641"} {
			status, resp := alDo(t, router, http.MethodPost, path, peer, body, nil)
			if !alEvaluated(t, status, resp) {
				t.Fatalf("%s from allowed %s: status=%d body=%s, want an evaluated decision", path, peer, status, resp)
			}
			if !strings.Contains(resp, `"Allow":true`) {
				t.Fatalf("%s from allowed %s: body=%s want Allow:true", path, peer, resp)
			}
		}
		for _, peer := range []string{"192.0.2.1:41641", "[2001:db9::1]:41641", "11.0.0.1:1"} {
			status, resp := alDo(t, router, http.MethodPost, path, peer, body, nil)
			alAssertForbidden(t, path+" from "+peer, status, resp)
		}
	}
	// Unknown and malformed relays are refused too: the whole /verify/* tree is covered.
	for _, path := range []string{"/verify/does-not-exist", "/verify/", "/verify/a/b"} {
		status, resp := alDo(t, router, http.MethodPost, path, "192.0.2.1:1", body, nil)
		alAssertForbidden(t, path, status, resp)
	}
}

func TestMetricsAllowlistAllowsAndRejects(t *testing.T) {
	router, _ := newTestRouter(t, alMetricsCIDRs("10.9.0.0/16", "::1/128"))

	for _, peer := range []string{"10.9.9.9:5000", "[::1]:5000", "[::ffff:10.9.1.1]:5000"} {
		body := alScrape(t, router, peer)
		if !strings.Contains(body, "# TYPE derp_admit_") {
			t.Fatalf("scrape from %s does not look like Prometheus exposition", peer)
		}
	}
	for _, peer := range []string{"192.0.2.1:5000", "10.10.0.1:5000"} {
		status, body := alDo(t, router, http.MethodGet, "/metrics", peer, nil, map[string]string{"X-Forwarded-For": "10.9.9.9"})
		alAssertForbidden(t, "/metrics from "+peer, status, body)
		if strings.Contains(body, "derp_admit_") {
			t.Fatalf("403 body leaked metrics: %s", body)
		}
	}

	// The metrics rejections are counted, as seen from an allowed scraper.
	out := alScrape(t, router, "10.9.9.9:5000")
	if !strings.Contains(out, `derp_admit_caller_rejected_total{endpoint="metrics"} 2`) {
		t.Fatalf("metrics rejection counter missing or wrong:\n%s", out)
	}
	// /verify is not restricted by METRICS_ALLOWED_CIDRS.
	status, resp := alDo(t, router, http.MethodPost, "/verify", "192.0.2.1:1", buildVerifyBody(t, newNodeKey(t)), nil)
	if !alEvaluated(t, status, resp) {
		t.Fatalf("/verify with only a metrics allowlist: status=%d body=%s", status, resp)
	}
}

func TestAllowlistUnsetAllowsEveryone(t *testing.T) {
	router, gormDB := newTestRouter(t)
	body := buildVerifyBody(t, newNodeKey(t))
	for _, peer := range []string{"192.0.2.1:1", "[2001:db8::1]:1", "203.0.113.9:443", "garbage"} {
		for _, path := range []string{"/verify", "/verify/default"} {
			status, resp := alDo(t, router, http.MethodPost, path, peer, body, nil)
			if !alEvaluated(t, status, resp) {
				t.Fatalf("%s from %s without allowlist: status=%d body=%s", path, peer, status, resp)
			}
		}
		if status, _ := alDo(t, router, http.MethodGet, "/metrics", peer, nil, nil); status != http.StatusOK {
			t.Fatalf("/metrics from %s without allowlist: status=%d", peer, status)
		}
	}
	if n := alCountAudit(t, gormDB); n != 8 {
		t.Fatalf("audit rows=%d want=8 (every unrestricted call is audited)", n)
	}
}

func TestAllowlistIgnoresForwardedHeaders(t *testing.T) {
	router, _ := newTestRouter(t, alVerifyCIDRs("10.0.0.0/8"), alMetricsCIDRs("10.0.0.0/8"))
	body := buildVerifyBody(t, newNodeKey(t))

	spoofAllowed := map[string]string{
		"X-Forwarded-For":  "10.0.0.5",
		"X-Real-IP":        "10.0.0.5",
		"Forwarded":        "for=10.0.0.5",
		"True-Client-IP":   "10.0.0.5",
		"CF-Connecting-IP": "10.0.0.5",
	}
	for _, path := range []string{"/verify", "/verify/default"} {
		status, resp := alDo(t, router, http.MethodPost, path, "192.0.2.1:1234", body, spoofAllowed)
		alAssertForbidden(t, path+" with spoofed allowed headers", status, resp)
	}
	status, resp := alDo(t, router, http.MethodGet, "/metrics", "192.0.2.1:1234", nil, spoofAllowed)
	alAssertForbidden(t, "/metrics with spoofed allowed headers", status, resp)

	spoofDisallowed := map[string]string{
		"X-Forwarded-For": "192.0.2.1",
		"X-Real-IP":       "192.0.2.1",
		"Forwarded":       "for=192.0.2.1",
	}
	for _, path := range []string{"/verify", "/verify/default"} {
		status, resp := alDo(t, router, http.MethodPost, path, "10.0.0.5:1234", body, spoofDisallowed)
		if !alEvaluated(t, status, resp) {
			t.Fatalf("%s from allowed peer with disallowed headers: status=%d body=%s", path, status, resp)
		}
	}
	if status, _ := alDo(t, router, http.MethodGet, "/metrics", "10.0.0.5:1234", nil, spoofDisallowed); status != http.StatusOK {
		t.Fatalf("/metrics from allowed peer with disallowed headers: status=%d", status)
	}
}

func TestAllowlistIPv4MappedPeer(t *testing.T) {
	router, _ := newTestRouter(t, alVerifyCIDRs("10.0.0.0/8"))
	body := buildVerifyBody(t, newNodeKey(t))

	status, resp := alDo(t, router, http.MethodPost, "/verify", "[::ffff:10.0.0.5]:41641", body, nil)
	if !alEvaluated(t, status, resp) {
		t.Fatalf("IPv4-mapped allowed peer: status=%d body=%s", status, resp)
	}
	status, resp = alDo(t, router, http.MethodPost, "/verify/default", "[::ffff:192.0.2.1]:41641", body, nil)
	alAssertForbidden(t, "IPv4-mapped disallowed peer", status, resp)
	// A zoned link-local peer is matched without its zone.
	router6, _ := newTestRouter(t, alVerifyCIDRs("fe80::/10"))
	status, resp = alDo(t, router6, http.MethodPost, "/verify", "[fe80::1%eth0]:41641", body, nil)
	if !alEvaluated(t, status, resp) {
		t.Fatalf("zoned allowed peer: status=%d body=%s", status, resp)
	}
}

func TestAllowlistUnparsablePeerRejected(t *testing.T) {
	router, gormDB := newTestRouter(t, alVerifyCIDRs("0.0.0.0/0", "::/0"), alMetricsCIDRs("0.0.0.0/0", "::/0"))
	body := buildVerifyBody(t, newNodeKey(t))
	for _, peer := range []string{"", "garbage", "pipe:1234", "@"} {
		status, resp := alDo(t, router, http.MethodPost, "/verify", peer, body, nil)
		alAssertForbidden(t, "verify from unparsable peer "+peer, status, resp)
		status, resp = alDo(t, router, http.MethodGet, "/metrics", peer, nil, nil)
		alAssertForbidden(t, "metrics from unparsable peer "+peer, status, resp)
	}
	// A bare address without a port still parses.
	status, resp := alDo(t, router, http.MethodPost, "/verify", "192.0.2.1", body, nil)
	if !alEvaluated(t, status, resp) {
		t.Fatalf("bare address peer: status=%d body=%s", status, resp)
	}
	if n := alCountAudit(t, gormDB); n != 1 {
		t.Fatalf("audit rows=%d want=1", n)
	}
}

func TestAllowlistRejectedCallerNotAuditedAndKeepsLimiter(t *testing.T) {
	application := bBuildSingleApp(t, func(c *config.Config) {
		c.VerifyRateLimitRPS = 0.0001 // effectively no refill during the test
		c.VerifyRateBurst = 1
		c.VerifyAllowedCIDRs = alPrefixes("10.0.0.0/8")
	})
	router := application.Router

	user := createUser(t, application.DB, "limiter-user")
	bBindUserRoles(t, application, user.ID, []string{policy.BuiltinRole})
	nodeKey := newNodeKey(t)
	createDevice(t, application.DB, user.ID, nodeKey, "laptop", nil)
	body := buildVerifyBody(t, nodeKey)

	const rejected = 50
	for i := 0; i < rejected; i++ {
		path := "/verify"
		if i%2 == 1 {
			path = "/verify/default"
		}
		status, resp := alDo(t, router, http.MethodPost, path, "192.0.2.1:1234", body, map[string]string{"X-Forwarded-For": "10.0.0.5"})
		alAssertForbidden(t, "outsider call", status, resp)
	}
	if n := alCountAudit(t, application.DB); n != 0 {
		t.Fatalf("audit rows after rejected calls=%d want=0", n)
	}

	status, resp := alDo(t, router, http.MethodPost, "/verify", "10.0.0.5:1234", body, nil)
	if !alEvaluated(t, status, resp) || !strings.Contains(resp, `"Allow":true`) {
		t.Fatalf("allowed call after %d rejections: status=%d body=%s, want Allow:true (limiter token must be intact)", rejected, status, resp)
	}
	// The single burst token is now spent: the next allowed call is rate limited,
	// which proves the limiter was live during the rejected calls.
	status, resp = alDo(t, router, http.MethodPost, "/verify", "10.0.0.5:1234", body, nil)
	if status != http.StatusOK || !strings.Contains(resp, "rate limited") {
		t.Fatalf("second allowed call: status=%d body=%s want rate limited", status, resp)
	}
	if n := alCountAudit(t, application.DB); n != 1 {
		t.Fatalf("audit rows=%d want=1 (only the allowed, evaluated call)", n)
	}

	_, _, out := bScrapeMetrics(t, router)
	for _, want := range []string{
		`derp_admit_caller_rejected_total{endpoint="verify"} 50`,
		`derp_admit_caller_rejected_total{endpoint="metrics"} 0`,
		`derp_admit_verify_decisions_total{allowed="true",reason="",relay="default"} 1`,
		`derp_admit_rate_limited_total{endpoint="verify"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("scrape missing %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "\nderp_admit_verify_decisions_total{") != 1 {
		t.Fatalf("rejected callers must not be counted as verify decisions:\n%s", out)
	}
}

func TestAllowlistDoesNotAffectOtherEndpoints(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt, alVerifyCIDRs("10.0.0.0/8"), alMetricsCIDRs("10.0.0.0/8"))
	const outsider = "192.0.2.1:1234"

	for _, path := range []string{"/healthz", "/readyz", "/"} {
		if status, body := alDo(t, router, http.MethodGet, path, outsider, nil, nil); status != http.StatusOK {
			t.Fatalf("GET %s from outsider: status=%d body=%s", path, status, body)
		}
	}
	status, _ := doAdminRequestFrom(t, router, http.MethodGet, "/admin/users", testAdminKey, outsider, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /admin/users from outsider: status=%d want=200", status)
	}

	user := createUser(t, gormDB, "register-user")
	token := "allowlist-enroll-token"
	createEnrollToken(t, gormDB, user.ID, "test-pepper", token, nil, nil, 0)
	regBody, _ := json.Marshal(map[string]any{"token": token, "nodeKey": newNodeKey(t), "label": "x"})
	if status, body := alDo(t, router, http.MethodPost, "/register", outsider, regBody, nil); status != http.StatusOK {
		t.Fatalf("POST /register from outsider: status=%d body=%s", status, body)
	}
}
