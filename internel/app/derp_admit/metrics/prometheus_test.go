package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/metrics"
)

func bScrape(t *testing.T, rec metrics.Recorder) string {
	t.Helper()
	h := rec.Handler()
	if h == nil {
		t.Fatalf("expected non-nil handler")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("scrape status=%d want=200", rr.Code)
	}
	return rr.Body.String()
}

func TestPrometheusSeparateRegistriesDoNotCollide(t *testing.T) {
	a := metrics.NewPrometheus()
	b := metrics.NewPrometheus()

	a.VerifyDecision("default", true, "")
	b.VerifyDecision("eu-1", false, "revoked")

	outA := bScrape(t, a)
	outB := bScrape(t, b)

	if !strings.Contains(outA, `derp_admit_verify_decisions_total{allowed="true",reason="",relay="default"} 1`) {
		t.Fatalf("instance A missing expected counter:\n%s", outA)
	}
	if strings.Contains(outA, `relay="eu-1"`) {
		t.Fatalf("instance A leaked instance B metric:\n%s", outA)
	}
	if !strings.Contains(outB, `derp_admit_verify_decisions_total{allowed="false",reason="revoked",relay="eu-1"} 1`) {
		t.Fatalf("instance B missing expected counter:\n%s", outB)
	}
}

func TestPrometheusRecordsAllSeries(t *testing.T) {
	p := metrics.NewPrometheus()

	p.VerifyDecision("default", false, "revoked")
	p.VerifyDecision("unknown", false, "unknown relay")
	p.RegisterOutcome(http.StatusOK)
	p.RegisterOutcome(http.StatusTooManyRequests)
	p.AdminRequest("none", http.StatusUnauthorized)
	p.AdminRequest("admin", http.StatusCreated)
	p.AdminRequest("operator", http.StatusInternalServerError)
	p.RateLimited(metrics.EndpointVerify)
	p.RateLimited(metrics.EndpointRegister)
	p.RateLimited(metrics.EndpointAdmin)
	p.CacheLookup(true)
	p.CacheLookup(true)
	p.CacheLookup(false)

	ts1 := time.Unix(1700000000, 0).UTC()
	p.PolicySync(true, 7, ts1)
	// Sync failure must increment failure counter and NOT advance last-success timestamp.
	p.PolicySync(false, 7, ts1.Add(time.Minute))
	p.PolicyReload(true)
	p.PolicyReload(false)

	out := bScrape(t, p)

	expected := []string{
		`derp_admit_verify_decisions_total{allowed="false",reason="revoked",relay="default"} 1`,
		`derp_admit_verify_decisions_total{allowed="false",reason="unknown relay",relay="unknown"} 1`,
		`derp_admit_register_requests_total{status="200"} 1`,
		`derp_admit_register_requests_total{status="429"} 1`,
		`derp_admit_admin_requests_total{status_class="4xx",tier="none"} 1`,
		`derp_admit_admin_requests_total{status_class="2xx",tier="admin"} 1`,
		`derp_admit_admin_requests_total{status_class="5xx",tier="operator"} 1`,
		`derp_admit_rate_limited_total{endpoint="verify"} 1`,
		`derp_admit_rate_limited_total{endpoint="register"} 1`,
		`derp_admit_rate_limited_total{endpoint="admin"} 1`,
		`derp_admit_verify_cache_lookups_total{result="hit"} 2`,
		`derp_admit_verify_cache_lookups_total{result="miss"} 1`,
		`derp_admit_policy_version 7`,
		`derp_admit_policy_sync_last_success_timestamp_seconds 1.7e+09`,
		`derp_admit_policy_sync_failures_total 1`,
		`derp_admit_policy_reloads_total{result="ok"} 1`,
		`derp_admit_policy_reloads_total{result="error"} 1`,
	}
	for _, want := range expected {
		if !strings.Contains(out, want) {
			t.Errorf("scrape output missing %q\nfull output:\n%s", want, out)
		}
	}
}
