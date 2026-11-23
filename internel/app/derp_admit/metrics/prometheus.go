package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus implements Recorder backed by a dedicated prometheus.Registry
// (never the global default registry, so multiple instances in one process do
// not collide).
type Prometheus struct {
	registry *prometheus.Registry
	handler  http.Handler

	verifyDecisions    *prometheus.CounterVec
	registerRequests   *prometheus.CounterVec
	adminRequests      *prometheus.CounterVec
	rateLimited        *prometheus.CounterVec
	verifyCacheLookups *prometheus.CounterVec
	policyVersion      prometheus.Gauge
	policyLastSyncTS   prometheus.Gauge
	policySyncFailures prometheus.Counter
	policyReloads      *prometheus.CounterVec
}

var _ Recorder = (*Prometheus)(nil)

// NewPrometheus constructs a Recorder exposing Prometheus metrics on its own
// registry.
func NewPrometheus() *Prometheus {
	reg := prometheus.NewRegistry()

	p := &Prometheus{
		registry: reg,
		verifyDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "derp_admit",
			Name:      "verify_decisions_total",
			Help:      "Total number of DERP verify decisions by relay, outcome, and deny reason.",
		}, []string{"relay", "allowed", "reason"}),
		registerRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "derp_admit",
			Name:      "register_requests_total",
			Help:      "Total number of device registration requests by HTTP status code.",
		}, []string{"status"}),
		adminRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "derp_admit",
			Name:      "admin_requests_total",
			Help:      "Total number of admin API requests by actor tier and HTTP status class.",
		}, []string{"tier", "status_class"}),
		rateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "derp_admit",
			Name:      "rate_limited_total",
			Help:      "Total number of requests rejected by rate limiters by endpoint.",
		}, []string{"endpoint"}),
		verifyCacheLookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "derp_admit",
			Name:      "verify_cache_lookups_total",
			Help:      "Total number of verify cache lookups by result (hit or miss).",
		}, []string{"result"}),
		policyVersion: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "derp_admit",
			Name:      "policy_version",
			Help:      "Current policy_state version published by this instance.",
		}),
		policyLastSyncTS: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "derp_admit",
			Name:      "policy_sync_last_success_timestamp_seconds",
			Help:      "Unix timestamp in seconds of the last successful policy sync check.",
		}),
		policySyncFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "derp_admit",
			Name:      "policy_sync_failures_total",
			Help:      "Total number of failed policy sync checks.",
		}),
		policyReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "derp_admit",
			Name:      "policy_reloads_total",
			Help:      "Total number of policy snapshot reloads by result (ok or error).",
		}, []string{"result"}),
	}

	reg.MustRegister(
		p.verifyDecisions,
		p.registerRequests,
		p.adminRequests,
		p.rateLimited,
		p.verifyCacheLookups,
		p.policyVersion,
		p.policyLastSyncTS,
		p.policySyncFailures,
		p.policyReloads,
	)

	// Pre-initialize bounded static label sets so zero values appear on scrapes.
	p.rateLimited.WithLabelValues(EndpointVerify)
	p.rateLimited.WithLabelValues(EndpointRegister)
	p.rateLimited.WithLabelValues(EndpointAdmin)
	p.verifyCacheLookups.WithLabelValues("hit")
	p.verifyCacheLookups.WithLabelValues("miss")
	p.policyReloads.WithLabelValues("ok")
	p.policyReloads.WithLabelValues("error")

	p.handler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	return p
}

func (p *Prometheus) VerifyDecision(relay string, allowed bool, reason string) {
	if relay == "" {
		relay = "unknown"
	}
	p.verifyDecisions.WithLabelValues(relay, strconv.FormatBool(allowed), reason).Inc()
}

func (p *Prometheus) RegisterOutcome(status int) {
	p.registerRequests.WithLabelValues(strconv.Itoa(status)).Inc()
}

func (p *Prometheus) AdminRequest(tier string, status int) {
	if tier == "" {
		tier = "none"
	}
	p.adminRequests.WithLabelValues(tier, statusClass(status)).Inc()
}

func (p *Prometheus) RateLimited(endpoint string) {
	if endpoint == "" {
		endpoint = "unknown"
	}
	p.rateLimited.WithLabelValues(endpoint).Inc()
}

func (p *Prometheus) CacheLookup(hit bool) {
	if hit {
		p.verifyCacheLookups.WithLabelValues("hit").Inc()
		return
	}
	p.verifyCacheLookups.WithLabelValues("miss").Inc()
}

func (p *Prometheus) PolicySync(ok bool, version int64, lastSuccess time.Time) {
	if ok {
		p.policyVersion.Set(float64(version))
		if !lastSuccess.IsZero() {
			p.policyLastSyncTS.Set(float64(lastSuccess.UnixNano()) / 1e9)
		}
		return
	}
	p.policySyncFailures.Inc()
}

func (p *Prometheus) PolicyReload(ok bool) {
	if ok {
		p.policyReloads.WithLabelValues("ok").Inc()
		return
	}
	p.policyReloads.WithLabelValues("error").Inc()
}

func (p *Prometheus) Handler() http.Handler {
	return p.handler
}

func statusClass(status int) string {
	switch {
	case status >= 100 && status < 200:
		return "1xx"
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "other"
	}
}
