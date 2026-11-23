package metrics

import (
	"net/http"
	"time"
)

const (
	EndpointVerify   = "verify"
	EndpointRegister = "register"
	EndpointAdmin    = "admin"
)

// Recorder records operational metrics across HTTP handlers, verification,
// caching, and policy sync.
type Recorder interface {
	VerifyDecision(relay string, allowed bool, reason string)
	RegisterOutcome(status int)
	AdminRequest(tier string, status int)
	RateLimited(endpoint string)
	CacheLookup(hit bool)
	PolicySync(ok bool, version int64, lastSuccess time.Time)
	PolicyReload(ok bool)
	Handler() http.Handler
}

type nop struct{}

// Nop discards all metrics and exposes no HTTP handler so /metrics stays unmounted.
var Nop Recorder = nop{}

func (nop) VerifyDecision(string, bool, string) {}
func (nop) RegisterOutcome(int)                 {}
func (nop) AdminRequest(string, int)            {}
func (nop) RateLimited(string)                  {}
func (nop) CacheLookup(bool)                    {}
func (nop) PolicySync(bool, int64, time.Time)   {}
func (nop) PolicyReload(bool)                   {}
func (nop) Handler() http.Handler               { return nil }
