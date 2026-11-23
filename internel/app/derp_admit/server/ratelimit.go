package server

import (
	"net/netip"
	"sync"

	"golang.org/x/time/rate"
)

// maxTrackedClients bounds the per-IP limiter map so a wide scan cannot grow
// it without limit; when full, an arbitrary half is shed (idle buckets refill
// to full burst anyway, so shedding only forgets in-progress throttling).
const maxTrackedClients = 10000

// ipRateLimiter applies an independent token bucket per client IP (exact
// address for IPv4, /64 prefix for IPv6), so one abusive client exhausts only
// its own budget instead of starving every other caller the way a single shared
// limiter would.
type ipRateLimiter struct {
	rps   rate.Limit
	burst int

	mu      sync.Mutex
	clients map[string]*rate.Limiter
}

func newIPRateLimiter(rps float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		rps:     rate.Limit(rps),
		burst:   burst,
		clients: map[string]*rate.Limiter{},
	}
}

func (l *ipRateLimiter) Allow(ip string) bool {
	key := rateLimitKey(ip)

	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, ok := l.clients[key]
	if !ok {
		if len(l.clients) >= maxTrackedClients {
			for k := range l.clients {
				delete(l.clients, k)
				if len(l.clients) <= maxTrackedClients/2 {
					break
				}
			}
		}
		limiter = rate.NewLimiter(l.rps, l.burst)
		l.clients[key] = limiter
	}
	return limiter.Allow()
}

func rateLimitKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	// Unmap IPv4-mapped IPv6 addresses (e.g. ::ffff:192.0.2.1) so they stay
	// bucketed per IPv4 address instead of all collapsing into one /64.
	addr = addr.Unmap()
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.String()
		}
	}
	return addr.String()
}
