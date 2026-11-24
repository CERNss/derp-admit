package server

import (
	"net"
	"net/http"
	"net/netip"

	"derp-admit/internel/app/derp_admit/metrics"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// callerAllowlist refuses, with 403, any request whose TCP peer address is not
// inside one of prefixes. It reads only Request.RemoteAddr: forwarded headers
// (X-Forwarded-For, X-Real-IP, ...) are never consulted. It must run before
// the handler so a refused caller spends no rate-limit token, writes no audit
// row and is not counted as a verify decision. An empty list returns nil so
// the caller can skip attaching the middleware.
func callerAllowlist(prefixes []netip.Prefix, endpoint string, logger *zap.Logger, rec metrics.Recorder) gin.HandlerFunc {
	if len(prefixes) == 0 {
		return nil
	}
	list := append([]netip.Prefix(nil), prefixes...)
	return func(c *gin.Context) {
		peer, ok := peerAddr(c.Request.RemoteAddr)
		if ok && prefixesContain(list, peer) {
			c.Next()
			return
		}
		clientIP := c.Request.RemoteAddr
		if ok {
			clientIP = peer.String()
		}
		logWithTrace(logger, c.Request.Context()).Warn("caller rejected by allowlist",
			zap.String("endpoint", endpoint),
			zap.String("client_ip", clientIP),
		)
		rec.CallerRejected(endpoint)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"ok": false, "error": "forbidden"})
	}
}

// peerAddr parses a RemoteAddr ("host:port", or a bare host) into an address
// that can be matched against IPv4 and IPv6 prefixes: IPv4-mapped IPv6
// addresses are unmapped and any zone is dropped.
func peerAddr(remoteAddr string) (netip.Addr, bool) {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

func prefixesContain(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// withAllowlist prepends mw to handlers when it is not nil.
func withAllowlist(mw gin.HandlerFunc, handlers ...gin.HandlerFunc) []gin.HandlerFunc {
	if mw == nil {
		return handlers
	}
	return append([]gin.HandlerFunc{mw}, handlers...)
}
