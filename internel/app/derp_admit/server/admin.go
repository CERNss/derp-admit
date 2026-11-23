package server

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// registerAdminRoutes mounts the authenticated /admin lifecycle API. It is only
// called when an admin API key is configured. The per-IP rate limiter runs
// before the key check so the static bearer key cannot be brute-forced at line
// rate.
func registerAdminRoutes(router *gin.Engine, svc *service.Service, apiKey string, limiter *ipRateLimiter, logger *zap.Logger) {
	admin := router.Group("/admin", adminRateLimit(limiter, logger), adminAuth(apiKey))
	registerLifecycleRoutes(admin, svc, logger)
}

func adminRateLimit(limiter *ipRateLimiter, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow(c.ClientIP()) {
			logWithTrace(logger, c.Request.Context()).Warn("admin request rate limited",
				zap.String("client_ip", c.ClientIP()),
			)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"ok": false, "error": "rate limited"})
			return
		}
		c.Next()
	}
}

func adminAuth(apiKey string) gin.HandlerFunc {
	want := []byte(apiKey)
	return func(c *gin.Context) {
		// Defense in depth: an empty configured key must never authenticate
		// (ConstantTimeCompare of two empty slices returns 1), regardless of
		// the config validation callers are expected to have done.
		if len(want) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "unauthorized"})
			return
		}
		const prefix = "Bearer "
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(header, prefix)), want) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "unauthorized"})
			return
		}
		c.Next()
	}
}

func parseUUID(c *gin.Context, raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid id"})
		return uuid.Nil, false
	}
	return id, true
}

func writeAdminError(c *gin.Context, logger *zap.Logger, err error) {
	switch {
	case errors.Is(err, service.ErrAdminNotFound):
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "error": "not found"})
	case errors.Is(err, service.ErrAdminConflict):
		c.JSON(http.StatusConflict, gin.H{"ok": false, "error": "conflict"})
	case errors.Is(err, service.ErrAdminInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": err.Error()})
	default:
		logWithTrace(logger, c.Request.Context()).Error("admin request failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false})
	}
}
