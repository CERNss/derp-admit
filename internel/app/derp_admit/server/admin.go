package server

import (
	"errors"
	"net/http"
	"strings"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/page"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type adminDeps struct {
	svc    *service.Service
	logger *zap.Logger
}

type adminRoute struct {
	Method, Path       string
	MinTier            actor.Tier
	Action, TargetType string // empty for GET
	TargetParam        string // "id" | "name" | ""
	Handle             func(d adminDeps) gin.HandlerFunc
}

func adminRoutes() []adminRoute {
	groups := [][]adminRoute{
		lifecycleRoutes(),
		accessRoutes(),
		keyRoutes(),
		auditRoutes(),
	}
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	out := make([]adminRoute, 0, total)
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// registerAdminRoutes mounts the authenticated /admin API from adminRoutes().
// It is only called when ADMIN_API_KEY is configured. The per-IP rate limiter
// runs before authentication so keys cannot be brute-forced at line rate.
func registerAdminRoutes(router *gin.Engine, svc *service.Service, limiter *ipRateLimiter, logger *zap.Logger, rec metrics.Recorder) {
	deps := adminDeps{svc: svc, logger: logger}
	admin := router.Group(
		"/admin",
		adminMetrics(rec),
		adminRateLimit(limiter, logger, rec),
		adminAuth(svc, logger),
	)

	for _, r := range adminRoutes() {
		route := r
		handlers := make([]gin.HandlerFunc, 0, 4)
		if route.Action != "" {
			handlers = append(handlers, attachAdminOp(route), adminAuditTail(svc))
		}
		handlers = append(handlers, requireTier(route.MinTier), route.Handle(deps))
		admin.Handle(route.Method, route.Path, handlers...)
	}
}

func adminMetrics(rec metrics.Recorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		tier := actor.TierNone.String()
		if a, ok := actor.From(c.Request.Context()); ok {
			tier = a.Tier.String()
		}
		rec.AdminRequest(tier, c.Writer.Status())
	}
}

func adminRateLimit(limiter *ipRateLimiter, logger *zap.Logger, rec metrics.Recorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow(c.ClientIP()) {
			logWithTrace(logger, c.Request.Context()).Warn("admin request rate limited",
				zap.String("client_ip", c.ClientIP()),
			)
			rec.RateLimited(metrics.EndpointAdmin)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"ok": false, "error": "rate limited"})
			return
		}
		c.Next()
	}
}

func adminAuth(svc *service.Service, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		const prefix = "Bearer "
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, prefix) {
			logWithTrace(logger, c.Request.Context()).Warn("admin request unauthorized",
				zap.String("client_ip", c.ClientIP()),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "unauthorized"})
			return
		}
		bearer := strings.TrimPrefix(header, prefix)
		a, ok, err := svc.AuthenticateAdminKey(c.Request.Context(), bearer)
		if err != nil {
			logWithTrace(logger, c.Request.Context()).Error("authenticate admin key failed",
				zap.Error(err),
				zap.String("client_ip", c.ClientIP()),
			)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"ok": false})
			return
		}
		if !ok {
			logWithTrace(logger, c.Request.Context()).Warn("admin request unauthorized",
				zap.String("client_ip", c.ClientIP()),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "unauthorized"})
			return
		}
		a.IP = c.ClientIP()
		c.Request = c.Request.WithContext(actor.With(c.Request.Context(), a))
		c.Next()
	}
}

func attachAdminOp(route adminRoute) gin.HandlerFunc {
	return func(c *gin.Context) {
		targetID := ""
		if route.TargetParam != "" {
			targetID = strings.TrimSpace(c.Param(route.TargetParam))
		}
		op := &actor.Op{
			Action:     route.Action,
			TargetType: route.TargetType,
			TargetID:   targetID,
		}
		c.Request = c.Request.WithContext(actor.WithOp(c.Request.Context(), op))
		c.Next()
	}
}

// adminAuditTail records a standalone failure admin audit row for any
// authenticated mutating request whose handler did not commit a success audit
// row (covering 403, bindJSON/parseUUID 400s, 404/409 and 500s).
func adminAuditTail(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		op, hasOp := actor.OpFrom(c.Request.Context())
		if !hasOp || op.Recorded() {
			return
		}
		if _, hasActor := actor.From(c.Request.Context()); !hasActor {
			return
		}
		svc.WriteAdminAuditFailure(c.Request.Context(), c.Writer.Status())
	}
}

func requireTier(min actor.Tier) gin.HandlerFunc {
	return func(c *gin.Context) {
		a, ok := actor.From(c.Request.Context())
		if !ok || a.Tier < min {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"ok": false, "error": "forbidden"})
			return
		}
		c.Next()
	}
}

func pageParams(c *gin.Context, list string) (page.Request, bool) {
	req, err := page.Parse(list, c.Query("limit"), c.Query("cursor"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": err.Error()})
		return page.Request{}, false
	}
	return req, true
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
