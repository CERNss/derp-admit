package server

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/model"
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

	admin.POST("/users", func(c *gin.Context) {
		var req struct {
			Username string  `json:"username"`
			Email    *string `json:"email"`
		}
		if !bindJSON(c, &req) {
			return
		}
		user, err := svc.CreateUser(c.Request.Context(), service.CreateUserInput{
			Username: req.Username,
			Email:    req.Email,
		})
		if err != nil {
			writeAdminError(c, logger, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"ok": true, "user": userView(user)})
	})

	admin.GET("/users", func(c *gin.Context) {
		users, err := svc.ListUsers(c.Request.Context())
		if err != nil {
			writeAdminError(c, logger, err)
			return
		}
		views := make([]gin.H, 0, len(users))
		for _, u := range users {
			views = append(views, userView(u))
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "users": views})
	})

	admin.POST("/users/:id/disable", func(c *gin.Context) {
		setUserDisabled(c, svc, logger, true)
	})
	admin.POST("/users/:id/enable", func(c *gin.Context) {
		setUserDisabled(c, svc, logger, false)
	})

	admin.POST("/tokens", func(c *gin.Context) {
		var req struct {
			UserID     string     `json:"userId"`
			ExpiresAt  *time.Time `json:"expiresAt"`
			MaxDevices *int       `json:"maxDevices"`
			Note       string     `json:"note"`
		}
		if !bindJSON(c, &req) {
			return
		}
		userID, ok := parseUUID(c, req.UserID)
		if !ok {
			return
		}
		// Omitting maxDevices defaults to 1 device per token; unlimited must
		// be requested explicitly with 0 so a leaked token can't silently
		// enroll unbounded devices.
		maxDevices := 1
		if req.MaxDevices != nil {
			maxDevices = *req.MaxDevices
		}
		result, err := svc.CreateToken(c.Request.Context(), service.CreateTokenInput{
			UserID:     userID,
			ExpiresAt:  req.ExpiresAt,
			MaxDevices: maxDevices,
			Note:       req.Note,
		})
		if err != nil {
			writeAdminError(c, logger, err)
			return
		}
		// Plaintext token is returned exactly once here; only its hash is stored.
		c.JSON(http.StatusCreated, gin.H{
			"ok":    true,
			"token": result.Plain,
			"meta":  tokenView(result.Token),
		})
	})

	admin.GET("/tokens", func(c *gin.Context) {
		tokens, err := svc.ListTokens(c.Request.Context())
		if err != nil {
			writeAdminError(c, logger, err)
			return
		}
		views := make([]gin.H, 0, len(tokens))
		for _, t := range tokens {
			views = append(views, tokenView(t))
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "tokens": views})
	})

	admin.POST("/tokens/:id/revoke", func(c *gin.Context) {
		id, ok := parseUUID(c, c.Param("id"))
		if !ok {
			return
		}
		if err := svc.RevokeToken(c.Request.Context(), id); err != nil {
			writeAdminError(c, logger, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	admin.GET("/devices", func(c *gin.Context) {
		var userID *uuid.UUID
		if raw := strings.TrimSpace(c.Query("userId")); raw != "" {
			parsed, err := uuid.Parse(raw)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid userId"})
				return
			}
			userID = &parsed
		}
		devices, err := svc.ListDevices(c.Request.Context(), userID)
		if err != nil {
			writeAdminError(c, logger, err)
			return
		}
		views := make([]gin.H, 0, len(devices))
		for _, d := range devices {
			views = append(views, deviceView(d))
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "devices": views})
	})

	admin.POST("/devices/:id/revoke", func(c *gin.Context) {
		setDeviceRevoked(c, svc, logger, true)
	})
	admin.POST("/devices/:id/enable", func(c *gin.Context) {
		setDeviceRevoked(c, svc, logger, false)
	})
}

func setUserDisabled(c *gin.Context, svc *service.Service, logger *zap.Logger, disabled bool) {
	id, ok := parseUUID(c, c.Param("id"))
	if !ok {
		return
	}
	if err := svc.SetUserDisabled(c.Request.Context(), id, disabled); err != nil {
		writeAdminError(c, logger, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func setDeviceRevoked(c *gin.Context, svc *service.Service, logger *zap.Logger, revoked bool) {
	id, ok := parseUUID(c, c.Param("id"))
	if !ok {
		return
	}
	if err := svc.SetDeviceRevoked(c.Request.Context(), id, revoked); err != nil {
		writeAdminError(c, logger, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
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

func userView(u model.User) gin.H {
	return gin.H{
		"id":         u.ID,
		"username":   u.Username,
		"email":      u.Email,
		"disabledAt": u.DisabledAt,
		"createdAt":  u.CreatedAt,
	}
}

func tokenView(t model.EnrollToken) gin.H {
	return gin.H{
		"id":         t.ID,
		"userId":     t.UserID,
		"expiresAt":  t.ExpiresAt,
		"revokedAt":  t.RevokedAt,
		"maxDevices": t.MaxDevices,
		"note":       t.Note,
		"createdAt":  t.CreatedAt,
	}
}

func deviceView(d model.Device) gin.H {
	return gin.H{
		"id":         d.ID,
		"userId":     d.UserID,
		"nodeKey":    d.NodeKey,
		"label":      d.Label,
		"createdAt":  d.CreatedAt,
		"lastSeenAt": d.LastSeenAt,
		"revokedAt":  d.RevokedAt,
	}
}
