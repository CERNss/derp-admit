package server

import (
	"net/http"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func lifecycleRoutes() []adminRoute {
	return []adminRoute{
		{
			Method:     http.MethodPost,
			Path:       "/users",
			MinTier:    actor.TierOperator,
			Action:     "user.create",
			TargetType: "user",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					var req struct {
						Username string  `json:"username"`
						Email    *string `json:"email"`
					}
					if !bindJSON(c, &req) {
						return
					}
					user, err := d.svc.CreateUser(c.Request.Context(), service.CreateUserInput{
						Username: req.Username,
						Email:    req.Email,
					})
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					c.JSON(http.StatusCreated, gin.H{"ok": true, "user": userView(user)})
				}
			},
		},
		{
			Method:  http.MethodGet,
			Path:    "/users",
			MinTier: actor.TierViewer,
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					users, err := d.svc.ListUsers(c.Request.Context())
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					views := make([]gin.H, 0, len(users))
					for _, u := range users {
						views = append(views, userView(u))
					}
					c.JSON(http.StatusOK, gin.H{"ok": true, "users": views})
				}
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/users/:id/disable",
			MinTier:     actor.TierOperator,
			Action:      "user.disable",
			TargetType:  "user",
			TargetParam: "id",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					setUserDisabled(c, d.svc, d.logger, true)
				}
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/users/:id/enable",
			MinTier:     actor.TierOperator,
			Action:      "user.enable",
			TargetType:  "user",
			TargetParam: "id",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					setUserDisabled(c, d.svc, d.logger, false)
				}
			},
		},
		{
			Method:     http.MethodPost,
			Path:       "/tokens",
			MinTier:    actor.TierOperator,
			Action:     "token.create",
			TargetType: "token",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
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
					result, err := d.svc.CreateToken(c.Request.Context(), service.CreateTokenInput{
						UserID:     userID,
						ExpiresAt:  req.ExpiresAt,
						MaxDevices: maxDevices,
						Note:       req.Note,
					})
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					// Plaintext token is returned exactly once here; only its hash is stored.
					c.JSON(http.StatusCreated, gin.H{
						"ok":    true,
						"token": result.Plain,
						"meta":  tokenView(result.Token),
					})
				}
			},
		},
		{
			Method:  http.MethodGet,
			Path:    "/tokens",
			MinTier: actor.TierViewer,
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					tokens, err := d.svc.ListTokens(c.Request.Context())
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					views := make([]gin.H, 0, len(tokens))
					for _, t := range tokens {
						views = append(views, tokenView(t))
					}
					c.JSON(http.StatusOK, gin.H{"ok": true, "tokens": views})
				}
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/tokens/:id/revoke",
			MinTier:     actor.TierOperator,
			Action:      "token.revoke",
			TargetType:  "token",
			TargetParam: "id",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					id, ok := parseUUID(c, c.Param("id"))
					if !ok {
						return
					}
					if err := d.svc.RevokeToken(c.Request.Context(), id); err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					c.JSON(http.StatusOK, gin.H{"ok": true})
				}
			},
		},
		{
			Method:  http.MethodGet,
			Path:    "/devices",
			MinTier: actor.TierViewer,
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					var userID *uuid.UUID
					if raw := strings.TrimSpace(c.Query("userId")); raw != "" {
						parsed, err := uuid.Parse(raw)
						if err != nil {
							c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid userId"})
							return
						}
						userID = &parsed
					}
					devices, err := d.svc.ListDevices(c.Request.Context(), userID)
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					views := make([]gin.H, 0, len(devices))
					for _, dev := range devices {
						views = append(views, deviceView(dev))
					}
					c.JSON(http.StatusOK, gin.H{"ok": true, "devices": views})
				}
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/devices/:id/revoke",
			MinTier:     actor.TierOperator,
			Action:      "device.revoke",
			TargetType:  "device",
			TargetParam: "id",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					setDeviceRevoked(c, d.svc, d.logger, true)
				}
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/devices/:id/enable",
			MinTier:     actor.TierOperator,
			Action:      "device.enable",
			TargetType:  "device",
			TargetParam: "id",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					setDeviceRevoked(c, d.svc, d.logger, false)
				}
			},
		},
	}
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
