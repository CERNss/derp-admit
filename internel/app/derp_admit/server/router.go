package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

func NewRouter(svc *service.Service, cfg config.Config, logger *slog.Logger) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	limiter := rate.NewLimiter(rate.Limit(cfg.VerifyRateLimitRPS), cfg.VerifyRateBurst)

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	router.GET("/readyz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), cfg.DBTimeout)
		defer cancel()
		if err := svc.Ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"ok": false})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	router.POST("/register", func(c *gin.Context) {
		var req service.RegisterInput
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid request"})
			return
		}

		status, err := svc.Register(c.Request.Context(), req)
		if err != nil {
			logger.Error("register failed", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"ok": false})
			return
		}

		if status == http.StatusOK {
			c.JSON(http.StatusOK, gin.H{"ok": true})
			return
		}
		c.JSON(status, gin.H{"ok": false})
	})

	router.POST("/verify", func(c *gin.Context) {
		if !limiter.Allow() {
			resp := derp.BuildResponse(false, "rate limited")
			c.JSON(http.StatusOK, resp)
			return
		}

		var raw json.RawMessage
		if err := c.ShouldBindJSON(&raw); err != nil {
			resp := derp.BuildResponse(false, service.DenyReasonInvalidReq)
			c.JSON(http.StatusOK, resp)
			return
		}

		allow, denyReason := svc.Verify(c.Request.Context(), raw)
		resp := derp.BuildResponse(allow, denyReason)
		c.JSON(http.StatusOK, resp)
	})

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "derp-verifier",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	return router
}
