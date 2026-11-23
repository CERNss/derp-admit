package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// maxRequestBodyBytes caps inbound request bodies to protect the admission
// path from large-payload memory pressure.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

type RouterOption func(*routerOptions)

type routerOptions struct {
	metrics metrics.Recorder
}

func WithMetrics(r metrics.Recorder) RouterOption {
	return func(o *routerOptions) {
		if r != nil {
			o.metrics = r
		}
	}
}

func NewRouter(svc *service.Service, cfg config.Config, logger *zap.Logger, opts ...RouterOption) *gin.Engine {
	ro := routerOptions{metrics: metrics.Nop}
	for _, opt := range opts {
		if opt != nil {
			opt(&ro)
		}
	}
	rec := ro.metrics

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	// Trust no proxy headers: ClientIP is the TCP peer address, so the per-IP
	// register and admin limiters cannot be reset with a spoofed X-Forwarded-For.
	_ = router.SetTrustedProxies(nil)
	router.Use(gin.Recovery())
	router.Use(limitRequestBody(maxRequestBodyBytes))
	if cfg.OTELEnabled {
		router.Use(otelgin.Middleware(cfg.OTELServiceName))
	}

	verifyLimiter := rate.NewLimiter(rate.Limit(cfg.VerifyRateLimitRPS), cfg.VerifyRateBurst)
	registerLimiter := newIPRateLimiter(cfg.RegisterRateLimitRPS, cfg.RegisterRateBurst)

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
		if svc.SyncStale() {
			c.JSON(http.StatusServiceUnavailable, gin.H{"ok": false})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	if cfg.MetricsEnabled {
		if h := rec.Handler(); h != nil {
			router.GET("/metrics", gin.WrapH(h))
		}
	}

	router.POST("/register", func(c *gin.Context) {
		if !registerLimiter.Allow(c.ClientIP()) {
			logWithTrace(logger, c.Request.Context()).Warn("register request rate limited",
				zap.String("client_ip", c.ClientIP()),
			)
			rec.RateLimited(metrics.EndpointRegister)
			rec.RegisterOutcome(http.StatusTooManyRequests)
			c.JSON(http.StatusTooManyRequests, gin.H{"ok": false, "error": "rate limited"})
			return
		}

		var req service.RegisterInput
		if !bindJSON(c, &req) {
			rec.RegisterOutcome(c.Writer.Status())
			return
		}

		status, err := svc.Register(c.Request.Context(), req)
		if err != nil {
			logWithTrace(logger, c.Request.Context()).Error("register failed",
				zap.Error(err),
			)
			rec.RegisterOutcome(http.StatusInternalServerError)
			c.JSON(http.StatusInternalServerError, gin.H{"ok": false})
			return
		}

		rec.RegisterOutcome(status)
		if status == http.StatusOK {
			c.JSON(http.StatusOK, gin.H{"ok": true})
			return
		}
		c.JSON(status, gin.H{"ok": false})
	})

	router.POST("/verify", verifyHandler(svc, verifyLimiter, logger, rec, true))
	router.POST("/verify/*relay", verifyHandler(svc, verifyLimiter, logger, rec, false))

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "derp-verifier",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	if cfg.AdminAPIKey != "" {
		adminLimiter := newIPRateLimiter(cfg.AdminRateLimitRPS, cfg.AdminRateBurst)
		registerAdminRoutes(router, svc, adminLimiter, logger, rec)
		logger.Info("admin API enabled", zap.String("prefix", "/admin"))
	} else {
		logger.Warn("admin API disabled: ADMIN_API_KEY not set (provision via SQL)")
	}

	return router
}

// bindJSON binds the request body and writes the error response on failure:
// 413 when the body exceeded the request-size cap, 400 otherwise.
func bindJSON(c *gin.Context, out any) bool {
	if err := c.ShouldBindJSON(out); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"ok": false, "error": "request body too large"})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid request"})
		}
		return false
	}
	return true
}

func limitRequestBody(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		}
		c.Next()
	}
}

func logWithTrace(logger *zap.Logger, ctx context.Context) *zap.Logger {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return logger
	}

	return logger.With(
		zap.String("trace_id", spanCtx.TraceID().String()),
		zap.String("span_id", spanCtx.SpanID().String()),
	)
}
