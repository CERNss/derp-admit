package server

import (
	"io"
	"net/http"
	"strings"

	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func verifyHandler(svc *service.Service, verifyLimiter *rate.Limiter, logger *zap.Logger, rec metrics.Recorder, defaultRelay bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !verifyLimiter.Allow() {
			logWithTrace(logger, c.Request.Context()).Warn("verify request rate limited")
			rec.RateLimited(metrics.EndpointVerify)
			resp := derp.BuildResponse(false, "rate limited")
			c.JSON(http.StatusOK, resp)
			return
		}

		var relay string
		if defaultRelay {
			relay = policy.BuiltinRelay
		} else {
			relay = strings.TrimPrefix(c.Param("relay"), "/")
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			logWithTrace(logger, c.Request.Context()).Warn("read verify request body",
				zap.Error(err),
			)
			body = nil
		}

		allow, denyReason := svc.Verify(c.Request.Context(), relay, body)
		resp := derp.BuildResponse(allow, denyReason)
		c.JSON(http.StatusOK, resp)
	}
}
