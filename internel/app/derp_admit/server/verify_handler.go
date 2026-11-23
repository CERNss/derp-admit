package server

import (
	"encoding/json"
	"net/http"

	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func verifyHandler(svc *service.Service, verifyLimiter *rate.Limiter, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !verifyLimiter.Allow() {
			logWithTrace(logger, c.Request.Context()).Warn("verify request rate limited")
			resp := derp.BuildResponse(false, "rate limited")
			c.JSON(http.StatusOK, resp)
			return
		}

		var raw json.RawMessage
		if err := c.ShouldBindJSON(&raw); err != nil {
			logWithTrace(logger, c.Request.Context()).Warn("invalid verify json payload",
				zap.Error(err),
			)
			resp := derp.BuildResponse(false, service.DenyReasonInvalidReq)
			c.JSON(http.StatusOK, resp)
			return
		}

		allow, denyReason := svc.Verify(c.Request.Context(), raw)
		resp := derp.BuildResponse(allow, denyReason)
		c.JSON(http.StatusOK, resp)
	}
}
