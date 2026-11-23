package server

import (
	"net/http"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func auditRoutes() []adminRoute {
	return []adminRoute{
		{
			Method:  http.MethodGet,
			Path:    "/audit/admin",
			MinTier: actor.TierAdmin,
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					pg, ok := pageParams(c, "admin_audit")
					if !ok {
						return
					}
					filter, ok := parseAdminAuditFilter(c)
					if !ok {
						return
					}
					entries, nextCursor, err := d.svc.ListAdminAudit(c.Request.Context(), filter, pg)
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					views := make([]gin.H, 0, len(entries))
					for _, e := range entries {
						views = append(views, adminAuditView(e))
					}
					c.JSON(http.StatusOK, gin.H{"ok": true, "entries": views, "nextCursor": nextCursor})
				}
			},
		},
		{
			Method:  http.MethodGet,
			Path:    "/audit/verify",
			MinTier: actor.TierViewer,
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					pg, ok := pageParams(c, "verify_audit")
					if !ok {
						return
					}
					filter, ok := parseVerifyAuditFilter(c)
					if !ok {
						return
					}
					entries, nextCursor, err := d.svc.ListVerifyAudit(c.Request.Context(), filter, pg)
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					views := make([]gin.H, 0, len(entries))
					for _, e := range entries {
						views = append(views, verifyAuditView(e))
					}
					c.JSON(http.StatusOK, gin.H{"ok": true, "entries": views, "nextCursor": nextCursor})
				}
			},
		},
	}
}

func parseAdminAuditFilter(c *gin.Context) (service.AdminAuditFilter, bool) {
	var f service.AdminAuditFilter
	if raw := strings.TrimSpace(c.Query("actorKeyId")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid actorKeyId"})
			return service.AdminAuditFilter{}, false
		}
		f.ActorKeyID = &parsed
	}
	f.Action = strings.TrimSpace(c.Query("action"))
	f.TargetType = strings.TrimSpace(c.Query("targetType"))
	f.TargetID = strings.TrimSpace(c.Query("targetId"))

	since, ok := parseOptionalRFC3339(c, "since")
	if !ok {
		return service.AdminAuditFilter{}, false
	}
	f.Since = since

	until, ok := parseOptionalRFC3339(c, "until")
	if !ok {
		return service.AdminAuditFilter{}, false
	}
	f.Until = until

	return f, true
}

func parseVerifyAuditFilter(c *gin.Context) (service.VerifyAuditFilter, bool) {
	var f service.VerifyAuditFilter
	f.NodeKey = strings.TrimSpace(c.Query("nodeKey"))
	if raw := strings.TrimSpace(c.Query("deviceId")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid deviceId"})
			return service.VerifyAuditFilter{}, false
		}
		f.DeviceID = &parsed
	}
	f.Relay = strings.TrimSpace(c.Query("relay"))
	if raw := strings.TrimSpace(c.Query("allowed")); raw != "" {
		switch raw {
		case "true":
			v := true
			f.Allowed = &v
		case "false":
			v := false
			f.Allowed = &v
		default:
			c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid allowed"})
			return service.VerifyAuditFilter{}, false
		}
	}

	since, ok := parseOptionalRFC3339(c, "since")
	if !ok {
		return service.VerifyAuditFilter{}, false
	}
	f.Since = since

	until, ok := parseOptionalRFC3339(c, "until")
	if !ok {
		return service.VerifyAuditFilter{}, false
	}
	f.Until = until

	return f, true
}

func parseOptionalRFC3339(c *gin.Context, param string) (*time.Time, bool) {
	raw := strings.TrimSpace(c.Query(param))
	if raw == "" {
		return nil, true
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid " + param})
		return nil, false
	}
	utc := parsed.UTC()
	return &utc, true
}
