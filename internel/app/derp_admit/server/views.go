package server

import (
	"encoding/json"
	"strings"

	"derp-admit/internel/app/derp_admit/model"

	"github.com/gin-gonic/gin"
)

func userView(u model.User, roles []string) gin.H {
	if roles == nil {
		roles = []string{}
	}
	return gin.H{
		"id":         u.ID,
		"username":   u.Username,
		"email":      u.Email,
		"disabledAt": u.DisabledAt,
		"createdAt":  u.CreatedAt,
		"roles":      roles,
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

func adminAuditView(e model.AdminAuditLog) gin.H {
	return gin.H{
		"id":         e.ID,
		"ts":         e.TS,
		"actorKeyId": e.ActorKeyID,
		"actorName":  e.ActorName,
		"actorTier":  e.ActorTier,
		"action":     e.Action,
		"targetType": e.TargetType,
		"targetId":   e.TargetID,
		"outcome":    e.Outcome,
		"httpStatus": e.HTTPStatus,
		"clientIp":   e.ClientIP,
		"summary":    parseAuditSummary(e.Summary),
	}
}

func verifyAuditView(e model.AuditLog) gin.H {
	return gin.H{
		"id":       e.ID,
		"deviceId": e.DeviceID,
		"nodeKey":  e.NodeKey,
		"relay":    e.Relay,
		"allowed":  e.Allowed,
		"reason":   e.Reason,
		"ts":       e.TS,
	}
}

func parseAuditSummary(raw string) any {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]any{}
	}
	if json.Valid([]byte(trimmed)) {
		return json.RawMessage(trimmed)
	}
	return raw
}
