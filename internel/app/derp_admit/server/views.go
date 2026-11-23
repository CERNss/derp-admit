package server

import (
	"derp-admit/internel/app/derp_admit/model"

	"github.com/gin-gonic/gin"
)

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
