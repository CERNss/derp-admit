package server

import (
	"net/http"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
)

const adminKeysListName = "keys"

// keyRoutes returns the admin-key management routes (Track C).
func keyRoutes() []adminRoute {
	return []adminRoute{
		{
			Method:     http.MethodPost,
			Path:       "/keys",
			MinTier:    actor.TierAdmin,
			Action:     "admin_key.create",
			TargetType: "admin_key",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					var req struct {
						Name      string     `json:"name"`
						Tier      string     `json:"tier"`
						ExpiresAt *time.Time `json:"expiresAt"`
					}
					if !bindJSON(c, &req) {
						return
					}
					result, err := d.svc.CreateAdminKey(c.Request.Context(), service.CreateAdminKeyInput{
						Name:      req.Name,
						Tier:      req.Tier,
						ExpiresAt: req.ExpiresAt,
					})
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					// Plaintext key is returned exactly once here; only its hash is stored.
					c.JSON(http.StatusCreated, gin.H{
						"ok":   true,
						"key":  result.Plain,
						"meta": adminKeyView(result.Key),
					})
				}
			},
		},
		{
			Method:  http.MethodGet,
			Path:    "/keys",
			MinTier: actor.TierAdmin,
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					pageReq, ok := pageParams(c, adminKeysListName)
					if !ok {
						return
					}
					keys, nextCursor, err := d.svc.ListAdminKeys(c.Request.Context(), pageReq)
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					views := make([]gin.H, 0, len(keys))
					for _, k := range keys {
						views = append(views, adminKeyView(k))
					}
					c.JSON(http.StatusOK, gin.H{
						"ok":         true,
						"keys":       views,
						"nextCursor": nextCursor,
					})
				}
			},
		},
		{
			Method:      http.MethodPost,
			Path:        "/keys/:id/revoke",
			MinTier:     actor.TierAdmin,
			Action:      "admin_key.revoke",
			TargetType:  "admin_key",
			TargetParam: "id",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					id, ok := parseUUID(c, c.Param("id"))
					if !ok {
						return
					}
					if err := d.svc.RevokeAdminKey(c.Request.Context(), id); err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					c.JSON(http.StatusOK, gin.H{"ok": true})
				}
			},
		},
	}
}

func adminKeyView(k model.AdminKey) gin.H {
	return gin.H{
		"id":         k.ID,
		"name":       k.Name,
		"tier":       k.Tier,
		"createdAt":  k.CreatedAt,
		"expiresAt":  k.ExpiresAt,
		"revokedAt":  k.RevokedAt,
		"lastUsedAt": k.LastUsedAt,
	}
}
