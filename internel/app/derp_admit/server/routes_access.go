package server

import (
	"net/http"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
)

// accessRoutes returns the role/relay access-management routes (Track D).
func accessRoutes() []adminRoute {
	return []adminRoute{
		{
			Method:     http.MethodPost,
			Path:       "/relays",
			MinTier:    actor.TierAdmin,
			Action:     "relay.create",
			TargetType: "relay",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					var req struct {
						Name        string `json:"name"`
						Description string `json:"description"`
					}
					if !bindJSON(c, &req) {
						return
					}
					relay, err := d.svc.CreateRelay(c.Request.Context(), service.CreateRelayInput{
						Name:        req.Name,
						Description: req.Description,
					})
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					c.JSON(http.StatusCreated, gin.H{
						"ok":    true,
						"relay": relayView(relay),
					})
				}
			},
		},
		{
			Method:  http.MethodGet,
			Path:    "/relays",
			MinTier: actor.TierViewer,
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					p, ok := pageParams(c, "relays")
					if !ok {
						return
					}
					relays, nextCursor, err := d.svc.ListRelays(c.Request.Context(), p)
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					views := make([]gin.H, 0, len(relays))
					for _, r := range relays {
						views = append(views, relayView(r))
					}
					c.JSON(http.StatusOK, gin.H{
						"ok":         true,
						"relays":     views,
						"nextCursor": nextCursor,
					})
				}
			},
		},
		{
			Method:      http.MethodDelete,
			Path:        "/relays/:name",
			MinTier:     actor.TierAdmin,
			Action:      "relay.delete",
			TargetType:  "relay",
			TargetParam: "name",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					if err := d.svc.DeleteRelay(c.Request.Context(), c.Param("name")); err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					c.JSON(http.StatusOK, gin.H{"ok": true})
				}
			},
		},
		{
			Method:     http.MethodPost,
			Path:       "/roles",
			MinTier:    actor.TierAdmin,
			Action:     "role.create",
			TargetType: "role",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					var req struct {
						Name        string   `json:"name"`
						Description string   `json:"description"`
						Relays      []string `json:"relays"`
					}
					if !bindJSON(c, &req) {
						return
					}
					role, err := d.svc.CreateRole(c.Request.Context(), service.CreateRoleInput{
						Name:        req.Name,
						Description: req.Description,
						Relays:      req.Relays,
					})
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					c.JSON(http.StatusCreated, gin.H{
						"ok":   true,
						"role": roleView(role),
					})
				}
			},
		},
		{
			Method:  http.MethodGet,
			Path:    "/roles",
			MinTier: actor.TierViewer,
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					p, ok := pageParams(c, "roles")
					if !ok {
						return
					}
					roles, nextCursor, err := d.svc.ListRoles(c.Request.Context(), p)
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					views := make([]gin.H, 0, len(roles))
					for _, r := range roles {
						views = append(views, roleView(r))
					}
					c.JSON(http.StatusOK, gin.H{
						"ok":         true,
						"roles":      views,
						"nextCursor": nextCursor,
					})
				}
			},
		},
		{
			Method:      http.MethodPut,
			Path:        "/roles/:name/relays",
			MinTier:     actor.TierAdmin,
			Action:      "role.grants.set",
			TargetType:  "role",
			TargetParam: "name",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					var req struct {
						Relays *[]string `json:"relays"`
					}
					if !bindJSON(c, &req) {
						return
					}
					if req.Relays == nil {
						c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "relays is required"})
						return
					}
					name := c.Param("name")
					relays, err := d.svc.SetRoleRelays(c.Request.Context(), name, *req.Relays)
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					c.JSON(http.StatusOK, gin.H{
						"ok":     true,
						"role":   name,
						"relays": relays,
					})
				}
			},
		},
		{
			Method:      http.MethodDelete,
			Path:        "/roles/:name",
			MinTier:     actor.TierAdmin,
			Action:      "role.delete",
			TargetType:  "role",
			TargetParam: "name",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					removed, err := d.svc.DeleteRole(c.Request.Context(), c.Param("name"))
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					c.JSON(http.StatusOK, gin.H{
						"ok":              true,
						"removedBindings": removed,
					})
				}
			},
		},
		{
			Method:      http.MethodPut,
			Path:        "/users/:id/roles",
			MinTier:     actor.TierOperator,
			Action:      "user.roles.set",
			TargetType:  "user",
			TargetParam: "id",
			Handle: func(d adminDeps) gin.HandlerFunc {
				return func(c *gin.Context) {
					id, ok := parseUUID(c, c.Param("id"))
					if !ok {
						return
					}
					var req struct {
						Roles *[]string `json:"roles"`
					}
					if !bindJSON(c, &req) {
						return
					}
					if req.Roles == nil {
						c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "roles is required"})
						return
					}
					roles, err := d.svc.SetUserRoles(c.Request.Context(), id, *req.Roles)
					if err != nil {
						writeAdminError(c, d.logger, err)
						return
					}
					c.JSON(http.StatusOK, gin.H{
						"ok":     true,
						"userId": id,
						"roles":  roles,
					})
				}
			},
		},
	}
}

func relayView(r model.Relay) gin.H {
	return gin.H{
		"name":        r.Name,
		"description": r.Description,
		"createdAt":   r.CreatedAt,
	}
}

func roleView(r service.RoleWithGrants) gin.H {
	relays := r.Relays
	if relays == nil {
		relays = []string{}
	}
	return gin.H{
		"name":        r.Role.Name,
		"description": r.Role.Description,
		"createdAt":   r.Role.CreatedAt,
		"relays":      relays,
	}
}
