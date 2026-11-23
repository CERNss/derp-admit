package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const intTestAdminKey = "integration-admin-key-0123456789"

func intBuildServer(t *testing.T) (http.Handler, *gorm.DB, *service.Service) {
	t.Helper()
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "int.db")
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := gormDB.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("seed builtins: %v", err)
	}
	engine, err := policy.NewEngine(gormDB)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "int-pepper",
		AdminAPIKey:          intTestAdminKey,
		MetricsEnabled:       true,
		DBTimeout:            5 * time.Second,
		PolicySyncInterval:   2 * time.Second,
		VerifyRateLimitRPS:   1000,
		VerifyRateBurst:      1000,
		RegisterRateLimitRPS: 1000,
		RegisterRateBurst:    1000,
		AdminRateLimitRPS:    1000,
		AdminRateBurst:       1000,
	}
	logger := zap.NewNop()
	svc := service.New(gormDB, engine, cfg.TokenPepper, cfg.DBTimeout, service.NewVerifyCache(0), logger)
	if err := svc.SyncBootstrapKey(context.Background(), cfg.AdminAPIKey); err != nil {
		t.Fatalf("SyncBootstrapKey: %v", err)
	}
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	router := NewRouter(svc, cfg, logger, WithMetrics(metrics.Nop))
	return router, gormDB, svc
}

func intInsertKey(t *testing.T, gormDB *gorm.DB, name string, tier actor.Tier) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	plain := "dak_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plain + ":int-pepper"))
	k := model.AdminKey{
		ID:      uuid.New(),
		Name:    name,
		Tier:    tier.String(),
		KeyHash: hex.EncodeToString(sum[:]),
	}
	if err := gormDB.Create(&k).Error; err != nil {
		t.Fatalf("insert key %s: %v", name, err)
	}
	return plain
}

func intDoAdmin(t *testing.T, router http.Handler, method, path, bearer string, payload any) (int, map[string]any) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestAdminTierMatrix(t *testing.T) {
	// Expected minimum tiers written directly from
	// openspec/changes/rework-access-control-and-admin/specs/admin-access-control/spec.md
	// (NOT read from adminRoutes()), so a misconfigured MinTier fails this test.
	expectedMinTier := map[string]actor.Tier{
		// Viewer tier: reads lifecycle and access data + verify audit.
		"GET /users":        actor.TierViewer,
		"GET /tokens":       actor.TierViewer,
		"GET /devices":      actor.TierViewer,
		"GET /roles":        actor.TierViewer,
		"GET /relays":       actor.TierViewer,
		"GET /audit/verify": actor.TierViewer,

		// Operator tier: users, user roles, tokens, devices.
		"POST /users":              actor.TierOperator,
		"DELETE /users/:id":        actor.TierOperator,
		"POST /users/:id/disable":  actor.TierOperator,
		"POST /users/:id/enable":   actor.TierOperator,
		"PUT /users/:id/roles":     actor.TierOperator,
		"POST /tokens":             actor.TierOperator,
		"DELETE /tokens/:id":       actor.TierOperator,
		"POST /tokens/:id/revoke":  actor.TierOperator,
		"DELETE /devices/:id":      actor.TierOperator,
		"POST /devices/:id/revoke": actor.TierOperator,
		"POST /devices/:id/enable": actor.TierOperator,

		// Admin tier: roles, grants, relays, admin keys, admin audit.
		"POST /relays":            actor.TierAdmin,
		"DELETE /relays/:name":    actor.TierAdmin,
		"POST /roles":             actor.TierAdmin,
		"PUT /roles/:name/relays": actor.TierAdmin,
		"DELETE /roles/:name":     actor.TierAdmin,
		"POST /keys":              actor.TierAdmin,
		"GET /keys":               actor.TierAdmin,
		"POST /keys/:id/revoke":   actor.TierAdmin,
		"GET /audit/admin":        actor.TierAdmin,
	}

	routes := adminRoutes()
	seen := make(map[string]bool, len(routes))
	for _, r := range routes {
		key := r.Method + " " + r.Path
		seen[key] = true
		if _, ok := expectedMinTier[key]; !ok {
			t.Fatalf("route %q in adminRoutes() is missing from TestAdminTierMatrix spec table", key)
		}
	}
	for key := range expectedMinTier {
		if !seen[key] {
			t.Fatalf("spec table entry %q is not present in adminRoutes()", key)
		}
	}

	router, gormDB, _ := intBuildServer(t)
	keys := []struct {
		tier  actor.Tier
		token string
	}{
		{actor.TierViewer, intInsertKey(t, gormDB, "matrix-viewer", actor.TierViewer)},
		{actor.TierOperator, intInsertKey(t, gormDB, "matrix-operator", actor.TierOperator)},
		{actor.TierAdmin, intInsertKey(t, gormDB, "matrix-admin", actor.TierAdmin)},
	}

	// Substitute path params with valid non-existent values so handlers at or above
	// MinTier reach their business logic cleanly without mutating shared fixtures.
	materializePath := func(path string) string {
		p := strings.ReplaceAll(path, ":id", uuid.New().String())
		p = strings.ReplaceAll(p, ":name", "nonexistent-name")
		return "/admin" + p
	}

	for _, r := range routes {
		routeKey := r.Method + " " + r.Path
		minTier := expectedMinTier[routeKey]
		t.Run(routeKey, func(t *testing.T) {
			for _, k := range keys {
				var payload any
				if r.Method == http.MethodPost || r.Method == http.MethodPut {
					payload = map[string]any{}
				}
				status, _ := intDoAdmin(t, router, r.Method, materializePath(r.Path), k.token, payload)
				if k.tier < minTier {
					if status != http.StatusForbidden {
						t.Errorf("tier=%s calling %s: status=%d want=403", k.tier, routeKey, status)
					}
				} else {
					if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusMethodNotAllowed {
						t.Errorf("tier=%s calling %s: status=%d (must reach handler, not be blocked by auth/tier)", k.tier, routeKey, status)
					}
					if r.Method == http.MethodGet && status != http.StatusOK {
						t.Errorf("tier=%s calling %s: status=%d want=200", k.tier, routeKey, status)
					}
				}
			}
		})
	}
}

type dbSnapshot struct {
	PolicyVersion int64
	Users         []model.User
	Tokens        []model.EnrollToken
	Devices       []model.Device
	Roles         []model.Role
	Relays        []model.Relay
	CasbinRules   []model.CasbinRule
	AdminKeys     []model.AdminKey
	AuditLogs     []model.AuditLog
	AdminAudits   []model.AdminAuditLog
}

func captureSnapshot(t *testing.T, gormDB *gorm.DB) dbSnapshot {
	t.Helper()
	ver, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("ReadVersion: %v", err)
	}
	var snap dbSnapshot
	snap.PolicyVersion = ver
	if err := gormDB.Order("id asc").Find(&snap.Users).Error; err != nil {
		t.Fatalf("snapshot users: %v", err)
	}
	if err := gormDB.Order("id asc").Find(&snap.Tokens).Error; err != nil {
		t.Fatalf("snapshot tokens: %v", err)
	}
	if err := gormDB.Order("id asc").Find(&snap.Devices).Error; err != nil {
		t.Fatalf("snapshot devices: %v", err)
	}
	if err := gormDB.Order("name asc").Find(&snap.Roles).Error; err != nil {
		t.Fatalf("snapshot roles: %v", err)
	}
	if err := gormDB.Order("name asc").Find(&snap.Relays).Error; err != nil {
		t.Fatalf("snapshot relays: %v", err)
	}
	if err := gormDB.Order("id asc").Find(&snap.CasbinRules).Error; err != nil {
		t.Fatalf("snapshot casbin_rule: %v", err)
	}
	if err := gormDB.Order("id asc").Find(&snap.AdminKeys).Error; err != nil {
		t.Fatalf("snapshot admin_keys: %v", err)
	}
	if err := gormDB.Order("id asc").Find(&snap.AuditLogs).Error; err != nil {
		t.Fatalf("snapshot audit_logs: %v", err)
	}
	if err := gormDB.Order("id asc").Find(&snap.AdminAudits).Error; err != nil {
		t.Fatalf("snapshot admin_audit_logs: %v", err)
	}
	return snap
}

func TestAdminAuditSuccessIsAtomic(t *testing.T) {
	type atomicCase struct {
		method     string
		routePath  string
		wantStatus int
		setup      func(t *testing.T, gormDB *gorm.DB) (path string, payload any)
	}

	seedBase := func(t *testing.T, gormDB *gorm.DB) (model.User, model.EnrollToken, model.Device, model.AdminKey) {
		t.Helper()
		u := model.User{ID: uuid.New(), Username: "atomic-user"}
		if err := gormDB.Create(&u).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		if err := gormDB.Transaction(func(tx *gorm.DB) error {
			return policy.SetUserRoles(tx, u.ID, []string{policy.BuiltinRole})
		}); err != nil {
			t.Fatalf("bind standard: %v", err)
		}
		tok := model.EnrollToken{
			ID:         uuid.New(),
			UserID:     u.ID,
			TokenHash:  "hash-" + uuid.NewString(),
			MaxDevices: 1,
		}
		if err := gormDB.Create(&tok).Error; err != nil {
			t.Fatalf("seed token: %v", err)
		}
		dev := model.Device{
			ID:      uuid.New(),
			UserID:  u.ID,
			NodeKey: "nodekey:atomic-" + uuid.NewString(),
			Label:   "laptop",
		}
		if err := gormDB.Create(&dev).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
		// Seed a verify audit row so device/user delete also exercises audit_logs.device_id=NULL rollback.
		if err := gormDB.Create(&model.AuditLog{
			DeviceID: &dev.ID,
			NodeKey:  dev.NodeKey,
			Allowed:  true,
			TS:       time.Now().UTC(),
		}).Error; err != nil {
			t.Fatalf("seed verify audit: %v", err)
		}
		// Seed a revocable non-admin key so key revoke succeeds.
		k := model.AdminKey{
			ID:      uuid.New(),
			Name:    "atomic-revocable-key",
			Tier:    model.AdminTierViewer,
			KeyHash: "keyhash-" + uuid.NewString(),
		}
		if err := gormDB.Create(&k).Error; err != nil {
			t.Fatalf("seed revocable key: %v", err)
		}
		// Seed custom relay & role for update/delete routes.
		if err := gormDB.Create(&model.Relay{Name: "eu-1"}).Error; err != nil {
			t.Fatalf("seed relay: %v", err)
		}
		if err := gormDB.Create(&model.Role{Name: "ops"}).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
		if err := gormDB.Transaction(func(tx *gorm.DB) error {
			return policy.SetRoleGrants(tx, "ops", []string{"eu-1"})
		}); err != nil {
			t.Fatalf("seed ops grants: %v", err)
		}
		return u, tok, dev, k
	}

	cases := []atomicCase{
		{
			method: http.MethodPost, routePath: "/users", wantStatus: http.StatusCreated,
			setup: func(t *testing.T, _ *gorm.DB) (string, any) {
				return "/admin/users", map[string]any{"username": "new-atomic-user"}
			},
		},
		{
			method: http.MethodDelete, routePath: "/users/:id", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				u, _, _, _ := seedBase(t, db)
				return "/admin/users/" + u.ID.String(), nil
			},
		},
		{
			method: http.MethodPost, routePath: "/users/:id/disable", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				u, _, _, _ := seedBase(t, db)
				return "/admin/users/" + u.ID.String() + "/disable", nil
			},
		},
		{
			method: http.MethodPost, routePath: "/users/:id/enable", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				u, _, _, _ := seedBase(t, db)
				now := time.Now().UTC()
				if err := db.Model(&model.User{}).Where("id = ?", u.ID).Update("disabled_at", &now).Error; err != nil {
					t.Fatalf("pre-disable user: %v", err)
				}
				return "/admin/users/" + u.ID.String() + "/enable", nil
			},
		},
		{
			method: http.MethodPut, routePath: "/users/:id/roles", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				u, _, _, _ := seedBase(t, db)
				return "/admin/users/" + u.ID.String() + "/roles", map[string]any{"roles": []string{"ops"}}
			},
		},
		{
			method: http.MethodPost, routePath: "/tokens", wantStatus: http.StatusCreated,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				u, _, _, _ := seedBase(t, db)
				return "/admin/tokens", map[string]any{"userId": u.ID.String()}
			},
		},
		{
			method: http.MethodDelete, routePath: "/tokens/:id", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				_, tok, _, _ := seedBase(t, db)
				return "/admin/tokens/" + tok.ID.String(), nil
			},
		},
		{
			method: http.MethodPost, routePath: "/tokens/:id/revoke", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				_, tok, _, _ := seedBase(t, db)
				return "/admin/tokens/" + tok.ID.String() + "/revoke", nil
			},
		},
		{
			method: http.MethodDelete, routePath: "/devices/:id", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				_, _, dev, _ := seedBase(t, db)
				return "/admin/devices/" + dev.ID.String(), nil
			},
		},
		{
			method: http.MethodPost, routePath: "/devices/:id/revoke", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				_, _, dev, _ := seedBase(t, db)
				return "/admin/devices/" + dev.ID.String() + "/revoke", nil
			},
		},
		{
			method: http.MethodPost, routePath: "/devices/:id/enable", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				_, _, dev, _ := seedBase(t, db)
				now := time.Now().UTC()
				if err := db.Model(&model.Device{}).Where("id = ?", dev.ID).Update("revoked_at", &now).Error; err != nil {
					t.Fatalf("pre-revoke device: %v", err)
				}
				return "/admin/devices/" + dev.ID.String() + "/enable", nil
			},
		},
		{
			method: http.MethodPost, routePath: "/relays", wantStatus: http.StatusCreated,
			setup: func(t *testing.T, _ *gorm.DB) (string, any) {
				return "/admin/relays", map[string]any{"name": "us-1", "description": "US"}
			},
		},
		{
			method: http.MethodDelete, routePath: "/relays/:name", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				seedBase(t, db)
				return "/admin/relays/eu-1", nil
			},
		},
		{
			method: http.MethodPost, routePath: "/roles", wantStatus: http.StatusCreated,
			setup: func(t *testing.T, _ *gorm.DB) (string, any) {
				return "/admin/roles", map[string]any{"name": "devops", "relays": []string{"default"}}
			},
		},
		{
			method: http.MethodPut, routePath: "/roles/:name/relays", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				seedBase(t, db)
				return "/admin/roles/ops/relays", map[string]any{"relays": []string{"default"}}
			},
		},
		{
			method: http.MethodDelete, routePath: "/roles/:name", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				seedBase(t, db)
				return "/admin/roles/ops", nil
			},
		},
		{
			method: http.MethodPost, routePath: "/keys", wantStatus: http.StatusCreated,
			setup: func(t *testing.T, _ *gorm.DB) (string, any) {
				return "/admin/keys", map[string]any{"name": "new-atomic-key", "tier": "viewer"}
			},
		},
		{
			method: http.MethodPost, routePath: "/keys/:id/revoke", wantStatus: http.StatusOK,
			setup: func(t *testing.T, db *gorm.DB) (string, any) {
				_, _, _, k := seedBase(t, db)
				return "/admin/keys/" + k.ID.String() + "/revoke", nil
			},
		},
	}

	// Ensure every mutating route in adminRoutes() is covered by this table.
	covered := make(map[string]bool, len(cases))
	for _, tc := range cases {
		covered[tc.method+" "+tc.routePath] = true
	}
	for _, r := range adminRoutes() {
		if r.Method == http.MethodGet {
			continue
		}
		key := r.Method + " " + r.Path
		if !covered[key] {
			t.Fatalf("mutating route %q is missing from TestAdminAuditSuccessIsAtomic", key)
		}
	}

	for _, tc := range cases {
		name := tc.method + " " + tc.routePath
		t.Run(name, func(t *testing.T) {
			// Part 1: Success writes exactly one non-system audit row.
			t.Run("success_writes_one_audit_row", func(t *testing.T) {
				router, gormDB, _ := intBuildServer(t)
				path, payload := tc.setup(t, gormDB)

				status, body := intDoAdmin(t, router, tc.method, path, intTestAdminKey, payload)
				if status != tc.wantStatus {
					t.Fatalf("%s status=%d want=%d body=%v", name, status, tc.wantStatus, body)
				}

				var rows []model.AdminAuditLog
				if err := gormDB.Where("NOT (actor_key_id IS NULL AND actor_name = ?)", actor.System.Name).Order("id asc").Find(&rows).Error; err != nil {
					t.Fatalf("query admin_audit_logs: %v", err)
				}
				if len(rows) != 1 {
					t.Fatalf("%s non-system audit count=%d want=1", name, len(rows))
				}
				if rows[0].Outcome != service.AuditOutcomeSuccess || rows[0].HTTPStatus == nil || *rows[0].HTTPStatus != tc.wantStatus {
					t.Fatalf("%s unexpected audit row: %+v", name, rows[0])
				}
			})

			// Part 2: Forced audit insert failure rolls back the entire change and policy version.
			t.Run("audit_failure_rolls_back_all_tables", func(t *testing.T) {
				router, gormDB, _ := intBuildServer(t)
				path, payload := tc.setup(t, gormDB)

				// Authenticate once first so bootstrap's last_used_at is populated, then
				// ignore last_used_at when comparing admin_keys since auth updates it before Mutate.
				before := captureSnapshot(t, gormDB)

				const cbName = "int_fail_admin_audit_insert"
				if err := gormDB.Callback().Create().Before("gorm:create").Register(cbName, func(tx *gorm.DB) {
					if tx.Statement != nil && tx.Statement.Table == "admin_audit_logs" {
						_ = tx.AddError(errors.New("forced admin_audit_logs insert failure"))
					}
				}); err != nil {
					t.Fatalf("register callback: %v", err)
				}

				status, _ := intDoAdmin(t, router, tc.method, path, intTestAdminKey, payload)
				_ = gormDB.Callback().Create().Remove(cbName)

				if status != http.StatusInternalServerError {
					t.Fatalf("%s with forced audit failure: status=%d want=500", name, status)
				}

				after := captureSnapshot(t, gormDB)
				// AuthenticateAdminKey updates bootstrap.last_used_at best-effort before Mutate runs;
				// zero it out on both snapshots before deep-comparing every table and policy version.
				for i := range before.AdminKeys {
					before.AdminKeys[i].LastUsedAt = nil
				}
				for i := range after.AdminKeys {
					after.AdminKeys[i].LastUsedAt = nil
				}

				if after.PolicyVersion != before.PolicyVersion {
					t.Fatalf("%s policy version changed on rollback: before=%d after=%d", name, before.PolicyVersion, after.PolicyVersion)
				}
				if !reflect.DeepEqual(after, before) {
					t.Fatalf("%s database state changed after audit insert failure:\nbefore=%+v\nafter=%+v", name, before, after)
				}
			})
		})
	}
}
