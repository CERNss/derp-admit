package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func TestAdminRouteTableIsValid(t *testing.T) {
	if err := validateAdminRoutes(adminRoutes()); err != nil {
		t.Fatalf("adminRoutes() failed validation: %v", err)
	}
}

func TestAdminRouteTableRejectsBadEntries(t *testing.T) {
	noop := func(adminDeps) gin.HandlerFunc {
		return func(c *gin.Context) { c.Status(http.StatusOK) }
	}

	cases := []struct {
		name   string
		routes []adminRoute
	}{
		{
			name: "zero_min_tier",
			routes: []adminRoute{
				{Method: http.MethodGet, Path: "/x", MinTier: actor.TierNone, Handle: noop},
			},
		},
		{
			name: "post_missing_action",
			routes: []adminRoute{
				{Method: http.MethodPost, Path: "/x", MinTier: actor.TierOperator, TargetType: "x", Handle: noop},
			},
		},
		{
			name: "put_missing_target_type",
			routes: []adminRoute{
				{Method: http.MethodPut, Path: "/x", MinTier: actor.TierOperator, Action: "x.put", Handle: noop},
			},
		},
		{
			name: "delete_missing_action_and_target_type",
			routes: []adminRoute{
				{Method: http.MethodDelete, Path: "/x", MinTier: actor.TierOperator, Handle: noop},
			},
		},
		{
			name: "get_with_non_empty_action",
			routes: []adminRoute{
				{Method: http.MethodGet, Path: "/x", MinTier: actor.TierViewer, Action: "x.get", Handle: noop},
			},
		},
		{
			name: "duplicate_method_and_path",
			routes: []adminRoute{
				{Method: http.MethodGet, Path: "/dup", MinTier: actor.TierViewer, Handle: noop},
				{Method: http.MethodGet, Path: "/dup", MinTier: actor.TierAdmin, Handle: noop},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateAdminRoutes(tc.routes); err == nil {
				t.Fatalf("expected validation error for case %s, got nil", tc.name)
			}
		})
	}
}

func TestAdminAuditRecordsPanic(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "panic.db")
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
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
		t.Fatalf("new policy engine: %v", err)
	}

	const adminKey = "panic-test-admin-key-0123456789"
	logger := zap.NewNop()
	svc := service.New(gormDB, engine, "test-pepper", 2*time.Second, service.NewVerifyCache(0), logger)
	sum := sha256.Sum256([]byte(adminKey + ":test-pepper"))
	if err := gormDB.Create(&model.AdminKey{
		Name:    "panic-test-admin",
		Tier:    model.AdminTierAdmin,
		KeyHash: hex.EncodeToString(sum[:]),
	}).Error; err != nil {
		t.Fatalf("seed admin key: %v", err)
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	mountAdminRoutes(router, svc, newIPRateLimiter(1000, 1000), logger, metrics.Nop, []adminRoute{
		{
			Method:      http.MethodPost,
			Path:        "/panic/:id",
			MinTier:     actor.TierOperator,
			Action:      "test.panic",
			TargetType:  "test",
			TargetParam: "id",
			Handle: func(adminDeps) gin.HandlerFunc {
				return func(*gin.Context) {
					panic("boom")
				}
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/panic/target-123", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want=%d (panic must reach gin.Recovery)", rec.Code, http.StatusInternalServerError)
	}

	var rows []model.AdminAuditLog
	if err := gormDB.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("query admin_audit_logs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("admin audit row count=%d want=1", len(rows))
	}
	row := rows[0]
	if row.Action != "test.panic" || row.TargetType != "test" || row.TargetID != "target-123" {
		t.Fatalf("unexpected audit action/target: %+v", row)
	}
	if row.Outcome != service.AuditOutcomeFailure {
		t.Fatalf("outcome=%q want=%q", row.Outcome, service.AuditOutcomeFailure)
	}
	if row.HTTPStatus == nil || *row.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("http_status=%v want=%d", row.HTTPStatus, http.StatusInternalServerError)
	}
}
