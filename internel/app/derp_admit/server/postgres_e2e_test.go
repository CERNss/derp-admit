package server_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

func openFreshPostgresApp(t *testing.T, cacheTTL time.Duration) (*app.App, *gorm.DB) {
	t.Helper()

	baseURL := os.Getenv("TEST_POSTGRES_URL")
	if baseURL == "" {
		t.Skip("TEST_POSTGRES_URL is not set")
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse TEST_POSTGRES_URL: %v", err)
	}

	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("random db suffix: %v", err)
	}
	dbName := "derp_admit_test_" + hex.EncodeToString(raw)

	adminDB, err := db.OpenDatabase(baseURL)
	if err != nil {
		t.Fatalf("open postgres admin db: %v", err)
	}
	if err := adminDB.Exec(fmt.Sprintf(`CREATE DATABASE %s`, dbName)).Error; err != nil {
		t.Fatalf("create database %s: %v", dbName, err)
	}

	testURL := *parsed
	testURL.Path = "/" + dbName
	dbURL := testURL.String()

	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		_ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName)).Error
		t.Fatalf("open test database %s: %v", dbName, err)
	}

	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = adminDB.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ? AND pid <> pg_backend_pid()`, dbName).Error
		_ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName)).Error
		if sqlAdmin, err := adminDB.DB(); err == nil {
			_ = sqlAdmin.Close()
		}
	})

	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "pg-e2e-pepper",
		AdminAPIKey:          testAdminKey,
		EnableCasbin:         true,
		MetricsEnabled:       true,
		DBTimeout:            5 * time.Second,
		PolicySyncInterval:   2 * time.Second,
		VerifyCacheTTL:       cacheTTL,
		VerifyRateLimitRPS:   1000,
		VerifyRateBurst:      1000,
		RegisterRateLimitRPS: 1000,
		RegisterRateBurst:    1000,
		AdminRateLimitRPS:    1000,
		AdminRateBurst:       1000,
	}

	application, err := app.Build(context.Background(), gormDB, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("app.Build on postgres: %v", err)
	}
	t.Cleanup(application.Close)

	return application, gormDB
}

func TestPostgresEndToEnd(t *testing.T) {
	application, gormDB := openFreshPostgresApp(t, time.Minute)
	router := application.Router

	// 1. Create user 1 with default role ("standard").
	status, body := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "pg-u1",
	})
	if status != http.StatusCreated {
		t.Fatalf("create u1 status=%d want=%d", status, http.StatusCreated)
	}
	u1ID := body["user"].(map[string]any)["id"].(string)

	// 2. Create user 2 with explicit empty roles: [].
	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "pg-u2",
		"roles":    []string{},
	})
	if status != http.StatusCreated {
		t.Fatalf("create u2 status=%d want=%d", status, http.StatusCreated)
	}
	u2ID := body["user"].(map[string]any)["id"].(string)

	// 3 & 4. Mint a token (default maxDevices=1) for each user.
	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/tokens", testAdminKey, map[string]any{
		"userId": u1ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create token u1 status=%d want=%d", status, http.StatusCreated)
	}
	tok1 := body["token"].(string)

	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/tokens", testAdminKey, map[string]any{
		"userId": u2ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create token u2 status=%d want=%d", status, http.StatusCreated)
	}
	tok2 := body["token"].(string)

	// 5. Register a device for each user (200).
	nk1 := newNodeKey(t)
	nk2 := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   tok1,
		"nodeKey": nk1,
		"label":   "u1-laptop",
	}); status != http.StatusOK {
		t.Fatalf("register nk1 status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   tok2,
		"nodeKey": nk2,
		"label":   "u2-laptop",
	}); status != http.StatusOK {
		t.Fatalf("register nk2 status=%d want=%d", status, http.StatusOK)
	}

	// 6. Register the same key again (200).
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   tok1,
		"nodeKey": nk1,
		"label":   "u1-laptop-renamed",
	}); status != http.StatusOK {
		t.Fatalf("re-register nk1 status=%d want=%d", status, http.StatusOK)
	}

	// 7. Register a second device over maxDevices=1 (403).
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   tok1,
		"nodeKey": newNodeKey(t),
	}); status != http.StatusForbidden {
		t.Fatalf("over maxDevices status=%d want=%d", status, http.StatusForbidden)
	}

	// 8. Register u1's key with u2's token (409).
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   tok2,
		"nodeKey": nk1,
	}); status != http.StatusConflict {
		t.Fatalf("cross-user conflict status=%d want=%d", status, http.StatusConflict)
	}

	// 9. Verify first device (allow; twice to warm cache) and second (policy denied).
	for i := 0; i < 2; i++ {
		_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nk1))
		if allow, _ := payload["Allow"].(bool); !allow {
			t.Fatalf("verify nk1 #%d expected allow, got deny reason=%q", i, denyReason(payload))
		}
	}
	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nk2))
	if reason := denyReason(payload); reason != service.DenyReasonPolicyDenied {
		t.Fatalf("verify nk2 reason=%q want=%q", reason, service.DenyReasonPolicyDenied)
	}

	// Look up nk1's device id.
	status, body = doAdminRequest(t, router, http.MethodGet, "/admin/devices?userId="+u1ID, testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list u1 devices status=%d want=%d", status, http.StatusOK)
	}
	dev1ID := body["devices"].([]any)[0].(map[string]any)["id"].(string)

	// 10. Revoke nk1 with live verify cache and verify again (revoked).
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+dev1ID+"/revoke", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("revoke dev1 status=%d want=%d", status, http.StatusOK)
	}
	_, payload = doRawRequest(t, router, "/verify", buildVerifyBody(t, nk1))
	if reason := denyReason(payload); reason != service.DenyReasonRevoked {
		t.Fatalf("verify revoked nk1 reason=%q want=%q", reason, service.DenyReasonRevoked)
	}

	// 11. Re-register the revoked key (403).
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   tok1,
		"nodeKey": nk1,
	}); status != http.StatusForbidden {
		t.Fatalf("re-register revoked nk1 status=%d want=%d", status, http.StatusForbidden)
	}

	// 12. Enable nk1 and verify (allow).
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+dev1ID+"/enable", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("enable dev1 status=%d want=%d", status, http.StatusOK)
	}
	_, payload = doRawRequest(t, router, "/verify", buildVerifyBody(t, nk1))
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("verify re-enabled nk1 expected allow, got deny reason=%q", denyReason(payload))
	}

	// 13. Disable u1 and verify (user disabled).
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users/"+u1ID+"/disable", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("disable u1 status=%d want=%d", status, http.StatusOK)
	}
	_, payload = doRawRequest(t, router, "/verify", buildVerifyBody(t, nk1))
	if reason := denyReason(payload); reason != service.DenyReasonUserDisabled {
		t.Fatalf("verify disabled user nk1 reason=%q want=%q", reason, service.DenyReasonUserDisabled)
	}

	// 14. Exactly one admin audit row per mutating request (7 mutations),
	// one startup system row for bootstrap creation, and policy version > 0.
	var auditRows []model.AdminAuditLog
	if err := gormDB.Where("actor_name <> ?", actor.System.Name).Order("id asc").Find(&auditRows).Error; err != nil {
		t.Fatalf("query admin_audit_logs: %v", err)
	}
	const wantMutations = 7
	if len(auditRows) != wantMutations {
		t.Fatalf("admin audit row count=%d want=%d", len(auditRows), wantMutations)
	}
	for i, row := range auditRows {
		if row.Outcome != service.AuditOutcomeSuccess {
			t.Fatalf("audit row %d outcome=%q want=%q", i, row.Outcome, service.AuditOutcomeSuccess)
		}
	}

	var systemRows []model.AdminAuditLog
	if err := gormDB.Where("actor_name = ?", actor.System.Name).Order("id asc").Find(&systemRows).Error; err != nil {
		t.Fatalf("query system admin_audit_logs: %v", err)
	}
	if len(systemRows) != 1 || systemRows[0].Action != "bootstrap.create" {
		t.Fatalf("system audit rows=%+v want exactly 1 bootstrap.create row", systemRows)
	}

	ver, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("ReadVersion: %v", err)
	}
	if ver <= 0 {
		t.Fatalf("policy version=%d want > 0", ver)
	}
}

func TestPostgresConcurrentRegisterRespectsLimit(t *testing.T) {
	application, gormDB := openFreshPostgresApp(t, 0)
	router := application.Router

	_, token := provisionUserAndToken(t, router, "pg-race-user")

	const workers = 8
	keys := make([]string, workers)
	for i := range keys {
		keys[i] = newNodeKey(t)
	}

	statuses := make([]int, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			status, _ := doJSONRequest(t, router, "/register", map[string]any{
				"token":   token,
				"nodeKey": keys[idx],
			})
			statuses[idx] = status
		}(i)
	}
	close(start)
	wg.Wait()

	okCount, forbiddenCount := 0, 0
	for i, st := range statuses {
		switch st {
		case http.StatusOK:
			okCount++
		case http.StatusForbidden:
			forbiddenCount++
		default:
			t.Errorf("worker %d: unexpected status=%d", i, st)
		}
	}
	if okCount != 1 || forbiddenCount != workers-1 {
		t.Fatalf("statuses: ok=%d forbidden=%d want ok=1 forbidden=%d (all=%v)", okCount, forbiddenCount, workers-1, statuses)
	}

	var devCount int64
	if err := gormDB.Model(&model.Device{}).Count(&devCount).Error; err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if devCount != 1 {
		t.Fatalf("device row count=%d want=1", devCount)
	}
}
