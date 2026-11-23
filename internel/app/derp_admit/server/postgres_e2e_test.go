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

func createFreshPostgresDB(t *testing.T, prefix string) string {
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
	dbName := prefix + hex.EncodeToString(raw)

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

	t.Cleanup(func() {
		_ = adminDB.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ? AND pid <> pg_backend_pid()`, dbName).Error
		_ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName)).Error
		if sqlAdmin, err := adminDB.DB(); err == nil {
			_ = sqlAdmin.Close()
		}
	})

	return dbURL
}

func openFreshPostgresApp(t *testing.T, cacheTTL time.Duration) (*app.App, *gorm.DB) {
	t.Helper()

	dbURL := createFreshPostgresDB(t, "derp_admit_test_")

	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "pg-e2e-pepper",
		AdminAPIKey:          testAdminKey,
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

	// 14. Create a relay and a role through the API, bind u2 to it, verify on /verify/eu-1 allowed and default denied.
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
		"name":        "eu-1",
		"description": "Frankfurt",
	}); status != http.StatusCreated {
		t.Fatalf("create relay eu-1 status=%d want=201", status)
	}
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "eu-only",
		"relays": []string{"eu-1"},
	}); status != http.StatusCreated {
		t.Fatalf("create role eu-only status=%d want=201", status)
	}
	if status, _ := doAdminRequest(t, router, http.MethodPut, "/admin/users/"+u2ID+"/roles", testAdminKey, map[string]any{
		"roles": []string{"eu-only"},
	}); status != http.StatusOK {
		t.Fatalf("bind u2 to eu-only status=%d want=200", status)
	}
	_, payload = doRawRequest(t, router, "/verify/eu-1", buildVerifyBody(t, nk2))
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("verify nk2 on /verify/eu-1 expected allow, got deny reason=%q", denyReason(payload))
	}
	_, payload = doRawRequest(t, router, "/verify", buildVerifyBody(t, nk2))
	if reason := denyReason(payload); reason != service.DenyReasonPolicyDenied {
		t.Fatalf("verify nk2 on default reason=%q want=%q", reason, service.DenyReasonPolicyDenied)
	}

	// 15. Delete dev1 -> verify returns not registered.
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/devices/"+dev1ID, testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("delete dev1 status=%d want=200", status)
	}
	_, payload = doRawRequest(t, router, "/verify", buildVerifyBody(t, nk1))
	if reason := denyReason(payload); reason != service.DenyReasonNotRegistered {
		t.Fatalf("verify deleted nk1 reason=%q want=%q", reason, service.DenyReasonNotRegistered)
	}

	// 16. Delete u2 -> verify audit rows keep node_key with null device_id.
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/users/"+u2ID, testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("delete u2 status=%d want=200", status)
	}
	_, payload = doRawRequest(t, router, "/verify/eu-1", buildVerifyBody(t, nk2))
	if reason := denyReason(payload); reason != service.DenyReasonNotRegistered {
		t.Fatalf("verify deleted user nk2 reason=%q want=%q", reason, service.DenyReasonNotRegistered)
	}
	var nk2Audits []model.AuditLog
	if err := gormDB.Where("node_key = ?", nk2).Find(&nk2Audits).Error; err != nil {
		t.Fatalf("query nk2 audit_logs: %v", err)
	}
	if len(nk2Audits) < 3 {
		t.Fatalf("expected nk2 verify audit rows preserved, got %d", len(nk2Audits))
	}
	for _, row := range nk2Audits {
		if row.DeviceID != nil {
			t.Fatalf("expected null device_id on preserved audit row %d after user delete, got %v", row.ID, row.DeviceID)
		}
	}

	// 17. Create a named admin key, use it, revoke bootstrap, and verify last-admin guard (409).
	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/keys", testAdminKey, map[string]any{
		"name": "pg-named-admin",
		"tier": "admin",
	})
	if status != http.StatusCreated {
		t.Fatalf("create named admin key status=%d want=201", status)
	}
	namedAdminID := body["meta"].(map[string]any)["id"].(string)
	namedAdminPlain := body["key"].(string)

	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/keys", namedAdminPlain, nil); status != http.StatusOK {
		t.Fatalf("GET /admin/keys with named admin status=%d want=200", status)
	}

	var bootKey model.AdminKey
	if err := gormDB.Where("name = ?", service.BootstrapKeyName).First(&bootKey).Error; err != nil {
		t.Fatalf("load bootstrap key: %v", err)
	}
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+bootKey.ID.String()+"/revoke", namedAdminPlain, nil); status != http.StatusOK {
		t.Fatalf("revoke bootstrap status=%d want=200", status)
	}
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/keys", testAdminKey, nil); status != http.StatusUnauthorized {
		t.Fatalf("revoked bootstrap status=%d want=401", status)
	}
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+namedAdminID+"/revoke", namedAdminPlain, nil); status != http.StatusConflict {
		t.Fatalf("revoke last active admin status=%d want=409", status)
	}

	// 18. Exactly one admin audit row per mutating request (14 successful + 1 failed 409),
	// one startup system row for bootstrap creation, and policy version > 0.
	var auditRows []model.AdminAuditLog
	if err := gormDB.Where("NOT (actor_key_id IS NULL AND actor_name = ?)", actor.System.Name).Order("id asc").Find(&auditRows).Error; err != nil {
		t.Fatalf("query admin_audit_logs: %v", err)
	}
	const wantSuccessMutations = 14
	const wantTotalMutations = 15 // 14 successes + 1 failed 409 on last-admin revoke
	if len(auditRows) != wantTotalMutations {
		t.Fatalf("admin audit row count=%d want=%d", len(auditRows), wantTotalMutations)
	}
	successCount, failCount := 0, 0
	for _, row := range auditRows {
		switch row.Outcome {
		case service.AuditOutcomeSuccess:
			successCount++
		case service.AuditOutcomeFailure:
			failCount++
		}
	}
	if successCount != wantSuccessMutations || failCount != 1 {
		t.Fatalf("audit outcomes: success=%d failure=%d want success=%d failure=1", successCount, failCount, wantSuccessMutations)
	}

	var systemRows []model.AdminAuditLog
	if err := gormDB.Where("actor_key_id IS NULL AND actor_name = ?", actor.System.Name).Order("id asc").Find(&systemRows).Error; err != nil {
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

func TestPostgresRoleDeleteRacesBinding(t *testing.T) {
	application, gormDB := openFreshPostgresApp(t, 0)
	router := application.Router

	status, body := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "pg-race-bind-user",
		"roles":    []string{},
	})
	if status != http.StatusCreated {
		t.Fatalf("create user status=%d want=201", status)
	}
	userID := body["user"].(map[string]any)["id"].(string)

	const rounds = 25
	for i := 0; i < rounds; i++ {
		roleName := fmt.Sprintf("race-role-%d", i)
		if st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
			"name":   roleName,
			"relays": []string{"default"},
		}); st != http.StatusCreated {
			t.Fatalf("round %d create role status=%d want=201", i, st)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		var bindStatus, delStatus int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			bindStatus, _ = doAdminRequest(t, router, http.MethodPut, "/admin/users/"+userID+"/roles", testAdminKey, map[string]any{
				"roles": []string{roleName},
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			delStatus, _ = doAdminRequest(t, router, http.MethodDelete, "/admin/roles/"+roleName, testAdminKey, nil)
		}()
		close(start)
		wg.Wait()

		if delStatus != http.StatusOK {
			t.Fatalf("round %d delete role status=%d want=200", i, delStatus)
		}
		if bindStatus != http.StatusOK && bindStatus != http.StatusBadRequest {
			t.Fatalf("round %d unexpected bind status=%d (want 200 or 400)", i, bindStatus)
		}

		// After the delete completes, NO casbin_rule row may reference the deleted role.
		var orphanCount int64
		if err := gormDB.Model(&model.CasbinRule{}).
			Where("(ptype = 'g' AND v1 = ?) OR (ptype = 'p' AND v0 = ?)", "role:"+roleName, "role:"+roleName).
			Count(&orphanCount).Error; err != nil {
			t.Fatalf("round %d count orphan role rules: %v", i, err)
		}
		if orphanCount != 0 {
			t.Fatalf("round %d orphan casbin_rule rows for deleted role %s = %d want=0", i, roleName, orphanCount)
		}
	}
}

func TestPostgresRelayDeleteRacesGrant(t *testing.T) {
	application, gormDB := openFreshPostgresApp(t, 0)
	router := application.Router

	if st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "pg-race-grant-role",
		"relays": []string{},
	}); st != http.StatusCreated {
		t.Fatalf("create role status=%d want=201", st)
	}

	const rounds = 25
	for i := 0; i < rounds; i++ {
		relayName := fmt.Sprintf("race-relay-%d", i)
		if st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
			"name": relayName,
		}); st != http.StatusCreated {
			t.Fatalf("round %d create relay status=%d want=201", i, st)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		var grantStatus, delStatus int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			grantStatus, _ = doAdminRequest(t, router, http.MethodPut, "/admin/roles/pg-race-grant-role/relays", testAdminKey, map[string]any{
				"relays": []string{relayName},
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			delStatus, _ = doAdminRequest(t, router, http.MethodDelete, "/admin/relays/"+relayName, testAdminKey, nil)
		}()
		close(start)
		wg.Wait()

		if delStatus != http.StatusOK {
			t.Fatalf("round %d delete relay status=%d want=200", i, delStatus)
		}
		if grantStatus != http.StatusOK && grantStatus != http.StatusBadRequest {
			t.Fatalf("round %d unexpected grant status=%d (want 200 or 400)", i, grantStatus)
		}

		// After the delete completes, NO casbin_rule row may reference the deleted relay.
		var orphanCount int64
		if err := gormDB.Model(&model.CasbinRule{}).
			Where("ptype = 'p' AND v1 = ?", "derp:"+relayName).
			Count(&orphanCount).Error; err != nil {
			t.Fatalf("round %d count orphan relay rules: %v", i, err)
		}
		if orphanCount != 0 {
			t.Fatalf("round %d orphan casbin_rule rows for deleted relay %s = %d want=0", i, relayName, orphanCount)
		}
	}
}

func TestPostgresRevokeLastAdminConcurrent(t *testing.T) {
	application, gormDB := openFreshPostgresApp(t, 0)
	router := application.Router

	var boot model.AdminKey
	if err := gormDB.Where("name = ?", service.BootstrapKeyName).First(&boot).Error; err != nil {
		t.Fatalf("load bootstrap key: %v", err)
	}

	survivorID := boot.ID.String()
	survivorPlain := testAdminKey

	const rounds = 20
	for i := 0; i < rounds; i++ {
		st, body := doAdminRequest(t, router, http.MethodPost, "/admin/keys", survivorPlain, map[string]any{
			"name": fmt.Sprintf("pg-concurrent-admin-%d", i),
			"tier": "admin",
		})
		if st != http.StatusCreated {
			t.Fatalf("round %d create second admin status=%d want=201", i, st)
		}
		otherID := body["meta"].(map[string]any)["id"].(string)
		otherPlain := body["key"].(string)

		// Concurrently revoke each admin key using the other admin key.
		start := make(chan struct{})
		var wg sync.WaitGroup
		var st1, st2 int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			st1, _ = doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+otherID+"/revoke", survivorPlain, nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			st2, _ = doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+survivorID+"/revoke", otherPlain, nil)
		}()
		close(start)
		wg.Wait()

		// Valid pairs: {200, 409} (both authenticated, one hit last-admin guard)
		// or {200, 401} (one revoked the other before the other's auth ran).
		// {200, 200} is a lockout bug and MUST fail.
		validPair := (st1 == http.StatusOK && (st2 == http.StatusConflict || st2 == http.StatusUnauthorized)) ||
			(st2 == http.StatusOK && (st1 == http.StatusConflict || st1 == http.StatusUnauthorized))
		if !validPair {
			t.Fatalf("round %d invalid concurrent revoke statuses: st1=%d st2=%d", i, st1, st2)
		}

		var activeAdmins []model.AdminKey
		if err := gormDB.Where("tier = ? AND revoked_at IS NULL", model.AdminTierAdmin).Find(&activeAdmins).Error; err != nil {
			t.Fatalf("round %d query active admins: %v", i, err)
		}
		if len(activeAdmins) != 1 {
			t.Fatalf("round %d active admin count=%d want=1", i, len(activeAdmins))
		}
		if activeAdmins[0].ID.String() == otherID {
			survivorID = otherID
			survivorPlain = otherPlain
		}
	}

	// Also verify direct self-revoke race (where 401 cannot preempt auth) always
	// produces exactly one 200 and one 409.
	for i := 0; i < 10; i++ {
		st, body := doAdminRequest(t, router, http.MethodPost, "/admin/keys", survivorPlain, map[string]any{
			"name": fmt.Sprintf("pg-self-revoke-admin-%d", i),
			"tier": "admin",
		})
		if st != http.StatusCreated {
			t.Fatalf("self-revoke round %d create admin status=%d want=201", i, st)
		}
		otherID := body["meta"].(map[string]any)["id"].(string)
		otherPlain := body["key"].(string)

		start := make(chan struct{})
		var wg sync.WaitGroup
		var st1, st2 int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			st1, _ = doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+survivorID+"/revoke", survivorPlain, nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			st2, _ = doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+otherID+"/revoke", otherPlain, nil)
		}()
		close(start)
		wg.Wait()

		if !((st1 == http.StatusOK && st2 == http.StatusConflict) || (st2 == http.StatusOK && st1 == http.StatusConflict)) {
			t.Fatalf("self-revoke round %d statuses=(%d, %d) want one 200 and one 409", i, st1, st2)
		}

		var activeAdmins []model.AdminKey
		if err := gormDB.Where("tier = ? AND revoked_at IS NULL", model.AdminTierAdmin).Find(&activeAdmins).Error; err != nil {
			t.Fatalf("self-revoke round %d query active admins: %v", i, err)
		}
		if len(activeAdmins) != 1 {
			t.Fatalf("self-revoke round %d active admin count=%d want=1", i, len(activeAdmins))
		}
		if activeAdmins[0].ID.String() == otherID {
			survivorID = otherID
			survivorPlain = otherPlain
		}
	}
}

func TestPostgresBootstrapConcurrentStartup(t *testing.T) {
	dbURL := createFreshPostgresDB(t, "derp_admit_boot_")

	const instances = 6
	conns := make([]*gorm.DB, instances)
	for i := 0; i < instances; i++ {
		c, err := db.OpenDatabase(dbURL)
		if err != nil {
			t.Fatalf("open postgres conn %d: %v", i, err)
		}
		conns[i] = c
		t.Cleanup(func() {
			if sqlDB, err := c.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
	}

	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "pg-boot-pepper",
		AdminAPIKey:          testAdminKey,
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

	start := make(chan struct{})
	apps := make([]*app.App, instances)
	errs := make([]error, instances)
	var wg sync.WaitGroup
	for i := 0; i < instances; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			apps[idx], errs[idx] = app.Build(ctx, conns[idx], cfg, zap.NewNop())
		}(i)
	}
	close(start)
	wg.Wait()

	for i, a := range apps {
		if a != nil {
			t.Cleanup(a.Close)
		}
		if errs[i] != nil {
			t.Fatalf("instance %d app.Build failed: %v", i, errs[i])
		}
	}

	var bootCount int64
	if err := conns[0].Model(&model.AdminKey{}).Where("name = ?", service.BootstrapKeyName).Count(&bootCount).Error; err != nil {
		t.Fatalf("count bootstrap rows: %v", err)
	}
	if bootCount != 1 {
		t.Fatalf("bootstrap row count=%d want=1", bootCount)
	}

	var sysAudits []model.AdminAuditLog
	if err := conns[0].Where("actor_key_id IS NULL AND actor_name = ?", actor.System.Name).Find(&sysAudits).Error; err != nil {
		t.Fatalf("query system audits: %v", err)
	}
	if len(sysAudits) != 1 || sysAudits[0].Action != "bootstrap.create" {
		t.Fatalf("system audits=%+v want exactly 1 bootstrap.create row", sysAudits)
	}

	for i, a := range apps {
		if st, _ := doAdminRequest(t, a.Router, http.MethodGet, "/admin/keys", testAdminKey, nil); st != http.StatusOK {
			t.Fatalf("instance %d GET /admin/keys status=%d want=200", i, st)
		}
	}
}
