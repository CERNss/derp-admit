package server_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
)

func cOpenTempDB(t *testing.T, name string) (string, *gorm.DB) {
	t.Helper()
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), name)
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return dbURL, gormDB
}

func cBuildApp(t *testing.T, dbURL string, gormDB *gorm.DB, adminKey string, logger *zap.Logger) *app.App {
	t.Helper()
	if logger == nil {
		logger = zap.NewNop()
	}
	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "test-pepper",
		AdminAPIKey:          adminKey,
		EnableCasbin:         true,
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
	application, err := app.Build(context.Background(), gormDB, cfg, logger)
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	t.Cleanup(application.Close)
	return application
}

func cCreateKey(t *testing.T, router http.Handler, callerKey, name, tier string, expiresAt *time.Time) (string, string) {
	t.Helper()
	payload := map[string]any{
		"name": name,
		"tier": tier,
	}
	if expiresAt != nil {
		payload["expiresAt"] = expiresAt.UTC().Format(time.RFC3339)
	}
	status, body := doAdminRequest(t, router, http.MethodPost, "/admin/keys", callerKey, payload)
	if status != http.StatusCreated {
		t.Fatalf("POST /admin/keys name=%q status=%d want=%d body=%v", name, status, http.StatusCreated, body)
	}
	plain, _ := body["key"].(string)
	meta, _ := body["meta"].(map[string]any)
	id, _ := meta["id"].(string)
	if plain == "" || id == "" {
		t.Fatalf("unexpected create key response: %v", body)
	}
	return id, plain
}

// --- 4.1 Authentication ---

func TestAdminAuthStoredKey(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	viewerKey := insertAdminKey(t, gormDB, "stored-viewer", actor.TierViewer)

	var before model.AdminKey
	if err := gormDB.Where("name = ?", "stored-viewer").First(&before).Error; err != nil {
		t.Fatalf("load stored-viewer before: %v", err)
	}
	if before.LastUsedAt != nil {
		t.Fatalf("expected nil last_used_at before first use, got %v", before.LastUsedAt)
	}

	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/users", viewerKey, nil); status != http.StatusOK {
		t.Fatalf("GET /admin/users with stored key status=%d want=%d", status, http.StatusOK)
	}

	var after model.AdminKey
	if err := gormDB.Where("name = ?", "stored-viewer").First(&after).Error; err != nil {
		t.Fatalf("load stored-viewer after: %v", err)
	}
	if after.LastUsedAt == nil {
		t.Fatalf("expected last_used_at to be updated on authenticated request")
	}
}

func TestAdminAuthRevokedKey(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	plain := insertAdminKey(t, gormDB, "revoked-key", actor.TierAdmin)

	now := time.Now().UTC().Add(-time.Minute)
	if err := gormDB.Model(&model.AdminKey{}).Where("name = ?", "revoked-key").Update("revoked_at", now).Error; err != nil {
		t.Fatalf("revoke key: %v", err)
	}

	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/keys", plain, nil); status != http.StatusUnauthorized {
		t.Fatalf("revoked key status=%d want=%d", status, http.StatusUnauthorized)
	}
}

func TestAdminAuthExpiredKey(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	plain := insertAdminKey(t, gormDB, "expired-key", actor.TierAdmin)

	past := time.Now().UTC().Add(-time.Minute)
	if err := gormDB.Model(&model.AdminKey{}).Where("name = ?", "expired-key").Update("expires_at", past).Error; err != nil {
		t.Fatalf("expire key: %v", err)
	}

	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/keys", plain, nil); status != http.StatusUnauthorized {
		t.Fatalf("expired key status=%d want=%d", status, http.StatusUnauthorized)
	}
}

func TestAdminDisabledWhenNoKeyIgnoresStoredKeys(t *testing.T) {
	router, gormDB := newTestRouter(t) // ADMIN_API_KEY unset
	storedAdmin := insertAdminKey(t, gormDB, "active-stored-admin", actor.TierAdmin)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/users"},
		{http.MethodGet, "/admin/keys"},
		{http.MethodPost, "/admin/keys"},
	} {
		status, _ := doAdminRequest(t, router, tc.method, tc.path, storedAdmin, nil)
		if status != http.StatusNotFound {
			t.Fatalf("%s %s with stored key when ADMIN_API_KEY unset: status=%d want=%d",
				tc.method, tc.path, status, http.StatusNotFound)
		}
	}
}

func TestAdminAuthDBErrorReturns500(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	const cbName = "c_fail_auth_lookup_500"
	if err := gormDB.Callback().Query().Before("gorm:query").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "admin_keys" {
			_ = tx.AddError(errors.New("simulated db outage"))
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	defer func() {
		_ = gormDB.Callback().Query().Remove(cbName)
	}()

	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/keys", testAdminKey, nil); status != http.StatusInternalServerError {
		t.Fatalf("DB error during auth status=%d want=%d", status, http.StatusInternalServerError)
	}
}

// --- 4.2 Bootstrap key ---

func TestBootstrapFirstStart(t *testing.T) {
	dbURL, gormDB := cOpenTempDB(t, "bootstrap-first.db")
	application := cBuildApp(t, dbURL, gormDB, testAdminKey, nil)

	// Bootstrap row exists with tier admin and hashed key (not plaintext).
	var boot model.AdminKey
	if err := gormDB.Where("name = ?", service.BootstrapKeyName).First(&boot).Error; err != nil {
		t.Fatalf("lookup bootstrap key: %v", err)
	}
	if boot.Tier != model.AdminTierAdmin {
		t.Fatalf("bootstrap tier=%q want=%q", boot.Tier, model.AdminTierAdmin)
	}
	if boot.KeyHash != hashToken(testAdminKey, "test-pepper") {
		t.Fatalf("bootstrap key_hash mismatch")
	}
	if boot.RevokedAt != nil || boot.ExpiresAt != nil {
		t.Fatalf("bootstrap should be active: revoked=%v expires=%v", boot.RevokedAt, boot.ExpiresAt)
	}

	// Requests with ADMIN_API_KEY authenticate as tier admin.
	if status, _ := doAdminRequest(t, application.Router, http.MethodGet, "/admin/keys", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("GET /admin/keys with bootstrap key status=%d want=%d", status, http.StatusOK)
	}

	// Exactly one system audit row recorded the bootstrap creation.
	var audits []model.AdminAuditLog
	if err := gormDB.Order("id asc").Find(&audits).Error; err != nil {
		t.Fatalf("load admin audits: %v", err)
	}
	if len(audits) != 1 {
		t.Fatalf("audit count=%d want=1", len(audits))
	}
	row := audits[0]
	if row.ActorName != actor.System.Name || row.ActorKeyID != nil || row.HTTPStatus != nil {
		t.Fatalf("unexpected system audit actor/status: %+v", row)
	}
	if row.TargetType != "admin_key" || row.TargetID != boot.ID.String() || row.Outcome != service.AuditOutcomeSuccess {
		t.Fatalf("unexpected system audit target/outcome: %+v", row)
	}
}

func TestBootstrapFollowsRotatedEnvKey(t *testing.T) {
	dbURL, gormDB := cOpenTempDB(t, "bootstrap-rotate.db")

	const key1 = "bootstrap-key-one-0123456789"
	const key2 = "bootstrap-key-two-9876543210"

	app1 := cBuildApp(t, dbURL, gormDB, key1, nil)
	if status, _ := doAdminRequest(t, app1.Router, http.MethodGet, "/admin/keys", key1, nil); status != http.StatusOK {
		t.Fatalf("initial key1 status=%d want=%d", status, http.StatusOK)
	}

	// Restart with rotated ADMIN_API_KEY while bootstrap is active.
	app2 := cBuildApp(t, dbURL, gormDB, key2, nil)
	if status, _ := doAdminRequest(t, app2.Router, http.MethodGet, "/admin/keys", key2, nil); status != http.StatusOK {
		t.Fatalf("rotated key2 status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doAdminRequest(t, app2.Router, http.MethodGet, "/admin/keys", key1, nil); status != http.StatusUnauthorized {
		t.Fatalf("old key1 status=%d want=%d", status, http.StatusUnauthorized)
	}

	// Two system audit rows: initial create + rotation.
	var audits []model.AdminAuditLog
	if err := gormDB.Where("actor_name = ?", actor.System.Name).Order("id asc").Find(&audits).Error; err != nil {
		t.Fatalf("load system audits: %v", err)
	}
	if len(audits) != 2 {
		t.Fatalf("system audit count=%d want=2", len(audits))
	}
}

func TestBootstrapRestoredWhenNoActiveAdmin(t *testing.T) {
	dbURL, gormDB := cOpenTempDB(t, "bootstrap-restore.db")

	const key1 = "bootstrap-initial-key-0123456789"
	const key2 = "bootstrap-recovery-key-9876543210"

	app1 := cBuildApp(t, dbURL, gormDB, key1, nil)

	// Create a second admin key so we can revoke bootstrap through the API.
	secondID, secondPlain := cCreateKey(t, app1.Router, key1, "second-admin", model.AdminTierAdmin, nil)

	var boot model.AdminKey
	if err := gormDB.Where("name = ?", service.BootstrapKeyName).First(&boot).Error; err != nil {
		t.Fatalf("load bootstrap: %v", err)
	}
	if status, _ := doAdminRequest(t, app1.Router, http.MethodPost, "/admin/keys/"+boot.ID.String()+"/revoke", secondPlain, nil); status != http.StatusOK {
		t.Fatalf("revoke bootstrap status=%d want=%d", status, http.StatusOK)
	}

	// Expire the second admin key so zero active admin-tier keys remain.
	past := time.Now().UTC().Add(-time.Minute)
	if err := gormDB.Model(&model.AdminKey{}).Where("id = ?", uuid.MustParse(secondID)).Update("expires_at", past).Error; err != nil {
		t.Fatalf("expire second admin: %v", err)
	}

	// Restart: bootstrap must be reactivated with key2.
	app2 := cBuildApp(t, dbURL, gormDB, key2, nil)
	if status, _ := doAdminRequest(t, app2.Router, http.MethodGet, "/admin/keys", key2, nil); status != http.StatusOK {
		t.Fatalf("restored bootstrap key2 status=%d want=%d", status, http.StatusOK)
	}

	var restored model.AdminKey
	if err := gormDB.Where("name = ?", service.BootstrapKeyName).First(&restored).Error; err != nil {
		t.Fatalf("reload bootstrap: %v", err)
	}
	if restored.ID != boot.ID {
		t.Fatalf("expected existing bootstrap row reactivated, got id=%s want=%s", restored.ID, boot.ID)
	}
	if restored.RevokedAt != nil || restored.ExpiresAt != nil || restored.Tier != model.AdminTierAdmin {
		t.Fatalf("unexpected restored bootstrap state: %+v", restored)
	}

	var sysCount int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Where("actor_name = ?", actor.System.Name).Count(&sysCount).Error; err != nil {
		t.Fatalf("count system audits: %v", err)
	}
	if sysCount != 2 {
		t.Fatalf("system audit count=%d want=2 (create + reactivate)", sysCount)
	}
}

func TestBootstrapIgnoredWhenRevokedAndOtherAdminExists(t *testing.T) {
	dbURL, gormDB := cOpenTempDB(t, "bootstrap-ignored.db")

	const key1 = "bootstrap-env-first-0123456789"
	const key2 = "bootstrap-env-second-9876543210"

	app1 := cBuildApp(t, dbURL, gormDB, key1, nil)
	_, namedAdminPlain := cCreateKey(t, app1.Router, key1, "named-admin", model.AdminTierAdmin, nil)

	var boot model.AdminKey
	if err := gormDB.Where("name = ?", service.BootstrapKeyName).First(&boot).Error; err != nil {
		t.Fatalf("load bootstrap: %v", err)
	}
	if status, _ := doAdminRequest(t, app1.Router, http.MethodPost, "/admin/keys/"+boot.ID.String()+"/revoke", namedAdminPlain, nil); status != http.StatusOK {
		t.Fatalf("revoke bootstrap status=%d want=%d", status, http.StatusOK)
	}

	var auditBefore int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Count(&auditBefore).Error; err != nil {
		t.Fatalf("count audits before restart: %v", err)
	}

	// Restart with a new ADMIN_API_KEY while bootstrap is revoked and named-admin is active.
	core, logs := observer.New(zapcore.WarnLevel)
	app2 := cBuildApp(t, dbURL, gormDB, key2, zap.New(core))

	// Configured ADMIN_API_KEY must return 401; named-admin still works.
	if status, _ := doAdminRequest(t, app2.Router, http.MethodGet, "/admin/keys", key2, nil); status != http.StatusUnauthorized {
		t.Fatalf("ignored ADMIN_API_KEY status=%d want=%d", status, http.StatusUnauthorized)
	}
	if status, _ := doAdminRequest(t, app2.Router, http.MethodGet, "/admin/keys", key1, nil); status != http.StatusUnauthorized {
		t.Fatalf("revoked bootstrap key1 status=%d want=%d", status, http.StatusUnauthorized)
	}
	if status, _ := doAdminRequest(t, app2.Router, http.MethodGet, "/admin/keys", namedAdminPlain, nil); status != http.StatusOK {
		t.Fatalf("named-admin status=%d want=%d", status, http.StatusOK)
	}

	// Warning logged, no secret leaked, no audit row added.
	foundWarn := false
	for _, entry := range logs.All() {
		if entry.Level == zapcore.WarnLevel && strings.Contains(entry.Message, "ADMIN_API_KEY") && strings.Contains(entry.Message, "no access") {
			foundWarn = true
		}
		if strings.Contains(entry.Message, key2) || strings.Contains(entry.Message, hashToken(key2, "test-pepper")) {
			t.Fatalf("log message leaked secret: %q", entry.Message)
		}
	}
	if !foundWarn {
		t.Fatalf("expected warning log stating ADMIN_API_KEY grants no access, got %v", logs.All())
	}

	var auditAfter int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Count(&auditAfter).Error; err != nil {
		t.Fatalf("count audits after restart: %v", err)
	}
	if auditAfter != auditBefore {
		t.Fatalf("audit count changed on ignored bootstrap restart: before=%d after=%d", auditBefore, auditAfter)
	}
}

func TestBootstrapUnchangedRestartWritesNoAudit(t *testing.T) {
	dbURL, gormDB := cOpenTempDB(t, "bootstrap-unchanged.db")

	_ = cBuildApp(t, dbURL, gormDB, testAdminKey, nil)
	var afterFirst int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Count(&afterFirst).Error; err != nil {
		t.Fatalf("count audits after first start: %v", err)
	}
	if afterFirst != 1 {
		t.Fatalf("audit count after first start=%d want=1", afterFirst)
	}

	// Second start with identical ADMIN_API_KEY must write zero audit rows.
	app2 := cBuildApp(t, dbURL, gormDB, testAdminKey, nil)
	var afterSecond int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Count(&afterSecond).Error; err != nil {
		t.Fatalf("count audits after second start: %v", err)
	}
	if afterSecond != afterFirst {
		t.Fatalf("unchanged restart wrote audit rows: first=%d second=%d", afterFirst, afterSecond)
	}
	if status, _ := doAdminRequest(t, app2.Router, http.MethodGet, "/admin/keys", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("GET /admin/keys after unchanged restart status=%d want=%d", status, http.StatusOK)
	}
}

func TestBootstrapConcurrentStartup(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "bootstrap-concurrent.db")

	// Pre-migrate on one connection so concurrent app.Build calls race directly on
	// startup seeding and SyncBootstrapKey without hitting SQLite DDL races.
	initDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open init db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), initDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	const instances = 4
	dbs := make([]*gorm.DB, instances)
	for i := 0; i < instances; i++ {
		conn, err := db.OpenDatabase(dbURL)
		if err != nil {
			t.Fatalf("open db %d: %v", i, err)
		}
		dbs[i] = conn
	}

	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "test-pepper",
		AdminAPIKey:          testAdminKey,
		EnableCasbin:         true,
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
			apps[idx], errs[idx] = app.Build(context.Background(), dbs[idx], cfg, zap.NewNop())
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < instances; i++ {
		if errs[i] != nil {
			t.Fatalf("instance %d app.Build failed: %v", i, errs[i])
		}
		t.Cleanup(apps[i].Close)
	}

	var bootCount int64
	if err := initDB.Model(&model.AdminKey{}).Where("name = ?", service.BootstrapKeyName).Count(&bootCount).Error; err != nil {
		t.Fatalf("count bootstrap rows: %v", err)
	}
	if bootCount != 1 {
		t.Fatalf("bootstrap row count=%d want=1", bootCount)
	}

	var sysCount int64
	if err := initDB.Model(&model.AdminAuditLog{}).Where("actor_name = ?", actor.System.Name).Count(&sysCount).Error; err != nil {
		t.Fatalf("count system audit rows: %v", err)
	}
	if sysCount != 1 {
		t.Fatalf("system audit row count=%d want=1", sysCount)
	}

	for i, a := range apps {
		if status, _ := doAdminRequest(t, a.Router, http.MethodGet, "/admin/keys", testAdminKey, nil); status != http.StatusOK {
			t.Fatalf("instance %d GET /admin/keys status=%d want=%d", i, status, http.StatusOK)
		}
	}
}

// --- 4.3 Key endpoints ---

func TestAdminKeyCreateReturnsPlaintextOnce(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	exp := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)

	status, body := doAdminRequest(t, router, http.MethodPost, "/admin/keys", testAdminKey, map[string]any{
		"name":      "ci-operator",
		"tier":      "operator",
		"expiresAt": exp.Format(time.RFC3339),
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /admin/keys status=%d want=%d body=%v", status, http.StatusCreated, body)
	}

	plain, _ := body["key"].(string)
	if !strings.HasPrefix(plain, "dak_") {
		t.Fatalf("plaintext key %q does not start with dak_", plain)
	}
	rawBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(plain, "dak_"))
	if err != nil {
		t.Fatalf("plaintext suffix is not valid raw base64url: %v", err)
	}
	if len(rawBytes) != 32 {
		t.Fatalf("key entropy bytes=%d want=32", len(rawBytes))
	}

	meta, ok := body["meta"].(map[string]any)
	if !ok {
		t.Fatalf("missing meta object in response: %v", body)
	}
	if meta["name"] != "ci-operator" || meta["tier"] != "operator" {
		t.Fatalf("unexpected meta: %v", meta)
	}
	if _, hasHash := meta["keyHash"]; hasHash {
		t.Fatalf("meta must not include keyHash")
	}

	// Only the peppered hash is stored in the database.
	var stored model.AdminKey
	if err := gormDB.Where("name = ?", "ci-operator").First(&stored).Error; err != nil {
		t.Fatalf("load stored key: %v", err)
	}
	if stored.KeyHash != hashToken(plain, "test-pepper") {
		t.Fatalf("stored key_hash mismatch")
	}
	if stored.KeyHash == plain {
		t.Fatalf("plaintext key must not be stored")
	}
	if stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(exp) {
		t.Fatalf("stored expires_at=%v want=%v", stored.ExpiresAt, exp)
	}

	// Listing does not return the plaintext or hash.
	status, listBody := doAdminRequest(t, router, http.MethodGet, "/admin/keys", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /admin/keys status=%d want=%d", status, http.StatusOK)
	}
	listStr := fmt.Sprint(listBody)
	if strings.Contains(listStr, plain) || strings.Contains(listStr, stored.KeyHash) {
		t.Fatalf("GET /admin/keys leaked secret or hash")
	}

	// The freshly created key works for authentication with its tier.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/users", plain, nil); status != http.StatusOK {
		t.Fatalf("created operator key GET /admin/users status=%d want=%d", status, http.StatusOK)
	}
}

func TestAdminKeyCreateValidation(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	cases := []struct {
		name    string
		payload map[string]any
	}{
		{name: "missing_name", payload: map[string]any{"tier": "viewer"}},
		{name: "blank_name", payload: map[string]any{"name": "   ", "tier": "viewer"}},
		{name: "missing_tier", payload: map[string]any{"name": "no-tier"}},
		{name: "unknown_tier", payload: map[string]any{"name": "bad-tier", "tier": "superadmin"}},
		{name: "uppercase_tier", payload: map[string]any{"name": "upper-tier", "tier": "ADMIN"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys", testAdminKey, tc.payload)
			if status != http.StatusBadRequest {
				t.Fatalf("case %s status=%d want=%d", tc.name, status, http.StatusBadRequest)
			}
		})
	}

	var count int64
	if err := gormDB.Model(&model.AdminKey{}).Where("name <> ?", service.BootstrapKeyName).Count(&count).Error; err != nil {
		t.Fatalf("count keys: %v", err)
	}
	if count != 0 {
		t.Fatalf("non-bootstrap key count=%d want=0", count)
	}
}

func TestAdminKeyNameConflict(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt)
	cCreateKey(t, router, testAdminKey, "dup-key", model.AdminTierViewer, nil)

	status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys", testAdminKey, map[string]any{
		"name": "dup-key",
		"tier": "operator",
	})
	if status != http.StatusConflict {
		t.Fatalf("duplicate key name status=%d want=%d", status, http.StatusConflict)
	}
}

func TestAdminKeyBootstrapNameReserved(t *testing.T) {
	router, _ := newTestRouter(t, adminKeyOpt)

	for _, name := range []string{"bootstrap", "  bootstrap  "} {
		status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys", testAdminKey, map[string]any{
			"name": name,
			"tier": "admin",
		})
		if status != http.StatusConflict {
			t.Fatalf("reserved name %q status=%d want=%d", name, status, http.StatusConflict)
		}
	}
}

func TestAdminKeyRevokeIdempotent(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	keyID, keyPlain := cCreateKey(t, router, testAdminKey, "revocable-op", model.AdminTierOperator, nil)

	// Malformed UUID -> 400; unknown UUID -> 404.
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/not-a-uuid/revoke", testAdminKey, nil); status != http.StatusBadRequest {
		t.Fatalf("malformed id status=%d want=%d", status, http.StatusBadRequest)
	}
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+uuid.NewString()+"/revoke", testAdminKey, nil); status != http.StatusNotFound {
		t.Fatalf("unknown id status=%d want=%d", status, http.StatusNotFound)
	}

	// First revoke succeeds.
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+keyID+"/revoke", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("first revoke status=%d want=%d", status, http.StatusOK)
	}
	var afterFirst model.AdminKey
	if err := gormDB.First(&afterFirst, "id = ?", uuid.MustParse(keyID)).Error; err != nil {
		t.Fatalf("load key after first revoke: %v", err)
	}
	if afterFirst.RevokedAt == nil {
		t.Fatalf("expected revoked_at set after revoke")
	}

	// Revoked key is immediately rejected with 401.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/users", keyPlain, nil); status != http.StatusUnauthorized {
		t.Fatalf("revoked key auth status=%d want=%d", status, http.StatusUnauthorized)
	}

	// Second revoke is idempotent: 200 and preserves original revoked_at.
	time.Sleep(5 * time.Millisecond)
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+keyID+"/revoke", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("second revoke status=%d want=%d", status, http.StatusOK)
	}
	var afterSecond model.AdminKey
	if err := gormDB.First(&afterSecond, "id = ?", uuid.MustParse(keyID)).Error; err != nil {
		t.Fatalf("load key after second revoke: %v", err)
	}
	if afterSecond.RevokedAt == nil || !afterSecond.RevokedAt.Equal(*afterFirst.RevokedAt) {
		t.Fatalf("second revoke changed revoked_at: first=%v second=%v", afterFirst.RevokedAt, afterSecond.RevokedAt)
	}
}

func TestAdminKeyRevokeLastAdminRefused(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	var boot model.AdminKey
	if err := gormDB.Where("name = ?", service.BootstrapKeyName).First(&boot).Error; err != nil {
		t.Fatalf("load bootstrap: %v", err)
	}

	// Only bootstrap is active admin -> revoking it must return 409 and leave it active.
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+boot.ID.String()+"/revoke", testAdminKey, nil); status != http.StatusConflict {
		t.Fatalf("revoke sole admin status=%d want=%d", status, http.StatusConflict)
	}
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/keys", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("bootstrap should still be active after 409, status=%d", status)
	}

	// Adding a second active admin allows revoking bootstrap, then refuses revoking the second.
	secondID, secondPlain := cCreateKey(t, router, testAdminKey, "admin-two", model.AdminTierAdmin, nil)
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+boot.ID.String()+"/revoke", secondPlain, nil); status != http.StatusOK {
		t.Fatalf("revoke bootstrap with second admin present status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+secondID+"/revoke", secondPlain, nil); status != http.StatusConflict {
		t.Fatalf("revoke remaining sole admin status=%d want=%d", status, http.StatusConflict)
	}
}

func TestAdminKeyRevokeLastAdminConcurrent(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Start with 4 active admins (bootstrap + 3 created). Each goroutine
	// authenticates with its own key and revokes itself, so no goroutine can
	// invalidate another goroutine's bearer token before adminAuth runs; every
	// goroutine races inside RevokeAdminKey's transaction.
	var boot model.AdminKey
	if err := gormDB.Where("name = ?", service.BootstrapKeyName).First(&boot).Error; err != nil {
		t.Fatalf("load bootstrap: %v", err)
	}
	type adminCred struct {
		id    string
		plain string
	}
	creds := []adminCred{{id: boot.ID.String(), plain: testAdminKey}}
	for i := 1; i <= 3; i++ {
		id, plain := cCreateKey(t, router, testAdminKey, fmt.Sprintf("concurrent-admin-%d", i), model.AdminTierAdmin, nil)
		creds = append(creds, adminCred{id: id, plain: plain})
	}

	start := make(chan struct{})
	statuses := make([]int, len(creds))
	var wg sync.WaitGroup
	for i, cred := range creds {
		wg.Add(1)
		go func(idx int, c adminCred) {
			defer wg.Done()
			<-start
			statuses[idx], _ = doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+c.id+"/revoke", c.plain, nil)
		}(i, cred)
	}
	close(start)
	wg.Wait()

	okCount, conflictCount := 0, 0
	for _, st := range statuses {
		switch st {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			conflictCount++
		default:
			t.Fatalf("unexpected concurrent revoke status=%d (all=%v)", st, statuses)
		}
	}
	if okCount != len(creds)-1 || conflictCount != 1 {
		t.Fatalf("concurrent last-admin revoke outcomes: ok=%d conflict=%d (statuses=%v), want %d ok and 1 conflict",
			okCount, conflictCount, statuses, len(creds)-1)
	}

	var activeAdmins int64
	if err := gormDB.Model(&model.AdminKey{}).Where("tier = ? AND revoked_at IS NULL", model.AdminTierAdmin).Count(&activeAdmins).Error; err != nil {
		t.Fatalf("count active admins: %v", err)
	}
	if activeAdmins != 1 {
		t.Fatalf("active admin count=%d want=1", activeAdmins)
	}
}

func TestAdminKeyListPaginatedWithoutHash(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Seed keys with explicit created_at values including ties to verify tie-breaking by id.
	base := time.Date(2026, 11, 24, 1, 0, 0, 0, time.UTC)
	plainSecrets := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i/2) * time.Second)
		plain := fmt.Sprintf("dak_seeded_plain_%d_0123456789", i)
		plainSecrets = append(plainSecrets, plain)
		entry := model.AdminKey{
			ID:        uuid.New(),
			Name:      fmt.Sprintf("page-key-%d", i),
			Tier:      model.AdminTierViewer,
			KeyHash:   hashToken(plain, "test-pepper"),
			CreatedAt: ts,
		}
		if err := gormDB.Create(&entry).Error; err != nil {
			t.Fatalf("seed key %d: %v", i, err)
		}
	}

	// Expected full order from DB: created_at ASC, id ASC (includes bootstrap + 5 seeded = 6 keys).
	var expected []model.AdminKey
	if err := gormDB.Order("created_at ASC, id ASC").Find(&expected).Error; err != nil {
		t.Fatalf("load expected order: %v", err)
	}
	if len(expected) != 6 {
		t.Fatalf("expected 6 keys total, got %d", len(expected))
	}

	// Walk pages of size 2 and verify exact ordering, fields, no hash, and null nextCursor on last page.
	var seenIDs []string
	cursor := ""
	pages := 0
	for {
		pages++
		path := "/admin/keys?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		status, body := doAdminRequest(t, router, http.MethodGet, path, testAdminKey, nil)
		if status != http.StatusOK {
			t.Fatalf("page %d status=%d want=%d body=%v", pages, status, http.StatusOK, body)
		}
		rawItems, ok := body["keys"].([]any)
		if !ok {
			t.Fatalf("page %d missing keys array: %v", pages, body)
		}
		for _, item := range rawItems {
			m := item.(map[string]any)
			for _, required := range []string{"id", "name", "tier", "createdAt", "expiresAt", "revokedAt", "lastUsedAt"} {
				if _, exists := m[required]; !exists {
					t.Fatalf("key view missing field %q: %v", required, m)
				}
			}
			for _, forbidden := range []string{"keyHash", "key_hash", "key", "plain"} {
				if _, exists := m[forbidden]; exists {
					t.Fatalf("key view must not expose %q: %v", forbidden, m)
				}
			}
			seenIDs = append(seenIDs, m["id"].(string))
		}

		// Ensure no secret or hash appears anywhere in the serialized body.
		bodyStr := fmt.Sprint(body)
		for _, s := range plainSecrets {
			if strings.Contains(bodyStr, s) || strings.Contains(bodyStr, hashToken(s, "test-pepper")) {
				t.Fatalf("list response leaked secret or hash")
			}
		}

		nextVal, hasNextField := body["nextCursor"]
		if !hasNextField {
			t.Fatalf("page %d missing nextCursor field", pages)
		}
		if nextVal == nil {
			break
		}
		cursor = nextVal.(string)
		if pages > 10 {
			t.Fatalf("pagination did not terminate")
		}
	}

	if len(seenIDs) != len(expected) {
		t.Fatalf("collected %d keys want %d", len(seenIDs), len(expected))
	}
	for i := range expected {
		if seenIDs[i] != expected[i].ID.String() {
			t.Fatalf("index %d id=%s want=%s", i, seenIDs[i], expected[i].ID)
		}
	}

	// Invalid limit, malformed cursor, and foreign-list cursor all return 400.
	foreignCursor := page.Cursor{L: "users", T: base, K: uuid.NewString()}.Encode()
	for _, badPath := range []string{
		"/admin/keys?limit=0",
		"/admin/keys?limit=201",
		"/admin/keys?limit=abc",
		"/admin/keys?cursor=not-valid!!!",
		"/admin/keys?cursor=" + foreignCursor,
	} {
		if status, _ := doAdminRequest(t, router, http.MethodGet, badPath, testAdminKey, nil); status != http.StatusBadRequest {
			t.Fatalf("GET %s status=%d want=%d", badPath, status, http.StatusBadRequest)
		}
	}
}

func TestAdminKeyRoutesRequireAdminTier(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	viewerKey := insertAdminKey(t, gormDB, "tier-viewer", actor.TierViewer)
	operatorKey := insertAdminKey(t, gormDB, "tier-operator", actor.TierOperator)
	targetID, _ := cCreateKey(t, router, testAdminKey, "tier-target", model.AdminTierViewer, nil)

	routes := []struct {
		method  string
		path    string
		payload any
	}{
		{http.MethodGet, "/admin/keys", nil},
		{http.MethodPost, "/admin/keys", map[string]any{"name": "blocked-key", "tier": "viewer"}},
		{http.MethodPost, "/admin/keys/" + targetID + "/revoke", nil},
	}

	for _, caller := range []struct {
		name string
		key  string
	}{
		{"viewer", viewerKey},
		{"operator", operatorKey},
	} {
		for _, r := range routes {
			status, _ := doAdminRequest(t, router, r.method, r.path, caller.key, r.payload)
			if status != http.StatusForbidden {
				t.Fatalf("%s calling %s %s: status=%d want=%d", caller.name, r.method, r.path, status, http.StatusForbidden)
			}
		}
	}
}

func TestAdminKeyAuditHasNoSecrets(t *testing.T) {
	dbURL, gormDB := cOpenTempDB(t, "audit-no-secrets.db")

	const bootKey1 = "bootstrap-secret-one-0123456789"
	const bootKey2 = "bootstrap-secret-two-9876543210"

	// 1. Bootstrap create.
	_ = cBuildApp(t, dbURL, gormDB, bootKey1, nil)
	// 2. Bootstrap rotation.
	app2 := cBuildApp(t, dbURL, gormDB, bootKey2, nil)
	// 3. Create a named key via API.
	createdID, createdPlain := cCreateKey(t, app2.Router, bootKey2, "audited-key", model.AdminTierOperator, nil)
	// 4. Revoke that named key via API.
	if status, _ := doAdminRequest(t, app2.Router, http.MethodPost, "/admin/keys/"+createdID+"/revoke", bootKey2, nil); status != http.StatusOK {
		t.Fatalf("revoke created key status=%d want=%d", status, http.StatusOK)
	}

	secrets := []string{
		bootKey1, hashToken(bootKey1, "test-pepper"),
		bootKey2, hashToken(bootKey2, "test-pepper"),
		createdPlain, hashToken(createdPlain, "test-pepper"),
	}

	var rows []model.AdminAuditLog
	if err := gormDB.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("load admin_audit_logs: %v", err)
	}
	if len(rows) < 4 {
		t.Fatalf("expected at least 4 admin audit rows (bootstrap create, rotate, key create, key revoke), got %d", len(rows))
	}

	foundCreateSummary := false
	for _, row := range rows {
		fields := []struct {
			col string
			val string
		}{
			{"actor_name", row.ActorName},
			{"actor_tier", row.ActorTier},
			{"action", row.Action},
			{"target_type", row.TargetType},
			{"target_id", row.TargetID},
			{"outcome", row.Outcome},
			{"client_ip", row.ClientIP},
			{"summary", row.Summary},
		}
		if row.ActorKeyID != nil {
			fields = append(fields, struct{ col, val string }{"actor_key_id", row.ActorKeyID.String()})
		}
		for _, f := range fields {
			for _, secret := range secrets {
				if strings.Contains(f.val, secret) {
					t.Fatalf("admin audit row %d (%s) leaked secret in column %s: %q", row.ID, row.Action, f.col, f.val)
				}
			}
		}
		if row.Action == "admin_key.create" && row.TargetID == createdID {
			if strings.Contains(row.Summary, "audited-key") && strings.Contains(row.Summary, "operator") {
				foundCreateSummary = true
			}
		}
	}
	if !foundCreateSummary {
		t.Fatalf("expected admin_key.create audit summary to contain key name and tier")
	}
}
