package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
)

func cOpenTestDB(t *testing.T, name string) *gorm.DB {
	t.Helper()
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), name)
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
	return gormDB
}

func cNewTestService(t *testing.T, gormDB *gorm.DB, logger *zap.Logger, opts ...Option) *Service {
	t.Helper()
	if logger == nil {
		logger = zap.NewNop()
	}
	engine, err := policy.NewEngine(gormDB)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("reload policy engine: %v", err)
	}
	return New(gormDB, engine, "track-c-pepper", 5*time.Second, NewVerifyCache(0), logger, opts...)
}

func cAdminCtx(action, targetType, targetID string) context.Context {
	keyID := uuid.New()
	ctx := actor.With(context.Background(), actor.Actor{
		KeyID: &keyID,
		Name:  "test-admin",
		Tier:  actor.TierAdmin,
		IP:    "127.0.0.1",
	})
	return actor.WithOp(ctx, &actor.Op{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
	})
}

func TestAdminAuthRejectsStaticKeyWithoutStoredRow(t *testing.T) {
	const staticKey = "static-env-key-0123456789abcdef"
	gormDB := cOpenTestDB(t, "no-fallback.db")
	svc := cNewTestService(t, gormDB, nil)

	// Static fallback must be gone: without a stored row, ADMIN_API_KEY is rejected.
	a, ok, err := svc.AuthenticateAdminKey(context.Background(), staticKey)
	if err != nil {
		t.Fatalf("AuthenticateAdminKey err=%v want=nil", err)
	}
	if ok || a.Tier != actor.TierNone {
		t.Fatalf("expected static key without stored row to be rejected, got actor=%+v ok=%v", a, ok)
	}
}

func TestAdminAuthLastUsedAtWriteFailureStillAuthenticates(t *testing.T) {
	gormDB := cOpenTestDB(t, "last-used-best-effort.db")
	svc := cNewTestService(t, gormDB, nil)

	res, err := svc.CreateAdminKey(cAdminCtx("admin_key.create", "admin_key", ""), CreateAdminKeyInput{
		Name: "best-effort-key",
		Tier: model.AdminTierViewer,
	})
	if err != nil {
		t.Fatalf("CreateAdminKey: %v", err)
	}

	const cbName = "c_fail_last_used_at_update"
	if err := gormDB.Callback().Update().Before("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "admin_keys" {
			_ = tx.AddError(errors.New("simulated last_used_at write error"))
		}
	}); err != nil {
		t.Fatalf("register update callback: %v", err)
	}
	defer func() {
		_ = gormDB.Callback().Update().Remove(cbName)
	}()

	a, ok, err := svc.AuthenticateAdminKey(context.Background(), res.Plain)
	if err != nil {
		t.Fatalf("AuthenticateAdminKey err=%v want=nil when last_used_at write fails", err)
	}
	if !ok {
		t.Fatalf("AuthenticateAdminKey ok=false want=true")
	}
	if a.KeyID == nil || *a.KeyID != res.Key.ID || a.Name != "best-effort-key" || a.Tier != actor.TierViewer {
		t.Fatalf("unexpected actor: %+v", a)
	}
}

func TestAdminAuthDBErrorFailsClosed(t *testing.T) {
	gormDB := cOpenTestDB(t, "auth-db-err.db")
	svc := cNewTestService(t, gormDB, nil)

	forcedErr := errors.New("database unreachable")
	const cbName = "c_fail_admin_key_query"
	if err := gormDB.Callback().Query().Before("gorm:query").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "admin_keys" {
			_ = tx.AddError(forcedErr)
		}
	}); err != nil {
		t.Fatalf("register query callback: %v", err)
	}
	defer func() {
		_ = gormDB.Callback().Query().Remove(cbName)
	}()

	_, ok, err := svc.AuthenticateAdminKey(context.Background(), "dak_anything")
	if !errors.Is(err, forcedErr) {
		t.Fatalf("AuthenticateAdminKey err=%v want=%v", err, forcedErr)
	}
	if ok {
		t.Fatalf("AuthenticateAdminKey ok=true want=false on DB error")
	}
}

func TestBootstrapExpiredAndAbsentCases(t *testing.T) {
	const envKey = "bootstrap-env-key-0123456789"

	t.Run("empty_env_key_is_noop", func(t *testing.T) {
		gormDB := cOpenTestDB(t, "bootstrap-empty.db")
		svc := cNewTestService(t, gormDB, nil)

		if err := svc.SyncBootstrapKey(context.Background(), ""); err != nil {
			t.Fatalf("SyncBootstrapKey empty: %v", err)
		}
		var keyCount, auditCount int64
		_ = gormDB.Model(&model.AdminKey{}).Count(&keyCount).Error
		_ = gormDB.Model(&model.AdminAuditLog{}).Count(&auditCount).Error
		if keyCount != 0 || auditCount != 0 {
			t.Fatalf("expected 0 keys and 0 audits for empty env key, got keys=%d audits=%d", keyCount, auditCount)
		}
	})

	t.Run("expired_bootstrap_restored_when_no_other_active_admin", func(t *testing.T) {
		gormDB := cOpenTestDB(t, "bootstrap-expired-restore.db")
		svc := cNewTestService(t, gormDB, nil)

		past := time.Now().UTC().Add(-time.Hour)
		existing := model.AdminKey{
			Name:      BootstrapKeyName,
			Tier:      model.AdminTierAdmin,
			KeyHash:   svc.hashToken("old-expired-bootstrap-key"),
			ExpiresAt: &past,
		}
		if err := gormDB.Create(&existing).Error; err != nil {
			t.Fatalf("seed expired bootstrap: %v", err)
		}

		if err := svc.SyncBootstrapKey(context.Background(), envKey); err != nil {
			t.Fatalf("SyncBootstrapKey: %v", err)
		}

		var reloaded model.AdminKey
		if err := gormDB.Where("name = ?", BootstrapKeyName).First(&reloaded).Error; err != nil {
			t.Fatalf("load bootstrap: %v", err)
		}
		if reloaded.ID != existing.ID {
			t.Fatalf("expected existing bootstrap row to be reactivated, id=%s want=%s", reloaded.ID, existing.ID)
		}
		if reloaded.RevokedAt != nil || reloaded.ExpiresAt != nil {
			t.Fatalf("expected revoked_at and expires_at cleared, got revoked=%v expires=%v", reloaded.RevokedAt, reloaded.ExpiresAt)
		}
		if reloaded.KeyHash != svc.hashToken(envKey) {
			t.Fatalf("bootstrap hash mismatch after reactivation")
		}

		var audits []model.AdminAuditLog
		if err := gormDB.Find(&audits).Error; err != nil {
			t.Fatalf("load audits: %v", err)
		}
		if len(audits) != 1 || audits[0].ActorName != actor.System.Name || audits[0].TargetID != existing.ID.String() {
			t.Fatalf("unexpected audits: %+v", audits)
		}
	})

	t.Run("expired_bootstrap_ignored_when_other_active_admin_exists", func(t *testing.T) {
		gormDB := cOpenTestDB(t, "bootstrap-expired-ignored.db")
		core, logs := observer.New(zapcore.WarnLevel)
		svc := cNewTestService(t, gormDB, zap.New(core))

		past := time.Now().UTC().Add(-time.Hour)
		expiredBoot := model.AdminKey{
			Name:      BootstrapKeyName,
			Tier:      model.AdminTierAdmin,
			KeyHash:   svc.hashToken("old-expired-bootstrap-key"),
			ExpiresAt: &past,
		}
		if err := gormDB.Create(&expiredBoot).Error; err != nil {
			t.Fatalf("seed expired bootstrap: %v", err)
		}
		other := model.AdminKey{
			Name:    "named-admin",
			Tier:    model.AdminTierAdmin,
			KeyHash: svc.hashToken("dak_named_admin_key_value"),
		}
		if err := gormDB.Create(&other).Error; err != nil {
			t.Fatalf("seed other admin: %v", err)
		}

		if err := svc.SyncBootstrapKey(context.Background(), envKey); err != nil {
			t.Fatalf("SyncBootstrapKey: %v", err)
		}

		if _, ok, err := svc.AuthenticateAdminKey(context.Background(), envKey); err != nil || ok {
			t.Fatalf("expected env key rejected when expired bootstrap ignored, ok=%v err=%v", ok, err)
		}
		var auditCount int64
		_ = gormDB.Model(&model.AdminAuditLog{}).Count(&auditCount).Error
		if auditCount != 0 {
			t.Fatalf("audit count=%d want=0", auditCount)
		}
		if logs.Len() == 0 {
			t.Fatalf("expected warning log stating ADMIN_API_KEY grants no access")
		}
		for _, entry := range logs.All() {
			if strings.Contains(entry.Message, envKey) {
				t.Fatalf("warning log leaked ADMIN_API_KEY")
			}
		}
	})

	t.Run("absent_bootstrap_ignored_when_other_active_admin_exists", func(t *testing.T) {
		gormDB := cOpenTestDB(t, "bootstrap-absent-ignored.db")
		core, logs := observer.New(zapcore.WarnLevel)
		svc := cNewTestService(t, gormDB, zap.New(core))

		other := model.AdminKey{
			Name:    "named-admin-only",
			Tier:    model.AdminTierAdmin,
			KeyHash: svc.hashToken("dak_named_admin_only"),
		}
		if err := gormDB.Create(&other).Error; err != nil {
			t.Fatalf("seed other admin: %v", err)
		}

		if err := svc.SyncBootstrapKey(context.Background(), envKey); err != nil {
			t.Fatalf("SyncBootstrapKey: %v", err)
		}

		var count int64
		_ = gormDB.Model(&model.AdminKey{}).Where("name = ?", BootstrapKeyName).Count(&count).Error
		if count != 0 {
			t.Fatalf("bootstrap row count=%d want=0 when another active admin exists", count)
		}
		if logs.Len() == 0 {
			t.Fatalf("expected warning log when absent bootstrap is ignored")
		}
	})
}

func TestAdminKeyRevokeNonAdminAndExpiredAdminAllowedWhenOneActiveAdmin(t *testing.T) {
	gormDB := cOpenTestDB(t, "revoke-non-admin.db")
	svc := cNewTestService(t, gormDB, nil)

	adminKey, err := svc.CreateAdminKey(cAdminCtx("admin_key.create", "admin_key", ""), CreateAdminKeyInput{
		Name: "sole-active-admin",
		Tier: model.AdminTierAdmin,
	})
	if err != nil {
		t.Fatalf("create sole active admin: %v", err)
	}
	viewerKey, err := svc.CreateAdminKey(cAdminCtx("admin_key.create", "admin_key", ""), CreateAdminKeyInput{
		Name: "viewer-1",
		Tier: model.AdminTierViewer,
	})
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	expiredAdmin, err := svc.CreateAdminKey(cAdminCtx("admin_key.create", "admin_key", ""), CreateAdminKeyInput{
		Name:      "expired-admin",
		Tier:      model.AdminTierAdmin,
		ExpiresAt: &past,
	})
	if err != nil {
		t.Fatalf("create expired admin: %v", err)
	}

	// Revoking viewer succeeds.
	if err := svc.RevokeAdminKey(cAdminCtx("admin_key.revoke", "admin_key", viewerKey.Key.ID.String()), viewerKey.Key.ID); err != nil {
		t.Fatalf("revoke viewer: %v", err)
	}
	// Revoking an already-expired admin key succeeds even though only 1 active admin exists.
	if err := svc.RevokeAdminKey(cAdminCtx("admin_key.revoke", "admin_key", expiredAdmin.Key.ID.String()), expiredAdmin.Key.ID); err != nil {
		t.Fatalf("revoke expired admin: %v", err)
	}
	// Revoking the sole active admin key must fail with ErrAdminConflict.
	if err := svc.RevokeAdminKey(cAdminCtx("admin_key.revoke", "admin_key", adminKey.Key.ID.String()), adminKey.Key.ID); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("revoke sole active admin err=%v want=%v", err, ErrAdminConflict)
	}

	// Verify policy_state.version was never bumped by any admin key mutation (EffectNone).
	v, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("ReadVersion: %v", err)
	}
	if v != 0 {
		t.Fatalf("policy version=%d want=0 for EffectNone admin key operations", v)
	}
}

func TestAdminKeyListRejectsNonUUIDCursorKey(t *testing.T) {
	gormDB := cOpenTestDB(t, "bad-cursor-key.db")
	svc := cNewTestService(t, gormDB, nil)

	cur := page.Cursor{L: "keys", T: time.Now().UTC(), K: "not-a-uuid"}.Encode()
	req, err := page.Parse("keys", "10", cur)
	if err != nil {
		t.Fatalf("page.Parse: %v", err)
	}
	if _, _, err := svc.ListAdminKeys(context.Background(), req); !errors.Is(err, ErrAdminInvalid) {
		t.Fatalf("ListAdminKeys err=%v want=%v", err, ErrAdminInvalid)
	}
}

func TestAdminKeyRevokeLastAdminConcurrentService(t *testing.T) {
	gormDB := cOpenTestDB(t, "revoke-last-admin-race.db")
	svc := cNewTestService(t, gormDB, nil)

	const totalAdmins = 4
	ids := make([]uuid.UUID, totalAdmins)
	for i := 0; i < totalAdmins; i++ {
		res, err := svc.CreateAdminKey(cAdminCtx("admin_key.create", "admin_key", ""), CreateAdminKeyInput{
			Name: "race-admin-" + uuid.NewString()[:8],
			Tier: model.AdminTierAdmin,
		})
		if err != nil {
			t.Fatalf("create admin %d: %v", i, err)
		}
		ids[i] = res.Key.ID
	}

	start := make(chan struct{})
	errs := make([]error, totalAdmins)
	var wg sync.WaitGroup
	for i := 0; i < totalAdmins; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			errs[idx] = svc.RevokeAdminKey(cAdminCtx("admin_key.revoke", "admin_key", ids[idx].String()), ids[idx])
		}(i)
	}
	close(start)
	wg.Wait()

	okCount, conflictCount := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			okCount++
		case errors.Is(err, ErrAdminConflict):
			conflictCount++
		default:
			t.Errorf("worker %d unexpected error: %v", i, err)
		}
	}
	if okCount != totalAdmins-1 || conflictCount != 1 {
		t.Fatalf("ok=%d conflict=%d want ok=%d conflict=1", okCount, conflictCount, totalAdmins-1)
	}

	var activeCount int64
	if err := gormDB.Model(&model.AdminKey{}).
		Where("tier = ? AND revoked_at IS NULL", model.AdminTierAdmin).
		Count(&activeCount).Error; err != nil {
		t.Fatalf("count active admins: %v", err)
	}
	if activeCount != 1 {
		t.Fatalf("remaining active admin count=%d want=1", activeCount)
	}
}
