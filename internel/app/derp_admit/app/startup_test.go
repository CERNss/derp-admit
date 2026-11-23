package app_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func aNewNodeKey(t *testing.T) string {
	t.Helper()
	pub := key.NewNode().Public()
	body, err := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: pub})
	if err != nil {
		t.Fatalf("marshal node key: %v", err)
	}
	_, nodeKey, err := derp.ParseRequest(body)
	if err != nil {
		t.Fatalf("parse node key: %v", err)
	}
	return nodeKey
}

func aVerifyBody(t *testing.T, nodeKey string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"NodePublic": nodeKey, "Source": ""})
	if err != nil {
		t.Fatalf("marshal verify body: %v", err)
	}
	return body
}

// aSeedPreUpgradeData populates a database with pre-upgrade tables (users,
// devices, casbin_rule) containing:
//   - a covered user with two active devices: one with a legacy device rule
//     (must stay allowed) and one without (must be revoked exactly once with
//     one system audit row)
//   - a custom role "ops" granted on "default" and "eu-1"
func aSeedPreUpgradeData(t *testing.T, gormDB *gorm.DB, dbURL string) (allowedKey, revokedKey string, revokedDevID uuid.UUID) {
	t.Helper()

	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("seed pre-upgrade migrations: %v", err)
	}

	u := model.User{ID: uuid.New(), Username: "concurrent-alice"}
	if err := gormDB.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	allowedKey = aNewNodeKey(t)
	revokedKey = aNewNodeKey(t)
	dAllowed := model.Device{ID: uuid.New(), UserID: u.ID, NodeKey: allowedKey, Label: "good"}
	dRevoked := model.Device{ID: uuid.New(), UserID: u.ID, NodeKey: revokedKey, Label: "missing-legacy"}
	if err := gormDB.Create(&dAllowed).Error; err != nil {
		t.Fatalf("create allowed device: %v", err)
	}
	if err := gormDB.Create(&dRevoked).Error; err != nil {
		t.Fatalf("create revoked device: %v", err)
	}

	rules := []model.CasbinRule{
		{Ptype: "p", V0: "role:ops", V1: "derp:default", V2: "connect"},
		{Ptype: "p", V0: "role:ops", V1: "derp:eu-1", V2: "connect"},
		{Ptype: "g", V0: policy.UserSubject(u.ID), V1: "role:ops"},
		{Ptype: "g", V0: "device:" + allowedKey, V1: policy.UserSubject(u.ID)},
	}
	if err := gormDB.Create(&rules).Error; err != nil {
		t.Fatalf("seed casbin_rule: %v", err)
	}

	return allowedKey, revokedKey, dRevoked.ID
}

func aTestConfig(dbURL string) config.Config {
	return config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "concurrent-pepper",
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
}

func aAssertConcurrentStartupOutcome(t *testing.T, checkDB *gorm.DB, apps []*app.App, allowedKey, revokedKey string, revokedDevID uuid.UUID) {
	t.Helper()

	var relayDefaultCount, relayEUCount, roleStandardCount, roleOpsCount int64
	if err := checkDB.Model(&model.Relay{}).Where("name = ?", policy.BuiltinRelay).Count(&relayDefaultCount).Error; err != nil {
		t.Fatalf("count default relay: %v", err)
	}
	if err := checkDB.Model(&model.Relay{}).Where("name = ?", "eu-1").Count(&relayEUCount).Error; err != nil {
		t.Fatalf("count eu-1 relay: %v", err)
	}
	if err := checkDB.Model(&model.Role{}).Where("name = ?", policy.BuiltinRole).Count(&roleStandardCount).Error; err != nil {
		t.Fatalf("count standard role: %v", err)
	}
	if err := checkDB.Model(&model.Role{}).Where("name = ?", "ops").Count(&roleOpsCount).Error; err != nil {
		t.Fatalf("count ops role: %v", err)
	}
	if relayDefaultCount != 1 || relayEUCount != 1 || roleStandardCount != 1 || roleOpsCount != 1 {
		t.Fatalf("registry counts default=%d eu-1=%d standard=%d ops=%d want all 1",
			relayDefaultCount, relayEUCount, roleStandardCount, roleOpsCount)
	}

	var state model.PolicyState
	if err := checkDB.First(&state, "id = ?", model.PolicyStateRowID).Error; err != nil {
		t.Fatalf("read policy_state: %v", err)
	}
	if state.UpgradedAt == nil {
		t.Fatalf("policy_state.upgraded_at is nil, want non-nil")
	}
	if state.Version != 1 {
		t.Fatalf("policy_state.version=%d want=1 (single upgrade bump)", state.Version)
	}

	var revokedDev model.Device
	if err := checkDB.First(&revokedDev, "id = ?", revokedDevID).Error; err != nil {
		t.Fatalf("load revoked device: %v", err)
	}
	if revokedDev.RevokedAt == nil {
		t.Fatalf("expected device without legacy rule to be revoked")
	}

	var audits []model.AdminAuditLog
	if err := checkDB.Order("id asc").Find(&audits).Error; err != nil {
		t.Fatalf("load admin_audit_logs: %v", err)
	}
	if len(audits) != 2 {
		t.Fatalf("admin_audit_logs count=%d want=2 (device.revoke + upgrade.run, upgrade must run once)", len(audits))
	}
	var revokeRows, runRows []model.AdminAuditLog
	for _, a := range audits {
		if a.ActorName != actor.System.Name || a.ActorKeyID != nil {
			t.Fatalf("unexpected non-system audit row: %+v", a)
		}
		switch a.Action {
		case "device.revoke":
			revokeRows = append(revokeRows, a)
		case "upgrade.run":
			runRows = append(runRows, a)
		default:
			t.Fatalf("unexpected system audit action %q", a.Action)
		}
	}
	if len(revokeRows) != 1 || revokeRows[0].TargetID != revokedDevID.String() {
		t.Fatalf("device.revoke rows=%+v want 1 row targeting %s", revokeRows, revokedDevID)
	}
	if len(runRows) != 1 {
		t.Fatalf("upgrade.run rows=%d want=1", len(runRows))
	}

	for i, instance := range apps {
		allow, reason := instance.Service.Verify(context.Background(), policy.BuiltinRelay, aVerifyBody(t, allowedKey))
		if !allow {
			t.Fatalf("instance %d verify allowedKey: allow=false reason=%q want allow=true", i, reason)
		}
		allow, reason = instance.Service.Verify(context.Background(), policy.BuiltinRelay, aVerifyBody(t, revokedKey))
		if allow || reason != service.DenyReasonRevoked {
			t.Fatalf("instance %d verify revokedKey: allow=%v reason=%q want false, %q", i, allow, reason, service.DenyReasonRevoked)
		}
	}
}

func TestConcurrentStartupUpgradesOnce(t *testing.T) {
	t.Run("sqlite_fresh_empty", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "fresh.db")
		dbURL := "sqlite://" + dbPath
		const instances = 4

		conns := make([]*gorm.DB, instances)
		for i := range conns {
			c, err := db.OpenDatabase(dbURL)
			if err != nil {
				t.Fatalf("open sqlite conn %d: %v", i, err)
			}
			conns[i] = c
			t.Cleanup(func() {
				if sqlDB, err := c.DB(); err == nil {
					_ = sqlDB.Close()
				}
			})
		}

		apps := make([]*app.App, instances)
		errs := make([]error, instances)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < instances; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				a, err := app.Build(ctx, conns[idx], aTestConfig(dbURL), zap.NewNop())
				apps[idx] = a
				errs[idx] = err
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

		var state model.PolicyState
		if err := conns[0].First(&state, "id = ?", model.PolicyStateRowID).Error; err != nil {
			t.Fatalf("read policy_state: %v", err)
		}
		if state.UpgradedAt == nil {
			t.Fatalf("expected upgraded_at to be set")
		}
	})

	t.Run("sqlite_upgrade", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "upgrade.db")
		dbURL := "sqlite://" + dbPath

		seedDB, err := db.OpenDatabase(dbURL)
		if err != nil {
			t.Fatalf("open seed db: %v", err)
		}
		t.Cleanup(func() {
			if sqlDB, err := seedDB.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
		allowedKey, revokedKey, revokedDevID := aSeedPreUpgradeData(t, seedDB, dbURL)

		const instances = 4
		conns := make([]*gorm.DB, instances)
		for i := range conns {
			c, err := db.OpenDatabase(dbURL)
			if err != nil {
				t.Fatalf("open conn %d: %v", i, err)
			}
			conns[i] = c
			t.Cleanup(func() {
				if sqlDB, err := c.DB(); err == nil {
					_ = sqlDB.Close()
				}
			})
		}

		apps := make([]*app.App, instances)
		errs := make([]error, instances)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < instances; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				a, err := app.Build(ctx, conns[idx], aTestConfig(dbURL), zap.NewNop())
				apps[idx] = a
				errs[idx] = err
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

		aAssertConcurrentStartupOutcome(t, seedDB, apps, allowedKey, revokedKey, revokedDevID)
	})

	t.Run("postgres", func(t *testing.T) {
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
		dbName := "derp_admit_startup_" + hex.EncodeToString(raw)

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

		seedDB, err := db.OpenDatabase(dbURL)
		if err != nil {
			_ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName)).Error
			t.Fatalf("open seed postgres db: %v", err)
		}
		t.Cleanup(func() {
			if sqlDB, err := seedDB.DB(); err == nil {
				_ = sqlDB.Close()
			}
			_ = adminDB.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ? AND pid <> pg_backend_pid()`, dbName).Error
			_ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName)).Error
			if sqlAdmin, err := adminDB.DB(); err == nil {
				_ = sqlAdmin.Close()
			}
		})

		allowedKey, revokedKey, revokedDevID := aSeedPreUpgradeData(t, seedDB, dbURL)

		const instances = 4
		conns := make([]*gorm.DB, instances)
		for i := range conns {
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

		apps := make([]*app.App, instances)
		errs := make([]error, instances)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < instances; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				a, err := app.Build(ctx, conns[idx], aTestConfig(dbURL), zap.NewNop())
				apps[idx] = a
				errs[idx] = err
			}(i)
		}
		close(start)
		wg.Wait()

		for i, a := range apps {
			if a != nil {
				t.Cleanup(a.Close)
			}
			if errs[i] != nil {
				t.Fatalf("postgres instance %d app.Build failed: %v", i, errs[i])
			}
		}

		aAssertConcurrentStartupOutcome(t, seedDB, apps, allowedKey, revokedKey, revokedDevID)
	})
}

func TestBuildLogsConfigWarnings(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "warnings.db")
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	cfg := aTestConfig(dbURL)
	cfg.Warnings = []string{
		"ENABLE_CASBIN / enable_casbin is deprecated and ignored",
		"second startup config warning",
	}

	core, logs := observer.New(zapcore.WarnLevel)
	application, err := app.Build(context.Background(), gormDB, cfg, zap.New(core))
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	t.Cleanup(application.Close)

	var got []string
	for _, entry := range logs.FilterLevelExact(zapcore.WarnLevel).All() {
		got = append(got, entry.Message)
	}
	for _, want := range cfg.Warnings {
		found := false
		for _, msg := range got {
			if msg == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected warning %q to be logged at warn level; got %v", want, got)
		}
	}
}

func TestBuildFailsOnAmbiguousUpgrade(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "ambiguous.db")
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

	u := model.User{ID: uuid.New(), Username: "ambiguous-user"}
	if err := gormDB.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	nk := aNewNodeKey(t)
	d := model.Device{ID: uuid.New(), UserID: u.ID, NodeKey: nk, Label: "laptop"}
	if err := gormDB.Create(&d).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	// Absent legacy setting on a DB with active devices and zero device rules must fail app.Build.
	cfg := aTestConfig(dbURL)
	if _, err := app.Build(context.Background(), gormDB, cfg, zap.NewNop()); err == nil {
		t.Fatalf("expected app.Build to fail on ambiguous upgrade")
	} else {
		msg := err.Error()
		for _, want := range []string{"1", "0", "ENABLE_CASBIN=false", "ENABLE_CASBIN=true"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("error %q missing expected substring %q", msg, want)
			}
		}
	}

	// Marker must not be set and device must remain unrevoked.
	var state model.PolicyState
	if err := gormDB.First(&state, "id = ?", model.PolicyStateRowID).Error; err != nil {
		t.Fatalf("read policy_state: %v", err)
	}
	if state.UpgradedAt != nil {
		t.Fatalf("expected upgraded_at to stay nil after refused upgrade")
	}
	var reloadedDev model.Device
	if err := gormDB.First(&reloadedDev, "id = ?", d.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if reloadedDev.RevokedAt != nil {
		t.Fatalf("expected device not to be revoked after refused upgrade")
	}

	// Starting once with explicit ENABLE_CASBIN=false succeeds and keeps the device allowed.
	disabled := false
	cfg.LegacyCasbinEnabled = &disabled
	application, err := app.Build(context.Background(), gormDB, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("app.Build with LegacyCasbinEnabled=false failed: %v", err)
	}
	t.Cleanup(application.Close)

	if allow, reason := application.Service.Verify(context.Background(), policy.BuiltinRelay, aVerifyBody(t, nk)); !allow {
		t.Fatalf("verify after explicit false upgrade: allow=false reason=%q want allow=true", reason)
	}
}
