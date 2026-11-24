package app_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/model"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
)

func rOpenDB(t *testing.T, name string) (*gorm.DB, string) {
	t.Helper()
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), name)
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return gormDB, dbURL
}

func rBuild(t *testing.T, gormDB *gorm.DB, cfg config.Config, logger *zap.Logger, opts ...app.Option) *app.App {
	t.Helper()
	if logger == nil {
		logger = zap.NewNop()
	}
	application, err := app.Build(context.Background(), gormDB, cfg, logger, opts...)
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	return application
}

func rCountVerify(t *testing.T, gormDB *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := gormDB.Model(&model.AuditLog{}).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestBuildLogsAllowlistState checks that both allowlists are always stated at
// startup at info level: the entry count when set, an "any peer" line when
// unset (the metrics line only when metrics are enabled).
func TestBuildLogsAllowlistState(t *testing.T) {
	const (
		verifySet     = "verify caller allowlist set"
		verifyUnset   = "verify caller allowlist not set: any peer may call /verify"
		metricsSet    = "metrics caller allowlist set"
		metricsUnset  = "metrics caller allowlist not set: any peer may read /metrics"
		allowlistWord = "allowlist"
	)
	cases := []struct {
		name           string
		verify, metric []netip.Prefix
		metricsEnabled bool
		want           map[string]int64 // message -> entries (-1: no entries field)
	}{
		{"both unset", nil, nil, true, map[string]int64{verifyUnset: -1, metricsUnset: -1}},
		{"both set", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.7/32")},
			[]netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}, true, map[string]int64{verifySet: 2, metricsSet: 1}},
		{"verify set, metrics unset", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil, true,
			map[string]int64{verifySet: 1, metricsUnset: -1}},
		{"verify unset, metrics set", nil, []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}, true,
			map[string]int64{verifyUnset: -1, metricsSet: 1}},
		{"metrics disabled", nil, nil, false, map[string]int64{verifyUnset: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gormDB, dbURL := rOpenDB(t, "allowlist_log.db")
			cfg := aTestConfig(dbURL)
			cfg.VerifyAllowedCIDRs = tc.verify
			cfg.MetricsAllowedCIDRs = tc.metric
			cfg.MetricsEnabled = tc.metricsEnabled
			core, logs := observer.New(zapcore.DebugLevel)
			application := rBuild(t, gormDB, cfg, zap.New(core))
			defer application.Close()

			var got []observer.LoggedEntry
			for _, e := range logs.AllUntimed() {
				if strings.Contains(e.Message, allowlistWord) {
					got = append(got, e)
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("allowlist lines=%v want exactly %v", got, tc.want)
			}
			for _, e := range got {
				entries, ok := tc.want[e.Message]
				if !ok {
					t.Fatalf("unexpected allowlist line %q", e.Message)
				}
				if e.Level != zapcore.InfoLevel {
					t.Fatalf("%q logged at %s want info", e.Message, e.Level)
				}
				field, has := e.ContextMap()["entries"]
				if entries < 0 && has {
					t.Fatalf("%q has an entries field", e.Message)
				}
				if entries >= 0 && field != entries {
					t.Fatalf("%q entries=%v want %d", e.Message, field, entries)
				}
			}
		})
	}
}

// TestBuildSchedulesAuditPruning proves app.Build starts the pruner on its
// own: old rows disappear without the test calling PruneOnce.
func TestBuildSchedulesAuditPruning(t *testing.T) {
	gormDB, dbURL := rOpenDB(t, "pruner_sched.db")
	cfg := aTestConfig(dbURL)
	cfg.VerifyAuditRetentionDays = 30
	cfg.AdminAuditRetentionDays = 365

	core, logs := observer.New(zapcore.InfoLevel)
	application := rBuild(t, gormDB, cfg, zap.New(core), app.WithPruneScheduleForTest(10*time.Millisecond, 20*time.Millisecond))
	defer application.Close()
	if n := logs.FilterMessage("audit retention enabled").Len(); n != 1 {
		t.Fatalf("audit retention info lines=%d want=1", n)
	}

	fresh := model.AuditLog{NodeKey: "nodekey:fresh", TS: time.Now().UTC()}
	if err := gormDB.Create(&fresh).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Seed old rows repeatedly over several ticks so the check does not depend
	// on whether the first pass ran before or after the insert.
	deadline := time.Now().Add(30 * time.Second)
	for {
		old := model.AuditLog{NodeKey: "nodekey:old", TS: time.Now().UTC().AddDate(0, 0, -31)}
		if err := gormDB.Create(&old).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
		waitUntil := time.Now().Add(5 * time.Second)
		for time.Now().Before(waitUntil) {
			var n int64
			gormDB.Model(&model.AuditLog{}).Where("id = ?", old.ID).Count(&n)
			if n == 0 {
				var left []model.AuditLog
				if err := gormDB.Find(&left).Error; err != nil {
					t.Fatalf("read rows: %v", err)
				}
				if len(left) != 1 || left[0].ID != fresh.ID {
					t.Fatalf("rows left=%+v want only the fresh row", left)
				}
				if logs.FilterMessage("audit retention pruned rows").Len() == 0 {
					t.Fatalf("scheduled pass deleted rows without an info line")
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		if time.Now().After(deadline) {
			t.Fatalf("old verify rows were never pruned by the scheduled pruner")
		}
	}
}

// TestCloseWaitsForPruneInFlight proves App.Close does not return while a
// prune statement is running: the statement is held open by a callback and
// Close must stay blocked until it is released.
func TestCloseWaitsForPruneInFlight(t *testing.T) {
	gormDB, dbURL := rOpenDB(t, "pruner_close.db")
	cfg := aTestConfig(dbURL)
	cfg.VerifyAuditRetentionDays = 30

	entered := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	var finished atomic.Bool
	if err := gormDB.Callback().Raw().Before("gorm:raw").Register("test:hold_prune", func(tx *gorm.DB) {
		if strings.HasPrefix(tx.Statement.SQL.String(), "DELETE FROM audit_logs ") && once.CompareAndSwap(false, true) {
			close(entered)
			<-release
			finished.Store(true)
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}

	application := rBuild(t, gormDB, cfg, nil, app.WithPruneScheduleForTest(5*time.Millisecond, time.Hour))
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		close(release)
		application.Close()
		t.Fatalf("no prune pass started: app.Build did not schedule the pruner")
	}

	closed := make(chan struct{})
	go func() { application.Close(); close(closed) }()
	select {
	case <-closed:
		close(release)
		t.Fatalf("App.Close returned while a prune statement was still in flight")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(30 * time.Second):
		t.Fatalf("App.Close did not return after the prune statement finished")
	}
	if !finished.Load() {
		t.Fatalf("Close returned before the in-flight statement finished")
	}
}

func TestBuildStartsAndStopsAuditPruner(t *testing.T) {
	t.Run("retention set", func(t *testing.T) {
		gormDB, dbURL := rOpenDB(t, "pruner.db")
		cfg := aTestConfig(dbURL)
		cfg.VerifyAuditRetentionDays = 30
		cfg.AdminAuditRetentionDays = 365
		application := rBuild(t, gormDB, cfg, nil)
		if !application.AuditPruner.Enabled() {
			t.Fatalf("pruner must be enabled when a retention is set")
		}

		old := model.AuditLog{NodeKey: "nodekey:old", TS: time.Now().UTC().AddDate(0, 0, -31)}
		fresh := model.AuditLog{NodeKey: "nodekey:fresh", TS: time.Now().UTC()}
		if err := gormDB.Create(&old).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := gormDB.Create(&fresh).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
		deleted, err := application.AuditPruner.PruneOnce(context.Background())
		if err != nil || deleted[metrics.AuditTableVerify] != 1 {
			t.Fatalf("PruneOnce deleted=%v err=%v want 1 verify row", deleted, err)
		}
		var left []model.AuditLog
		if err := gormDB.Find(&left).Error; err != nil {
			t.Fatalf("read verify rows: %v", err)
		}
		if len(left) != 1 || left[0].ID != fresh.ID {
			t.Fatalf("verify rows left=%+v want only the fresh row %d", left, fresh.ID)
		}

		closed := make(chan struct{})
		go func() { application.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(20 * time.Second):
			t.Fatalf("App.Close did not return: pruner did not stop")
		}
	})

	t.Run("retention unset", func(t *testing.T) {
		gormDB, dbURL := rOpenDB(t, "nopruner.db")
		core, logs := observer.New(zapcore.InfoLevel)
		application := rBuild(t, gormDB, aTestConfig(dbURL), zap.New(core), app.WithPruneScheduleForTest(time.Millisecond, time.Millisecond))
		defer application.Close()
		if application.AuditPruner.Enabled() {
			t.Fatalf("pruner must be disabled when no retention is set")
		}
		if n := logs.FilterMessage("audit retention enabled").Len(); n != 0 {
			t.Fatalf("audit retention logged with the settings unset")
		}
		old := model.AuditLog{NodeKey: "nodekey:old", TS: time.Now().UTC().AddDate(-5, 0, 0)}
		if err := gormDB.Create(&old).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		if n := rCountVerify(t, gormDB); n != 1 {
			t.Fatalf("rows=%d want=1: nothing may be pruned with retention unset", n)
		}
		if n := logs.FilterLevelExact(zapcore.WarnLevel).FilterMessageSnippet("allowlist").Len(); n != 0 {
			t.Fatalf("unrestricted /verify must not warn")
		}
	})
}
