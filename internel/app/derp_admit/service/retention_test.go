package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/model"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
)

// rNow is the fixed "now" every pruner test uses.
var rNow = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func rNewPruner(gormDB *gorm.DB, verifyDays, adminDays int, logger *zap.Logger, rec metrics.Recorder) *AuditPruner {
	p := NewAuditPruner(gormDB, verifyDays, adminDays, 5*time.Second, logger, rec)
	p.now = func() time.Time { return rNow }
	return p
}

// rSeedVerify inserts n verify audit rows with timestamp ts.
func rSeedVerify(t *testing.T, gormDB *gorm.DB, n int, ts time.Time, tag string) {
	t.Helper()
	rows := make([]model.AuditLog, n)
	relay := "default"
	for i := range rows {
		rows[i] = model.AuditLog{NodeKey: fmt.Sprintf("nodekey:%s-%d", tag, i), Relay: &relay, Reason: tag, TS: ts.UTC()}
	}
	if err := gormDB.CreateInBatches(rows, 500).Error; err != nil {
		t.Fatalf("seed verify audit: %v", err)
	}
}

// rSeedAdmin inserts n admin audit rows with timestamp ts.
func rSeedAdmin(t *testing.T, gormDB *gorm.DB, n int, ts time.Time, tag string) {
	t.Helper()
	rows := make([]model.AdminAuditLog, n)
	for i := range rows {
		rows[i] = model.AdminAuditLog{TS: ts.UTC(), ActorName: "seed", Action: "seed." + tag, Outcome: AuditOutcomeSuccess, TargetID: fmt.Sprint(i)}
	}
	if err := gormDB.CreateInBatches(rows, 500).Error; err != nil {
		t.Fatalf("seed admin audit: %v", err)
	}
}

func rCount(t *testing.T, gormDB *gorm.DB, m any, where string, args ...any) int64 {
	t.Helper()
	var n int64
	q := gormDB.Model(m)
	if where != "" {
		q = q.Where(where, args...)
	}
	if err := q.Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// rCountDeletes registers a callback that counts DELETE statements against
// table issued through gormDB.
func rCountDeletes(t *testing.T, gormDB *gorm.DB, table string) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	name := "test:count_deletes_" + table
	if err := gormDB.Callback().Raw().After("gorm:raw").Register(name, func(tx *gorm.DB) {
		if strings.HasPrefix(tx.Statement.SQL.String(), "DELETE FROM "+table+" ") {
			n.Add(1)
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	return &n
}

func rScrape(t *testing.T, rec metrics.Recorder) string {
	t.Helper()
	rr := httptest.NewRecorder()
	rec.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rr.Body.String()
}

func TestPruneDeletesOnlyRowsOlderThanCutoff(t *testing.T) {
	gormDB := cOpenTestDB(t, "prune_cutoff.db")
	cutoff := rNow.AddDate(0, 0, -30)

	rSeedVerify(t, gormDB, 5, cutoff.Add(-31*24*time.Hour), "very-old")
	rSeedVerify(t, gormDB, 5, cutoff.Add(-time.Second), "just-old")
	rSeedVerify(t, gormDB, 4, cutoff, "at-cutoff") // not older than the cutoff: kept
	rSeedVerify(t, gormDB, 3, cutoff.Add(time.Millisecond), "just-new")
	rSeedVerify(t, gormDB, 2, rNow, "now")
	rSeedAdmin(t, gormDB, 3, cutoff.Add(-24*time.Hour), "admin-old")
	rSeedAdmin(t, gormDB, 2, rNow, "admin-new")

	p := rNewPruner(gormDB, 30, 90, nil, nil)
	deleted, err := p.PruneOnce(context.Background())
	if err != nil {
		t.Fatalf("PruneOnce: %v", err)
	}
	if deleted[metrics.AuditTableVerify] != 10 {
		t.Fatalf("verify deleted=%d want=10", deleted[metrics.AuditTableVerify])
	}
	if got := rCount(t, gormDB, &model.AuditLog{}, ""); got != 9 {
		t.Fatalf("verify rows left=%d want=9", got)
	}
	if got := rCount(t, gormDB, &model.AuditLog{}, "ts < ?", cutoff); got != 0 {
		t.Fatalf("verify rows older than cutoff left=%d want=0", got)
	}
	for tag, want := range map[string]int64{"at-cutoff": 4, "just-new": 3, "now": 2} {
		if got := rCount(t, gormDB, &model.AuditLog{}, "reason = ?", tag); got != want {
			t.Fatalf("rows %s left=%d want=%d", tag, got, want)
		}
	}
	// 90-day admin retention: the 31-day-old admin rows are newer than its cutoff.
	if got := rCount(t, gormDB, &model.AdminAuditLog{}, ""); got != 5 {
		t.Fatalf("admin rows=%d want=5", got)
	}
	// A second pass finds nothing.
	deleted, err = p.PruneOnce(context.Background())
	if err != nil || deleted[metrics.AuditTableVerify] != 0 {
		t.Fatalf("second pass deleted=%v err=%v want nothing", deleted, err)
	}
}

func TestPruneUsesMultipleBatches(t *testing.T) {
	t.Run("default batch size with more than 1000 old rows", func(t *testing.T) {
		gormDB := cOpenTestDB(t, "prune_batches_default.db")
		rSeedVerify(t, gormDB, 2345, rNow.AddDate(0, 0, -40), "old")
		rSeedVerify(t, gormDB, 10, rNow.AddDate(0, 0, -1), "new")
		deletes := rCountDeletes(t, gormDB, "audit_logs")

		p := rNewPruner(gormDB, 30, 0, nil, nil)
		if p.batchSize != 1000 {
			t.Fatalf("default batch size=%d want=1000", p.batchSize)
		}
		deleted, err := p.PruneOnce(context.Background())
		if err != nil {
			t.Fatalf("PruneOnce: %v", err)
		}
		if deleted[metrics.AuditTableVerify] != 2345 {
			t.Fatalf("deleted=%d want=2345", deleted[metrics.AuditTableVerify])
		}
		// 1000 + 1000 + 345 + one empty statement that ends the loop.
		if got := deletes.Load(); got != 4 {
			t.Fatalf("DELETE statements=%d want=4", got)
		}
		if got := rCount(t, gormDB, &model.AuditLog{}, ""); got != 10 {
			t.Fatalf("rows left=%d want=10", got)
		}
	})

	t.Run("injected small batch size", func(t *testing.T) {
		gormDB := cOpenTestDB(t, "prune_batches_small.db")
		rSeedAdmin(t, gormDB, 23, rNow.AddDate(0, 0, -400), "old")
		rSeedAdmin(t, gormDB, 4, rNow, "new")
		deletes := rCountDeletes(t, gormDB, "admin_audit_logs")

		p := rNewPruner(gormDB, 0, 365, nil, nil)
		p.batchSize = 5
		deleted, err := p.PruneOnce(context.Background())
		if err != nil {
			t.Fatalf("PruneOnce: %v", err)
		}
		if deleted[metrics.AuditTableAdmin] != 23 {
			t.Fatalf("deleted=%d want=23", deleted[metrics.AuditTableAdmin])
		}
		if got := deletes.Load(); got != 6 { // 5,5,5,5,3,0
			t.Fatalf("DELETE statements=%d want=6", got)
		}
		if got := rCount(t, gormDB, &model.AdminAuditLog{}, ""); got != 4 {
			t.Fatalf("rows left=%d want=4", got)
		}
	})
}

func TestPruneLeavesOtherTableAlone(t *testing.T) {
	gormDB := cOpenTestDB(t, "prune_other_table.db")
	old := rNow.AddDate(-3, 0, 0)
	rSeedVerify(t, gormDB, 7, old, "old")
	rSeedAdmin(t, gormDB, 6, old, "old")

	// Only verify retention set: admin rows untouched.
	p := rNewPruner(gormDB, 1, 0, nil, nil)
	if _, err := p.PruneOnce(context.Background()); err != nil {
		t.Fatalf("PruneOnce: %v", err)
	}
	if got := rCount(t, gormDB, &model.AuditLog{}, ""); got != 0 {
		t.Fatalf("verify rows=%d want=0", got)
	}
	if got := rCount(t, gormDB, &model.AdminAuditLog{}, ""); got != 6 {
		t.Fatalf("admin rows=%d want=6 (admin retention is 0)", got)
	}

	// Only admin retention set: new verify rows untouched.
	rSeedVerify(t, gormDB, 5, old, "old-again")
	p = rNewPruner(gormDB, 0, 1, nil, nil)
	if _, err := p.PruneOnce(context.Background()); err != nil {
		t.Fatalf("PruneOnce: %v", err)
	}
	if got := rCount(t, gormDB, &model.AdminAuditLog{}, ""); got != 0 {
		t.Fatalf("admin rows=%d want=0", got)
	}
	if got := rCount(t, gormDB, &model.AuditLog{}, ""); got != 5 {
		t.Fatalf("verify rows=%d want=5 (verify retention is 0)", got)
	}
}

func TestPruneRetentionZeroDeletesNothing(t *testing.T) {
	gormDB := cOpenTestDB(t, "prune_zero.db")
	ancient := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	rSeedVerify(t, gormDB, 3, ancient, "ancient")
	rSeedAdmin(t, gormDB, 3, ancient, "ancient")
	verifyDeletes := rCountDeletes(t, gormDB, "audit_logs")
	adminDeletes := rCountDeletes(t, gormDB, "admin_audit_logs")

	p := rNewPruner(gormDB, 0, 0, nil, nil)
	if p.Enabled() {
		t.Fatalf("pruner with both retentions 0 must be disabled")
	}
	p.firstDelay, p.interval = time.Millisecond, time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	deleted, err := p.PruneOnce(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	p.Wait()
	if err != nil || len(deleted) != 0 {
		t.Fatalf("PruneOnce deleted=%v err=%v want nothing", deleted, err)
	}
	if verifyDeletes.Load() != 0 || adminDeletes.Load() != 0 {
		t.Fatalf("statements issued: verify=%d admin=%d want 0", verifyDeletes.Load(), adminDeletes.Load())
	}
	if rCount(t, gormDB, &model.AuditLog{}, "") != 3 || rCount(t, gormDB, &model.AdminAuditLog{}, "") != 3 {
		t.Fatalf("rows deleted with retention 0")
	}
}

func TestPruneConcurrentPrunersAreHarmless(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "prune_concurrent.db")
	first, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), first, dbURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// A second connection pool stands in for a second replica.
	second, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open second db: %v", err)
	}
	t.Cleanup(func() {
		for _, g := range []*gorm.DB{first, second} {
			if sqlDB, err := g.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}
	})

	const oldVerify, oldAdmin, keep = 3000, 1200, 150
	rSeedVerify(t, first, oldVerify, rNow.AddDate(0, 0, -10), "old")
	rSeedVerify(t, first, keep, rNow.AddDate(0, 0, -6), "new")
	rSeedAdmin(t, first, oldAdmin, rNow.AddDate(0, 0, -10), "old")
	rSeedAdmin(t, first, keep, rNow.AddDate(0, 0, -6), "new")

	pruners := []*AuditPruner{
		rNewPruner(first, 7, 7, nil, nil),
		rNewPruner(second, 7, 7, nil, nil),
	}
	for _, p := range pruners {
		p.batchSize = 100
	}

	type result struct {
		deleted map[string]int64
		err     error
	}
	results := make([]result, len(pruners))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, p := range pruners {
		wg.Add(1)
		go func(i int, p *AuditPruner) {
			defer wg.Done()
			<-start
			d, err := p.PruneOnce(context.Background())
			results[i] = result{d, err}
		}(i, p)
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("concurrent pruners did not finish (deadlock?)")
	}

	var sumVerify, sumAdmin int64
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("pruner %d: %v", i, r.err)
		}
		sumVerify += r.deleted[metrics.AuditTableVerify]
		sumAdmin += r.deleted[metrics.AuditTableAdmin]
	}
	if sumVerify != oldVerify || sumAdmin != oldAdmin {
		t.Fatalf("deleted verify=%d admin=%d want %d/%d (each old row exactly once)", sumVerify, sumAdmin, oldVerify, oldAdmin)
	}
	if got := rCount(t, first, &model.AuditLog{}, ""); got != keep {
		t.Fatalf("verify rows left=%d want=%d", got, keep)
	}
	if got := rCount(t, first, &model.AdminAuditLog{}, ""); got != keep {
		t.Fatalf("admin rows left=%d want=%d", got, keep)
	}
}

func TestPruneCountsMetricsAndLogs(t *testing.T) {
	gormDB := cOpenTestDB(t, "prune_metrics.db")
	rSeedVerify(t, gormDB, 1500, rNow.AddDate(0, 0, -31), "old")
	rSeedAdmin(t, gormDB, 3, rNow.AddDate(0, 0, -91), "old")
	rSeedAdmin(t, gormDB, 2, rNow.AddDate(0, 0, -89), "new")

	core, logs := observer.New(zapcore.InfoLevel)
	rec := metrics.NewPrometheus()
	p := rNewPruner(gormDB, 30, 90, zap.New(core), rec)
	if _, err := p.PruneOnce(context.Background()); err != nil {
		t.Fatalf("PruneOnce: %v", err)
	}
	out := rScrape(t, rec)
	for _, want := range []string{
		`derp_admit_audit_pruned_total{table="verify"} 1500`,
		`derp_admit_audit_pruned_total{table="admin"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("scrape missing %q:\n%s", want, out)
		}
	}

	entries := logs.FilterMessage("audit retention pruned rows").AllUntimed()
	if len(entries) != 2 {
		t.Fatalf("info lines=%d want=2 (one per table with deletions): %+v", len(entries), entries)
	}
	got := map[string]int64{}
	for _, e := range entries {
		if e.Level != zapcore.InfoLevel {
			t.Fatalf("level=%s want info", e.Level)
		}
		f := e.ContextMap()
		if _, ok := f["cutoff"]; !ok {
			t.Fatalf("log line has no cutoff: %v", f)
		}
		got[f["table"].(string)] = f["deleted"].(int64)
	}
	if got[metrics.AuditTableVerify] != 1500 || got[metrics.AuditTableAdmin] != 3 {
		t.Fatalf("logged counts=%v", got)
	}

	// A pass that deletes nothing logs nothing and leaves the counters alone.
	if _, err := p.PruneOnce(context.Background()); err != nil {
		t.Fatalf("second PruneOnce: %v", err)
	}
	if n := logs.FilterMessage("audit retention pruned rows").Len(); n != 2 {
		t.Fatalf("info lines after empty pass=%d want=2", n)
	}
	if out := rScrape(t, rec); !strings.Contains(out, `derp_admit_audit_pruned_total{table="verify"} 1500`) {
		t.Fatalf("counter changed on empty pass:\n%s", out)
	}
}

func TestPruneDoesNotTouchPolicyOrAdminAudit(t *testing.T) {
	gormDB := cOpenTestDB(t, "prune_policy.db")
	readVersion := func() int64 {
		var st model.PolicyState
		if err := gormDB.First(&st, "id = ?", model.PolicyStateRowID).Error; err != nil {
			t.Fatalf("read policy_state: %v", err)
		}
		return st.Version
	}
	before := readVersion()
	rSeedVerify(t, gormDB, 20, rNow.AddDate(0, 0, -100), "old")
	rSeedAdmin(t, gormDB, 20, rNow.AddDate(0, 0, -100), "old")
	rSeedAdmin(t, gormDB, 3, rNow, "new")
	var maxIDBefore int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Select("MAX(id)").Scan(&maxIDBefore).Error; err != nil {
		t.Fatalf("max id: %v", err)
	}

	p := rNewPruner(gormDB, 30, 30, nil, nil)
	if _, err := p.PruneOnce(context.Background()); err != nil {
		t.Fatalf("PruneOnce: %v", err)
	}
	if after := readVersion(); after != before {
		t.Fatalf("policy_state.version changed %d -> %d", before, after)
	}
	if n := rCount(t, gormDB, &model.AdminAuditLog{}, "id > ?", maxIDBefore); n != 0 {
		t.Fatalf("pruning wrote %d admin audit rows", n)
	}
	if n := rCount(t, gormDB, &model.AdminAuditLog{}, ""); n != 3 {
		t.Fatalf("admin rows=%d want=3", n)
	}
}

func TestPruneFailureIsLoggedAndRetried(t *testing.T) {
	gormDB := cOpenTestDB(t, "prune_failure.db")
	rSeedVerify(t, gormDB, 12, rNow.AddDate(0, 0, -40), "old")

	// Fail the first two DELETE statements, then let them through.
	var failures atomic.Int64
	if err := gormDB.Callback().Raw().Before("gorm:raw").Register("test:fail_prune", func(tx *gorm.DB) {
		if strings.HasPrefix(tx.Statement.SQL.String(), "DELETE FROM audit_logs ") && failures.Add(1) <= 2 {
			_ = tx.AddError(errors.New("injected prune failure"))
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}

	core, logs := observer.New(zapcore.InfoLevel)
	p := rNewPruner(gormDB, 30, 0, zap.New(core), nil)
	p.firstDelay = time.Millisecond
	p.interval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	deadline := time.Now().Add(20 * time.Second)
	for rCount(t, gormDB, &model.AuditLog{}, "") != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("rows never pruned after injected failures")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	p.Wait()

	errLines := logs.FilterMessage("audit retention prune failed").AllUntimed()
	if len(errLines) < 2 {
		t.Fatalf("error lines=%d want >= 2", len(errLines))
	}
	for _, e := range errLines {
		if e.Level != zapcore.ErrorLevel {
			t.Fatalf("failure logged at %s want error", e.Level)
		}
	}
	if logs.FilterMessage("audit retention pruned rows").Len() < 1 {
		t.Fatalf("no info line for the successful retry")
	}
}

func TestPrunerStopsOnShutdown(t *testing.T) {
	gormDB := cOpenTestDB(t, "prune_shutdown.db")
	deletes := rCountDeletes(t, gormDB, "audit_logs")

	p := rNewPruner(gormDB, 30, 0, nil, nil)
	p.firstDelay = time.Millisecond
	p.interval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)

	// Let it run a few passes.
	deadline := time.Now().Add(20 * time.Second)
	for deletes.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("pruner never ran")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	stopped := make(chan struct{})
	go func() { p.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(20 * time.Second):
		t.Fatalf("pruner did not stop after cancel")
	}

	// After shutdown nothing runs: old rows stay and no statement is issued.
	issued := deletes.Load()
	rSeedVerify(t, gormDB, 5, rNow.AddDate(0, 0, -40), "after-stop")
	time.Sleep(200 * time.Millisecond)
	if got := deletes.Load(); got != issued {
		t.Fatalf("statements after shutdown: %d -> %d", issued, got)
	}
	if got := rCount(t, gormDB, &model.AuditLog{}, ""); got != 5 {
		t.Fatalf("rows=%d want=5 after shutdown", got)
	}
	// Start after the context is done does not restart it.
	p.Start(ctx)
	p.Wait()
}

func TestPruneCutoffClampsHugeRetention(t *testing.T) {
	c := retentionCutoff(rNow, 1<<40)
	if !c.Before(rNow) || c.Year() < 1700 {
		t.Fatalf("cutoff=%s for huge retention, want a sane date in the past", c)
	}
}

// TestPruneStatementPlanUsesTSIndex pins the SQLite plan of the prune
// statement: the inner select must search the ts index (not scan the table in
// rowid order) and the outer delete must go by primary key, for both tables.
func TestPruneStatementPlanUsesTSIndex(t *testing.T) {
	gormDB := cOpenTestDB(t, "prune_plan.db")
	if name := gormDB.Dialector.Name(); name != "sqlite" {
		t.Fatalf("dialect=%q want sqlite", name)
	}
	for table, index := range map[string]string{
		"audit_logs":       "idx_audit_logs_ts",
		"admin_audit_logs": "idx_admin_audit_logs_ts_id",
	} {
		stmt := pruneStatement(gormDB.Dialector.Name(), table)
		type planRow struct {
			ID      int
			Parent  int
			Notused int
			Detail  string
		}
		var rows []planRow
		if err := gormDB.Raw("EXPLAIN QUERY PLAN "+stmt, rNow, 1000).Scan(&rows).Error; err != nil {
			t.Fatalf("explain %s: %v", table, err)
		}
		var details []string
		for _, r := range rows {
			details = append(details, r.Detail)
		}
		plan := strings.Join(details, "\n")
		t.Logf("%s plan:\n%s", table, plan)
		if !strings.Contains(plan, "USING COVERING INDEX "+index+" (ts<?)") && !strings.Contains(plan, "USING INDEX "+index+" (ts<?)") {
			t.Fatalf("%s: inner select does not search %s:\n%s", table, index, plan)
		}
		if !strings.Contains(plan, "SEARCH "+table+" USING INTEGER PRIMARY KEY (rowid=?)") {
			t.Fatalf("%s: outer delete does not go by primary key:\n%s", table, plan)
		}
		for _, d := range details {
			if strings.HasPrefix(d, "SCAN "+table) {
				t.Fatalf("%s: plan scans the table:\n%s", table, plan)
			}
		}
	}
}
