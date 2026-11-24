package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/service"
)

func rpRetentionOpt(verifyDays, adminDays int) func(*config.Config) {
	return func(c *config.Config) {
		c.VerifyAuditRetentionDays = verifyDays
		c.AdminAuditRetentionDays = adminDays
	}
}

func rpSeed(t *testing.T, application *app.App, n int, ts time.Time, tag string) {
	t.Helper()
	relay := "default"
	status := http.StatusOK
	for i := 0; i < n; i++ {
		v := model.AuditLog{NodeKey: fmt.Sprintf("nodekey:%s-%03d", tag, i), Relay: &relay, Reason: tag, TS: ts.Add(time.Duration(i) * time.Second).UTC()}
		if err := application.DB.Create(&v).Error; err != nil {
			t.Fatalf("seed verify audit: %v", err)
		}
		a := model.AdminAuditLog{
			TS: ts.Add(time.Duration(i) * time.Second).UTC(), ActorName: "seed", ActorTier: model.AdminTierAdmin,
			Action: "seed." + tag, TargetType: "user", TargetID: fmt.Sprint(i),
			Outcome: service.AuditOutcomeSuccess, HTTPStatus: &status, Summary: "{}",
		}
		if err := application.DB.Create(&a).Error; err != nil {
			t.Fatalf("seed admin audit: %v", err)
		}
	}
}

func rpPage(t *testing.T, application *app.App, path string, limit int, cursor string) ([]int64, string) {
	t.Helper()
	q := fmt.Sprintf("%s?limit=%d", path, limit)
	if cursor != "" {
		q += "&cursor=" + url.QueryEscape(cursor)
	}
	status, body := doAdminRequest(t, application.Router, http.MethodGet, q, testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("GET %s status=%d want=200 body=%v", q, status, body)
	}
	ids := eExtractInt64IDs(t, body)
	next, _ := body["nextCursor"].(string)
	if body["nextCursor"] != nil && next == "" {
		t.Fatalf("nextCursor has unexpected type: %#v", body["nextCursor"])
	}
	return ids, next
}

func rpCountOlder(t *testing.T, application *app.App, m any, cutoff time.Time) int64 {
	t.Helper()
	var n int64
	if err := application.DB.Model(m).Where("ts < ?", cutoff.UTC()).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// rpAssertPaginationSurvivesPrune walks both audit lists across a prune that
// removes rows from later pages, including the row a cursor points at.
func rpAssertPaginationSurvivesPrune(t *testing.T, newApp func(t *testing.T) *app.App) {
	endpoints := []struct {
		name, path string
		model      any
	}{
		{"verify", "/admin/audit/verify", &model.AuditLog{}},
		{"admin", "/admin/audit/admin", &model.AdminAuditLog{}},
	}

	now := time.Now().UTC()
	for _, ep := range endpoints {
		t.Run(ep.name+"/later pages pruned", func(t *testing.T) {
			application := newApp(t)
			rpSeed(t, application, 10, now.AddDate(0, 0, -60), "old")
			rpSeed(t, application, 20, now.AddDate(0, 0, -2), "new")

			page1, cursor := rpPage(t, application, ep.path, 12, "")
			if len(page1) != 12 || cursor == "" {
				t.Fatalf("page1 len=%d cursor=%q want 12 rows and a cursor", len(page1), cursor)
			}

			if _, err := application.AuditPruner.PruneOnce(context.Background()); err != nil {
				t.Fatalf("PruneOnce: %v", err)
			}
			if n := rpCountOlder(t, application, ep.model, now.AddDate(0, 0, -30)); n != 0 {
				t.Fatalf("old rows left after prune: %d", n)
			}

			var rest []int64
			for cursor != "" {
				var ids []int64
				ids, cursor = rpPage(t, application, ep.path, 12, cursor)
				rest = append(rest, ids...)
			}
			seen := map[int64]bool{}
			for _, id := range page1 {
				seen[id] = true
			}
			for _, id := range rest {
				if seen[id] {
					t.Fatalf("row %d repeated after prune", id)
				}
				seen[id] = true
			}
			// Everything still in the table appears exactly once across the walk.
			var total int64
			if err := application.DB.Model(ep.model).Count(&total).Error; err != nil {
				t.Fatalf("count: %v", err)
			}
			if int64(len(seen)) != total {
				t.Fatalf("walked %d distinct rows, table has %d", len(seen), total)
			}
			for i := 1; i < len(rest); i++ {
				if rest[i] >= rest[i-1] && ep.name == "verify" {
					t.Fatalf("verify ids not newest first after prune: %v", rest)
				}
			}
		})

		t.Run(ep.name+"/cursor row pruned", func(t *testing.T) {
			application := newApp(t)
			rpSeed(t, application, 10, now.AddDate(0, 0, -60), "old")
			rpSeed(t, application, 5, now.AddDate(0, 0, -2), "new")

			// The admin list also holds the fresh startup bootstrap row.
			var fresh int64
			if err := application.DB.Model(ep.model).Where("ts >= ?", now.AddDate(0, 0, -30)).Count(&fresh).Error; err != nil {
				t.Fatalf("count: %v", err)
			}
			limit := int(fresh) + 2 // page 1 ends on an old row
			page1, cursor := rpPage(t, application, ep.path, limit, "")
			if len(page1) != limit || cursor == "" {
				t.Fatalf("page1 len=%d cursor=%q", len(page1), cursor)
			}

			if _, err := application.AuditPruner.PruneOnce(context.Background()); err != nil {
				t.Fatalf("PruneOnce: %v", err)
			}
			var cursorRowLeft int64
			if err := application.DB.Model(ep.model).Where("id = ?", page1[len(page1)-1]).Count(&cursorRowLeft).Error; err != nil {
				t.Fatalf("count: %v", err)
			}
			if cursorRowLeft != 0 {
				t.Fatalf("test setup: the cursor row was not pruned")
			}

			page2, next := rpPage(t, application, ep.path, limit, cursor)
			if len(page2) != 0 || next != "" {
				t.Fatalf("page2=%v next=%q want empty page and null cursor", page2, next)
			}
		})
	}
}

func TestAuditPaginationSurvivesPrune(t *testing.T) {
	rpAssertPaginationSurvivesPrune(t, func(t *testing.T) *app.App {
		dbURL := "sqlite://" + filepath.Join(t.TempDir(), "prune_pages.db")
		return bBuildAppOnDB(t, dbURL, rpRetentionOpt(30, 30))
	})
}

func TestPostgresAuditPaginationSurvivesPrune(t *testing.T) {
	rpAssertPaginationSurvivesPrune(t, func(t *testing.T) *app.App {
		return bBuildAppOnDB(t, createFreshPostgresDB(t, "derp_admit_prune_"), rpRetentionOpt(30, 30))
	})
}

func TestPostgresConcurrentAuditPrune(t *testing.T) {
	dbURL := createFreshPostgresDB(t, "derp_admit_prune_cc_")
	appA := bBuildAppOnDB(t, dbURL, rpRetentionOpt(7, 7))
	appB := bBuildAppOnDB(t, dbURL, rpRetentionOpt(7, 7))

	now := time.Now().UTC()
	const oldVerify, oldAdmin, keep = 3500, 2100, 40
	relay := "default"
	verifyRows := make([]model.AuditLog, 0, oldVerify+keep)
	for i := 0; i < oldVerify; i++ {
		verifyRows = append(verifyRows, model.AuditLog{NodeKey: fmt.Sprintf("nodekey:old-%d", i), Relay: &relay, TS: now.AddDate(0, 0, -10)})
	}
	for i := 0; i < keep; i++ {
		verifyRows = append(verifyRows, model.AuditLog{NodeKey: fmt.Sprintf("nodekey:new-%d", i), Relay: &relay, TS: now.AddDate(0, 0, -6)})
	}
	if err := appA.DB.CreateInBatches(verifyRows, 500).Error; err != nil {
		t.Fatalf("seed verify: %v", err)
	}
	var adminBefore int64
	appA.DB.Model(&model.AdminAuditLog{}).Count(&adminBefore)
	adminRows := make([]model.AdminAuditLog, 0, oldAdmin)
	for i := 0; i < oldAdmin; i++ {
		adminRows = append(adminRows, model.AdminAuditLog{TS: now.AddDate(0, 0, -10), ActorName: "seed", Action: "seed.old", Outcome: service.AuditOutcomeSuccess})
	}
	if err := appA.DB.CreateInBatches(adminRows, 500).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	type result struct {
		deleted map[string]int64
		err     error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, a := range []*app.App{appA, appB} {
		wg.Add(1)
		go func(i int, a *app.App) {
			defer wg.Done()
			<-start
			d, err := a.AuditPruner.PruneOnce(context.Background())
			results[i] = result{d, err}
		}(i, a)
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatalf("concurrent pruners did not finish")
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
		t.Fatalf("deleted verify=%d admin=%d want %d/%d", sumVerify, sumAdmin, oldVerify, oldAdmin)
	}
	var left int64
	appA.DB.Model(&model.AuditLog{}).Count(&left)
	if left != keep {
		t.Fatalf("verify rows left=%d want=%d", left, keep)
	}
	appA.DB.Model(&model.AdminAuditLog{}).Count(&left)
	if left != adminBefore {
		t.Fatalf("admin rows left=%d want=%d (startup rows kept)", left, adminBefore)
	}
}

// TestPostgresPruneSkipsLockedRows holds row locks on some old rows in an open
// transaction, as another replica's pruner would, and checks that a prune pass
// does not wait on them: it returns promptly, without error, having deleted
// the unlocked old rows and left the locked ones. Once the transaction ends, a
// second pass deletes the rest.
func TestPostgresPruneSkipsLockedRows(t *testing.T) {
	const dbTimeout = 4 * time.Second
	dbURL := createFreshPostgresDB(t, "derp_admit_prune_lock_")
	application := bBuildAppOnDB(t, dbURL, rpRetentionOpt(7, 7), func(c *config.Config) { c.DBTimeout = dbTimeout })

	now := time.Now().UTC()
	const oldVerify, oldAdmin, locked, keep = 30, 20, 8, 5
	relay := "default"
	var verifyRows []model.AuditLog
	for i := 0; i < oldVerify; i++ {
		verifyRows = append(verifyRows, model.AuditLog{NodeKey: fmt.Sprintf("nodekey:old-%d", i), Relay: &relay, TS: now.AddDate(0, 0, -10)})
	}
	for i := 0; i < keep; i++ {
		verifyRows = append(verifyRows, model.AuditLog{NodeKey: fmt.Sprintf("nodekey:new-%d", i), Relay: &relay, TS: now})
	}
	if err := application.DB.Create(&verifyRows).Error; err != nil {
		t.Fatalf("seed verify: %v", err)
	}
	var adminRows []model.AdminAuditLog
	for i := 0; i < oldAdmin; i++ {
		adminRows = append(adminRows, model.AdminAuditLog{TS: now.AddDate(0, 0, -10), ActorName: "seed", Action: "seed.old", Outcome: service.AuditOutcomeSuccess})
	}
	if err := application.DB.Create(&adminRows).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	var adminTotal int64
	application.DB.Model(&model.AdminAuditLog{}).Count(&adminTotal)

	lockedVerify := []int64{}
	for _, r := range verifyRows[:locked] {
		lockedVerify = append(lockedVerify, r.ID)
	}
	lockedAdmin := []int64{}
	for _, r := range adminRows[len(adminRows)-locked:] {
		lockedAdmin = append(lockedAdmin, r.ID)
	}

	tx := application.DB.Begin()
	if tx.Error != nil {
		t.Fatalf("begin: %v", tx.Error)
	}
	defer tx.Rollback()
	var got []int64
	if err := tx.Raw(`SELECT id FROM audit_logs WHERE id IN ? FOR UPDATE`, lockedVerify).Scan(&got).Error; err != nil || len(got) != locked {
		t.Fatalf("lock verify rows: got=%v err=%v", got, err)
	}
	got = nil
	if err := tx.Raw(`SELECT id FROM admin_audit_logs WHERE id IN ? FOR UPDATE`, lockedAdmin).Scan(&got).Error; err != nil || len(got) != locked {
		t.Fatalf("lock admin rows: got=%v err=%v", got, err)
	}

	start := time.Now()
	deleted, err := application.AuditPruner.PruneOnce(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("prune while rows are locked: %v (after %s)", err, elapsed)
	}
	if elapsed > dbTimeout/2 {
		t.Fatalf("prune took %s with rows locked: it waited on the locks", elapsed)
	}
	if deleted[metrics.AuditTableVerify] != oldVerify-locked || deleted[metrics.AuditTableAdmin] != oldAdmin-locked {
		t.Fatalf("deleted=%v want verify=%d admin=%d", deleted, oldVerify-locked, oldAdmin-locked)
	}
	var n int64
	application.DB.Model(&model.AuditLog{}).Where("id IN ?", lockedVerify).Count(&n)
	if n != locked {
		t.Fatalf("locked verify rows left=%d want=%d", n, locked)
	}
	application.DB.Model(&model.AdminAuditLog{}).Where("id IN ?", lockedAdmin).Count(&n)
	if n != locked {
		t.Fatalf("locked admin rows left=%d want=%d", n, locked)
	}

	if err := tx.Rollback().Error; err != nil {
		t.Fatalf("rollback: %v", err)
	}
	deleted, err = application.AuditPruner.PruneOnce(context.Background())
	if err != nil || deleted[metrics.AuditTableVerify] != locked || deleted[metrics.AuditTableAdmin] != locked {
		t.Fatalf("second pass deleted=%v err=%v want %d per table", deleted, err, locked)
	}
	application.DB.Model(&model.AuditLog{}).Count(&n)
	if n != keep {
		t.Fatalf("verify rows left=%d want=%d", n, keep)
	}
	application.DB.Model(&model.AdminAuditLog{}).Count(&n)
	if n != adminTotal-oldAdmin {
		t.Fatalf("admin rows left=%d want=%d", n, adminTotal-oldAdmin)
	}
}
