package service

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type bFakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func bNewFakeClock(start time.Time) *bFakeClock {
	return &bFakeClock{now: start.UTC()}
}

func (c *bFakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *bFakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type bRecordingMetrics struct {
	mu          sync.Mutex
	cacheHits   int
	cacheMisses int
	syncOK      int
	syncFail    int
	lastVersion int64
	lastSyncTS  time.Time
	reloadsOK   int
	reloadsFail int
	verifyCalls int
}

func (m *bRecordingMetrics) VerifyDecision(string, bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifyCalls++
}
func (m *bRecordingMetrics) RegisterOutcome(int)      {}
func (m *bRecordingMetrics) AdminRequest(string, int) {}
func (m *bRecordingMetrics) RateLimited(string)       {}
func (m *bRecordingMetrics) Handler() http.Handler    { return nil }
func (m *bRecordingMetrics) CacheLookup(hit bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if hit {
		m.cacheHits++
	} else {
		m.cacheMisses++
	}
}
func (m *bRecordingMetrics) PolicySync(ok bool, version int64, lastSuccess time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.syncOK++
		m.lastVersion = version
		m.lastSyncTS = lastSuccess
		return
	}
	m.syncFail++
}
func (m *bRecordingMetrics) PolicyReload(ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.reloadsOK++
	} else {
		m.reloadsFail++
	}
}

type bCountingPolicyEngine struct {
	inner       *policy.Engine
	reloadCalls atomic.Int64
	failReload  atomic.Bool
}

func (e *bCountingPolicyEngine) Enforce(req policy.Request) (bool, error) {
	return e.inner.Enforce(req)
}
func (e *bCountingPolicyEngine) Version() int64 {
	return e.inner.Version()
}
func (e *bCountingPolicyEngine) HasRelay(name string) bool {
	return e.inner.HasRelay(name)
}
func (e *bCountingPolicyEngine) Reload(ctx context.Context) error {
	e.reloadCalls.Add(1)
	if e.failReload.Load() {
		return errors.New("forced reload error")
	}
	return e.inner.Reload(ctx)
}

func bSeedAllowedDevice(t *testing.T, svc *Service, gormDB *gorm.DB, username string) (model.User, model.Device, []byte) {
	t.Helper()
	user := model.User{ID: uuid.New(), Username: username}
	if err := gormDB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	nk := bNewNodeKey()
	dev := model.Device{ID: uuid.New(), UserID: user.ID, NodeKey: nk}
	if err := gormDB.Create(&dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := svc.Mutate(context.Background(), EffectPolicy, http.StatusOK, func(tx *gorm.DB, _ *Change) error {
		return policy.SetUserRoles(tx, user.ID, []string{policy.BuiltinRole})
	}); err != nil {
		t.Fatalf("bind standard role: %v", err)
	}
	return user, dev, bNewVerifyBody(t, nk)
}

func TestSyncStaleInstanceFailsClosed(t *testing.T) {
	interval := 2 * time.Second
	svc, _, gormDB := bSetupService(t, time.Minute, interval)
	rec := &bRecordingMetrics{}
	svc.metrics = rec

	clock := bNewFakeClock(time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC))
	svc.sync.setClock(clock.Now)

	_, dev, body := bSeedAllowedDevice(t, svc, gormDB, "stale-user")

	// Initial check succeeds and warms the verify cache.
	if err := svc.syncOnce(context.Background()); err != nil {
		t.Fatalf("initial syncOnce: %v", err)
	}
	if svc.SyncStale() {
		t.Fatalf("expected fresh instance immediately after successful check")
	}
	for i := 0; i < 2; i++ {
		if allow, reason := svc.Verify(context.Background(), policy.BuiltinRelay, body); !allow || reason != "" {
			t.Fatalf("verify %d=(%v, %q) want allow", i, allow, reason)
		}
	}
	rec.mu.Lock()
	hitsBefore := rec.cacheHits
	tsBefore := rec.lastSyncTS
	rec.mu.Unlock()
	if hitsBefore < 1 {
		t.Fatalf("expected cache hit before staleness, hits=%d", hitsBefore)
	}

	// Simulate unreachable DB for version checks.
	svc.sync.setVersionReader(func(context.Context) (int64, error) {
		return 0, errors.New("db unreachable")
	})

	// Up to and including 3 intervals, the instance is not yet stale.
	for step := 1; step <= 3; step++ {
		clock.Advance(interval)
		if err := svc.syncOnce(context.Background()); err == nil {
			t.Fatalf("step %d: expected version check error", step)
		}
		if svc.SyncStale() {
			t.Fatalf("step %d (elapsed=%v): should not be stale at <= 3*interval", step, time.Duration(step)*interval)
		}
	}

	// Verify failures were counted and last-successful-sync time did not advance.
	rec.mu.Lock()
	if rec.syncFail != 3 {
		t.Fatalf("syncFail=%d want=3", rec.syncFail)
	}
	if !rec.lastSyncTS.Equal(tsBefore) {
		t.Fatalf("lastSyncTS advanced on failure: got=%v want=%v", rec.lastSyncTS, tsBefore)
	}
	rec.mu.Unlock()

	// Cross > 3 intervals: instance must fail closed even for cached devices.
	clock.Advance(time.Millisecond)
	if !svc.SyncStale() {
		t.Fatalf("expected SyncStale()=true after > 3*interval without success")
	}

	var auditBefore int64
	if err := gormDB.Model(&model.AuditLog{}).Count(&auditBefore).Error; err != nil {
		t.Fatalf("count audit before: %v", err)
	}

	allow, reason := svc.Verify(context.Background(), policy.BuiltinRelay, body)
	if allow || reason != DenyReasonInternal {
		t.Fatalf("stale verify=(%v, %q) want=(false, %q)", allow, reason, DenyReasonInternal)
	}

	// Verify the stale denial was audited.
	var lastAudit model.AuditLog
	if err := gormDB.Order("id desc").First(&lastAudit).Error; err != nil {
		t.Fatalf("load stale audit row: %v", err)
	}
	var auditAfter int64
	if err := gormDB.Model(&model.AuditLog{}).Count(&auditAfter).Error; err != nil {
		t.Fatalf("count audit after: %v", err)
	}
	if auditAfter != auditBefore+1 {
		t.Fatalf("audit count=%d want=%d", auditAfter, auditBefore+1)
	}
	if lastAudit.Allowed || lastAudit.Reason != DenyReasonInternal || lastAudit.NodeKey != dev.NodeKey {
		t.Fatalf("unexpected stale audit row: %+v", lastAudit)
	}
	if lastAudit.Relay == nil || *lastAudit.Relay != policy.BuiltinRelay {
		t.Fatalf("stale audit relay=%v want=%q", lastAudit.Relay, policy.BuiltinRelay)
	}
}

func TestSyncRecoversAfterSuccessfulCheck(t *testing.T) {
	interval := 2 * time.Second
	svc, realEngine, gormDB := bSetupService(t, time.Minute, interval)
	counting := &bCountingPolicyEngine{inner: realEngine}
	svc.policy = counting
	rec := &bRecordingMetrics{}
	svc.metrics = rec

	clock := bNewFakeClock(time.Date(2026, 11, 23, 13, 0, 0, 0, time.UTC))
	svc.sync.setClock(clock.Now)

	_, dev, body := bSeedAllowedDevice(t, svc, gormDB, "recover-user")

	if err := svc.syncOnce(context.Background()); err != nil {
		t.Fatalf("initial syncOnce: %v", err)
	}
	if allow, reason := svc.Verify(context.Background(), policy.BuiltinRelay, body); !allow || reason != "" {
		t.Fatalf("initial verify=(%v, %q) want allow", allow, reason)
	}

	// Force staleness past 3 intervals.
	svc.sync.setVersionReader(func(context.Context) (int64, error) {
		return 0, errors.New("temporary outage")
	})
	clock.Advance(3*interval + time.Second)
	_ = svc.syncOnce(context.Background())
	if !svc.SyncStale() {
		t.Fatalf("expected stale during outage")
	}

	// Meanwhile another instance revokes the device and bumps the stored version.
	now := time.Now().UTC()
	var newVer int64
	if err := gormDB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.Device{}).Where("id = ?", dev.ID).Update("revoked_at", &now).Error; err != nil {
			return err
		}
		var err error
		newVer, err = policy.BumpVersion(tx)
		return err
	}); err != nil {
		t.Fatalf("simulate remote revoke: %v", err)
	}

	// If version check succeeds but the needed reload fails, instance MUST stay stale.
	svc.sync.setVersionReader(nil) // restore real policy.ReadVersion
	counting.failReload.Store(true)
	if err := svc.syncOnce(context.Background()); err == nil {
		t.Fatalf("expected syncOnce to fail while reload fails")
	}
	if !svc.SyncStale() {
		t.Fatalf("instance must remain stale until needed reload completes")
	}

	// Once reload succeeds, instance recovers and reflects the remote revocation.
	counting.failReload.Store(false)
	clock.Advance(interval)
	if err := svc.syncOnce(context.Background()); err != nil {
		t.Fatalf("recovery syncOnce: %v", err)
	}
	if svc.SyncStale() {
		t.Fatalf("expected SyncStale()=false after recovery")
	}
	if got := counting.Version(); got < newVer {
		t.Fatalf("published version=%d want >= %d", got, newVer)
	}

	allow, reason := svc.Verify(context.Background(), policy.BuiltinRelay, body)
	if allow || reason != DenyReasonRevoked {
		t.Fatalf("verify after recovery=(%v, %q) want=(false, %q)", allow, reason, DenyReasonRevoked)
	}
}

func TestSyncDoesNotReloadWhenVersionUnchanged(t *testing.T) {
	interval := 2 * time.Second
	svc, realEngine, gormDB := bSetupService(t, time.Minute, interval)
	counting := &bCountingPolicyEngine{inner: realEngine}
	svc.policy = counting
	rec := &bRecordingMetrics{}
	svc.metrics = rec
	svc.logger = zap.NewNop()

	clock := bNewFakeClock(time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC))
	svc.sync.setClock(clock.Now)

	_, _, body := bSeedAllowedDevice(t, svc, gormDB, "unchanged-user")

	// Reset reload counter after fixture setup.
	counting.reloadCalls.Store(0)

	// Warm the cache (1 miss, then 1 hit).
	if allow, reason := svc.Verify(context.Background(), policy.BuiltinRelay, body); !allow || reason != "" {
		t.Fatalf("warm verify=(%v, %q) want allow", allow, reason)
	}

	// Run several sync checks with no version change.
	for i := 0; i < 5; i++ {
		clock.Advance(interval)
		if err := svc.syncOnce(context.Background()); err != nil {
			t.Fatalf("syncOnce %d: %v", i, err)
		}
	}

	if calls := counting.reloadCalls.Load(); calls != 0 {
		t.Fatalf("reloadCalls=%d want=0 when stored version is unchanged", calls)
	}

	// Verify cache was NOT purged: next verify must be a cache hit.
	rec.mu.Lock()
	missesBefore := rec.cacheMisses
	hitsBefore := rec.cacheHits
	rec.mu.Unlock()

	if allow, reason := svc.Verify(context.Background(), policy.BuiltinRelay, body); !allow || reason != "" {
		t.Fatalf("post-sync verify=(%v, %q) want allow", allow, reason)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.cacheHits != hitsBefore+1 || rec.cacheMisses != missesBefore {
		t.Fatalf("expected cache hit without purge: hits %d->%d misses %d->%d",
			hitsBefore, rec.cacheHits, missesBefore, rec.cacheMisses)
	}
}
