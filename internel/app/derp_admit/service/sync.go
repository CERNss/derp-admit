package service

// Policy sync & staleness model:
//
// Staleness is decided by comparing version numbers rather than toggling a
// boolean flag, so an older concurrent reload that finishes after a newer
// mutation's reload failed can never clear staleness:
//
//   - Published version: PolicyEngine.Version(), read inside the same
//     consistent read transaction as the policy rules and published atomically
//     with the snapshot.
//   - Required version: syncer.required, the highest policy_state.version that
//     any local mutation or sync check has observed (raised monotonically via
//     Require(v)).
//   - Generation mark: syncer.markGen / syncer.satisfiedGen, for callers that
//     need to mark the instance stale without knowing a version (MarkStale()).
//     Only a Reload that STARTS after the MarkStale() call and completes
//     successfully can advance satisfiedGen to cover that mark.
//   - Time-based staleness: lastSuccessNano tracks the timestamp of the last
//     successful version check (including any reload it triggered). Once the
//     poller is active (intervalNano > 0), Stale() also returns true when
//     now - lastSuccess > 3 * interval, until a check (and reload) succeeds.
//   - Stale(publishedVersion): returns true when publishedVersion < required
//     OR satisfiedGen < markGen OR now - lastSuccess > 3 * interval. While
//     stale, /verify fails closed with DenyReasonInternal (audited) and /readyz
//     returns 503.

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"derp-admit/internel/app/derp_admit/policy"

	"go.uber.org/zap"
)

type syncer struct {
	required        atomic.Int64
	markGen         atomic.Uint64
	satisfiedGen    atomic.Uint64
	started         atomic.Bool
	intervalNano    atomic.Int64
	lastSuccessNano atomic.Int64
	clock           atomic.Pointer[func() time.Time]
	versionReader   atomic.Pointer[func(context.Context) (int64, error)]
}

func newSyncer() *syncer {
	return &syncer{}
}

func (s *syncer) now() time.Time {
	if fn := s.clock.Load(); fn != nil && *fn != nil {
		return (*fn)()
	}
	return time.Now().UTC()
}

func (s *syncer) setClock(fn func() time.Time) {
	s.clock.Store(&fn)
}

func (s *syncer) setVersionReader(fn func(context.Context) (int64, error)) {
	s.versionReader.Store(&fn)
}

func (s *syncer) ensureInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	s.intervalNano.CompareAndSwap(0, int64(interval))
}

func (s *syncer) recordSuccess(t time.Time) {
	ns := t.UTC().UnixNano()
	for {
		cur := s.lastSuccessNano.Load()
		if cur >= ns {
			return
		}
		if s.lastSuccessNano.CompareAndSwap(cur, ns) {
			return
		}
	}
}

func (s *syncer) lastSuccessTime() time.Time {
	ns := s.lastSuccessNano.Load()
	if ns <= 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

// Require records that the published policy snapshot must cover at least v.
func (s *syncer) Require(v int64) {
	for {
		cur := s.required.Load()
		if cur >= v {
			return
		}
		if s.required.CompareAndSwap(cur, v) {
			return
		}
	}
}

// MarkStale marks the instance stale for callers without a version number.
// Only a Reload started after this call that succeeds can satisfy the mark.
func (s *syncer) MarkStale() {
	s.markGen.Add(1)
}

// Reload captures the current mark generation before calling engine.Reload, so
// only a reload started after a MarkStale call can satisfy that mark on success.
func (s *syncer) Reload(ctx context.Context, engine policy.PolicyEngine) error {
	gen := s.markGen.Load()
	if err := engine.Reload(ctx); err != nil {
		return err
	}
	for {
		cur := s.satisfiedGen.Load()
		if cur >= gen {
			return nil
		}
		if s.satisfiedGen.CompareAndSwap(cur, gen) {
			return nil
		}
	}
}

func (s *syncer) needsReload(publishedVersion int64) bool {
	if publishedVersion < s.required.Load() {
		return true
	}
	return s.satisfiedGen.Load() < s.markGen.Load()
}

// Stale reports whether the currently published snapshot version lags behind
// the highest required version, has an unsatisfied MarkStale generation, or
// has gone longer than three sync intervals without a successful check.
func (s *syncer) Stale(publishedVersion int64) bool {
	if s.needsReload(publishedVersion) {
		return true
	}
	if interval := time.Duration(s.intervalNano.Load()); interval > 0 {
		if last := s.lastSuccessNano.Load(); last > 0 {
			if s.now().Sub(time.Unix(0, last)) > 3*interval {
				return true
			}
		}
	}
	return false
}

// Start begins periodic policy version checks until ctx is cancelled.
func (s *Service) StartSync(ctx context.Context) {
	interval := s.policySyncInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if !s.sync.started.CompareAndSwap(false, true) {
		return
	}
	s.sync.intervalNano.Store(int64(interval))
	now := s.sync.now()
	s.sync.recordSuccess(now)
	s.metrics.PolicySync(true, s.publishedVersion(), now)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.syncOnce(ctx)
			}
		}
	}()
}

func (s *Service) publishedVersion() int64 {
	if s.policy == nil {
		return 0
	}
	return s.policy.Version()
}

func (s *Service) readPolicyVersion(ctx context.Context) (int64, error) {
	if fn := s.sync.versionReader.Load(); fn != nil && *fn != nil {
		return (*fn)(ctx)
	}
	return policy.ReadVersion(ctx, s.db)
}

func (s *Service) syncOnce(ctx context.Context) error {
	s.sync.ensureInterval(s.policySyncInterval)

	checkCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	stored, err := s.readPolicyVersion(checkCtx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.metrics.PolicySync(false, s.publishedVersion(), s.sync.lastSuccessTime())
		s.logger.Warn("policy sync version check failed", zap.Error(err))
		return err
	}

	published := s.publishedVersion()
	if stored > published || s.sync.needsReload(published) {
		s.sync.Require(stored)
		if err := s.ReloadPolicy(checkCtx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.metrics.PolicySync(false, s.publishedVersion(), s.sync.lastSuccessTime())
			s.logger.Warn("policy sync reload failed",
				zap.Error(err),
				zap.Int64("stored_version", stored),
			)
			return err
		}
		published = s.publishedVersion()
		if published < stored || s.sync.needsReload(published) {
			s.metrics.PolicySync(false, published, s.sync.lastSuccessTime())
			return fmt.Errorf("policy reload published version %d, want at least %d", published, stored)
		}
	}

	now := s.sync.now()
	s.sync.recordSuccess(now)
	s.metrics.PolicySync(true, published, now)
	return nil
}

func (s *Service) SyncStale() bool {
	return s.sync.Stale(s.publishedVersion())
}

// ReloadPolicy runs a policy reload through the syncer and purges the local
// verify cache afterwards.
func (s *Service) ReloadPolicy(ctx context.Context) error {
	err := s.sync.Reload(ctx, s.policy)
	s.metrics.PolicyReload(err == nil)
	s.cache.Purge()
	return err
}
