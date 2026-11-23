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
//     any local mutation has committed (raised monotonically via Require(v)).
//   - Generation mark: syncer.markGen / syncer.satisfiedGen, for callers that
//     need to mark the instance stale without knowing a version (MarkStale()).
//     Only a Reload that STARTS after the MarkStale() call and completes
//     successfully can advance satisfiedGen to cover that mark.
//   - Stale(publishedVersion): returns true when publishedVersion < required
//     OR satisfiedGen < markGen. While stale, /verify fails closed with
//     DenyReasonInternal (audited) and /readyz returns 503.
//
// What Track B adds on top of this model:
//   - A periodic poller running every s.policySyncInterval (started by
//     StartSync) that reads policy.ReadVersion. When the stored version moves
//     ahead of the published version, it calls sync.Require(v), sync.Reload, and
//     cache.Purge (in that order).
//   - Time-based staleness: tracking the timestamp of the last successful
//     version check (and any needed reload); Stale() also becomes true when
//     now - lastSuccess > 3 * interval, until a check (and reload) succeeds.

import (
	"context"
	"sync/atomic"

	"derp-admit/internel/app/derp_admit/policy"
)

type syncer struct {
	required     atomic.Int64
	markGen      atomic.Uint64
	satisfiedGen atomic.Uint64
}

func newSyncer() *syncer {
	return &syncer{}
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

// Stale reports whether the currently published snapshot version lags behind
// the highest required version or an unsatisfied MarkStale generation.
func (s *syncer) Stale(publishedVersion int64) bool {
	if publishedVersion < s.required.Load() {
		return true
	}
	return s.satisfiedGen.Load() < s.markGen.Load()
}

func (s *syncer) Start(_ context.Context) {}

func (s *Service) StartSync(ctx context.Context) {
	s.sync.Start(ctx)
}

func (s *Service) SyncStale() bool {
	var published int64
	if s.policy != nil {
		published = s.policy.Version()
	}
	return s.sync.Stale(published)
}

// ReloadPolicy runs a policy reload through the syncer and purges the local
// verify cache afterwards.
func (s *Service) ReloadPolicy(ctx context.Context) error {
	err := s.sync.Reload(ctx, s.policy)
	s.metrics.PolicyReload(err == nil)
	s.cache.Purge()
	return err
}
