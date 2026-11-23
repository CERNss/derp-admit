package service

import (
	"context"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/policy"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Effect describes the post-commit side effects a mutation requires.
type Effect uint8

const (
	EffectNone   Effect = 0
	EffectCache  Effect = 1 << 0
	EffectPolicy Effect = 1 << 1
)

// Change reports the outcome of a mutation callback to Mutate.
// Mutate initializes Changed to true; idempotent no-ops set Changed = false so
// an audit row is still written while the policy version and post-commit
// effects are skipped.
type Change struct {
	Changed  bool           // false = idempotent no-op: audit row yes, bump no, effects no
	TargetID string         // overrides Op.TargetID (creates)
	Summary  map[string]any // never plaintext keys/tokens or any hash
}

// Mutate runs fn inside a single database transaction. When Changed is true and
// eff is non-zero it bumps the stored policy version in the same transaction.
// When ctx carries an actor.Op it inserts the success admin audit row in the
// same transaction. After commit, for every mutation that bumped the version
// (EffectPolicy or EffectCache), it reloads the policy snapshot, records the
// committed version as required with the syncer (so a failed or older reload
// leaves the instance stale until a reload covering that version succeeds),
// and purges the verify cache (reload before purge so the cache epoch advances
// after the snapshot is refreshed).
func (s *Service) Mutate(ctx context.Context, eff Effect, okStatus int, fn func(tx *gorm.DB, ch *Change) error) error {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var bumpedVersion int64
	ch := Change{Changed: true}
	err := s.db.WithContext(dbCtx).Transaction(func(tx *gorm.DB) error {
		if err := fn(tx, &ch); err != nil {
			return err
		}
		if ch.Changed && eff != EffectNone {
			v, err := policy.BumpVersion(tx)
			if err != nil {
				return err
			}
			bumpedVersion = v
		}
		if op, ok := actor.OpFrom(ctx); ok {
			if err := insertAdminAudit(tx, ctx, op, &ch, okStatus); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if op, ok := actor.OpFrom(ctx); ok {
		op.MarkRecorded()
	}

	if !ch.Changed || eff == EffectNone {
		return nil
	}

	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), s.dbTimeout)
	reloadErr := s.sync.Reload(reloadCtx, s.policy)
	reloadCancel()
	s.sync.Require(bumpedVersion)
	if reloadErr != nil {
		s.metrics.PolicyReload(false)
		loggerWithTrace(s.logger, ctx).Error("reload policy after mutation commit", zap.Error(reloadErr))
	} else {
		s.metrics.PolicyReload(true)
	}
	s.cache.Purge()

	return nil
}
