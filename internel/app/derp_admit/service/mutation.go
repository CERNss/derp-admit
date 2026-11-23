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
// same transaction. After commit, if Changed is true, it applies EffectPolicy
// (engine.Reload followed by cache.Purge so the cache epoch advances after the
// snapshot is refreshed) or EffectCache (cache.Purge). If Reload fails after
// commit, the instance marks sync stale (fail closed), logs, and returns nil.
func (s *Service) Mutate(ctx context.Context, eff Effect, okStatus int, fn func(tx *gorm.DB, ch *Change) error) error {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	ch := Change{Changed: true}
	err := s.db.WithContext(dbCtx).Transaction(func(tx *gorm.DB) error {
		if err := fn(tx, &ch); err != nil {
			return err
		}
		if ch.Changed && eff != EffectNone {
			if _, err := policy.BumpVersion(tx); err != nil {
				return err
			}
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

	if !ch.Changed {
		return nil
	}

	if eff&EffectPolicy != 0 {
		reloadCtx, reloadCancel := context.WithTimeout(context.Background(), s.dbTimeout)
		reloadErr := s.policy.Reload(reloadCtx)
		reloadCancel()
		if reloadErr != nil {
			s.sync.MarkStale()
			s.metrics.PolicyReload(false)
			loggerWithTrace(s.logger, ctx).Error("reload policy after mutation commit", zap.Error(reloadErr))
		} else {
			s.metrics.PolicyReload(true)
		}
		s.cache.Purge()
	} else if eff&EffectCache != 0 {
		s.cache.Purge()
	}

	return nil
}
