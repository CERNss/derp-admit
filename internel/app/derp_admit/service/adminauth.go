package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// AuthenticateAdminKey resolves a bearer token to an admin Actor by looking up
// its peppered hash in admin_keys. Revoked or expired keys are rejected with
// (zero, false, nil); database errors are returned so callers fail closed with
// HTTP 500. last_used_at is updated best-effort so a write failure does not
// fail an otherwise valid request.
func (s *Service) AuthenticateAdminKey(ctx context.Context, bearer string) (actor.Actor, bool, error) {
	if bearer == "" {
		return actor.Actor{}, false, nil
	}

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	keyHash := s.hashToken(bearer)
	var key model.AdminKey
	err := s.db.WithContext(dbCtx).Where("key_hash = ?", keyHash).First(&key).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return actor.Actor{}, false, nil
		}
		return actor.Actor{}, false, fmt.Errorf("lookup admin key: %w", err)
	}

	now := time.Now().UTC()
	if !isAdminKeyActive(key, now) {
		return actor.Actor{}, false, nil
	}
	tier, ok := actor.ParseTier(key.Tier)
	if !ok {
		return actor.Actor{}, false, fmt.Errorf("invalid tier %q on admin key %s", key.Tier, key.ID)
	}
	if updErr := s.db.WithContext(dbCtx).Model(&model.AdminKey{}).
		Where("id = ?", key.ID).Update("last_used_at", now).Error; updErr != nil {
		loggerWithTrace(s.logger, ctx).Warn("update admin key last_used_at",
			zap.Error(updErr),
			zap.String("key_id", key.ID.String()),
		)
	}
	id := key.ID
	return actor.Actor{
		KeyID: &id,
		Name:  key.Name,
		Tier:  tier,
	}, true, nil
}
