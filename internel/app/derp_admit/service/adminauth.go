package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// AuthenticateAdminKey resolves a bearer token to an admin Actor. It looks up
// the peppered hash in admin_keys (rejecting revoked or expired keys and
// updating last_used_at best-effort), falling back to constant-time comparison
// against ADMIN_API_KEY until Track C removes the static fallback.
func (s *Service) AuthenticateAdminKey(ctx context.Context, bearer string) (actor.Actor, bool, error) {
	if bearer == "" {
		return actor.Actor{}, false, nil
	}

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	keyHash := s.hashToken(bearer)
	var key model.AdminKey
	err := s.db.WithContext(dbCtx).Where("key_hash = ?", keyHash).First(&key).Error
	if err == nil {
		now := time.Now().UTC()
		if key.RevokedAt != nil || (key.ExpiresAt != nil && !key.ExpiresAt.After(now)) {
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
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return actor.Actor{}, false, fmt.Errorf("lookup admin key: %w", err)
	}

	if len(s.adminAPIKey) > 0 && subtle.ConstantTimeCompare([]byte(bearer), []byte(s.adminAPIKey)) == 1 {
		return actor.Actor{
			Name: "static",
			Tier: actor.TierAdmin,
		}, true, nil
	}

	return actor.Actor{}, false, nil
}
