package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type CreateUserInput struct {
	Username string
	Email    *string
}

func (s *Service) CreateUser(ctx context.Context, in CreateUserInput) (model.User, error) {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" {
		return model.User{}, fmt.Errorf("%w: username required", ErrAdminInvalid)
	}
	if in.Email != nil {
		trimmed := strings.TrimSpace(*in.Email)
		if trimmed == "" {
			in.Email = nil
		} else {
			in.Email = &trimmed
		}
	}

	// Uniqueness is enforced by the DB indexes on username/email, which is
	// race-free where a check-then-insert would not be.
	user := model.User{Username: in.Username, Email: in.Email}
	if err := s.db.WithContext(dbCtx).Create(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return model.User{}, fmt.Errorf("%w: username or email taken", ErrAdminConflict)
		}
		return model.User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (s *Service) ListUsers(ctx context.Context) ([]model.User, error) {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var users []model.User
	if err := s.db.WithContext(dbCtx).Order("created_at asc").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// SetUserDisabled toggles a user's disabled state. Disabling also invalidates
// the decision cache for all of the user's devices so revocation takes effect
// immediately rather than waiting out the cache TTL.
func (s *Service) SetUserDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var user model.User
	if err := s.db.WithContext(dbCtx).First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAdminNotFound
		}
		return fmt.Errorf("lookup user: %w", err)
	}
	if disabled == (user.DisabledAt != nil) {
		// Already in the requested state; keep the original timestamp.
		return nil
	}

	var disabledAt *time.Time
	if disabled {
		now := time.Now().UTC()
		disabledAt = &now
	}
	if err := s.db.WithContext(dbCtx).Model(&model.User{}).
		Where("id = ?", id).Update("disabled_at", disabledAt).Error; err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	s.invalidateUserDevices(dbCtx, id)
	return nil
}

func (s *Service) invalidateUserDevices(ctx context.Context, userID uuid.UUID) {
	var keys []string
	if err := s.db.WithContext(ctx).Model(&model.Device{}).
		Where("user_id = ?", userID).Pluck("node_key", &keys).Error; err != nil {
		s.logger.Warn("invalidate user devices: pluck node keys failed")
		return
	}
	for _, k := range keys {
		s.cache.Invalidate(k)
	}
}
