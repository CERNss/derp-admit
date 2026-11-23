package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type CreateUserInput struct {
	Username string
	Email    *string
	// Roles is nil when omitted (defaults to ["standard"]); an explicit empty
	// slice binds no roles (decision A6).
	Roles *[]string
}

func (s *Service) CreateUser(ctx context.Context, in CreateUserInput) (model.User, error) {
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

	roles := []string{policy.BuiltinRole}
	if in.Roles != nil {
		roles = *in.Roles
	}

	var user model.User
	err := s.Mutate(ctx, EffectPolicy, http.StatusCreated, func(tx *gorm.DB, ch *Change) error {
		// Uniqueness is enforced by the DB indexes on username/email, which is
		// race-free where a check-then-insert would not be.
		u := model.User{Username: in.Username, Email: in.Email}
		if err := tx.Create(&u).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return fmt.Errorf("%w: username or email taken", ErrAdminConflict)
			}
			return fmt.Errorf("create user: %w", err)
		}
		if err := policy.SetUserRoles(tx, u.ID, roles); err != nil {
			if errors.Is(err, policy.ErrUnknownRole) {
				return fmt.Errorf("%w: %v", ErrAdminInvalid, err)
			}
			return fmt.Errorf("bind user roles: %w", err)
		}
		user = u
		ch.Changed = true
		ch.TargetID = u.ID.String()
		ch.Summary = map[string]any{
			"username": u.Username,
			"roles":    roles,
		}
		return nil
	})
	if err != nil {
		return model.User{}, err
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
// cached decisions so revocation takes effect immediately rather than waiting
// out the cache TTL.
func (s *Service) SetUserDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	return s.Mutate(ctx, EffectCache, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		var user model.User
		if err := tx.First(&user, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup user: %w", err)
		}

		ch.TargetID = id.String()
		ch.Summary = map[string]any{"disabled": disabled}
		if disabled == (user.DisabledAt != nil) {
			// Already in the requested state; keep the original timestamp.
			ch.Changed = false
			return nil
		}

		var disabledAt *time.Time
		if disabled {
			now := time.Now().UTC()
			disabledAt = &now
		}
		if err := tx.Model(&model.User{}).
			Where("id = ?", id).Update("disabled_at", disabledAt).Error; err != nil {
			return fmt.Errorf("update user: %w", err)
		}

		ch.Changed = true
		return nil
	})
}
