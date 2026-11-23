package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"
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

type UserWithRoles struct {
	User  model.User
	Roles []string
}

func (s *Service) CreateUser(ctx context.Context, in CreateUserInput) (model.User, error) {
	res, err := s.CreateUserWithRoles(ctx, in)
	if err != nil {
		return model.User{}, err
	}
	return res.User, nil
}

func (s *Service) CreateUserWithRoles(ctx context.Context, in CreateUserInput) (UserWithRoles, error) {
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" {
		return UserWithRoles{}, fmt.Errorf("%w: username required", ErrAdminInvalid)
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
		roles = dedupeSortedStrings(*in.Roles)
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
		return UserWithRoles{}, err
	}
	return UserWithRoles{User: user, Roles: roles}, nil
}

func (s *Service) ListUsers(ctx context.Context, pg page.Request) ([]UserWithRoles, *string, error) {
	if pg.After != nil {
		if _, err := uuid.Parse(pg.After.K); err != nil {
			return nil, nil, fmt.Errorf("%w: invalid cursor", ErrAdminInvalid)
		}
	}

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var users []model.User
	if err := page.Asc(s.db.WithContext(dbCtx).Model(&model.User{}), pg, "created_at", "id", page.KeyString).
		Find(&users).Error; err != nil {
		if errors.Is(err, page.ErrInvalid) {
			return nil, nil, fmt.Errorf("%w: %v", ErrAdminInvalid, err)
		}
		return nil, nil, fmt.Errorf("list users: %w", err)
	}

	users, nextCursor := page.Cut(users, pg, func(u model.User) (time.Time, string) {
		return u.CreatedAt, u.ID.String()
	})

	ids := make([]uuid.UUID, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	rolesByUser, err := policy.UserRoles(dbCtx, s.db, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("load user roles: %w", err)
	}

	out := make([]UserWithRoles, 0, len(users))
	for _, u := range users {
		roles := rolesByUser[u.ID]
		if roles == nil {
			roles = []string{}
		}
		out = append(out, UserWithRoles{User: u, Roles: roles})
	}
	return out, nextCursor, nil
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

// DeleteUser explicitly removes the user together with their enroll tokens,
// devices, role bindings and legacy device rules in one transaction, while
// preserving verify audit rows with device_id set to null.
func (s *Service) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return s.Mutate(ctx, EffectPolicy, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		var user model.User
		if err := tx.First(&user, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup user: %w", err)
		}

		var devices []model.Device
		if err := tx.Select("id", "node_key").Where("user_id = ?", id).Find(&devices).Error; err != nil {
			return fmt.Errorf("lookup user devices: %w", err)
		}

		deviceIDs := make([]uuid.UUID, 0, len(devices))
		nodeKeys := make([]string, 0, len(devices))
		for _, dev := range devices {
			deviceIDs = append(deviceIDs, dev.ID)
			nodeKeys = append(nodeKeys, dev.NodeKey)
		}

		if len(deviceIDs) > 0 {
			if err := tx.Model(&model.AuditLog{}).
				Where("device_id IN ?", deviceIDs).
				Update("device_id", nil).Error; err != nil {
				return fmt.Errorf("clear verify audit device_id: %w", err)
			}
		}

		if err := policy.DeleteUserRules(tx, id, nodeKeys); err != nil {
			return fmt.Errorf("delete user policy rules: %w", err)
		}

		tokRes := tx.Where("user_id = ?", id).Delete(&model.EnrollToken{})
		if tokRes.Error != nil {
			return fmt.Errorf("delete user enroll tokens: %w", tokRes.Error)
		}

		devRes := tx.Where("user_id = ?", id).Delete(&model.Device{})
		if devRes.Error != nil {
			return fmt.Errorf("delete user devices: %w", devRes.Error)
		}

		userRes := tx.Where("id = ?", id).Delete(&model.User{})
		if userRes.Error != nil {
			return fmt.Errorf("delete user: %w", userRes.Error)
		}
		if userRes.RowsAffected == 0 {
			return ErrAdminNotFound
		}

		ch.Changed = true
		ch.TargetID = id.String()
		ch.Summary = map[string]any{
			"username":       user.Username,
			"tokensDeleted":  tokRes.RowsAffected,
			"devicesDeleted": devRes.RowsAffected,
		}
		return nil
	})
}
