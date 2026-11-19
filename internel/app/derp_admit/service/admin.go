package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Sentinel errors admin handlers map to HTTP status codes.
var (
	ErrAdminNotFound = errors.New("not found")
	ErrAdminConflict = errors.New("conflict")
	ErrAdminInvalid  = errors.New("invalid")
)

type CreateUserInput struct {
	Username string
	Email    *string
}

type CreateTokenInput struct {
	UserID     uuid.UUID
	ExpiresAt  *time.Time
	MaxDevices int
	Note       string
}

// CreateTokenResult carries the one-time plaintext token. Only the hash is
// stored; the plaintext is returned to the caller exactly once here.
type CreateTokenResult struct {
	Token model.EnrollToken
	Plain string
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

func (s *Service) CreateToken(ctx context.Context, in CreateTokenInput) (CreateTokenResult, error) {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	if in.MaxDevices < 0 {
		return CreateTokenResult{}, fmt.Errorf("%w: maxDevices must be >= 0", ErrAdminInvalid)
	}

	var user model.User
	if err := s.db.WithContext(dbCtx).First(&user, "id = ?", in.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return CreateTokenResult{}, ErrAdminNotFound
		}
		return CreateTokenResult{}, fmt.Errorf("lookup user: %w", err)
	}

	plain, err := generateToken()
	if err != nil {
		return CreateTokenResult{}, fmt.Errorf("generate token: %w", err)
	}

	token := model.EnrollToken{
		UserID:     in.UserID,
		TokenHash:  s.hashToken(plain),
		ExpiresAt:  in.ExpiresAt,
		MaxDevices: in.MaxDevices,
		Note:       strings.TrimSpace(in.Note),
	}
	if err := s.db.WithContext(dbCtx).Create(&token).Error; err != nil {
		return CreateTokenResult{}, fmt.Errorf("create token: %w", err)
	}

	return CreateTokenResult{Token: token, Plain: plain}, nil
}

func (s *Service) ListTokens(ctx context.Context) ([]model.EnrollToken, error) {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var tokens []model.EnrollToken
	if err := s.db.WithContext(dbCtx).Order("created_at asc").Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	return tokens, nil
}

func (s *Service) RevokeToken(ctx context.Context, id uuid.UUID) error {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var token model.EnrollToken
	if err := s.db.WithContext(dbCtx).First(&token, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAdminNotFound
		}
		return fmt.Errorf("lookup token: %w", err)
	}
	if token.RevokedAt != nil {
		return nil
	}

	now := time.Now().UTC()
	if err := s.db.WithContext(dbCtx).Model(&model.EnrollToken{}).
		Where("id = ?", id).Update("revoked_at", now).Error; err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

func (s *Service) ListDevices(ctx context.Context, userID *uuid.UUID) ([]model.Device, error) {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	q := s.db.WithContext(dbCtx).Order("created_at asc")
	if userID != nil {
		q = q.Where("user_id = ?", *userID)
	}

	var devices []model.Device
	if err := q.Find(&devices).Error; err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return devices, nil
}

// SetDeviceRevoked toggles a device's revoked state and invalidates its cached
// decision so the change takes effect immediately.
func (s *Service) SetDeviceRevoked(ctx context.Context, id uuid.UUID, revoked bool) error {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var device model.Device
	if err := s.db.WithContext(dbCtx).First(&device, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAdminNotFound
		}
		return fmt.Errorf("lookup device: %w", err)
	}
	if revoked == (device.RevokedAt != nil) {
		// Already in the requested state; keep the original timestamp.
		return nil
	}

	var revokedAt *time.Time
	if revoked {
		now := time.Now().UTC()
		revokedAt = &now
	}
	if err := s.db.WithContext(dbCtx).Model(&model.Device{}).
		Where("id = ?", id).Update("revoked_at", revokedAt).Error; err != nil {
		return fmt.Errorf("update device: %w", err)
	}

	s.cache.Invalidate(device.NodeKey)
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

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
