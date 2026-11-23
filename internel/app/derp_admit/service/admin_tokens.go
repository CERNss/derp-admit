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

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
