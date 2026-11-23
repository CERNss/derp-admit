package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"

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
	if in.MaxDevices < 0 {
		return CreateTokenResult{}, fmt.Errorf("%w: maxDevices must be >= 0", ErrAdminInvalid)
	}

	plain, err := generateToken()
	if err != nil {
		return CreateTokenResult{}, fmt.Errorf("generate token: %w", err)
	}

	var token model.EnrollToken
	err = s.Mutate(ctx, EffectNone, http.StatusCreated, func(tx *gorm.DB, ch *Change) error {
		var user model.User
		if err := tx.First(&user, "id = ?", in.UserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup user: %w", err)
		}

		note := strings.TrimSpace(in.Note)
		t := model.EnrollToken{
			UserID:     in.UserID,
			TokenHash:  s.hashToken(plain),
			ExpiresAt:  in.ExpiresAt,
			MaxDevices: in.MaxDevices,
			Note:       note,
		}
		if err := tx.Create(&t).Error; err != nil {
			return fmt.Errorf("create token: %w", err)
		}

		token = t
		ch.Changed = true
		ch.TargetID = t.ID.String()
		summary := map[string]any{
			"userId":     in.UserID.String(),
			"maxDevices": in.MaxDevices,
			"note":       note,
		}
		if in.ExpiresAt != nil {
			summary["expiresAt"] = in.ExpiresAt.UTC().Format(time.RFC3339)
		}
		ch.Summary = summary
		return nil
	})
	if err != nil {
		return CreateTokenResult{}, err
	}

	return CreateTokenResult{Token: token, Plain: plain}, nil
}

func (s *Service) ListTokens(ctx context.Context, pg page.Request) ([]model.EnrollToken, *string, error) {
	if pg.After != nil {
		if _, err := uuid.Parse(pg.After.K); err != nil {
			return nil, nil, fmt.Errorf("%w: invalid cursor", ErrAdminInvalid)
		}
	}

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var tokens []model.EnrollToken
	if err := page.Asc(s.db.WithContext(dbCtx).Model(&model.EnrollToken{}), pg, "created_at", "id", page.KeyString).
		Find(&tokens).Error; err != nil {
		if errors.Is(err, page.ErrInvalid) {
			return nil, nil, fmt.Errorf("%w: %v", ErrAdminInvalid, err)
		}
		return nil, nil, fmt.Errorf("list tokens: %w", err)
	}

	tokens, nextCursor := page.Cut(tokens, pg, func(t model.EnrollToken) (time.Time, string) {
		return t.CreatedAt, t.ID.String()
	})
	return tokens, nextCursor, nil
}

func (s *Service) RevokeToken(ctx context.Context, id uuid.UUID) error {
	return s.Mutate(ctx, EffectNone, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		var token model.EnrollToken
		if err := tx.First(&token, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup token: %w", err)
		}

		ch.TargetID = id.String()
		ch.Summary = map[string]any{"revoked": true}
		if token.RevokedAt != nil {
			ch.Changed = false
			return nil
		}

		now := time.Now().UTC()
		if err := tx.Model(&model.EnrollToken{}).
			Where("id = ?", id).Update("revoked_at", now).Error; err != nil {
			return fmt.Errorf("revoke token: %w", err)
		}

		ch.Changed = true
		return nil
	})
}

// DeleteToken removes an enroll token without affecting devices previously
// enrolled with it.
func (s *Service) DeleteToken(ctx context.Context, id uuid.UUID) error {
	return s.Mutate(ctx, EffectNone, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		var token model.EnrollToken
		if err := tx.First(&token, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup token: %w", err)
		}

		res := tx.Where("id = ?", id).Delete(&model.EnrollToken{})
		if res.Error != nil {
			return fmt.Errorf("delete token: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrAdminNotFound
		}

		ch.Changed = true
		ch.TargetID = id.String()
		ch.Summary = map[string]any{
			"userId": token.UserID.String(),
			"note":   token.Note,
		}
		return nil
	})
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
