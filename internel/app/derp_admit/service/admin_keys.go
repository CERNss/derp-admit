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

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const adminKeyPrefix = "dak_"

type CreateAdminKeyInput struct {
	Name      string
	Tier      string
	ExpiresAt *time.Time
}

// CreateAdminKeyResult carries the one-time plaintext admin key. Only its
// peppered hash is stored in admin_keys.
type CreateAdminKeyResult struct {
	Key   model.AdminKey
	Plain string
}

func (s *Service) CreateAdminKey(ctx context.Context, in CreateAdminKeyInput) (CreateAdminKeyResult, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return CreateAdminKeyResult{}, fmt.Errorf("%w: name required", ErrAdminInvalid)
	}
	if _, ok := actor.ParseTier(in.Tier); !ok {
		return CreateAdminKeyResult{}, fmt.Errorf("%w: tier must be viewer, operator, or admin", ErrAdminInvalid)
	}
	if strings.EqualFold(name, BootstrapKeyName) || strings.EqualFold(name, actor.System.Name) {
		return CreateAdminKeyResult{}, fmt.Errorf("%w: name %q is reserved", ErrAdminConflict, name)
	}

	var expiresAt *time.Time
	if in.ExpiresAt != nil {
		t := in.ExpiresAt.UTC()
		expiresAt = &t
	}

	plain, err := generateAdminKey()
	if err != nil {
		return CreateAdminKeyResult{}, fmt.Errorf("generate admin key: %w", err)
	}

	var created model.AdminKey
	err = s.Mutate(ctx, EffectNone, http.StatusCreated, func(tx *gorm.DB, ch *Change) error {
		k := model.AdminKey{
			Name:      name,
			Tier:      in.Tier,
			KeyHash:   s.hashToken(plain),
			ExpiresAt: expiresAt,
		}
		if err := tx.Create(&k).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return fmt.Errorf("%w: admin key name already exists", ErrAdminConflict)
			}
			return fmt.Errorf("create admin key: %w", err)
		}

		created = k
		ch.Changed = true
		ch.TargetID = k.ID.String()
		summary := map[string]any{
			"name": k.Name,
			"tier": k.Tier,
		}
		if k.ExpiresAt != nil {
			summary["expiresAt"] = k.ExpiresAt.UTC().Format(time.RFC3339)
		}
		ch.Summary = summary
		return nil
	})
	if err != nil {
		return CreateAdminKeyResult{}, err
	}

	return CreateAdminKeyResult{Key: created, Plain: plain}, nil
}

func (s *Service) ListAdminKeys(ctx context.Context, req page.Request) ([]model.AdminKey, *string, error) {
	if req.After != nil {
		if _, err := uuid.Parse(req.After.K); err != nil {
			return nil, nil, fmt.Errorf("%w: invalid cursor", ErrAdminInvalid)
		}
	}

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var rows []model.AdminKey
	q := page.Asc(s.db.WithContext(dbCtx).Model(&model.AdminKey{}), req, "created_at", "id", page.KeyString)
	if err := q.Find(&rows).Error; err != nil {
		return nil, nil, fmt.Errorf("list admin keys: %w", err)
	}

	items, nextCursor := page.Cut(rows, req, func(k model.AdminKey) (time.Time, string) {
		return k.CreatedAt, k.ID.String()
	})
	return items, nextCursor, nil
}

// RevokeAdminKey revokes an admin key idempotently while refusing to revoke the
// last active admin-tier key (decision D4).
func (s *Service) RevokeAdminKey(ctx context.Context, id uuid.UUID) error {
	return s.Mutate(ctx, EffectNone, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		if err := lockAdminKeyMutation(tx); err != nil {
			return err
		}

		var target model.AdminKey
		if err := lockedAdminKeyQuery(tx).First(&target, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup admin key: %w", err)
		}

		ch.TargetID = id.String()
		ch.Summary = map[string]any{
			"name":    target.Name,
			"tier":    target.Tier,
			"revoked": true,
		}
		if target.RevokedAt != nil {
			ch.Changed = false
			return nil
		}

		now := time.Now().UTC()
		if target.Tier == model.AdminTierAdmin && isAdminKeyActive(target, now) {
			var others []model.AdminKey
			if err := lockedAdminKeyQuery(tx).
				Where("tier = ? AND revoked_at IS NULL AND id <> ?", model.AdminTierAdmin, target.ID).
				Order("id ASC").
				Find(&others).Error; err != nil {
				return fmt.Errorf("check active admin keys: %w", err)
			}
			otherActive := 0
			for _, k := range others {
				if isAdminKeyActive(k, now) {
					otherActive++
				}
			}
			if otherActive == 0 {
				return fmt.Errorf("%w: cannot revoke last active admin key", ErrAdminConflict)
			}
		}

		if err := tx.Model(&model.AdminKey{}).
			Where("id = ?", id).Update("revoked_at", now).Error; err != nil {
			return fmt.Errorf("revoke admin key: %w", err)
		}

		ch.Changed = true
		return nil
	})
}

func generateAdminKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return adminKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}
