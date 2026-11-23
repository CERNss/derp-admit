package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"derp-admit/internel/app/derp_admit/model"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// BootstrapKeyName is the reserved name of the startup-managed admin key
// derived from ADMIN_API_KEY (decision D3 / R11).
const BootstrapKeyName = "bootstrap"

const (
	// Transaction-scoped PostgreSQL advisory lock coordinates shared by
	// SyncBootstrapKey and RevokeAdminKey so concurrent startup syncs and
	// last-admin revocations serialize cleanly under READ COMMITTED.
	adminKeyLockClass int32 = 0x6461646d // "dadm"
	adminKeyLockObj   int32 = 1
)

var errBootstrapRace = errors.New("bootstrap key concurrent creation")

func isAdminKeyActive(k model.AdminKey, now time.Time) bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
		return false
	}
	return true
}

func lockAdminKeyMutation(tx *gorm.DB) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?, ?)", adminKeyLockClass, adminKeyLockObj).Error; err != nil {
		return fmt.Errorf("acquire admin key lock: %w", err)
	}
	return nil
}

func lockedAdminKeyQuery(tx *gorm.DB) *gorm.DB {
	if tx.Dialector.Name() == "sqlite" {
		return tx
	}
	return tx.Clauses(clause.Locking{Strength: "UPDATE"})
}

// SyncBootstrapKey reconciles the startup-managed "bootstrap" admin key with
// ADMIN_API_KEY (decision D3):
//  1. If "bootstrap" exists and is active, update its hash to match adminAPIKey.
//  2. Else, if no other active admin-tier key exists, create "bootstrap" (or
//     reactivate the existing row by clearing revoked_at and expires_at).
//  3. Else, leave "bootstrap" untouched and log at warning level that
//     ADMIN_API_KEY grants no access.
//
// Creating, reactivating, or re-hashing "bootstrap" writes one system admin
// audit row in the same transaction. No-op startups write no audit row.
func (s *Service) SyncBootstrapKey(ctx context.Context, adminAPIKey string) error {
	if adminAPIKey == "" {
		return nil
	}

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	keyHash := s.hashToken(adminAPIKey)
	ignored := false
	type hashCollision struct {
		name string
		tier string
	}
	var collision *hashCollision

	err := s.db.WithContext(dbCtx).Transaction(func(tx *gorm.DB) error {
		if err := lockAdminKeyMutation(tx); err != nil {
			return err
		}

		var hashOwner model.AdminKey
		hashLookupErr := lockedAdminKeyQuery(tx).Where("key_hash = ?", keyHash).First(&hashOwner).Error
		switch {
		case hashLookupErr == nil:
			if hashOwner.Name != BootstrapKeyName {
				collision = &hashCollision{name: hashOwner.Name, tier: hashOwner.Tier}
				return nil
			}
		case errors.Is(hashLookupErr, gorm.ErrRecordNotFound):
			// No existing key owns this hash.
		default:
			return fmt.Errorf("lookup admin key by hash: %w", hashLookupErr)
		}

		now := time.Now().UTC()

		var bootstrap model.AdminKey
		bootstrapExists := false
		lookupErr := lockedAdminKeyQuery(tx).Where("name = ?", BootstrapKeyName).First(&bootstrap).Error
		switch {
		case lookupErr == nil:
			bootstrapExists = true
		case errors.Is(lookupErr, gorm.ErrRecordNotFound):
			bootstrapExists = false
		default:
			return fmt.Errorf("lookup bootstrap admin key: %w", lookupErr)
		}

		// Step 1: active bootstrap key follows ADMIN_API_KEY.
		if bootstrapExists && isAdminKeyActive(bootstrap, now) {
			if bootstrap.KeyHash == keyHash {
				return nil
			}
			if err := tx.Model(&model.AdminKey{}).Where("id = ?", bootstrap.ID).
				Update("key_hash", keyHash).Error; err != nil {
				return fmt.Errorf("update bootstrap admin key hash: %w", err)
			}
			return InsertSystemAudit(tx, "bootstrap.rotate", "admin_key", bootstrap.ID.String(), map[string]any{
				"name":   BootstrapKeyName,
				"tier":   bootstrap.Tier,
				"reason": "rotated",
			})
		}

		// Step 2: check whether any other active admin-tier key exists.
		var nonRevokedAdmins []model.AdminKey
		if err := lockedAdminKeyQuery(tx).
			Where("tier = ? AND revoked_at IS NULL", model.AdminTierAdmin).
			Order("id ASC").
			Find(&nonRevokedAdmins).Error; err != nil {
			return fmt.Errorf("list active admin keys: %w", err)
		}
		hasOtherActiveAdmin := false
		for _, k := range nonRevokedAdmins {
			if k.Name != BootstrapKeyName && isAdminKeyActive(k, now) {
				hasOtherActiveAdmin = true
				break
			}
		}

		if hasOtherActiveAdmin {
			// Step 3: another active admin key has taken over; ADMIN_API_KEY grants nothing.
			ignored = true
			return nil
		}

		if !bootstrapExists {
			created := model.AdminKey{
				Name:    BootstrapKeyName,
				Tier:    model.AdminTierAdmin,
				KeyHash: keyHash,
			}
			if err := tx.Create(&created).Error; err != nil {
				if errors.Is(err, gorm.ErrDuplicatedKey) {
					return errBootstrapRace
				}
				return fmt.Errorf("create bootstrap admin key: %w", err)
			}
			return InsertSystemAudit(tx, "bootstrap.create", "admin_key", created.ID.String(), map[string]any{
				"name": BootstrapKeyName,
				"tier": model.AdminTierAdmin,
			})
		}

		// Existing bootstrap row is revoked or expired: reactivate it.
		if err := tx.Model(&model.AdminKey{}).Where("id = ?", bootstrap.ID).Updates(map[string]any{
			"tier":       model.AdminTierAdmin,
			"key_hash":   keyHash,
			"revoked_at": nil,
			"expires_at": nil,
		}).Error; err != nil {
			return fmt.Errorf("reactivate bootstrap admin key: %w", err)
		}
		return InsertSystemAudit(tx, "bootstrap.reactivate", "admin_key", bootstrap.ID.String(), map[string]any{
			"name":   BootstrapKeyName,
			"tier":   model.AdminTierAdmin,
			"reason": "reactivated",
		})
	})
	if errors.Is(err, errBootstrapRace) {
		// Verify another replica actually created the bootstrap row rather than
		// a key_hash collision against an unrelated named key.
		var existing model.AdminKey
		if checkErr := s.db.WithContext(dbCtx).Where("name = ?", BootstrapKeyName).First(&existing).Error; checkErr == nil {
			return nil
		}
		return fmt.Errorf("create bootstrap admin key: %w", gorm.ErrDuplicatedKey)
	}
	if err != nil {
		return err
	}

	if collision != nil {
		loggerWithTrace(s.logger, ctx).Error(
			"ADMIN_API_KEY matches an existing admin key and was not installed as bootstrap",
			zap.String("key_name", collision.name),
			zap.String("key_tier", collision.tier),
		)
		return nil
	}

	if ignored {
		loggerWithTrace(s.logger, ctx).Warn("ADMIN_API_KEY grants no access: bootstrap key is inactive and another active admin key exists")
	}

	return nil
}
