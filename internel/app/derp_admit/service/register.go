package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RegisterInput struct {
	Token   string `json:"token"`
	NodeKey string `json:"nodeKey"`
	Label   string `json:"label"`
}

// Sentinel results the registration transaction maps to HTTP statuses.
var (
	errRegisterForbidden = errors.New("registration forbidden")
	errRegisterConflict  = errors.New("registration conflict")
)

func (s *Service) Register(ctx context.Context, in RegisterInput) (int, error) {
	in.Token = strings.TrimSpace(in.Token)
	in.NodeKey = strings.TrimSpace(in.NodeKey)
	in.Label = strings.TrimSpace(in.Label)

	if in.Token == "" || in.NodeKey == "" {
		return http.StatusBadRequest, nil
	}

	normalizedKey, err := derp.NormalizeNodeKey(in.NodeKey)
	if err != nil {
		return http.StatusBadRequest, nil
	}
	in.NodeKey = normalizedKey

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	tokenHash := s.hashToken(in.Token)

	// Fast-path rejection without opening a transaction; token and user
	// state are re-validated under lock inside the transaction below.
	var enroll model.EnrollToken
	if err := s.db.WithContext(dbCtx).Where("token_hash = ?", tokenHash).First(&enroll).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusUnauthorized, nil
		}
		return http.StatusInternalServerError, fmt.Errorf("lookup token: %w", err)
	}
	if enroll.RevokedAt != nil || (enroll.ExpiresAt != nil && enroll.ExpiresAt.Before(time.Now().UTC())) {
		return http.StatusForbidden, nil
	}

	// The transaction serializes concurrent registrations for the same user
	// (MaxDevices check-then-create) and re-validates the token and user on
	// locked rows, so an admin revoke/disable landing after the fast-path
	// checks cannot still produce an enrolled device.
	txErr := s.db.WithContext(dbCtx).Transaction(func(tx *gorm.DB) error {
		lockQuery := tx
		if tx.Dialector.Name() != "sqlite" {
			// sqlite has no SELECT ... FOR UPDATE; its write transactions are
			// serialized whole-database via the _txlock=immediate DSN option.
			lockQuery = tx.Clauses(clause.Locking{Strength: "UPDATE"})
		}

		now := time.Now().UTC()
		var token model.EnrollToken
		if err := lockQuery.First(&token, "id = ?", enroll.ID).Error; err != nil {
			return fmt.Errorf("lock token: %w", err)
		}
		if token.RevokedAt != nil || (token.ExpiresAt != nil && token.ExpiresAt.Before(now)) {
			return errRegisterForbidden
		}

		var user model.User
		if err := lockQuery.First(&user, "id = ?", token.UserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errRegisterForbidden
			}
			return fmt.Errorf("lock user: %w", err)
		}
		if user.DisabledAt != nil {
			return errRegisterForbidden
		}

		var existing model.Device
		err := tx.Where("node_key = ?", in.NodeKey).First(&existing).Error
		switch {
		case err == nil:
			if existing.UserID != token.UserID {
				return errRegisterConflict
			}
			if existing.RevokedAt != nil {
				return errRegisterForbidden
			}
			if in.Label != "" {
				if err := tx.Model(&model.Device{}).Where("id = ?", existing.ID).Update("label", in.Label).Error; err != nil {
					return fmt.Errorf("update existing device: %w", err)
				}
			}
			return nil
		case errors.Is(err, gorm.ErrRecordNotFound):
			// fall through to create
		default:
			return fmt.Errorf("lookup device: %w", err)
		}

		if err := checkDeviceLimit(tx, token); err != nil {
			return err
		}

		device := model.Device{
			UserID:  token.UserID,
			NodeKey: in.NodeKey,
			Label:   in.Label,
		}
		if err := tx.Create(&device).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				// Lost a same-node-key race against a concurrent registration.
				return errRegisterConflict
			}
			return fmt.Errorf("create device: %w", err)
		}
		return nil
	})
	switch {
	case txErr == nil:
	case errors.Is(txErr, errRegisterForbidden):
		return http.StatusForbidden, nil
	case errors.Is(txErr, errRegisterConflict):
		return http.StatusConflict, nil
	default:
		return http.StatusInternalServerError, txErr
	}

	policyErr := s.policy.EnsureDeviceForUser(in.NodeKey, enroll.UserID)
	// The device row is committed either way, so any cached decision for this
	// key is stale even when the policy write failed.
	s.cache.Invalidate(in.NodeKey)
	if policyErr != nil {
		return http.StatusInternalServerError, fmt.Errorf("ensure policy bindings: %w", policyErr)
	}

	return http.StatusOK, nil
}

// checkDeviceLimit returns errRegisterForbidden when the token's MaxDevices
// cap (0 = unlimited) is already reached by the user's active devices.
func checkDeviceLimit(tx *gorm.DB, token model.EnrollToken) error {
	if token.MaxDevices <= 0 {
		return nil
	}
	var count int64
	if err := tx.Model(&model.Device{}).
		Where("user_id = ? AND revoked_at IS NULL", token.UserID).
		Count(&count).Error; err != nil {
		return fmt.Errorf("count active devices: %w", err)
	}
	if count >= int64(token.MaxDevices) {
		return errRegisterForbidden
	}
	return nil
}
