package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func (s *Service) ListDevices(ctx context.Context, userID *uuid.UUID, pg page.Request) ([]model.Device, *string, error) {
	if pg.After != nil {
		if _, err := uuid.Parse(pg.After.K); err != nil {
			return nil, nil, fmt.Errorf("%w: invalid cursor", ErrAdminInvalid)
		}
	}

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	q := s.db.WithContext(dbCtx).Model(&model.Device{})
	if userID != nil {
		q = q.Where("user_id = ?", *userID)
	}

	var devices []model.Device
	if err := page.Asc(q, pg, "created_at", "id", page.KeyString).Find(&devices).Error; err != nil {
		if errors.Is(err, page.ErrInvalid) {
			return nil, nil, fmt.Errorf("%w: %v", ErrAdminInvalid, err)
		}
		return nil, nil, fmt.Errorf("list devices: %w", err)
	}

	devices, nextCursor := page.Cut(devices, pg, func(d model.Device) (time.Time, string) {
		return d.CreatedAt, d.ID.String()
	})
	return devices, nextCursor, nil
}

// SetDeviceRevoked toggles a device's revoked state and purges cached
// decisions so the change takes effect immediately. Revoking preserves the
// device row and any legacy device rule; only DeleteDevice forgets them.
func (s *Service) SetDeviceRevoked(ctx context.Context, id uuid.UUID, revoked bool) error {
	return s.Mutate(ctx, EffectCache, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		var device model.Device
		if err := tx.First(&device, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup device: %w", err)
		}

		ch.TargetID = id.String()
		ch.Summary = map[string]any{"revoked": revoked}
		if revoked == (device.RevokedAt != nil) {
			// Already in the requested state; keep the original timestamp.
			ch.Changed = false
			return nil
		}

		var revokedAt *time.Time
		if revoked {
			now := time.Now().UTC()
			revokedAt = &now
		}
		if err := tx.Model(&model.Device{}).
			Where("id = ?", id).Update("revoked_at", revokedAt).Error; err != nil {
			return fmt.Errorf("update device: %w", err)
		}

		ch.Changed = true
		return nil
	})
}

// DeleteDevice removes the device and its legacy device rule while preserving
// verify audit rows with device_id set to null.
func (s *Service) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	return s.Mutate(ctx, EffectCache, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		var device model.Device
		if err := tx.First(&device, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup device: %w", err)
		}

		if err := tx.Model(&model.AuditLog{}).
			Where("device_id = ?", id).
			Update("device_id", nil).Error; err != nil {
			return fmt.Errorf("clear verify audit device_id: %w", err)
		}

		if err := policy.DeleteLegacyDeviceRule(tx, device.NodeKey, device.UserID); err != nil {
			return fmt.Errorf("delete legacy device rule: %w", err)
		}

		res := tx.Where("id = ?", id).Delete(&model.Device{})
		if res.Error != nil {
			return fmt.Errorf("delete device: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrAdminNotFound
		}

		ch.Changed = true
		ch.TargetID = id.String()
		ch.Summary = map[string]any{
			"userId":  device.UserID.String(),
			"nodeKey": device.NodeKey,
		}
		return nil
	})
}
