package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"derp-admit/internel/app/derp_admit/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

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
