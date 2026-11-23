package service

import (
	"context"
	"errors"
	"time"

	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/model"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	DenyReasonNotRegistered = "not registered"
	DenyReasonRevoked       = "revoked"
	DenyReasonUserDisabled  = "user disabled"
	DenyReasonPolicyDenied  = "policy denied"
	DenyReasonInvalidReq    = "invalid request"
	DenyReasonInternal      = "internal error"
)

func (s *Service) Verify(ctx context.Context, body []byte) (bool, string) {
	logger := loggerWithTrace(s.logger, ctx)

	_, nodeKey, err := derp.ParseRequest(body)
	if err != nil {
		logger.Warn("invalid verify request", zap.Error(err))
		s.writeAudit(context.Background(), nil, "", false, DenyReasonInvalidReq)
		return false, DenyReasonInvalidReq
	}

	if cached, ok := s.cache.Get(nodeKey); ok {
		s.writeAudit(context.Background(), cached.DeviceID, nodeKey, cached.Allow, cached.Reason)
		return cached.Allow, cached.Reason
	}

	// Snapshot before the DB reads: if a revoke/disable/registration
	// invalidates this key while the decision is being computed, Set drops
	// the now-stale decision instead of caching it past the invalidation.
	epoch := s.cache.Epoch()

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var device model.Device
	if err := s.db.WithContext(dbCtx).Where("node_key = ?", nodeKey).First(&device).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			s.writeAudit(context.Background(), nil, nodeKey, false, DenyReasonNotRegistered)
			s.cache.Set(nodeKey, epoch, false, DenyReasonNotRegistered, nil)
			return false, DenyReasonNotRegistered
		}
		logger.Error("lookup device during verify",
			zap.Error(err),
			zap.String("node_key", nodeKey),
		)
		s.writeAudit(context.Background(), nil, nodeKey, false, DenyReasonInternal)
		return false, DenyReasonInternal
	}

	if device.RevokedAt != nil {
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonRevoked)
		s.cache.Set(nodeKey, epoch, false, DenyReasonRevoked, &deviceID)
		return false, DenyReasonRevoked
	}

	var user model.User
	if err := s.db.WithContext(dbCtx).First(&user, "id = ?", device.UserID).Error; err != nil {
		logger.Error("lookup user during verify",
			zap.Error(err),
			zap.String("node_key", nodeKey),
			zap.String("user_id", device.UserID.String()),
		)
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonInternal)
		return false, DenyReasonInternal
	}
	if user.DisabledAt != nil {
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonUserDisabled)
		s.cache.Set(nodeKey, epoch, false, DenyReasonUserDisabled, &deviceID)
		return false, DenyReasonUserDisabled
	}

	allowed, err := s.policy.EnforceConnect(nodeKey)
	if err != nil {
		logger.Error("policy enforce failed",
			zap.Error(err),
			zap.String("node_key", nodeKey),
		)
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonInternal)
		return false, DenyReasonInternal
	}
	if !allowed {
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonPolicyDenied)
		s.cache.Set(nodeKey, epoch, false, DenyReasonPolicyDenied, &deviceID)
		return false, DenyReasonPolicyDenied
	}

	now := time.Now().UTC()
	if err := s.db.WithContext(dbCtx).
		Model(&model.Device{}).
		Where("id = ?", device.ID).
		Update("last_seen_at", now).Error; err != nil {
		// last_seen_at is best-effort telemetry: a write failure must not turn
		// an otherwise-authorized client into a denial.
		logger.Warn("update last_seen_at",
			zap.Error(err),
			zap.String("node_key", nodeKey),
			zap.String("device_id", device.ID.String()),
		)
	}

	deviceID := device.ID
	s.writeAudit(context.Background(), &deviceID, nodeKey, true, "")
	s.cache.Set(nodeKey, epoch, true, "", &deviceID)
	return true, ""
}

func (s *Service) writeAudit(ctx context.Context, deviceID *uuid.UUID, nodeKey string, allowed bool, reason string) {
	auditCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	entry := model.AuditLog{
		DeviceID: deviceID,
		NodeKey:  nodeKey,
		Allowed:  allowed,
		Reason:   reason,
		TS:       time.Now().UTC(),
	}
	if err := s.db.WithContext(auditCtx).Create(&entry).Error; err != nil {
		s.logger.Error("write audit log",
			zap.Error(err),
			zap.String("node_key", nodeKey),
			zap.Bool("allowed", allowed),
			zap.String("reason", reason),
		)
	}
}
