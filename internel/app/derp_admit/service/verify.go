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

type verifyDecision struct {
	allow    bool
	reason   string
	nodeKey  string
	deviceID *uuid.UUID
	cache    bool
	epoch    uint64
}

func (s *Service) Verify(ctx context.Context, relay string, body []byte) (bool, string) {
	dec := s.decide(ctx, relay, body)
	s.finish(relay, dec)
	return dec.allow, dec.reason
}

func (s *Service) decide(ctx context.Context, _ string, body []byte) verifyDecision {
	logger := loggerWithTrace(s.logger, ctx)

	_, nodeKey, err := derp.ParseRequest(body)
	if err != nil {
		logger.Warn("invalid verify request", zap.Error(err))
		return verifyDecision{allow: false, reason: DenyReasonInvalidReq}
	}

	if s.sync.Stale() {
		logger.Error("policy sync stale, denying verify request",
			zap.String("node_key", nodeKey),
		)
		return verifyDecision{allow: false, reason: DenyReasonInternal, nodeKey: nodeKey}
	}

	if cached, ok := s.cache.Get(nodeKey); ok {
		s.metrics.CacheLookup(true)
		return verifyDecision{
			allow:    cached.Allow,
			reason:   cached.Reason,
			nodeKey:  nodeKey,
			deviceID: cached.DeviceID,
		}
	}
	if s.cache.Enabled() {
		s.metrics.CacheLookup(false)
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
			return verifyDecision{
				allow:   false,
				reason:  DenyReasonNotRegistered,
				nodeKey: nodeKey,
				cache:   true,
				epoch:   epoch,
			}
		}
		logger.Error("lookup device during verify",
			zap.Error(err),
			zap.String("node_key", nodeKey),
		)
		return verifyDecision{allow: false, reason: DenyReasonInternal, nodeKey: nodeKey}
	}

	deviceID := device.ID
	if device.RevokedAt != nil {
		return verifyDecision{
			allow:    false,
			reason:   DenyReasonRevoked,
			nodeKey:  nodeKey,
			deviceID: &deviceID,
			cache:    true,
			epoch:    epoch,
		}
	}

	var user model.User
	if err := s.db.WithContext(dbCtx).First(&user, "id = ?", device.UserID).Error; err != nil {
		logger.Error("lookup user during verify",
			zap.Error(err),
			zap.String("node_key", nodeKey),
			zap.String("user_id", device.UserID.String()),
		)
		return verifyDecision{allow: false, reason: DenyReasonInternal, nodeKey: nodeKey, deviceID: &deviceID}
	}
	if user.DisabledAt != nil {
		return verifyDecision{
			allow:    false,
			reason:   DenyReasonUserDisabled,
			nodeKey:  nodeKey,
			deviceID: &deviceID,
			cache:    true,
			epoch:    epoch,
		}
	}

	allowed, err := s.policy.EnforceConnect(nodeKey)
	if err != nil {
		logger.Error("policy enforce failed",
			zap.Error(err),
			zap.String("node_key", nodeKey),
		)
		return verifyDecision{allow: false, reason: DenyReasonInternal, nodeKey: nodeKey, deviceID: &deviceID}
	}
	if !allowed {
		return verifyDecision{
			allow:    false,
			reason:   DenyReasonPolicyDenied,
			nodeKey:  nodeKey,
			deviceID: &deviceID,
			cache:    true,
			epoch:    epoch,
		}
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

	return verifyDecision{
		allow:    true,
		reason:   "",
		nodeKey:  nodeKey,
		deviceID: &deviceID,
		cache:    true,
		epoch:    epoch,
	}
}

func (s *Service) finish(relay string, dec verifyDecision) {
	s.writeAudit(context.Background(), dec.deviceID, dec.nodeKey, dec.allow, dec.reason)
	if dec.cache {
		s.cache.Set(dec.nodeKey, dec.epoch, dec.allow, dec.reason, dec.deviceID)
	}
	s.metrics.VerifyDecision(relay, dec.allow, dec.reason)
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
