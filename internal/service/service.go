package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"derp-admit/internal/derp"
	"derp-admit/internal/model"
	"derp-admit/internal/policy"

	"github.com/google/uuid"
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

type Service struct {
	db          *gorm.DB
	policy      *policy.Engine
	tokenPepper string
	dbTimeout   time.Duration
	cache       *VerifyCache
	logger      *slog.Logger
}

type RegisterInput struct {
	Token   string `json:"token"`
	NodeKey string `json:"nodeKey"`
	Label   string `json:"label"`
}

func New(db *gorm.DB, policyEngine *policy.Engine, tokenPepper string, dbTimeout time.Duration, cache *VerifyCache, logger *slog.Logger) *Service {
	return &Service{
		db:          db,
		policy:      policyEngine,
		tokenPepper: tokenPepper,
		dbTimeout:   dbTimeout,
		cache:       cache,
		logger:      logger,
	}
}

func (s *Service) Register(ctx context.Context, in RegisterInput) (int, error) {
	in.Token = strings.TrimSpace(in.Token)
	in.NodeKey = strings.TrimSpace(in.NodeKey)
	in.Label = strings.TrimSpace(in.Label)

	if in.Token == "" || in.NodeKey == "" {
		return http.StatusBadRequest, nil
	}

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	now := time.Now().UTC()
	tokenHash := s.hashToken(in.Token)

	var enroll model.EnrollToken
	if err := s.db.WithContext(dbCtx).Where("token_hash = ?", tokenHash).First(&enroll).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusUnauthorized, nil
		}
		return http.StatusInternalServerError, fmt.Errorf("lookup token: %w", err)
	}

	if enroll.RevokedAt != nil || (enroll.ExpiresAt != nil && enroll.ExpiresAt.Before(now)) {
		return http.StatusForbidden, nil
	}

	var user model.User
	if err := s.db.WithContext(dbCtx).First(&user, "id = ?", enroll.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusForbidden, nil
		}
		return http.StatusInternalServerError, fmt.Errorf("lookup user: %w", err)
	}
	if user.DisabledAt != nil {
		return http.StatusForbidden, nil
	}

	var existing model.Device
	err := s.db.WithContext(dbCtx).Where("node_key = ?", in.NodeKey).First(&existing).Error
	switch {
	case err == nil:
		if existing.UserID != enroll.UserID {
			return http.StatusConflict, nil
		}
		updates := map[string]any{}
		if existing.RevokedAt != nil {
			updates["revoked_at"] = nil
		}
		if in.Label != "" {
			updates["label"] = in.Label
		}
		if len(updates) > 0 {
			if err := s.db.WithContext(dbCtx).Model(&model.Device{}).Where("id = ?", existing.ID).Updates(updates).Error; err != nil {
				return http.StatusInternalServerError, fmt.Errorf("update existing device: %w", err)
			}
		}
		if err := s.policy.EnsureDeviceForUser(in.NodeKey, enroll.UserID); err != nil {
			return http.StatusInternalServerError, fmt.Errorf("ensure policy bindings: %w", err)
		}
		s.cache.Invalidate(in.NodeKey)
		return http.StatusOK, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		// continue
	default:
		return http.StatusInternalServerError, fmt.Errorf("lookup device: %w", err)
	}

	if enroll.MaxDevices > 0 {
		var count int64
		if err := s.db.WithContext(dbCtx).
			Model(&model.Device{}).
			Where("user_id = ? AND revoked_at IS NULL", enroll.UserID).
			Count(&count).Error; err != nil {
			return http.StatusInternalServerError, fmt.Errorf("count active devices: %w", err)
		}
		if count >= int64(enroll.MaxDevices) {
			return http.StatusForbidden, nil
		}
	}

	device := model.Device{
		UserID:  enroll.UserID,
		NodeKey: in.NodeKey,
		Label:   in.Label,
	}
	if err := s.db.WithContext(dbCtx).Create(&device).Error; err != nil {
		return http.StatusInternalServerError, fmt.Errorf("create device: %w", err)
	}

	if err := s.policy.EnsureDeviceForUser(in.NodeKey, enroll.UserID); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("ensure policy bindings: %w", err)
	}

	s.cache.Invalidate(in.NodeKey)
	return http.StatusOK, nil
}

func (s *Service) Verify(ctx context.Context, body []byte) (bool, string) {
	_, nodeKey, err := derp.ParseRequest(body)
	if err != nil {
		s.logger.Warn("invalid verify request", "error", err)
		s.writeAudit(context.Background(), nil, "", false, DenyReasonInvalidReq)
		return false, DenyReasonInvalidReq
	}

	if cached, ok := s.cache.Get(nodeKey); ok {
		s.writeAudit(context.Background(), cached.DeviceID, nodeKey, cached.Allow, cached.Reason)
		return cached.Allow, cached.Reason
	}

	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var device model.Device
	if err := s.db.WithContext(dbCtx).Where("node_key = ?", nodeKey).First(&device).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			s.writeAudit(context.Background(), nil, nodeKey, false, DenyReasonNotRegistered)
			s.cache.Set(nodeKey, false, DenyReasonNotRegistered, nil)
			return false, DenyReasonNotRegistered
		}
		s.logger.Error("lookup device during verify", "error", err)
		s.writeAudit(context.Background(), nil, nodeKey, false, DenyReasonInternal)
		return false, DenyReasonInternal
	}

	if device.RevokedAt != nil {
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonRevoked)
		s.cache.Set(nodeKey, false, DenyReasonRevoked, &deviceID)
		return false, DenyReasonRevoked
	}

	var user model.User
	if err := s.db.WithContext(dbCtx).First(&user, "id = ?", device.UserID).Error; err != nil {
		s.logger.Error("lookup user during verify", "error", err)
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonInternal)
		return false, DenyReasonInternal
	}
	if user.DisabledAt != nil {
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonUserDisabled)
		s.cache.Set(nodeKey, false, DenyReasonUserDisabled, &deviceID)
		return false, DenyReasonUserDisabled
	}

	allowed, err := s.policy.EnforceConnect(nodeKey)
	if err != nil {
		s.logger.Error("policy enforce failed", "error", err)
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonInternal)
		return false, DenyReasonInternal
	}
	if !allowed {
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonPolicyDenied)
		s.cache.Set(nodeKey, false, DenyReasonPolicyDenied, &deviceID)
		return false, DenyReasonPolicyDenied
	}

	now := time.Now().UTC()
	if err := s.db.WithContext(dbCtx).
		Model(&model.Device{}).
		Where("id = ?", device.ID).
		Update("last_seen_at", now).Error; err != nil {
		s.logger.Error("update last_seen_at", "error", err)
		deviceID := device.ID
		s.writeAudit(context.Background(), &deviceID, nodeKey, false, DenyReasonInternal)
		return false, DenyReasonInternal
	}

	deviceID := device.ID
	s.writeAudit(context.Background(), &deviceID, nodeKey, true, "")
	s.cache.Set(nodeKey, true, "", &deviceID)
	return true, ""
}

func (s *Service) Ping(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("get sql db: %w", err)
	}
	return sqlDB.PingContext(ctx)
}

func (s *Service) hashToken(token string) string {
	sum := sha256.Sum256([]byte(token + ":" + s.tokenPepper))
	return hex.EncodeToString(sum[:])
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
		s.logger.Error("write audit log", "error", err)
	}
}
