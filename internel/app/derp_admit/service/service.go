package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/derp"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	logger      *zap.Logger
}

type RegisterInput struct {
	Token   string `json:"token"`
	NodeKey string `json:"nodeKey"`
	Label   string `json:"label"`
}

func New(db *gorm.DB, policyEngine *policy.Engine, tokenPepper string, dbTimeout time.Duration, cache *VerifyCache, logger *zap.Logger) *Service {
	return &Service{
		db:          db,
		policy:      policyEngine,
		tokenPepper: tokenPepper,
		dbTimeout:   dbTimeout,
		cache:       cache,
		logger:      logger,
	}
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
			updates := map[string]any{}
			if existing.RevokedAt != nil {
				// Reactivating a revoked device re-counts against the limit.
				if err := checkDeviceLimit(tx, token); err != nil {
					return err
				}
				updates["revoked_at"] = nil
			}
			if in.Label != "" {
				updates["label"] = in.Label
			}
			if len(updates) > 0 {
				if err := tx.Model(&model.Device{}).Where("id = ?", existing.ID).Updates(updates).Error; err != nil {
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

func loggerWithTrace(logger *zap.Logger, ctx context.Context) *zap.Logger {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return logger
	}

	return logger.With(
		zap.String("trace_id", spanCtx.TraceID().String()),
		zap.String("span_id", spanCtx.SpanID().String()),
	)
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
		s.logger.Error("write audit log",
			zap.Error(err),
			zap.String("node_key", nodeKey),
			zap.Bool("allowed", allowed),
			zap.String("reason", reason),
		)
	}
}
