package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	AuditOutcomeSuccess = "success"
	AuditOutcomeFailure = "failure"
)

func insertAdminAudit(tx *gorm.DB, ctx context.Context, op *actor.Op, ch *Change, status int) error {
	a, _ := actor.From(ctx)
	targetID := op.TargetID
	if ch != nil && ch.TargetID != "" {
		targetID = ch.TargetID
	}
	var summaryMap map[string]any
	if ch != nil {
		summaryMap = ch.Summary
	}
	summary, err := encodeAuditSummary(summaryMap)
	if err != nil {
		return fmt.Errorf("encode admin audit summary: %w", err)
	}

	st := status
	entry := model.AdminAuditLog{
		TS:         time.Now().UTC(),
		ActorKeyID: copyUUIDPtr(a.KeyID),
		ActorName:  a.Name,
		ActorTier:  a.Tier.String(),
		Action:     op.Action,
		TargetType: op.TargetType,
		TargetID:   targetID,
		Outcome:    AuditOutcomeSuccess,
		HTTPStatus: &st,
		ClientIP:   a.IP,
		Summary:    summary,
	}
	if err := tx.Create(&entry).Error; err != nil {
		return fmt.Errorf("insert admin audit log: %w", err)
	}
	return nil
}

// WriteAdminAuditFailure writes a standalone admin audit row for an
// authenticated mutating request that failed (400, 403, 404, 409, 500) after
// any transaction rolled back or before Mutate ran.
func (s *Service) WriteAdminAuditFailure(ctx context.Context, status int) {
	a, hasActor := actor.From(ctx)
	op, hasOp := actor.OpFrom(ctx)
	if !hasActor || !hasOp {
		return
	}

	auditCtx, cancel := context.WithTimeout(context.Background(), s.dbTimeout)
	defer cancel()

	st := status
	entry := model.AdminAuditLog{
		TS:         time.Now().UTC(),
		ActorKeyID: copyUUIDPtr(a.KeyID),
		ActorName:  a.Name,
		ActorTier:  a.Tier.String(),
		Action:     op.Action,
		TargetType: op.TargetType,
		TargetID:   op.TargetID,
		Outcome:    AuditOutcomeFailure,
		HTTPStatus: &st,
		ClientIP:   a.IP,
		Summary:    "{}",
	}
	if err := s.db.WithContext(auditCtx).Create(&entry).Error; err != nil {
		loggerWithTrace(s.logger, ctx).Error("write admin audit failure row",
			zap.Error(err),
			zap.String("action", op.Action),
			zap.Int("http_status", status),
		)
	}
}

// InsertSystemAudit writes an admin audit row attributed to actor.System
// inside the caller's transaction.
func InsertSystemAudit(tx *gorm.DB, action, targetType, targetID string, summary map[string]any) error {
	encoded, err := encodeAuditSummary(summary)
	if err != nil {
		return fmt.Errorf("encode system audit summary: %w", err)
	}

	entry := model.AdminAuditLog{
		TS:         time.Now().UTC(),
		ActorKeyID: nil,
		ActorName:  actor.System.Name,
		ActorTier:  actor.System.Tier.String(),
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Outcome:    AuditOutcomeSuccess,
		HTTPStatus: nil,
		ClientIP:   "",
		Summary:    encoded,
	}
	if err := tx.Create(&entry).Error; err != nil {
		return fmt.Errorf("insert system audit log: %w", err)
	}
	return nil
}

func encodeAuditSummary(summary map[string]any) (string, error) {
	if len(summary) == 0 {
		return "{}", nil
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func copyUUIDPtr(id *uuid.UUID) *uuid.UUID {
	if id == nil {
		return nil
	}
	copied := *id
	return &copied
}
