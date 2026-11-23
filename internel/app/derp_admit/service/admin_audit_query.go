package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"

	"github.com/google/uuid"
)

type AdminAuditFilter struct {
	ActorKeyID *uuid.UUID
	Action     string
	TargetType string
	TargetID   string
	Since      *time.Time
	Until      *time.Time
}

type VerifyAuditFilter struct {
	NodeKey  string
	DeviceID *uuid.UUID
	Relay    string
	Allowed  *bool
	Since    *time.Time
	Until    *time.Time
}

func (s *Service) ListAdminAudit(ctx context.Context, filter AdminAuditFilter, pg page.Request) ([]model.AdminAuditLog, *string, error) {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	q := s.db.WithContext(dbCtx).Model(&model.AdminAuditLog{})
	if filter.ActorKeyID != nil {
		q = q.Where("actor_key_id = ?", *filter.ActorKeyID)
	}
	if filter.Action != "" {
		q = q.Where("action = ?", filter.Action)
	}
	if filter.TargetType != "" {
		q = q.Where("target_type = ?", filter.TargetType)
	}
	if filter.TargetID != "" {
		q = q.Where("target_id = ?", filter.TargetID)
	}
	if filter.Since != nil {
		q = q.Where("ts >= ?", filter.Since.UTC())
	}
	if filter.Until != nil {
		q = q.Where("ts <= ?", filter.Until.UTC())
	}

	var rows []model.AdminAuditLog
	if err := page.Desc(q, pg, "ts", "id", page.KeyInt).Find(&rows).Error; err != nil {
		if errors.Is(err, page.ErrInvalid) {
			return nil, nil, fmt.Errorf("%w: %v", ErrAdminInvalid, err)
		}
		return nil, nil, fmt.Errorf("list admin audit logs: %w", err)
	}

	rows, nextCursor := page.Cut(rows, pg, func(e model.AdminAuditLog) (time.Time, string) {
		return e.TS, strconv.FormatInt(e.ID, 10)
	})
	return rows, nextCursor, nil
}

func (s *Service) ListVerifyAudit(ctx context.Context, filter VerifyAuditFilter, pg page.Request) ([]model.AuditLog, *string, error) {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	q := s.db.WithContext(dbCtx).Model(&model.AuditLog{})
	if filter.NodeKey != "" {
		q = q.Where("node_key = ?", filter.NodeKey)
	}
	if filter.DeviceID != nil {
		q = q.Where("device_id = ?", *filter.DeviceID)
	}
	if filter.Relay != "" {
		q = q.Where("relay = ?", filter.Relay)
	}
	if filter.Allowed != nil {
		q = q.Where("allowed = ?", *filter.Allowed)
	}
	if filter.Since != nil {
		q = q.Where("ts >= ?", filter.Since.UTC())
	}
	if filter.Until != nil {
		q = q.Where("ts <= ?", filter.Until.UTC())
	}

	var rows []model.AuditLog
	if err := page.Desc(q, pg, "ts", "id", page.KeyInt).Find(&rows).Error; err != nil {
		if errors.Is(err, page.ErrInvalid) {
			return nil, nil, fmt.Errorf("%w: %v", ErrAdminInvalid, err)
		}
		return nil, nil, fmt.Errorf("list verify audit logs: %w", err)
	}

	rows, nextCursor := page.Cut(rows, pg, func(e model.AuditLog) (time.Time, string) {
		return e.TS, strconv.FormatInt(e.ID, 10)
	})
	return rows, nextCursor, nil
}
