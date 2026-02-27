package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey"`
	Username   string     `gorm:"uniqueIndex;not null"`
	Email      *string    `gorm:"uniqueIndex"`
	DisabledAt *time.Time `gorm:"index:idx_users_disabled_at"`
	CreatedAt  time.Time  `gorm:"not null"`
}

func (u *User) BeforeCreate(_ *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	return nil
}

type EnrollToken struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey"`
	UserID     uuid.UUID  `gorm:"type:uuid;index:idx_enroll_tokens_user_id;not null"`
	TokenHash  string     `gorm:"uniqueIndex;not null"`
	ExpiresAt  *time.Time `gorm:"index:idx_enroll_tokens_expires_at"`
	RevokedAt  *time.Time `gorm:"index:idx_enroll_tokens_revoked_at"`
	MaxDevices int        `gorm:"not null;default:0"`
	Note       string
	CreatedAt  time.Time `gorm:"not null"`
	User       User      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (e *EnrollToken) BeforeCreate(_ *gorm.DB) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	return nil
}

type Device struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID     uuid.UUID `gorm:"type:uuid;index:idx_devices_user_id;not null"`
	NodeKey    string    `gorm:"uniqueIndex;not null"`
	Label      string
	CreatedAt  time.Time  `gorm:"not null"`
	LastSeenAt *time.Time `gorm:"index:idx_devices_last_seen_at"`
	RevokedAt  *time.Time `gorm:"index:idx_devices_revoked_at"`
	User       User       `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (d *Device) BeforeCreate(_ *gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	return nil
}

type AuditLog struct {
	ID       int64      `gorm:"primaryKey;autoIncrement"`
	DeviceID *uuid.UUID `gorm:"type:uuid;index:idx_audit_logs_device_ts,priority:1"`
	NodeKey  string
	Allowed  bool
	Reason   string
	TS       time.Time `gorm:"not null;index:idx_audit_logs_ts;index:idx_audit_logs_device_ts,priority:2"`
}

func (a *AuditLog) BeforeCreate(_ *gorm.DB) error {
	if a.TS.IsZero() {
		a.TS = time.Now().UTC()
	}
	return nil
}
