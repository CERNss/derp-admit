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
	ID       int64      `gorm:"primaryKey;autoIncrement;index:idx_audit_logs_relay_ts_id,priority:3,sort:desc"`
	DeviceID *uuid.UUID `gorm:"type:uuid;index:idx_audit_logs_device_ts,priority:1"`
	NodeKey  string
	Relay    *string `gorm:"type:text;index:idx_audit_logs_relay_ts_id,priority:1"`
	Allowed  bool
	Reason   string
	TS       time.Time `gorm:"not null;index:idx_audit_logs_ts;index:idx_audit_logs_device_ts,priority:2;index:idx_audit_logs_relay_ts_id,priority:2,sort:desc"`
}

func (a *AuditLog) BeforeCreate(_ *gorm.DB) error {
	if a.TS.IsZero() {
		a.TS = time.Now().UTC()
	}
	return nil
}

type Role struct {
	Name        string    `gorm:"type:text;primaryKey;not null"`
	Description string    `gorm:"type:text;not null;default:''"`
	AllRelays   bool      `gorm:"not null;default:false"`
	CreatedAt   time.Time `gorm:"not null"`
}

func (r *Role) BeforeCreate(_ *gorm.DB) error {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	return nil
}

type Relay struct {
	Name        string    `gorm:"type:text;primaryKey;not null"`
	Description string    `gorm:"type:text;not null;default:''"`
	CreatedAt   time.Time `gorm:"not null"`
}

func (r *Relay) BeforeCreate(_ *gorm.DB) error {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	return nil
}

const PolicyStateRowID = 1

type PolicyState struct {
	ID         int   `gorm:"primaryKey;autoIncrement:false;not null;check:id = 1"`
	Version    int64 `gorm:"not null;default:0"`
	UpgradedAt *time.Time
}

func (PolicyState) TableName() string {
	return "policy_state"
}

const (
	AdminTierViewer   = "viewer"
	AdminTierOperator = "operator"
	AdminTierAdmin    = "admin"
)

type AdminKey struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;not null"`
	Name       string     `gorm:"uniqueIndex;not null"`
	Tier       string     `gorm:"not null;check:tier IN ('viewer','operator','admin');index:idx_admin_keys_tier"`
	KeyHash    string     `gorm:"uniqueIndex;not null"`
	CreatedAt  time.Time  `gorm:"not null"`
	ExpiresAt  *time.Time `gorm:"index:idx_admin_keys_expires_at"`
	RevokedAt  *time.Time `gorm:"index:idx_admin_keys_revoked_at"`
	LastUsedAt *time.Time
}

func (k *AdminKey) BeforeCreate(_ *gorm.DB) error {
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	return nil
}

type AdminAuditLog struct {
	ID         int64      `gorm:"primaryKey;autoIncrement;index:idx_admin_audit_logs_ts_id,priority:2,sort:desc;index:idx_admin_audit_logs_actor_key_ts_id,priority:3,sort:desc;index:idx_admin_audit_logs_action_ts_id,priority:3,sort:desc;index:idx_admin_audit_logs_target_ts_id,priority:4,sort:desc"`
	TS         time.Time  `gorm:"not null;index:idx_admin_audit_logs_ts_id,priority:1,sort:desc;index:idx_admin_audit_logs_actor_key_ts_id,priority:2,sort:desc;index:idx_admin_audit_logs_action_ts_id,priority:2,sort:desc;index:idx_admin_audit_logs_target_ts_id,priority:3,sort:desc"`
	ActorKeyID *uuid.UUID `gorm:"type:uuid;index:idx_admin_audit_logs_actor_key_ts_id,priority:1"`
	ActorName  string     `gorm:"not null"`
	ActorTier  string     `gorm:"not null;default:''"`
	Action     string     `gorm:"not null;index:idx_admin_audit_logs_action_ts_id,priority:1"`
	TargetType string     `gorm:"not null;default:'';index:idx_admin_audit_logs_target_ts_id,priority:1"`
	TargetID   string     `gorm:"not null;default:'';index:idx_admin_audit_logs_target_ts_id,priority:2"`
	Outcome    string     `gorm:"not null"`
	HTTPStatus *int
	ClientIP   string `gorm:"not null;default:''"`
	Summary    string `gorm:"not null;default:''"`
}

func (a *AdminAuditLog) BeforeCreate(_ *gorm.DB) error {
	if a.TS.IsZero() {
		a.TS = time.Now().UTC()
	}
	return nil
}

type CasbinRule struct {
	ID    int64  `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"column:ptype;size:100;not null;index:idx_casbin_rule_ptype"`
	V0    string `gorm:"column:v0;size:100;index:idx_casbin_rule_v0"`
	V1    string `gorm:"column:v1;size:100;index:idx_casbin_rule_v1"`
	V2    string `gorm:"column:v2;size:100;index:idx_casbin_rule_v2"`
	V3    string `gorm:"column:v3;size:100"`
	V4    string `gorm:"column:v4;size:100"`
	V5    string `gorm:"column:v5;size:100"`
}

func (CasbinRule) TableName() string {
	return "casbin_rule"
}
