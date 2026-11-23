package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"tailscale.com/types/key"
)

func eNewTestService(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()

	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "delete-atomic.db")
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := gormDB.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("seed builtins: %v", err)
	}
	engine, err := policy.NewEngine(gormDB)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	return New(gormDB, engine, "test-pepper", 5*time.Second, NewVerifyCache(time.Minute), zap.NewNop()), gormDB
}

func eAdminCtx(action, targetType, targetID string) context.Context {
	keyID := uuid.New()
	ctx := actor.With(context.Background(), actor.Actor{
		KeyID: &keyID,
		Name:  "e-operator",
		Tier:  actor.TierOperator,
		IP:    "127.0.0.1",
	})
	return actor.WithOp(ctx, &actor.Op{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
	})
}

func eFailAdminAudit(t *testing.T, gormDB *gorm.DB, name string, forcedErr error) func() {
	t.Helper()
	if err := gormDB.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "admin_audit_logs" {
			_ = tx.AddError(forcedErr)
		}
	}); err != nil {
		t.Fatalf("register callback %s: %v", name, err)
	}
	return func() {
		_ = gormDB.Callback().Create().Remove(name)
	}
}

func TestAdminDeletesAreAtomic(t *testing.T) {
	svc, gormDB := eNewTestService(t)

	// Seed a user with a role binding, a token, a device, a legacy device rule,
	// and a verify audit row referencing the device.
	user, err := svc.CreateUser(context.Background(), CreateUserInput{Username: "atomic-del-user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	tokRes, err := svc.CreateToken(context.Background(), CreateTokenInput{
		UserID:     user.ID,
		MaxDevices: 1,
		Note:       "atomic-note",
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	nodeKey := key.NewNode().Public().String()
	dev := model.Device{
		ID:      uuid.New(),
		UserID:  user.ID,
		NodeKey: nodeKey,
		Label:   "laptop",
	}
	if err := gormDB.Create(&dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	legacyRule := model.CasbinRule{
		Ptype: "g",
		V0:    "device:" + nodeKey,
		V1:    policy.UserSubject(user.ID),
	}
	if err := gormDB.Create(&legacyRule).Error; err != nil {
		t.Fatalf("create legacy rule: %v", err)
	}
	relay := "default"
	auditRow := model.AuditLog{
		DeviceID: &dev.ID,
		NodeKey:  nodeKey,
		Relay:    &relay,
		Allowed:  true,
		TS:       time.Now().UTC(),
	}
	if err := gormDB.Create(&auditRow).Error; err != nil {
		t.Fatalf("create verify audit row: %v", err)
	}

	v0, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read initial version: %v", err)
	}

	assertAllIntact := func(t *testing.T, phase string) {
		t.Helper()

		var userCount, tokCount, devCount, roleBindingCount, legacyCount, adminAuditCount int64
		if err := gormDB.Model(&model.User{}).Where("id = ?", user.ID).Count(&userCount).Error; err != nil {
			t.Fatalf("%s count users: %v", phase, err)
		}
		if err := gormDB.Model(&model.EnrollToken{}).Where("id = ?", tokRes.Token.ID).Count(&tokCount).Error; err != nil {
			t.Fatalf("%s count tokens: %v", phase, err)
		}
		if err := gormDB.Model(&model.Device{}).Where("id = ?", dev.ID).Count(&devCount).Error; err != nil {
			t.Fatalf("%s count devices: %v", phase, err)
		}
		if err := gormDB.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ?", "g", policy.UserSubject(user.ID)).Count(&roleBindingCount).Error; err != nil {
			t.Fatalf("%s count role bindings: %v", phase, err)
		}
		if err := gormDB.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ? AND v1 = ?", "g", "device:"+nodeKey, policy.UserSubject(user.ID)).Count(&legacyCount).Error; err != nil {
			t.Fatalf("%s count legacy rules: %v", phase, err)
		}
		if err := gormDB.Model(&model.AdminAuditLog{}).Count(&adminAuditCount).Error; err != nil {
			t.Fatalf("%s count admin audit logs: %v", phase, err)
		}
		if userCount != 1 || tokCount != 1 || devCount != 1 || roleBindingCount != 1 || legacyCount != 1 || adminAuditCount != 0 {
			t.Fatalf("%s state mutated on rollback: users=%d tokens=%d devices=%d bindings=%d legacy=%d adminAudit=%d",
				phase, userCount, tokCount, devCount, roleBindingCount, legacyCount, adminAuditCount)
		}

		var gotAudit model.AuditLog
		if err := gormDB.First(&gotAudit, auditRow.ID).Error; err != nil {
			t.Fatalf("%s load verify audit: %v", phase, err)
		}
		if gotAudit.DeviceID == nil || *gotAudit.DeviceID != dev.ID {
			t.Fatalf("%s verify audit device_id=%v want=%s", phase, gotAudit.DeviceID, dev.ID)
		}

		ver, err := policy.ReadVersion(context.Background(), gormDB)
		if err != nil {
			t.Fatalf("%s read version: %v", phase, err)
		}
		if ver != v0 {
			t.Fatalf("%s policy version=%d want=%d", phase, ver, v0)
		}
	}

	forcedErr := errors.New("forced admin audit failure")
	cleanup := eFailAdminAudit(t, gormDB, "e_fail_admin_audit_deletes", forcedErr)
	defer cleanup()

	// 1. DeleteUser rolls back user, token, device, role binding, legacy rule, audit_logs.device_id, and version.
	if err := svc.DeleteUser(eAdminCtx("user.delete", "user", user.ID.String()), user.ID); !errors.Is(err, forcedErr) {
		t.Fatalf("DeleteUser err=%v want %v", err, forcedErr)
	}
	assertAllIntact(t, "DeleteUser")

	// 2. DeleteDevice rolls back device, legacy rule, audit_logs.device_id, and version.
	if err := svc.DeleteDevice(eAdminCtx("device.delete", "device", dev.ID.String()), dev.ID); !errors.Is(err, forcedErr) {
		t.Fatalf("DeleteDevice err=%v want %v", err, forcedErr)
	}
	assertAllIntact(t, "DeleteDevice")

	// 3. DeleteToken rolls back token and leaves everything else intact.
	if err := svc.DeleteToken(eAdminCtx("token.delete", "token", tokRes.Token.ID.String()), tokRes.Token.ID); !errors.Is(err, forcedErr) {
		t.Fatalf("DeleteToken err=%v want %v", err, forcedErr)
	}
	assertAllIntact(t, "DeleteToken")
}
