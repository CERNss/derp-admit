package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func bNewVerifyBody(t *testing.T, nodeKey string) []byte {
	t.Helper()
	var pub key.NodePublic
	if err := pub.UnmarshalText([]byte(nodeKey)); err != nil {
		t.Fatalf("unmarshal node key: %v", err)
	}
	raw, err := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: pub})
	if err != nil {
		t.Fatalf("marshal verify body: %v", err)
	}
	return raw
}

func bNewNodeKey() string {
	return key.NewNode().Public().String()
}

func bSetupService(t *testing.T, cacheTTL, syncInterval time.Duration) (*Service, *policy.Engine, *gorm.DB) {
	t.Helper()

	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "trackb.db")
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := gormDB.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("seed builtins: %v", err)
	}
	engine, err := policy.NewEngine(gormDB, true)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	svc := New(
		gormDB,
		engine,
		"test-pepper",
		5*time.Second,
		NewVerifyCache(cacheTTL),
		zap.NewNop(),
		WithPolicySyncInterval(syncInterval),
	)
	return svc, engine, gormDB
}

func TestVerifyCachePerRelayAndInvalidate(t *testing.T) {
	c := NewVerifyCache(time.Hour)
	devID := uuid.New()

	ep := c.Epoch()
	c.Set("default", "node-1", ep, true, "", &devID)
	c.Set("eu-1", "node-1", ep, false, DenyReasonPolicyDenied, &devID)
	c.Set("eu-1", "node-2", ep, true, "", nil)

	gotDefault, ok := c.Get("default", "node-1")
	if !ok || !gotDefault.Allow {
		t.Fatalf("default cache entry=(%+v, %v), want allow hit", gotDefault, ok)
	}
	gotEU, ok := c.Get("eu-1", "node-1")
	if !ok || gotEU.Allow || gotEU.Reason != DenyReasonPolicyDenied {
		t.Fatalf("eu-1 cache entry=(%+v, %v), want policy denied hit", gotEU, ok)
	}
	if _, ok := c.Get("ap-1", "node-1"); ok {
		t.Fatalf("unexpected hit for uncached relay ap-1")
	}

	// Invalidate(nodeKey) must drop every relay cached for node-1 while keeping node-2,
	// and advance epoch so pre-invalidation Set calls are ignored.
	preInvEpoch := c.Epoch()
	c.Invalidate("node-1")
	if _, ok := c.Get("default", "node-1"); ok {
		t.Fatalf("default entry for node-1 should be invalidated")
	}
	if _, ok := c.Get("eu-1", "node-1"); ok {
		t.Fatalf("eu-1 entry for node-1 should be invalidated")
	}
	if _, ok := c.Get("eu-1", "node-2"); !ok {
		t.Fatalf("node-2 entry should remain cached after invalidating node-1")
	}

	c.Set("default", "node-1", preInvEpoch, true, "", &devID)
	if _, ok := c.Get("default", "node-1"); ok {
		t.Fatalf("stale pre-invalidation epoch must not populate cache")
	}

	// Purge clears all entries and advances epoch.
	prePurgeEpoch := c.Epoch()
	c.Purge()
	if _, ok := c.Get("eu-1", "node-2"); ok {
		t.Fatalf("node-2 entry should be cleared by Purge")
	}
	c.Set("eu-1", "node-2", prePurgeEpoch, true, "", nil)
	if _, ok := c.Get("eu-1", "node-2"); ok {
		t.Fatalf("stale pre-purge epoch must not populate cache")
	}
}

func TestVerifyRelaySnapshotLookupAndFallback(t *testing.T) {
	svc, engine, gormDB := bSetupService(t, time.Minute, 2*time.Second)

	if !engine.HasRelay(policy.BuiltinRelay) {
		t.Fatalf("expected engine snapshot to contain built-in relay %q", policy.BuiltinRelay)
	}
	if engine.HasRelay("eu-1") {
		t.Fatalf("did not expect engine snapshot to contain unregistered relay eu-1")
	}

	user := model.User{ID: uuid.New(), Username: "relay-unit-user"}
	if err := gormDB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	nk := bNewNodeKey()
	if err := gormDB.Create(&model.Device{ID: uuid.New(), UserID: user.ID, NodeKey: nk}).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := svc.Mutate(context.Background(), EffectPolicy, 200, func(tx *gorm.DB, _ *Change) error {
		if err := tx.Create(&model.Relay{Name: "eu-1"}).Error; err != nil {
			return err
		}
		if err := tx.Create(&model.Role{Name: "eu-only"}).Error; err != nil {
			return err
		}
		if err := policy.SetRoleGrants(tx, "eu-only", []string{"eu-1"}); err != nil {
			return err
		}
		return policy.SetUserRoles(tx, user.ID, []string{"eu-only"})
	}); err != nil {
		t.Fatalf("mutate relay/role: %v", err)
	}

	if !engine.HasRelay("eu-1") {
		t.Fatalf("expected engine snapshot to contain eu-1 after Mutate")
	}

	body := bNewVerifyBody(t, nk)
	if allow, reason := svc.Verify(context.Background(), "eu-1", body); !allow || reason != "" {
		t.Fatalf("verify eu-1=(%v, %q) want=(true, \"\")", allow, reason)
	}
	if allow, reason := svc.Verify(context.Background(), "default", body); allow || reason != DenyReasonPolicyDenied {
		t.Fatalf("verify default=(%v, %q) want=(false, %q)", allow, reason, DenyReasonPolicyDenied)
	}
	if allow, reason := svc.Verify(context.Background(), "ap-1", body); allow || reason != DenyReasonUnknownRelay {
		t.Fatalf("verify ap-1=(%v, %q) want=(false, %q)", allow, reason, DenyReasonUnknownRelay)
	}
}
