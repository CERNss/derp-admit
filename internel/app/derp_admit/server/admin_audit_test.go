package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/server"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func TestRequireTier(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	viewerKey := insertAdminKey(t, gormDB, "viewer-1", actor.TierViewer)

	// Viewer can access a read route.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/users", viewerKey, nil); status != http.StatusOK {
		t.Fatalf("viewer GET /admin/users status=%d want=%d", status, http.StatusOK)
	}

	// Viewer gets 403 on an operator mutation route and creates no user.
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", viewerKey, map[string]any{
		"username": "should-not-exist",
	}); status != http.StatusForbidden {
		t.Fatalf("viewer POST /admin/users status=%d want=%d", status, http.StatusForbidden)
	}

	var count int64
	if err := gormDB.Model(&model.User{}).Where("username = ?", "should-not-exist").Count(&count).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("user count=%d want=0", count)
	}
}

func TestAdminAuditRecordsForbidden(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	viewerKey := insertAdminKey(t, gormDB, "viewer-audit", actor.TierViewer)

	status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", viewerKey, map[string]any{
		"username": "denied-user",
	})
	if status != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", status, http.StatusForbidden)
	}

	var rows []model.AdminAuditLog
	if err := gormDB.Where("actor_name <> ?", actor.System.Name).Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("query admin_audit_logs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("admin audit row count=%d want=1", len(rows))
	}
	row := rows[0]
	if row.ActorName != "viewer-audit" || row.ActorTier != model.AdminTierViewer || row.ActorKeyID == nil {
		t.Fatalf("unexpected actor fields: name=%q tier=%q keyID=%v", row.ActorName, row.ActorTier, row.ActorKeyID)
	}
	if row.Action != "user.create" || row.TargetType != "user" {
		t.Fatalf("unexpected action/target: action=%q targetType=%q", row.Action, row.TargetType)
	}
	if row.Outcome != service.AuditOutcomeFailure {
		t.Fatalf("outcome=%q want=%q", row.Outcome, service.AuditOutcomeFailure)
	}
	if row.HTTPStatus == nil || *row.HTTPStatus != http.StatusForbidden {
		t.Fatalf("http_status=%v want=%d", row.HTTPStatus, http.StatusForbidden)
	}
}

func TestAdminAuditSkipsUnauthenticated(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Missing key.
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", "", map[string]any{
		"username": "unauth-1",
	}); status != http.StatusUnauthorized {
		t.Fatalf("missing key status=%d want=%d", status, http.StatusUnauthorized)
	}

	// Unknown key.
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", "dak_unknown_key_value", map[string]any{
		"username": "unauth-2",
	}); status != http.StatusUnauthorized {
		t.Fatalf("unknown key status=%d want=%d", status, http.StatusUnauthorized)
	}

	var count int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Where("actor_name <> ?", actor.System.Name).Count(&count).Error; err != nil {
		t.Fatalf("count admin_audit_logs: %v", err)
	}
	if count != 0 {
		t.Fatalf("admin audit count=%d want=0 for unauthenticated requests", count)
	}
}

func TestAdminAuditSkipsReads(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	viewerKey := insertAdminKey(t, gormDB, "viewer-reads", actor.TierViewer)

	for _, path := range []string{"/admin/users", "/admin/tokens", "/admin/devices"} {
		if status, _ := doAdminRequest(t, router, http.MethodGet, path, viewerKey, nil); status != http.StatusOK {
			t.Fatalf("GET %s status=%d want=%d", path, status, http.StatusOK)
		}
	}

	var count int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Where("actor_name <> ?", actor.System.Name).Count(&count).Error; err != nil {
		t.Fatalf("count admin_audit_logs: %v", err)
	}
	if count != 0 {
		t.Fatalf("admin audit count=%d want=0 for GET requests", count)
	}
}

func TestAdminAuditSuccessWritesExactlyOneRow(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	opKey := insertAdminKey(t, gormDB, "op-audit-ok", actor.TierOperator)

	var seenCount int64
	assertOneNewSuccess := func(t *testing.T, wantAction, wantTargetType, wantTargetID string, wantStatus int) {
		t.Helper()
		var rows []model.AdminAuditLog
		if err := gormDB.Where("actor_name <> ?", actor.System.Name).Order("id asc").Find(&rows).Error; err != nil {
			t.Fatalf("query admin_audit_logs: %v", err)
		}
		seenCount++
		if int64(len(rows)) != seenCount {
			t.Fatalf("%s: total audit rows=%d want=%d", wantAction, len(rows), seenCount)
		}
		last := rows[len(rows)-1]
		if last.Outcome != service.AuditOutcomeSuccess {
			t.Fatalf("%s: outcome=%q want=%q", wantAction, last.Outcome, service.AuditOutcomeSuccess)
		}
		if last.Action != wantAction || last.TargetType != wantTargetType || last.TargetID != wantTargetID {
			t.Fatalf("%s: got action=%q targetType=%q targetID=%q want %q/%q/%q",
				wantAction, last.Action, last.TargetType, last.TargetID, wantAction, wantTargetType, wantTargetID)
		}
		if last.HTTPStatus == nil || *last.HTTPStatus != wantStatus {
			t.Fatalf("%s: http_status=%v want=%d", wantAction, last.HTTPStatus, wantStatus)
		}
	}

	// 1. POST /admin/users
	status, body := doAdminRequest(t, router, http.MethodPost, "/admin/users", opKey, map[string]any{"username": "audit-u1"})
	if status != http.StatusCreated {
		t.Fatalf("create user status=%d want=%d", status, http.StatusCreated)
	}
	userID := body["user"].(map[string]any)["id"].(string)
	assertOneNewSuccess(t, "user.create", "user", userID, http.StatusCreated)

	// 2. POST /admin/users/:id/disable
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users/"+userID+"/disable", opKey, nil); status != http.StatusOK {
		t.Fatalf("disable user status=%d want=%d", status, http.StatusOK)
	}
	assertOneNewSuccess(t, "user.disable", "user", userID, http.StatusOK)

	// 3. POST /admin/users/:id/enable
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users/"+userID+"/enable", opKey, nil); status != http.StatusOK {
		t.Fatalf("enable user status=%d want=%d", status, http.StatusOK)
	}
	assertOneNewSuccess(t, "user.enable", "user", userID, http.StatusOK)

	// 4. POST /admin/tokens
	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/tokens", opKey, map[string]any{"userId": userID})
	if status != http.StatusCreated {
		t.Fatalf("create token status=%d want=%d", status, http.StatusCreated)
	}
	tokenID := body["meta"].(map[string]any)["id"].(string)
	assertOneNewSuccess(t, "token.create", "token", tokenID, http.StatusCreated)

	// 5. POST /admin/tokens/:id/revoke
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/tokens/"+tokenID+"/revoke", opKey, nil); status != http.StatusOK {
		t.Fatalf("revoke token status=%d want=%d", status, http.StatusOK)
	}
	assertOneNewSuccess(t, "token.revoke", "token", tokenID, http.StatusOK)

	// Seed a device directly so we can exercise the device mutation routes.
	dev := createDevice(t, gormDB, uuid.MustParse(userID), newNodeKey(t), "dev-1", nil)
	devID := dev.ID.String()

	// 6. POST /admin/devices/:id/revoke
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+devID+"/revoke", opKey, nil); status != http.StatusOK {
		t.Fatalf("revoke device status=%d want=%d", status, http.StatusOK)
	}
	assertOneNewSuccess(t, "device.revoke", "device", devID, http.StatusOK)

	// 7. POST /admin/devices/:id/enable
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+devID+"/enable", opKey, nil); status != http.StatusOK {
		t.Fatalf("enable device status=%d want=%d", status, http.StatusOK)
	}
	assertOneNewSuccess(t, "device.enable", "device", devID, http.StatusOK)
}

func TestAdminAuditRecordsFailedMutations(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	opKey := insertAdminKey(t, gormDB, "op-audit-fail", actor.TierOperator)

	// Seed one existing user directly via SQL so the conflict check starts with 0 audit rows.
	createUser(t, gormDB, "taken-user")

	cases := []struct {
		name       string
		path       string
		payload    any
		wantStatus int
		wantAction string
	}{
		{
			name:       "bad_uuid_400",
			path:       "/admin/users/not-a-uuid/disable",
			payload:    nil,
			wantStatus: http.StatusBadRequest,
			wantAction: "user.disable",
		},
		{
			name:       "blank_username_400",
			path:       "/admin/users",
			payload:    map[string]any{"username": "   "},
			wantStatus: http.StatusBadRequest,
			wantAction: "user.create",
		},
		{
			name:       "unknown_id_404",
			path:       "/admin/devices/" + uuid.New().String() + "/revoke",
			payload:    nil,
			wantStatus: http.StatusNotFound,
			wantAction: "device.revoke",
		},
		{
			name:       "duplicate_username_409",
			path:       "/admin/users",
			payload:    map[string]any{"username": "taken-user"},
			wantStatus: http.StatusConflict,
			wantAction: "user.create",
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := doAdminRequest(t, router, http.MethodPost, tc.path, opKey, tc.payload)
			if status != tc.wantStatus {
				t.Fatalf("status=%d want=%d", status, tc.wantStatus)
			}

			var rows []model.AdminAuditLog
			if err := gormDB.Where("actor_name <> ?", actor.System.Name).Order("id asc").Find(&rows).Error; err != nil {
				t.Fatalf("query admin_audit_logs: %v", err)
			}
			if len(rows) != i+1 {
				t.Fatalf("audit row count=%d want=%d", len(rows), i+1)
			}
			row := rows[len(rows)-1]
			if row.Outcome != service.AuditOutcomeFailure {
				t.Fatalf("outcome=%q want=%q", row.Outcome, service.AuditOutcomeFailure)
			}
			if row.Action != tc.wantAction {
				t.Fatalf("action=%q want=%q", row.Action, tc.wantAction)
			}
			if row.HTTPStatus == nil || *row.HTTPStatus != tc.wantStatus {
				t.Fatalf("http_status=%v want=%d", row.HTTPStatus, tc.wantStatus)
			}
		})
	}

	var successCount int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Where("actor_name <> ? AND outcome = ?", actor.System.Name, service.AuditOutcomeSuccess).Count(&successCount).Error; err != nil {
		t.Fatalf("count success rows: %v", err)
	}
	if successCount != 0 {
		t.Fatalf("success audit row count=%d want=0", successCount)
	}
}

type flakyPolicyEngine struct {
	inner      policy.PolicyEngine
	failReload atomic.Bool
}

func (f *flakyPolicyEngine) Enforce(req policy.Request) (bool, error) {
	return f.inner.Enforce(req)
}

func (f *flakyPolicyEngine) Reload(ctx context.Context) error {
	if f.failReload.Load() {
		return errors.New("forced policy reload failure")
	}
	return f.inner.Reload(ctx)
}

func (f *flakyPolicyEngine) Version() int64 {
	return f.inner.Version()
}

type controlledPolicyEngine struct {
	db        *gorm.DB
	active    atomic.Pointer[policy.Engine]
	mode      atomic.Int32 // 0=normal reload, 1=B reads then pauses, 2=A fails
	bReadDone chan struct{}
	releaseB  chan struct{}
}

func (c *controlledPolicyEngine) Enforce(req policy.Request) (bool, error) {
	return c.active.Load().Enforce(req)
}

func (c *controlledPolicyEngine) Version() int64 {
	return c.active.Load().Version()
}

func (c *controlledPolicyEngine) Reload(ctx context.Context) error {
	switch c.mode.Load() {
	case 1:
		// Mutation B's reload reads the DB now (capturing vB), signals bReadDone,
		// and pauses before publishing until releaseB is closed.
		snapB, err := policy.NewEngine(c.db, true)
		if err != nil {
			return err
		}
		close(c.bReadDone)
		<-c.releaseB
		c.active.Store(snapB)
		return nil
	case 2:
		return errors.New("forced A reload failure")
	default:
		snap, err := policy.NewEngine(c.db, true)
		if err != nil {
			return err
		}
		c.active.Store(snap)
		return nil
	}
}

func TestStaleNotClearedByOlderReload(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "stale-order.db")
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

	initialEngine, err := policy.NewEngine(gormDB, true)
	if err != nil {
		t.Fatalf("new initial policy engine: %v", err)
	}
	ctrl := &controlledPolicyEngine{
		db:        gormDB,
		bReadDone: make(chan struct{}),
		releaseB:  make(chan struct{}),
	}
	ctrl.active.Store(initialEngine)

	cfg := config.Config{
		AdminAPIKey:          testAdminKey,
		DBTimeout:            2 * time.Second,
		PolicySyncInterval:   2 * time.Second,
		VerifyCacheTTL:       time.Minute,
		VerifyRateLimitRPS:   1000,
		VerifyRateBurst:      1000,
		RegisterRateLimitRPS: 1000,
		RegisterRateBurst:    1000,
		AdminRateLimitRPS:    1000,
		AdminRateBurst:       1000,
	}
	logger := zap.NewNop()
	svc := service.New(
		gormDB,
		ctrl,
		"test-pepper",
		cfg.DBTimeout,
		service.NewVerifyCache(cfg.VerifyCacheTTL),
		logger,
		service.WithAdminAPIKey(testAdminKey),
	)
	if err := gormDB.Create(&model.AdminKey{
		Name:    "test-admin",
		Tier:    model.AdminTierAdmin,
		KeyHash: hashToken(testAdminKey, "test-pepper"),
	}).Error; err != nil {
		t.Fatalf("seed admin key: %v", err)
	}
	router := server.NewRouter(svc, cfg, logger)

	checkReadyz := func() int {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code
	}

	// Provision a user + device and confirm initial allow + 200 /readyz.
	_, token := provisionUserAndToken(t, router, "order-base-user")
	nodeKey := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}
	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
		t.Fatalf("initial verify expected allow, got deny reason=%q", denyReason(payload))
	}
	if code := checkReadyz(); code != http.StatusOK {
		t.Fatalf("initial /readyz=%d want=%d", code, http.StatusOK)
	}

	// Step 1: Start Mutation B; its reload reads DB at vB and pauses before publishing.
	ctrl.mode.Store(1)
	bDone := make(chan int, 1)
	go func() {
		status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
			"username": "mutation-b",
		})
		bDone <- status
	}()
	<-ctrl.bReadDone

	// Step 2 & 3: Mutation A commits vA (> vB) and A's reload fails.
	ctrl.mode.Store(2)
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "mutation-a",
	}); status != http.StatusCreated {
		t.Fatalf("mutation A status=%d want=%d", status, http.StatusCreated)
	}

	// Step 4: Let Mutation B's older reload (covering only vB) finish and publish.
	close(ctrl.releaseB)
	if bStatus := <-bDone; bStatus != http.StatusCreated {
		t.Fatalf("mutation B status=%d want=%d", bStatus, http.StatusCreated)
	}

	// Instance MUST remain stale because published version vB < required version vA.
	if code := checkReadyz(); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz after older reload finished=%d want=%d (must stay stale)", code, http.StatusServiceUnavailable)
	}
	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if allow, _ := payload["Allow"].(bool); allow {
		t.Fatalf("verify after older reload expected deny, got allow (fail-open!)")
	}
	if reason := denyReason(payload); reason != service.DenyReasonInternal {
		t.Fatalf("verify reason=%q want=%q", reason, service.DenyReasonInternal)
	}

	// Step 5: A reload covering vA makes the instance current again.
	ctrl.mode.Store(0)
	if err := svc.ReloadPolicy(context.Background()); err != nil {
		t.Fatalf("recovery ReloadPolicy: %v", err)
	}
	if code := checkReadyz(); code != http.StatusOK {
		t.Fatalf("recovered /readyz=%d want=%d", code, http.StatusOK)
	}
	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
		t.Fatalf("recovered verify expected allow, got deny reason=%q", denyReason(payload))
	}
}

func TestMutateReloadFailureFailsClosed(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "stale.db")
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

	realEngine, err := policy.NewEngine(gormDB, true)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	flaky := &flakyPolicyEngine{inner: realEngine}

	cfg := config.Config{
		AdminAPIKey:          testAdminKey,
		DBTimeout:            2 * time.Second,
		PolicySyncInterval:   2 * time.Second,
		VerifyCacheTTL:       time.Minute,
		VerifyRateLimitRPS:   1000,
		VerifyRateBurst:      1000,
		RegisterRateLimitRPS: 1000,
		RegisterRateBurst:    1000,
		AdminRateLimitRPS:    1000,
		AdminRateBurst:       1000,
	}
	logger := zap.NewNop()
	svc := service.New(
		gormDB,
		flaky,
		"test-pepper",
		cfg.DBTimeout,
		service.NewVerifyCache(cfg.VerifyCacheTTL),
		logger,
		service.WithAdminAPIKey(testAdminKey),
	)
	if err := gormDB.Create(&model.AdminKey{
		Name:    "test-admin",
		Tier:    model.AdminTierAdmin,
		KeyHash: hashToken(testAdminKey, "test-pepper"),
	}).Error; err != nil {
		t.Fatalf("seed admin key: %v", err)
	}
	router := server.NewRouter(svc, cfg, logger)

	// Provision a user + device and warm the verify cache with an allow.
	userID, token := provisionUserAndToken(t, router, "stale-check-user")
	_ = userID
	nodeKey := newNodeKey(t)
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}
	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
		t.Fatalf("initial verify expected allow, got deny reason=%q", denyReason(payload))
	}

	checkReadyz := func() int {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code
	}
	if code := checkReadyz(); code != http.StatusOK {
		t.Fatalf("initial /readyz=%d want=%d", code, http.StatusOK)
	}

	// Force post-commit policy reload to fail on the next EffectPolicy mutation.
	flaky.failReload.Store(true)
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "triggers-reload-fail",
	}); status != http.StatusCreated {
		t.Fatalf("mutation with failed reload status=%d want=%d", status, http.StatusCreated)
	}

	// Instance must now fail closed: /readyz is 503 and /verify denies with internal error (audited),
	// even for a device that was previously allowed and cached.
	if code := checkReadyz(); code != http.StatusServiceUnavailable {
		t.Fatalf("stale /readyz=%d want=%d", code, http.StatusServiceUnavailable)
	}
	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey))
	if allow, _ := payload["Allow"].(bool); allow {
		t.Fatalf("stale verify expected deny, got allow")
	}
	if reason := denyReason(payload); reason != service.DenyReasonInternal {
		t.Fatalf("stale verify reason=%q want=%q", reason, service.DenyReasonInternal)
	}

	var lastAudit model.AuditLog
	if err := gormDB.Order("id desc").First(&lastAudit).Error; err != nil {
		t.Fatalf("load latest verify audit: %v", err)
	}
	if lastAudit.Allowed || lastAudit.Reason != service.DenyReasonInternal || lastAudit.NodeKey != nodeKey {
		t.Fatalf("unexpected stale audit row: %+v", lastAudit)
	}

	// A subsequent successful reload through Mutate clears staleness and restores both.
	flaky.failReload.Store(false)
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "triggers-reload-recover",
	}); status != http.StatusCreated {
		t.Fatalf("recovery mutation status=%d want=%d", status, http.StatusCreated)
	}

	if code := checkReadyz(); code != http.StatusOK {
		t.Fatalf("recovered /readyz=%d want=%d", code, http.StatusOK)
	}
	if _, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nodeKey)); payload["Allow"] != true {
		t.Fatalf("recovered verify expected allow, got deny reason=%q", denyReason(payload))
	}
}

func TestRegisterNewDeviceBumpsVersion(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	_, token := provisionUserAndToken(t, router, "reg-bump-user")

	v0, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v0: %v", err)
	}

	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": newNodeKey(t),
		"label":   "laptop",
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}

	v1, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version v1: %v", err)
	}
	if v1 != v0+1 {
		t.Fatalf("version after new device=%d want=%d", v1, v0+1)
	}
}

func TestRegisterLabelUpdateDoesNotBumpVersion(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	_, token := provisionUserAndToken(t, router, "reg-rereg-user")
	nodeKey := newNodeKey(t)

	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
		"label":   "initial",
	}); status != http.StatusOK {
		t.Fatalf("initial register status=%d want=%d", status, http.StatusOK)
	}

	vAfterCreate, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version after create: %v", err)
	}

	// Re-register same active device with a new label: updates label, does not bump version.
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
		"label":   "renamed",
	}); status != http.StatusOK {
		t.Fatalf("label update register status=%d want=%d", status, http.StatusOK)
	}

	// Re-register same active device without a label: also does not bump version.
	if status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
	}); status != http.StatusOK {
		t.Fatalf("no-label re-register status=%d want=%d", status, http.StatusOK)
	}

	vAfterRereg, err := policy.ReadVersion(context.Background(), gormDB)
	if err != nil {
		t.Fatalf("read version after re-register: %v", err)
	}
	if vAfterRereg != vAfterCreate {
		t.Fatalf("version bumped on re-register: got=%d want=%d", vAfterRereg, vAfterCreate)
	}

	var dev model.Device
	if err := gormDB.Where("node_key = ?", nodeKey).First(&dev).Error; err != nil {
		t.Fatalf("load device: %v", err)
	}
	if dev.Label != "renamed" {
		t.Fatalf("device label=%q want=%q", dev.Label, "renamed")
	}
}
