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
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func bBuildAppOnDB(t *testing.T, dbURL string, opts ...func(*config.Config)) *app.App {
	t.Helper()

	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "test-pepper",
		AdminAPIKey:          testAdminKey,
		EnableCasbin:         true,
		MetricsEnabled:       true,
		DBTimeout:            2 * time.Second,
		PolicySyncInterval:   2 * time.Second,
		VerifyRateLimitRPS:   1000,
		VerifyRateBurst:      1000,
		RegisterRateLimitRPS: 1000,
		RegisterRateBurst:    1000,
		AdminRateLimitRPS:    1000,
		AdminRateBurst:       1000,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	application, err := app.Build(context.Background(), gormDB, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	t.Cleanup(func() {
		application.Close()
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return application
}

func bBuildSingleApp(t *testing.T, opts ...func(*config.Config)) *app.App {
	t.Helper()
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "verify_relay.db")
	return bBuildAppOnDB(t, dbURL, opts...)
}

func bAddRelayAndRole(t *testing.T, application *app.App, relayName, roleName string, grants []string) {
	t.Helper()
	err := application.Service.Mutate(context.Background(), service.EffectPolicy, http.StatusOK, func(tx *gorm.DB, _ *service.Change) error {
		if relayName != "" {
			if err := tx.Create(&model.Relay{Name: relayName}).Error; err != nil {
				return err
			}
		}
		if roleName != "" {
			if err := tx.Create(&model.Role{Name: roleName}).Error; err != nil {
				return err
			}
			if grants != nil {
				if err := policy.SetRoleGrants(tx, roleName, grants); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("add relay/role: %v", err)
	}
}

func bBindUserRoles(t *testing.T, application *app.App, userID uuid.UUID, roles []string) {
	t.Helper()
	err := application.Service.Mutate(context.Background(), service.EffectPolicy, http.StatusOK, func(tx *gorm.DB, _ *service.Change) error {
		return policy.SetUserRoles(tx, userID, roles)
	})
	if err != nil {
		t.Fatalf("bind user roles: %v", err)
	}
}

func bLastAuditLog(t *testing.T, dbConn *gorm.DB) model.AuditLog {
	t.Helper()
	var row model.AuditLog
	if err := dbConn.Order("id desc").First(&row).Error; err != nil {
		t.Fatalf("load latest audit_logs row: %v", err)
	}
	return row
}

func TestVerifyPlainPathIsDefaultRelay(t *testing.T) {
	application := bBuildSingleApp(t)
	bAddRelayAndRole(t, application, "eu-1", "eu-role", []string{"eu-1"})

	user := createUser(t, application.DB, "plain-default-user")
	bBindUserRoles(t, application, user.ID, []string{policy.BuiltinRole, "eu-role"})
	nk := newNodeKey(t)
	createDevice(t, application.DB, user.ID, nk, "laptop", nil)

	// Plain /verify evaluates relay "default".
	code, payload := doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, nk))
	if code != http.StatusOK {
		t.Fatalf("plain /verify status=%d want=200", code)
	}
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("plain /verify expected allow, got deny reason=%q", denyReason(payload))
	}
	audit := bLastAuditLog(t, application.DB)
	if !audit.Allowed || audit.Relay == nil || *audit.Relay != policy.BuiltinRelay {
		t.Fatalf("plain /verify audit=%+v want allowed=true relay=default", audit)
	}

	// Named /verify/eu-1 evaluates relay "eu-1".
	code, payload = doRawRequest(t, application.Router, "/verify/eu-1", buildVerifyBody(t, nk))
	if code != http.StatusOK {
		t.Fatalf("/verify/eu-1 status=%d want=200", code)
	}
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("/verify/eu-1 expected allow, got deny reason=%q", denyReason(payload))
	}
	audit = bLastAuditLog(t, application.DB)
	if !audit.Allowed || audit.Relay == nil || *audit.Relay != "eu-1" {
		t.Fatalf("/verify/eu-1 audit=%+v want allowed=true relay=eu-1", audit)
	}
}

func TestVerifyUnknownRelayDenied(t *testing.T) {
	application := bBuildSingleApp(t)
	bAddRelayAndRole(t, application, "", "all-access", []string{"*"})

	user := createUser(t, application.DB, "unknown-relay-user")
	bBindUserRoles(t, application, user.ID, []string{"all-access"})
	nk := newNodeKey(t)
	createDevice(t, application.DB, user.ID, nk, "laptop", nil)

	code, payload := doRawRequest(t, application.Router, "/verify/does-not-exist", buildVerifyBody(t, nk))
	if code != http.StatusOK {
		t.Fatalf("status=%d want=200", code)
	}
	if allow, _ := payload["Allow"].(bool); allow {
		t.Fatalf("expected deny for unknown relay")
	}
	if reason := denyReason(payload); reason != service.DenyReasonUnknownRelay {
		t.Fatalf("reason=%q want=%q", reason, service.DenyReasonUnknownRelay)
	}

	audit := bLastAuditLog(t, application.DB)
	if audit.Allowed || audit.Reason != service.DenyReasonUnknownRelay || audit.NodeKey != nk {
		t.Fatalf("unexpected audit row: %+v", audit)
	}
	if audit.Relay == nil || *audit.Relay != "does-not-exist" {
		t.Fatalf("audit relay=%v want=%q", audit.Relay, "does-not-exist")
	}
}

func TestVerifyMalformedRelayDenied(t *testing.T) {
	application := bBuildSingleApp(t)
	nk := newNodeKey(t)

	for _, badRelay := range []string{"Bad_Name", "-leading-dash", "UPPER", "has.dot"} {
		code, payload := doRawRequest(t, application.Router, "/verify/"+badRelay, buildVerifyBody(t, nk))
		if code != http.StatusOK {
			t.Fatalf("relay %q: status=%d want=200", badRelay, code)
		}
		if allow, _ := payload["Allow"].(bool); allow {
			t.Fatalf("relay %q: expected deny", badRelay)
		}
		if reason := denyReason(payload); reason != service.DenyReasonUnknownRelay {
			t.Fatalf("relay %q: reason=%q want=%q", badRelay, reason, service.DenyReasonUnknownRelay)
		}
		audit := bLastAuditLog(t, application.DB)
		if audit.Relay != nil {
			t.Fatalf("relay %q: audit relay=%q want=nil", badRelay, *audit.Relay)
		}
		if audit.Reason != service.DenyReasonUnknownRelay || audit.NodeKey != nk {
			t.Fatalf("relay %q: unexpected audit row: %+v", badRelay, audit)
		}
	}
}

func TestVerifyCheckOrder(t *testing.T) {
	application := bBuildSingleApp(t)

	// 1. Malformed body on an unknown relay -> invalid request (parse before relay).
	_, payload := doRawRequest(t, application.Router, "/verify/does-not-exist", []byte("{not-json"))
	if reason := denyReason(payload); reason != service.DenyReasonInvalidReq {
		t.Fatalf("malformed body + unknown relay: reason=%q want=%q", reason, service.DenyReasonInvalidReq)
	}

	// 2. Unknown relay and unregistered device -> unknown relay (relay before registered).
	unregKey := newNodeKey(t)
	_, payload = doRawRequest(t, application.Router, "/verify/does-not-exist", buildVerifyBody(t, unregKey))
	if reason := denyReason(payload); reason != service.DenyReasonUnknownRelay {
		t.Fatalf("unknown relay + unregistered: reason=%q want=%q", reason, service.DenyReasonUnknownRelay)
	}

	// 3. Revoked device of a disabled user -> revoked (revoked before user disabled).
	disabledUser := createUser(t, application.DB, "disabled-with-revoked")
	now := time.Now().UTC()
	disabledUser.DisabledAt = &now
	if err := application.DB.Save(&disabledUser).Error; err != nil {
		t.Fatalf("disable user: %v", err)
	}
	revokedKey := newNodeKey(t)
	createDevice(t, application.DB, disabledUser.ID, revokedKey, "", &now)

	_, payload = doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, revokedKey))
	if reason := denyReason(payload); reason != service.DenyReasonRevoked {
		t.Fatalf("revoked + disabled user: reason=%q want=%q", reason, service.DenyReasonRevoked)
	}

	// 4. Active device of disabled user without roles -> user disabled (user disabled before policy).
	activeOnDisabledKey := newNodeKey(t)
	createDevice(t, application.DB, disabledUser.ID, activeOnDisabledKey, "", nil)
	_, payload = doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, activeOnDisabledKey))
	if reason := denyReason(payload); reason != service.DenyReasonUserDisabled {
		t.Fatalf("disabled user + no role: reason=%q want=%q", reason, service.DenyReasonUserDisabled)
	}

	// 5. Active device of enabled user without roles -> policy denied.
	enabledUser := createUser(t, application.DB, "enabled-no-roles")
	noRoleKey := newNodeKey(t)
	createDevice(t, application.DB, enabledUser.ID, noRoleKey, "", nil)
	_, payload = doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, noRoleKey))
	if reason := denyReason(payload); reason != service.DenyReasonPolicyDenied {
		t.Fatalf("no role: reason=%q want=%q", reason, service.DenyReasonPolicyDenied)
	}
}

func TestVerifyCacheIsPerRelay(t *testing.T) {
	application := bBuildSingleApp(t, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
	})
	bAddRelayAndRole(t, application, "eu-1", "eu-access", []string{"eu-1"})

	user := createUser(t, application.DB, "per-relay-cache-user")
	bBindUserRoles(t, application, user.ID, []string{policy.BuiltinRole})
	nk := newNodeKey(t)
	createDevice(t, application.DB, user.ID, nk, "laptop", nil)

	// Warm cache on default -> allow.
	_, payload := doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, nk))
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("default verify expected allow, got deny reason=%q", denyReason(payload))
	}

	// Calling /verify/eu-1 MUST NOT reuse the cached default allow.
	_, payload = doRawRequest(t, application.Router, "/verify/eu-1", buildVerifyBody(t, nk))
	if allow, _ := payload["Allow"].(bool); allow {
		t.Fatalf("/verify/eu-1 unexpectedly allowed (used default cache entry?)")
	}
	if reason := denyReason(payload); reason != service.DenyReasonPolicyDenied {
		t.Fatalf("/verify/eu-1 reason=%q want=%q", reason, service.DenyReasonPolicyDenied)
	}

	// Grant eu-access to user and warm eu-1 cache with allow, then remove grant -> immediate deny.
	bBindUserRoles(t, application, user.ID, []string{policy.BuiltinRole, "eu-access"})
	_, payload = doRawRequest(t, application.Router, "/verify/eu-1", buildVerifyBody(t, nk))
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("/verify/eu-1 after bind expected allow, got deny reason=%q", denyReason(payload))
	}
	if err := application.Service.Mutate(context.Background(), service.EffectPolicy, http.StatusOK, func(tx *gorm.DB, _ *service.Change) error {
		return policy.SetRoleGrants(tx, "eu-access", []string{})
	}); err != nil {
		t.Fatalf("clear eu-access grants: %v", err)
	}
	_, payload = doRawRequest(t, application.Router, "/verify/eu-1", buildVerifyBody(t, nk))
	if reason := denyReason(payload); reason != service.DenyReasonPolicyDenied {
		t.Fatalf("/verify/eu-1 after grant removal reason=%q want=%q", reason, service.DenyReasonPolicyDenied)
	}
}

func TestVerifyAuditRelayValues(t *testing.T) {
	application := bBuildSingleApp(t)
	bAddRelayAndRole(t, application, "eu-1", "", nil)
	nk := newNodeKey(t)

	cases := []struct {
		name      string
		path      string
		wantRelay *string
	}{
		{name: "plain default", path: "/verify", wantRelay: bStrPtr("default")},
		{name: "registered relay", path: "/verify/eu-1", wantRelay: bStrPtr("eu-1")},
		{name: "well-formed unknown relay", path: "/verify/does-not-exist", wantRelay: bStrPtr("does-not-exist")},
		{name: "malformed relay", path: "/verify/Bad_Name", wantRelay: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := doRawRequest(t, application.Router, tc.path, buildVerifyBody(t, nk))
			if code != http.StatusOK {
				t.Fatalf("status=%d want=200", code)
			}
			audit := bLastAuditLog(t, application.DB)
			if tc.wantRelay == nil {
				if audit.Relay != nil {
					t.Fatalf("relay=%q want=nil", *audit.Relay)
				}
			} else {
				if audit.Relay == nil || *audit.Relay != *tc.wantRelay {
					t.Fatalf("relay=%v want=%q", audit.Relay, *tc.wantRelay)
				}
			}
		})
	}
}

func TestVerifyInvalidJSONIsAudited(t *testing.T) {
	application := bBuildSingleApp(t)
	bAddRelayAndRole(t, application, "eu-1", "", nil)

	cases := []struct {
		name      string
		path      string
		body      []byte
		wantRelay *string
	}{
		{name: "named relay non-JSON", path: "/verify/eu-1", body: []byte("not-json"), wantRelay: bStrPtr("eu-1")},
		{name: "plain verify non-JSON", path: "/verify", body: []byte("{"), wantRelay: bStrPtr("default")},
		{name: "malformed relay non-JSON", path: "/verify/Bad_Name", body: []byte("nope"), wantRelay: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var before int64
			if err := application.DB.Model(&model.AuditLog{}).Count(&before).Error; err != nil {
				t.Fatalf("count audit before: %v", err)
			}

			code, payload := doRawRequest(t, application.Router, tc.path, tc.body)
			if code != http.StatusOK {
				t.Fatalf("status=%d want=200", code)
			}
			if allow, _ := payload["Allow"].(bool); allow {
				t.Fatalf("expected deny for invalid JSON")
			}
			if reason := denyReason(payload); reason != service.DenyReasonInvalidReq {
				t.Fatalf("reason=%q want=%q", reason, service.DenyReasonInvalidReq)
			}

			var after int64
			if err := application.DB.Model(&model.AuditLog{}).Count(&after).Error; err != nil {
				t.Fatalf("count audit after: %v", err)
			}
			if after != before+1 {
				t.Fatalf("audit count=%d want=%d", after, before+1)
			}

			audit := bLastAuditLog(t, application.DB)
			if audit.Allowed || audit.NodeKey != "" || audit.DeviceID != nil || audit.Reason != service.DenyReasonInvalidReq {
				t.Fatalf("unexpected audit row: %+v", audit)
			}
			if audit.TS.IsZero() {
				t.Fatalf("expected non-zero audit timestamp")
			}
			if tc.wantRelay == nil {
				if audit.Relay != nil {
					t.Fatalf("relay=%q want=nil", *audit.Relay)
				}
			} else if audit.Relay == nil || *audit.Relay != *tc.wantRelay {
				t.Fatalf("relay=%v want=%q", audit.Relay, *tc.wantRelay)
			}
		})
	}
}

func TestVerifyRateLimitedIsNotAudited(t *testing.T) {
	application := bBuildSingleApp(t, func(c *config.Config) {
		c.VerifyRateLimitRPS = 0.01
		c.VerifyRateBurst = 1
	})

	nk := newNodeKey(t)
	body := buildVerifyBody(t, nk)

	// First request passes limiter and is audited.
	code, payload := doRawRequest(t, application.Router, "/verify", body)
	if code != http.StatusOK || denyReason(payload) != service.DenyReasonNotRegistered {
		t.Fatalf("first verify code=%d payload=%+v", code, payload)
	}

	var countAfterFirst int64
	if err := application.DB.Model(&model.AuditLog{}).Count(&countAfterFirst).Error; err != nil {
		t.Fatalf("count audit after first: %v", err)
	}
	if countAfterFirst != 1 {
		t.Fatalf("audit count after first=%d want=1", countAfterFirst)
	}

	// Second request is rate limited and MUST NOT create an audit row.
	code, payload = doRawRequest(t, application.Router, "/verify", body)
	if code != http.StatusOK {
		t.Fatalf("rate-limited verify status=%d want=200", code)
	}
	if allow, _ := payload["Allow"].(bool); allow {
		t.Fatalf("rate-limited verify expected deny")
	}
	if reason := denyReason(payload); reason != "rate limited" {
		t.Fatalf("reason=%q want=%q", reason, "rate limited")
	}

	var countAfterSecond int64
	if err := application.DB.Model(&model.AuditLog{}).Count(&countAfterSecond).Error; err != nil {
		t.Fatalf("count audit after second: %v", err)
	}
	if countAfterSecond != countAfterFirst {
		t.Fatalf("rate-limited verify created audit row: before=%d after=%d", countAfterFirst, countAfterSecond)
	}
}

func TestSyncRevokeAcrossInstances(t *testing.T) {
	const syncInterval = 200 * time.Millisecond
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "sync_revoke.db")

	appA := bBuildAppOnDB(t, dbURL, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
		c.PolicySyncInterval = syncInterval
	})
	appB := bBuildAppOnDB(t, dbURL, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
		c.PolicySyncInterval = syncInterval
	})

	userID, token := provisionUserAndToken(t, appA.Router, "sync-revoke-user")
	nk := newNodeKey(t)
	if status, _ := doJSONRequest(t, appA.Router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nk,
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=200", status)
	}

	// Wait until instance B allows the newly registered device (and warms B's cache).
	bWaitVerify(t, appB.Router, "/verify", nk, true, "", 5*syncInterval)
	// Second call on B hits B's verify cache.
	if _, payload := doRawRequest(t, appB.Router, "/verify", buildVerifyBody(t, nk)); payload["Allow"] != true {
		t.Fatalf("instance B cached verify expected allow, got %+v", payload)
	}

	// Find device id and revoke on instance A.
	status, body := doAdminRequest(t, appA.Router, http.MethodGet, "/admin/devices?userId="+userID, testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list devices status=%d want=200", status)
	}
	deviceID := body["devices"].([]any)[0].(map[string]any)["id"].(string)

	if status, _ := doAdminRequest(t, appA.Router, http.MethodPost, "/admin/devices/"+deviceID+"/revoke", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("revoke on instance A status=%d want=200", status)
	}

	// Instance B must reflect the revocation within two sync intervals.
	elapsed := bWaitVerify(t, appB.Router, "/verify", nk, false, service.DenyReasonRevoked, 2*syncInterval)
	t.Logf("TestSyncRevokeAcrossInstances: observed propagation delay=%v (bound 2*interval=%v)", elapsed, 2*syncInterval)
}

func TestSyncRoleBindingAcrossInstances(t *testing.T) {
	const syncInterval = 200 * time.Millisecond
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "sync_role.db")

	appA := bBuildAppOnDB(t, dbURL, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
		c.PolicySyncInterval = syncInterval
	})

	// Seed relay eu-1 and role eu-only before building appB so both instances know relay eu-1.
	bAddRelayAndRole(t, appA, "eu-1", "eu-only", []string{"eu-1"})

	appB := bBuildAppOnDB(t, dbURL, func(c *config.Config) {
		c.VerifyCacheTTL = time.Minute
		c.PolicySyncInterval = syncInterval
	})

	userIDRaw, token := provisionUserAndToken(t, appA.Router, "sync-role-user")
	userID := uuid.MustParse(userIDRaw)
	nk := newNodeKey(t)
	if status, _ := doJSONRequest(t, appA.Router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nk,
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=200", status)
	}

	// Wait until instance B sees the device and denies on eu-1 with policy denied (caching the deny).
	bWaitVerify(t, appB.Router, "/verify/eu-1", nk, false, service.DenyReasonPolicyDenied, 5*syncInterval)

	// Bind user to eu-only via Mutate on instance A.
	bBindUserRoles(t, appA, userID, []string{policy.BuiltinRole, "eu-only"})

	// Instance B must allow /verify/eu-1 within two sync intervals.
	elapsed := bWaitVerify(t, appB.Router, "/verify/eu-1", nk, true, "", 2*syncInterval)
	t.Logf("TestSyncRoleBindingAcrossInstances: observed propagation delay=%v (bound 2*interval=%v)", elapsed, 2*syncInterval)
}

func TestSyncStaleReadyzFailsClosedAndRecovers(t *testing.T) {
	const syncInterval = 40 * time.Millisecond
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "readyz_stale.db")

	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	// Register the callback BEFORE app.Build starts the background sync goroutine
	// so toggling failure via atomic.Bool is completely race-free.
	var failPolicyState atomic.Bool
	if err := gormDB.Callback().Query().Before("gorm:query").Register("b_fail_policy_state_query", func(tx *gorm.DB) {
		if failPolicyState.Load() && tx.Statement != nil && tx.Statement.Table == "policy_state" {
			_ = tx.AddError(errors.New("simulated policy_state outage"))
		}
	}); err != nil {
		t.Fatalf("register query callback: %v", err)
	}

	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "test-pepper",
		AdminAPIKey:          testAdminKey,
		EnableCasbin:         true,
		MetricsEnabled:       true,
		DBTimeout:            2 * time.Second,
		VerifyCacheTTL:       time.Minute,
		PolicySyncInterval:   syncInterval,
		VerifyRateLimitRPS:   1000,
		VerifyRateBurst:      1000,
		RegisterRateLimitRPS: 1000,
		RegisterRateBurst:    1000,
		AdminRateLimitRPS:    1000,
		AdminRateBurst:       1000,
	}
	application, err := app.Build(context.Background(), gormDB, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	t.Cleanup(func() {
		application.Close()
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	_, token := provisionUserAndToken(t, application.Router, "readyz-stale-user")
	nk := newNodeKey(t)
	if status, _ := doJSONRequest(t, application.Router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nk,
	}); status != http.StatusOK {
		t.Fatalf("register status=%d want=200", status)
	}

	// Warm verify cache and confirm /readyz is 200.
	if _, payload := doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, nk)); payload["Allow"] != true {
		t.Fatalf("initial verify expected allow, got %+v", payload)
	}
	checkReadyz := func() int {
		rec := httptest.NewRecorder()
		application.Router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code
	}
	if code := checkReadyz(); code != http.StatusOK {
		t.Fatalf("initial /readyz=%d want=200", code)
	}

	// Fail policy_state reads while keeping sqlDB Ping healthy.
	failPolicyState.Store(true)

	deadline := time.Now().Add(20 * syncInterval)
	for checkReadyz() != http.StatusServiceUnavailable {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for /readyz to return 503 while policy sync fails")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cached verify must now fail closed with internal error.
	_, payload := doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, nk))
	if allow, _ := payload["Allow"].(bool); allow || denyReason(payload) != service.DenyReasonInternal {
		t.Fatalf("stale verify payload=%+v want deny internal error", payload)
	}

	// Restore policy_state reads and confirm recovery.
	failPolicyState.Store(false)
	deadline = time.Now().Add(20 * syncInterval)
	for checkReadyz() != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for /readyz to recover to 200")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, payload := doRawRequest(t, application.Router, "/verify", buildVerifyBody(t, nk)); payload["Allow"] != true {
		t.Fatalf("recovered verify expected allow, got %+v", payload)
	}
}

func bWaitVerify(t *testing.T, handler http.Handler, path, nodeKey string, wantAllow bool, wantReason string, maxWait time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	body := buildVerifyBody(t, nodeKey)
	deadline := start.Add(maxWait)
	for {
		_, payload := doRawRequest(t, handler, path, body)
		allow, _ := payload["Allow"].(bool)
		reason := denyReason(payload)
		if allow == wantAllow && reason == wantReason {
			return time.Since(start)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s to return (%v, %q); last got (%v, %q)",
				maxWait, path, wantAllow, wantReason, allow, reason)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func bStrPtr(s string) *string { return &s }
