package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

func dNewApp(t *testing.T, opts ...func(*config.Config)) *app.App {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "track-d.db")
	dbURL := "sqlite://" + dbPath

	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	cfg := config.Config{
		DatabaseURL:          dbURL,
		TokenPepper:          "test-pepper",
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
		t.Fatalf("build app: %v", err)
	}
	t.Cleanup(func() {
		application.Close()
	})
	return application
}

func dStringSlice(t *testing.T, raw any) []string {
	t.Helper()
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("expected JSON array, got %T (%v)", raw, raw)
	}
	out := make([]string, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("expected string element at %d, got %T", i, item)
		}
		out[i] = s
	}
	return out
}

func dCreateUserWithDevice(t *testing.T, a *app.App, username string, roles []string) (uuid.UUID, string, []byte) {
	t.Helper()

	payload := map[string]any{"username": username}
	if roles != nil {
		payload["roles"] = roles
	}
	status, body := doAdminRequest(t, a.Router, http.MethodPost, "/admin/users", testAdminKey, payload)
	if status != http.StatusCreated {
		t.Fatalf("create user %s status=%d want=%d body=%v", username, status, http.StatusCreated, body)
	}
	userID := uuid.MustParse(body["user"].(map[string]any)["id"].(string))

	status, body = doAdminRequest(t, a.Router, http.MethodPost, "/admin/tokens", testAdminKey, map[string]any{
		"userId": userID.String(),
	})
	if status != http.StatusCreated {
		t.Fatalf("create token status=%d want=%d", status, http.StatusCreated)
	}
	token := body["token"].(string)

	nodeKey := newNodeKey(t)
	status, _ = doJSONRequest(t, a.Router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
		"label":   "device-1",
	})
	if status != http.StatusOK {
		t.Fatalf("register device status=%d want=%d", status, http.StatusOK)
	}
	return userID, nodeKey, buildVerifyBody(t, nodeKey)
}

func TestAccessRelayAndRoleNameValidation(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	invalidNames := []string{
		"",
		"Ops",
		"-ops",
		"ops_team",
		"eu 1",
		" eu-1",
		"eu-1 ",
		"eu.1",
		"*",
		strings.Repeat("a", 64),
	}

	for _, name := range invalidNames {
		status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
			"name": name,
		})
		if status != http.StatusBadRequest {
			t.Fatalf("POST /admin/relays name=%q status=%d want=%d", name, status, http.StatusBadRequest)
		}

		status, _ = doAdminRequest(t, router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
			"name": name,
		})
		if status != http.StatusBadRequest {
			t.Fatalf("POST /admin/roles name=%q status=%d want=%d", name, status, http.StatusBadRequest)
		}
	}

	// Only built-ins should exist after all invalid attempts.
	var relayCount, roleCount int64
	if err := gormDB.Model(&model.Relay{}).Count(&relayCount).Error; err != nil {
		t.Fatalf("count relays: %v", err)
	}
	if err := gormDB.Model(&model.Role{}).Count(&roleCount).Error; err != nil {
		t.Fatalf("count roles: %v", err)
	}
	if relayCount != 1 || roleCount != 1 {
		t.Fatalf("counts after invalid creates: relays=%d roles=%d want=1/1", relayCount, roleCount)
	}

	// Valid names including single character and 63-char maximum length succeed.
	validNames := []string{"eu-1", "a", strings.Repeat("b", 63)}
	for _, name := range validNames {
		status, body := doAdminRequest(t, router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
			"name": name,
		})
		if status != http.StatusCreated {
			t.Fatalf("POST /admin/relays valid name=%q status=%d want=%d body=%v", name, status, http.StatusCreated, body)
		}
		if body["relay"].(map[string]any)["name"] != name {
			t.Fatalf("relay name=%v want=%q", body["relay"].(map[string]any)["name"], name)
		}

		status, body = doAdminRequest(t, router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
			"name": name,
		})
		if status != http.StatusCreated {
			t.Fatalf("POST /admin/roles valid name=%q status=%d want=%d body=%v", name, status, http.StatusCreated, body)
		}
		if body["role"].(map[string]any)["name"] != name {
			t.Fatalf("role name=%v want=%q", body["role"].(map[string]any)["name"], name)
		}
	}
}

func TestAccessRelayCRUD(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Create relay with description.
	status, body := doAdminRequest(t, router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
		"name":        "eu-1",
		"description": "Frankfurt relay",
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /admin/relays status=%d want=%d body=%v", status, http.StatusCreated, body)
	}
	relayObj := body["relay"].(map[string]any)
	if relayObj["name"] != "eu-1" || relayObj["description"] != "Frankfurt relay" {
		t.Fatalf("unexpected relay view: %v", relayObj)
	}
	if _, err := time.Parse(time.RFC3339Nano, relayObj["createdAt"].(string)); err != nil {
		t.Fatalf("invalid createdAt %q: %v", relayObj["createdAt"], err)
	}

	// Duplicate relay name -> 409.
	for _, dup := range []string{"eu-1", "default"} {
		status, _ = doAdminRequest(t, router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
			"name": dup,
		})
		if status != http.StatusConflict {
			t.Fatalf("duplicate POST /admin/relays %q status=%d want=%d", dup, status, http.StatusConflict)
		}
	}

	// List relays -> default and eu-1.
	status, body = doAdminRequest(t, router, http.MethodGet, "/admin/relays", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /admin/relays status=%d want=%d", status, http.StatusOK)
	}
	if body["nextCursor"] != nil {
		t.Fatalf("expected nextCursor=null, got %v", body["nextCursor"])
	}
	relayItems := body["relays"].([]any)
	if len(relayItems) != 2 {
		t.Fatalf("relays len=%d want=2", len(relayItems))
	}

	// Grant eu-1 to a role, then delete eu-1 and confirm its grant is removed.
	status, _ = doAdminRequest(t, router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "ops",
		"relays": []string{"default", "eu-1"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create role ops status=%d want=%d", status, http.StatusCreated)
	}

	status, _ = doAdminRequest(t, router, http.MethodDelete, "/admin/relays/eu-1", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("DELETE /admin/relays/eu-1 status=%d want=%d", status, http.StatusOK)
	}

	// Relay no longer exists and no casbin_rule grant names derp:eu-1.
	var remainingRelays int64
	if err := gormDB.Model(&model.Relay{}).Where("name = ?", "eu-1").Count(&remainingRelays).Error; err != nil {
		t.Fatalf("count eu-1 relay: %v", err)
	}
	if remainingRelays != 0 {
		t.Fatalf("eu-1 relay count=%d want=0", remainingRelays)
	}
	var remainingGrants int64
	if err := gormDB.Model(&model.CasbinRule{}).Where("ptype = ? AND v1 = ?", "p", "derp:eu-1").Count(&remainingGrants).Error; err != nil {
		t.Fatalf("count eu-1 grants: %v", err)
	}
	if remainingGrants != 0 {
		t.Fatalf("eu-1 grant count=%d want=0", remainingGrants)
	}

	// GET /admin/roles reports ops with only ["default"].
	status, body = doAdminRequest(t, router, http.MethodGet, "/admin/roles", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /admin/roles status=%d want=%d", status, http.StatusOK)
	}
	var opsRelays []string
	for _, raw := range body["roles"].([]any) {
		item := raw.(map[string]any)
		if item["name"] == "ops" {
			opsRelays = dStringSlice(t, item["relays"])
		}
	}
	if !reflect.DeepEqual(opsRelays, []string{"default"}) {
		t.Fatalf("ops relays after deleting eu-1=%v want=[default]", opsRelays)
	}

	// Deleting an unknown relay -> 404.
	status, _ = doAdminRequest(t, router, http.MethodDelete, "/admin/relays/no-such-relay", testAdminKey, nil)
	if status != http.StatusNotFound {
		t.Fatalf("DELETE unknown relay status=%d want=%d", status, http.StatusNotFound)
	}

	// Deleting built-in relay default -> 409, and default remains.
	status, _ = doAdminRequest(t, router, http.MethodDelete, "/admin/relays/default", testAdminKey, nil)
	if status != http.StatusConflict {
		t.Fatalf("DELETE /admin/relays/default status=%d want=%d", status, http.StatusConflict)
	}
	var defaultCount int64
	if err := gormDB.Model(&model.Relay{}).Where("name = ?", "default").Count(&defaultCount).Error; err != nil {
		t.Fatalf("count default relay: %v", err)
	}
	if defaultCount != 1 {
		t.Fatalf("default relay count=%d want=1", defaultCount)
	}
}

func TestAccessRoleCRUDAndGrants(t *testing.T) {
	a := dNewApp(t, adminKeyOpt)

	// Create relay eu-1.
	if status, _ := doAdminRequest(t, a.Router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
		"name": "eu-1",
	}); status != http.StatusCreated {
		t.Fatalf("create eu-1 status=%d want=%d", status, http.StatusCreated)
	}

	// 1. Create role with named grants.
	status, body := doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":        "regional",
		"description": "EU and default",
		"relays":      []string{"eu-1", "default"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create role regional status=%d want=%d body=%v", status, http.StatusCreated, body)
	}
	roleObj := body["role"].(map[string]any)
	if roleObj["name"] != "regional" || roleObj["description"] != "EU and default" {
		t.Fatalf("unexpected role view: %v", roleObj)
	}
	if _, err := time.Parse(time.RFC3339Nano, roleObj["createdAt"].(string)); err != nil {
		t.Fatalf("invalid createdAt %q: %v", roleObj["createdAt"], err)
	}
	if !reflect.DeepEqual(dStringSlice(t, roleObj["relays"]), []string{"default", "eu-1"}) {
		t.Fatalf("regional relays=%v want=[default eu-1]", roleObj["relays"])
	}

	// 2. Create role without relays -> empty grants; user bound only to it is denied everywhere.
	status, body = doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name": "quarantine",
	})
	if status != http.StatusCreated {
		t.Fatalf("create role quarantine status=%d want=%d", status, http.StatusCreated)
	}
	if got := dStringSlice(t, body["role"].(map[string]any)["relays"]); len(got) != 0 {
		t.Fatalf("quarantine relays=%v want=[]", got)
	}
	_, _, qBody := dCreateUserWithDevice(t, a, "quarantine-user", []string{"quarantine"})
	for _, relay := range []string{"default", "eu-1"} {
		allow, reason := a.Service.Verify(context.Background(), relay, qBody)
		if allow || reason != service.DenyReasonPolicyDenied {
			t.Fatalf("quarantine verify on %s=(%v, %q) want=(false, %q)", relay, allow, reason, service.DenyReasonPolicyDenied)
		}
	}

	// 3. Create role with wildcard ["*"].
	status, body = doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "global",
		"relays": []string{"*"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create role global status=%d want=%d", status, http.StatusCreated)
	}
	if !reflect.DeepEqual(dStringSlice(t, body["role"].(map[string]any)["relays"]), []string{"*"}) {
		t.Fatalf("global relays=%v want=[*]", body["role"].(map[string]any)["relays"])
	}

	// 4. Duplicate role name -> 409.
	for _, dup := range []string{"regional", "standard"} {
		status, _ = doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
			"name": dup,
		})
		if status != http.StatusConflict {
			t.Fatalf("duplicate role %q status=%d want=%d", dup, status, http.StatusConflict)
		}
	}

	// 5. Unknown relay on POST /admin/roles -> 400 and role not created.
	status, _ = doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "bad-relay-role",
		"relays": []string{"default", "no-such-relay"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("create role unknown relay status=%d want=%d", status, http.StatusBadRequest)
	}
	var badRoleCount int64
	if err := a.DB.Model(&model.Role{}).Where("name = ?", "bad-relay-role").Count(&badRoleCount).Error; err != nil {
		t.Fatalf("count bad-relay-role: %v", err)
	}
	if badRoleCount != 0 {
		t.Fatalf("bad-relay-role count=%d want=0", badRoleCount)
	}

	// 6. Wildcard mixed with other entries on POST and PUT -> 400 and changes nothing.
	mixedCases := [][]string{
		{"*", "default"},
		{"default", "*"},
		{"*", "*"},
	}
	for _, mixed := range mixedCases {
		status, _ = doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
			"name":   "mixed-wild-role",
			"relays": mixed,
		})
		if status != http.StatusBadRequest {
			t.Fatalf("POST mixed wildcard %v status=%d want=%d", mixed, status, http.StatusBadRequest)
		}
		status, _ = doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/regional/relays", testAdminKey, map[string]any{
			"relays": mixed,
		})
		if status != http.StatusBadRequest {
			t.Fatalf("PUT mixed wildcard %v status=%d want=%d", mixed, status, http.StatusBadRequest)
		}
	}

	// 7. Unknown relay or missing relays field on PUT /admin/roles/:name/relays -> 400 and unchanged.
	status, _ = doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/regional/relays", testAdminKey, map[string]any{
		"relays": []string{"unknown-relay"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("PUT unknown relay status=%d want=%d", status, http.StatusBadRequest)
	}
	status, _ = doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/regional/relays", testAdminKey, map[string]any{})
	if status != http.StatusBadRequest {
		t.Fatalf("PUT missing relays status=%d want=%d", status, http.StatusBadRequest)
	}
	grantsMap, err := policy.RoleGrants(context.Background(), a.DB, []string{"regional"})
	if err != nil {
		t.Fatalf("RoleGrants regional: %v", err)
	}
	if !reflect.DeepEqual(grantsMap["regional"], []string{"default", "eu-1"}) {
		t.Fatalf("regional grants changed after failed PUTs: got=%v want=[default eu-1]", grantsMap["regional"])
	}

	// 8. Replace grants on regional: named -> ["eu-1"] -> ["*"] -> [].
	status, body = doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/regional/relays", testAdminKey, map[string]any{
		"relays": []string{"eu-1"},
	})
	if status != http.StatusOK {
		t.Fatalf("PUT regional relays=[eu-1] status=%d want=%d", status, http.StatusOK)
	}
	if !reflect.DeepEqual(dStringSlice(t, body["relays"]), []string{"eu-1"}) {
		t.Fatalf("PUT response relays=%v want=[eu-1]", body["relays"])
	}
	status, body = doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/regional/relays", testAdminKey, map[string]any{
		"relays": []string{"*"},
	})
	if status != http.StatusOK || !reflect.DeepEqual(dStringSlice(t, body["relays"]), []string{"*"}) {
		t.Fatalf("PUT regional relays=[*] status=%d body=%v", status, body)
	}
	status, body = doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/regional/relays", testAdminKey, map[string]any{
		"relays": []string{},
	})
	if status != http.StatusOK || len(dStringSlice(t, body["relays"])) != 0 {
		t.Fatalf("PUT regional relays=[] status=%d body=%v", status, body)
	}

	// 9. Unknown role on PUT and DELETE -> 404.
	status, _ = doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/no-such-role/relays", testAdminKey, map[string]any{
		"relays": []string{"default"},
	})
	if status != http.StatusNotFound {
		t.Fatalf("PUT unknown role status=%d want=%d", status, http.StatusNotFound)
	}
	status, _ = doAdminRequest(t, a.Router, http.MethodDelete, "/admin/roles/no-such-role", testAdminKey, nil)
	if status != http.StatusNotFound {
		t.Fatalf("DELETE unknown role status=%d want=%d", status, http.StatusNotFound)
	}

	// 10. Built-in role standard cannot be deleted (409), but its grants can be edited (200).
	status, _ = doAdminRequest(t, a.Router, http.MethodDelete, "/admin/roles/standard", testAdminKey, nil)
	if status != http.StatusConflict {
		t.Fatalf("DELETE /admin/roles/standard status=%d want=%d", status, http.StatusConflict)
	}
	status, body = doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/standard/relays", testAdminKey, map[string]any{
		"relays": []string{"default", "eu-1"},
	})
	if status != http.StatusOK {
		t.Fatalf("PUT /admin/roles/standard/relays status=%d want=%d body=%v", status, http.StatusOK, body)
	}
	if !reflect.DeepEqual(dStringSlice(t, body["relays"]), []string{"default", "eu-1"}) {
		t.Fatalf("standard relays=%v want=[default eu-1]", body["relays"])
	}

	// 11. GET /admin/roles lists every role with its current grants.
	status, body = doAdminRequest(t, a.Router, http.MethodGet, "/admin/roles", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /admin/roles status=%d want=%d", status, http.StatusOK)
	}
	gotByName := map[string][]string{}
	for _, raw := range body["roles"].([]any) {
		item := raw.(map[string]any)
		if _, ok := item["description"]; !ok {
			t.Fatalf("role item missing description: %v", item)
		}
		if _, err := time.Parse(time.RFC3339Nano, item["createdAt"].(string)); err != nil {
			t.Fatalf("role item invalid createdAt: %v", item)
		}
		gotByName[item["name"].(string)] = dStringSlice(t, item["relays"])
	}
	wantByName := map[string][]string{
		"standard":   {"default", "eu-1"},
		"regional":   {},
		"quarantine": {},
		"global":     {"*"},
	}
	if !reflect.DeepEqual(gotByName, wantByName) {
		t.Fatalf("GET /admin/roles=%v want=%v", gotByName, wantByName)
	}
}

func TestAccessDeleteRoleReportsRemovedBindings(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "team-a",
		"relays": []string{"default"},
	}); status != http.StatusCreated {
		t.Fatalf("create team-a status=%d want=%d", status, http.StatusCreated)
	}

	var userIDs []uuid.UUID
	for i := 0; i < 3; i++ {
		roles := []string{"team-a"}
		if i == 0 {
			roles = []string{"standard", "team-a"}
		}
		status, body := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
			"username": fmt.Sprintf("team-a-user-%d", i),
			"roles":    roles,
		})
		if status != http.StatusCreated {
			t.Fatalf("create user %d status=%d want=%d", i, status, http.StatusCreated)
		}
		userIDs = append(userIDs, uuid.MustParse(body["user"].(map[string]any)["id"].(string)))
	}

	status, body := doAdminRequest(t, router, http.MethodDelete, "/admin/roles/team-a", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("DELETE /admin/roles/team-a status=%d want=%d body=%v", status, http.StatusOK, body)
	}
	if removed, ok := body["removedBindings"].(float64); !ok || int64(removed) != 3 {
		t.Fatalf("removedBindings=%v want=3", body["removedBindings"])
	}

	// Role row and grants are removed.
	var roleCount int64
	if err := gormDB.Model(&model.Role{}).Where("name = ?", "team-a").Count(&roleCount).Error; err != nil {
		t.Fatalf("count team-a: %v", err)
	}
	if roleCount != 0 {
		t.Fatalf("team-a role count=%d want=0", roleCount)
	}
	var grantCount int64
	if err := gormDB.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ?", "p", "role:team-a").Count(&grantCount).Error; err != nil {
		t.Fatalf("count team-a grants: %v", err)
	}
	if grantCount != 0 {
		t.Fatalf("team-a grant count=%d want=0", grantCount)
	}

	// None of the three users remain bound to team-a; user 0 retains standard.
	rolesMap, err := policy.UserRoles(context.Background(), gormDB, userIDs)
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[userIDs[0]], []string{"standard"}) {
		t.Fatalf("user0 roles=%v want=[standard]", rolesMap[userIDs[0]])
	}
	for i := 1; i < 3; i++ {
		if len(rolesMap[userIDs[i]]) != 0 {
			t.Fatalf("user%d roles=%v want=[]", i, rolesMap[userIDs[i]])
		}
	}
}

func TestAccessSetUserRoles(t *testing.T) {
	a := dNewApp(t, adminKeyOpt)

	if status, _ := doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "ops",
		"relays": []string{"default"},
	}); status != http.StatusCreated {
		t.Fatalf("create ops role status=%d want=%d", status, http.StatusCreated)
	}
	if status, _ := doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "dev",
		"relays": []string{"default"},
	}); status != http.StatusCreated {
		t.Fatalf("create dev role status=%d want=%d", status, http.StatusCreated)
	}

	userID, _, verifyBody := dCreateUserWithDevice(t, a, "role-target", nil)

	// 1. Replace roles with ["ops", "dev"].
	status, body := doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+userID.String()+"/roles", testAdminKey, map[string]any{
		"roles": []string{"ops", "dev"},
	})
	if status != http.StatusOK {
		t.Fatalf("PUT user roles status=%d want=%d body=%v", status, http.StatusOK, body)
	}
	if !reflect.DeepEqual(dStringSlice(t, body["roles"]), []string{"dev", "ops"}) {
		t.Fatalf("response roles=%v want=[dev ops]", body["roles"])
	}
	rolesMap, err := policy.UserRoles(context.Background(), a.DB, []uuid.UUID{userID})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[userID], []string{"dev", "ops"}) {
		t.Fatalf("stored roles=%v want=[dev ops]", rolesMap[userID])
	}

	// 2. Unknown role -> 400 and bindings unchanged.
	status, _ = doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+userID.String()+"/roles", testAdminKey, map[string]any{
		"roles": []string{"dev", "no-such-role"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("PUT unknown role status=%d want=%d", status, http.StatusBadRequest)
	}
	rolesMap, err = policy.UserRoles(context.Background(), a.DB, []uuid.UUID{userID})
	if err != nil {
		t.Fatalf("UserRoles after 400: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[userID], []string{"dev", "ops"}) {
		t.Fatalf("roles changed after 400: got=%v want=[dev ops]", rolesMap[userID])
	}

	// 3. Missing roles field -> 400.
	status, _ = doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+userID.String()+"/roles", testAdminKey, map[string]any{})
	if status != http.StatusBadRequest {
		t.Fatalf("PUT missing roles status=%d want=%d", status, http.StatusBadRequest)
	}

	// 4. Clear roles with [] -> user has no bindings and verify returns policy denied.
	status, body = doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+userID.String()+"/roles", testAdminKey, map[string]any{
		"roles": []string{},
	})
	if status != http.StatusOK {
		t.Fatalf("PUT empty roles status=%d want=%d", status, http.StatusOK)
	}
	if got := dStringSlice(t, body["roles"]); len(got) != 0 {
		t.Fatalf("response roles=%v want=[]", got)
	}
	allow, reason := a.Service.Verify(context.Background(), "default", verifyBody)
	if allow || reason != service.DenyReasonPolicyDenied {
		t.Fatalf("verify after clearing roles=(%v, %q) want=(false, %q)", allow, reason, service.DenyReasonPolicyDenied)
	}

	// 5. Malformed user id -> 400, unknown UUID -> 404.
	status, _ = doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/not-a-uuid/roles", testAdminKey, map[string]any{
		"roles": []string{"standard"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("PUT malformed user id status=%d want=%d", status, http.StatusBadRequest)
	}
	status, _ = doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+uuid.New().String()+"/roles", testAdminKey, map[string]any{
		"roles": []string{"standard"},
	})
	if status != http.StatusNotFound {
		t.Fatalf("PUT unknown user id status=%d want=%d", status, http.StatusNotFound)
	}
}

func TestAccessTierChecks(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	viewerKey := insertAdminKey(t, gormDB, "d-viewer", actor.TierViewer)
	operatorKey := insertAdminKey(t, gormDB, "d-operator", actor.TierOperator)
	adminKey := insertAdminKey(t, gormDB, "d-admin", actor.TierAdmin)

	// Prepare a user, relay, and role for testing.
	userID, _ := provisionUserAndToken(t, router, "tier-user")
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/relays", adminKey, map[string]any{
		"name": "eu-1",
	}); status != http.StatusCreated {
		t.Fatalf("admin create eu-1 status=%d want=%d", status, http.StatusCreated)
	}
	if status, _ := doAdminRequest(t, router, http.MethodPost, "/admin/roles", adminKey, map[string]any{
		"name":   "ops",
		"relays": []string{"eu-1"},
	}); status != http.StatusCreated {
		t.Fatalf("admin create ops status=%d want=%d", status, http.StatusCreated)
	}

	// Viewer can read relays and roles.
	for _, path := range []string{"/admin/relays", "/admin/roles"} {
		if status, _ := doAdminRequest(t, router, http.MethodGet, path, viewerKey, nil); status != http.StatusOK {
			t.Fatalf("viewer GET %s status=%d want=%d", path, status, http.StatusOK)
		}
	}

	// Viewer cannot perform any access write (all 403).
	viewerForbidden := []struct {
		method  string
		path    string
		payload any
	}{
		{http.MethodPost, "/admin/relays", map[string]any{"name": "v-relay"}},
		{http.MethodDelete, "/admin/relays/eu-1", nil},
		{http.MethodPost, "/admin/roles", map[string]any{"name": "v-role"}},
		{http.MethodPut, "/admin/roles/ops/relays", map[string]any{"relays": []string{"default"}}},
		{http.MethodDelete, "/admin/roles/ops", nil},
		{http.MethodPut, "/admin/users/" + userID + "/roles", map[string]any{"roles": []string{"ops"}}},
	}
	for _, tc := range viewerForbidden {
		if status, _ := doAdminRequest(t, router, tc.method, tc.path, viewerKey, tc.payload); status != http.StatusForbidden {
			t.Fatalf("viewer %s %s status=%d want=%d", tc.method, tc.path, status, http.StatusForbidden)
		}
	}

	// Operator can read relays/roles and set user roles, but cannot write roles or relays.
	for _, path := range []string{"/admin/relays", "/admin/roles"} {
		if status, _ := doAdminRequest(t, router, http.MethodGet, path, operatorKey, nil); status != http.StatusOK {
			t.Fatalf("operator GET %s status=%d want=%d", path, status, http.StatusOK)
		}
	}
	if status, _ := doAdminRequest(t, router, http.MethodPut, "/admin/users/"+userID+"/roles", operatorKey, map[string]any{
		"roles": []string{"ops"},
	}); status != http.StatusOK {
		t.Fatalf("operator PUT /admin/users/:id/roles status=%d want=%d", status, http.StatusOK)
	}

	operatorForbidden := []struct {
		method  string
		path    string
		payload any
	}{
		{http.MethodPost, "/admin/relays", map[string]any{"name": "o-relay"}},
		{http.MethodDelete, "/admin/relays/eu-1", nil},
		{http.MethodPost, "/admin/roles", map[string]any{"name": "o-role"}},
		{http.MethodPut, "/admin/roles/ops/relays", map[string]any{"relays": []string{"default"}}},
		{http.MethodDelete, "/admin/roles/ops", nil},
	}
	for _, tc := range operatorForbidden {
		if status, _ := doAdminRequest(t, router, tc.method, tc.path, operatorKey, tc.payload); status != http.StatusForbidden {
			t.Fatalf("operator %s %s status=%d want=%d", tc.method, tc.path, status, http.StatusForbidden)
		}
	}

	// Confirm none of the forbidden writes took effect.
	var count int64
	if err := gormDB.Model(&model.Relay{}).Where("name IN ?", []string{"v-relay", "o-relay"}).Count(&count).Error; err != nil {
		t.Fatalf("count forbidden relays: %v", err)
	}
	if count != 0 {
		t.Fatalf("forbidden relays count=%d want=0", count)
	}
	if err := gormDB.Model(&model.Role{}).Where("name IN ?", []string{"v-role", "o-role"}).Count(&count).Error; err != nil {
		t.Fatalf("count forbidden roles: %v", err)
	}
	if count != 0 {
		t.Fatalf("forbidden roles count=%d want=0", count)
	}
	if err := gormDB.Model(&model.Relay{}).Where("name = ?", "eu-1").Count(&count).Error; err != nil {
		t.Fatalf("count eu-1: %v", err)
	}
	if count != 1 {
		t.Fatalf("eu-1 should still exist after forbidden deletes: count=%d", count)
	}

	// Admin can perform role/relay mutations.
	if status, _ := doAdminRequest(t, router, http.MethodPut, "/admin/roles/ops/relays", adminKey, map[string]any{
		"relays": []string{"default"},
	}); status != http.StatusOK {
		t.Fatalf("admin PUT role relays status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/roles/ops", adminKey, nil); status != http.StatusOK {
		t.Fatalf("admin DELETE role status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/relays/eu-1", adminKey, nil); status != http.StatusOK {
		t.Fatalf("admin DELETE relay status=%d want=%d", status, http.StatusOK)
	}
}

func TestAccessListPagination(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Seed 55 extra relays and 55 extra roles (56 total each, including built-ins)
	// with deliberate timestamp ties to exercise the name tie-break.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := gormDB.Model(&model.Relay{}).Where("name = ?", "default").Update("created_at", base).Error; err != nil {
		t.Fatalf("update default relay created_at: %v", err)
	}
	if err := gormDB.Model(&model.Role{}).Where("name = ?", "standard").Update("created_at", base).Error; err != nil {
		t.Fatalf("update standard role created_at: %v", err)
	}

	wantRelays := []string{"default"}
	wantRoles := []string{"standard"}
	for i := 0; i < 55; i++ {
		// Group in pairs sharing identical CreatedAt to verify ascending name tie-break.
		ts := base.Add(time.Duration(i/2+1) * time.Second)
		relayName := fmt.Sprintf("r-%02d", i)
		roleName := fmt.Sprintf("role-%02d", i)
		if err := gormDB.Create(&model.Relay{Name: relayName, CreatedAt: ts}).Error; err != nil {
			t.Fatalf("seed relay %s: %v", relayName, err)
		}
		if err := gormDB.Create(&model.Role{Name: roleName, CreatedAt: ts}).Error; err != nil {
			t.Fatalf("seed role %s: %v", roleName, err)
		}
		wantRelays = append(wantRelays, relayName)
		wantRoles = append(wantRoles, roleName)
	}

	checkPaginated := func(t *testing.T, path, field string, want []string) string {
		t.Helper()

		// 1. Default page size = 50.
		status, body := doAdminRequest(t, router, http.MethodGet, path, testAdminKey, nil)
		if status != http.StatusOK {
			t.Fatalf("GET %s status=%d want=%d", path, status, http.StatusOK)
		}
		page1 := body[field].([]any)
		if len(page1) != 50 {
			t.Fatalf("GET %s default page len=%d want=50", path, len(page1))
		}
		firstCursor, ok := body["nextCursor"].(string)
		if !ok || firstCursor == "" {
			t.Fatalf("GET %s expected non-empty nextCursor, got %v", path, body["nextCursor"])
		}

		// Follow default cursor to last page.
		status, body = doAdminRequest(t, router, http.MethodGet, path+"?cursor="+url.QueryEscape(firstCursor), testAdminKey, nil)
		if status != http.StatusOK {
			t.Fatalf("GET %s page2 status=%d want=%d", path, status, http.StatusOK)
		}
		page2 := body[field].([]any)
		if len(page2) != len(want)-50 {
			t.Fatalf("GET %s page2 len=%d want=%d", path, len(page2), len(want)-50)
		}
		if body["nextCursor"] != nil {
			t.Fatalf("GET %s last page nextCursor=%v want=null", path, body["nextCursor"])
		}

		// 2. Walk every page with limit=7 and assert exact ordering, no duplicates or skips.
		var collected []string
		cursor := ""
		for {
			reqPath := path + "?limit=7"
			if cursor != "" {
				reqPath += "&cursor=" + url.QueryEscape(cursor)
			}
			status, body = doAdminRequest(t, router, http.MethodGet, reqPath, testAdminKey, nil)
			if status != http.StatusOK {
				t.Fatalf("GET %s status=%d want=%d", reqPath, status, http.StatusOK)
			}
			for _, raw := range body[field].([]any) {
				collected = append(collected, raw.(map[string]any)["name"].(string))
			}
			if body["nextCursor"] == nil {
				break
			}
			cursor = body["nextCursor"].(string)
		}
		if !reflect.DeepEqual(collected, want) {
			t.Fatalf("GET %s walked order mismatch:\ngot=%v\nwant=%v", path, collected, want)
		}

		// 3. Invalid limits and cursors -> 400.
		for _, badQuery := range []string{"limit=0", "limit=-1", "limit=201", "limit=abc", "cursor=not-valid-base64!!!"} {
			status, _ = doAdminRequest(t, router, http.MethodGet, path+"?"+badQuery, testAdminKey, nil)
			if status != http.StatusBadRequest {
				t.Fatalf("GET %s?%s status=%d want=%d", path, badQuery, status, http.StatusBadRequest)
			}
		}

		return firstCursor
	}

	relaysCursor := checkPaginated(t, "/admin/relays", "relays", wantRelays)
	rolesCursor := checkPaginated(t, "/admin/roles", "roles", wantRoles)

	// Foreign list cursor -> 400.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/roles?cursor="+url.QueryEscape(relaysCursor), testAdminKey, nil); status != http.StatusBadRequest {
		t.Fatalf("relays cursor on /admin/roles status=%d want=%d", status, http.StatusBadRequest)
	}
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/relays?cursor="+url.QueryEscape(rolesCursor), testAdminKey, nil); status != http.StatusBadRequest {
		t.Fatalf("roles cursor on /admin/relays status=%d want=%d", status, http.StatusBadRequest)
	}
}

func TestAccessAdmissionEffects(t *testing.T) {
	a := dNewApp(t, adminKeyOpt)

	// Create relay eu-1 and role eu-only granted only eu-1.
	if status, _ := doAdminRequest(t, a.Router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
		"name": "eu-1",
	}); status != http.StatusCreated {
		t.Fatalf("create eu-1 status=%d want=%d", status, http.StatusCreated)
	}
	if status, _ := doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "eu-only",
		"relays": []string{"eu-1"},
	}); status != http.StatusCreated {
		t.Fatalf("create eu-only status=%d want=%d", status, http.StatusCreated)
	}

	userID, _, verifyBody := dCreateUserWithDevice(t, a, "eu-user", []string{"eu-only"})

	// 1. User bound to eu-only is allowed on eu-1 and denied on default with policy denied.
	allow, reason := a.Service.Verify(context.Background(), "eu-1", verifyBody)
	if !allow || reason != "" {
		t.Fatalf("verify on eu-1=(%v, %q) want=(true, \"\")", allow, reason)
	}
	allow, reason = a.Service.Verify(context.Background(), "default", verifyBody)
	if allow || reason != service.DenyReasonPolicyDenied {
		t.Fatalf("verify on default=(%v, %q) want=(false, %q)", allow, reason, service.DenyReasonPolicyDenied)
	}

	// 2. After PUT .../relays removes eu-1, next verify is denied without a restart.
	if status, _ := doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/eu-only/relays", testAdminKey, map[string]any{
		"relays": []string{},
	}); status != http.StatusOK {
		t.Fatalf("clear eu-only grants status=%d want=%d", status, http.StatusOK)
	}
	allow, reason = a.Service.Verify(context.Background(), "eu-1", verifyBody)
	if allow || reason != service.DenyReasonPolicyDenied {
		t.Fatalf("verify after removing grant=(%v, %q) want=(false, %q)", allow, reason, service.DenyReasonPolicyDenied)
	}

	// 3. A role with ["*"] is allowed on a relay created afterwards.
	if status, _ := doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
		"name":   "wild",
		"relays": []string{"*"},
	}); status != http.StatusCreated {
		t.Fatalf("create wild role status=%d want=%d", status, http.StatusCreated)
	}
	if status, _ := doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+userID.String()+"/roles", testAdminKey, map[string]any{
		"roles": []string{"wild"},
	}); status != http.StatusOK {
		t.Fatalf("bind wild role status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doAdminRequest(t, a.Router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
		"name": "ap-1",
	}); status != http.StatusCreated {
		t.Fatalf("create ap-1 after wild role status=%d want=%d", status, http.StatusCreated)
	}
	allow, reason = a.Service.Verify(context.Background(), "ap-1", verifyBody)
	if !allow || reason != "" {
		t.Fatalf("wild role verify on newly created ap-1=(%v, %q) want=(true, \"\")", allow, reason)
	}

	// 4. Deleting the role denies the next verify.
	if status, _ := doAdminRequest(t, a.Router, http.MethodDelete, "/admin/roles/wild", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("delete wild role status=%d want=%d", status, http.StatusOK)
	}
	allow, reason = a.Service.Verify(context.Background(), "ap-1", verifyBody)
	if allow || reason != service.DenyReasonPolicyDenied {
		t.Fatalf("verify after deleting role=(%v, %q) want=(false, %q)", allow, reason, service.DenyReasonPolicyDenied)
	}

	// 5. Re-bind a role granted ap-1, verify allow, then remove role from user -> denied.
	if status, _ := doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/eu-only/relays", testAdminKey, map[string]any{
		"relays": []string{"ap-1"},
	}); status != http.StatusOK {
		t.Fatalf("grant ap-1 to eu-only status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+userID.String()+"/roles", testAdminKey, map[string]any{
		"roles": []string{"eu-only"},
	}); status != http.StatusOK {
		t.Fatalf("bind eu-only status=%d want=%d", status, http.StatusOK)
	}
	if allow, reason := a.Service.Verify(context.Background(), "ap-1", verifyBody); !allow {
		t.Fatalf("expected allow after re-binding eu-only, got deny=%q", reason)
	}
	if status, _ := doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+userID.String()+"/roles", testAdminKey, map[string]any{
		"roles": []string{},
	}); status != http.StatusOK {
		t.Fatalf("clear user roles status=%d want=%d", status, http.StatusOK)
	}
	allow, reason = a.Service.Verify(context.Background(), "ap-1", verifyBody)
	if allow || reason != service.DenyReasonPolicyDenied {
		t.Fatalf("verify after removing role from user=(%v, %q) want=(false, %q)", allow, reason, service.DenyReasonPolicyDenied)
	}

	// 6. Deleting a relay denies subsequent verify on that relay.
	if status, _ := doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+userID.String()+"/roles", testAdminKey, map[string]any{
		"roles": []string{"eu-only"},
	}); status != http.StatusOK {
		t.Fatalf("rebind eu-only status=%d want=%d", status, http.StatusOK)
	}
	if allow, reason := a.Service.Verify(context.Background(), "ap-1", verifyBody); !allow {
		t.Fatalf("expected allow before deleting ap-1, got deny=%q", reason)
	}
	if status, _ := doAdminRequest(t, a.Router, http.MethodDelete, "/admin/relays/ap-1", testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("delete ap-1 status=%d want=%d", status, http.StatusOK)
	}
	if allow, _ := a.Service.Verify(context.Background(), "ap-1", verifyBody); allow {
		t.Fatalf("expected deny on deleted relay ap-1, got allow")
	}
}

func TestAccessAdmissionInvalidatesLiveCache(t *testing.T) {
	setup := func(t *testing.T) (*app.App, uuid.UUID, []byte) {
		t.Helper()
		a := dNewApp(t, adminKeyOpt, func(c *config.Config) {
			c.VerifyCacheTTL = time.Minute
		})
		if status, _ := doAdminRequest(t, a.Router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{
			"name": "eu-1",
		}); status != http.StatusCreated {
			t.Fatalf("create eu-1 status=%d want=%d", status, http.StatusCreated)
		}
		if status, _ := doAdminRequest(t, a.Router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{
			"name":   "ops",
			"relays": []string{"eu-1"},
		}); status != http.StatusCreated {
			t.Fatalf("create ops status=%d want=%d", status, http.StatusCreated)
		}
		userID, _, verifyBody := dCreateUserWithDevice(t, a, "cache-user", []string{"ops"})

		// Warm the live verify cache with an allow on eu-1.
		if allow, reason := a.Service.Verify(context.Background(), "eu-1", verifyBody); !allow {
			t.Fatalf("cache warm verify expected allow, got deny=%q", reason)
		}
		return a, userID, verifyBody
	}

	t.Run("remove_grant", func(t *testing.T) {
		a, _, verifyBody := setup(t)
		if status, _ := doAdminRequest(t, a.Router, http.MethodPut, "/admin/roles/ops/relays", testAdminKey, map[string]any{
			"relays": []string{},
		}); status != http.StatusOK {
			t.Fatalf("PUT role relays status=%d want=%d", status, http.StatusOK)
		}
		allow, reason := a.Service.Verify(context.Background(), "eu-1", verifyBody)
		if allow || reason != service.DenyReasonPolicyDenied {
			t.Fatalf("cached allow survived grant removal: (%v, %q)", allow, reason)
		}
	})

	t.Run("delete_role", func(t *testing.T) {
		a, _, verifyBody := setup(t)
		if status, _ := doAdminRequest(t, a.Router, http.MethodDelete, "/admin/roles/ops", testAdminKey, nil); status != http.StatusOK {
			t.Fatalf("DELETE role status=%d want=%d", status, http.StatusOK)
		}
		allow, reason := a.Service.Verify(context.Background(), "eu-1", verifyBody)
		if allow || reason != service.DenyReasonPolicyDenied {
			t.Fatalf("cached allow survived role deletion: (%v, %q)", allow, reason)
		}
	})

	t.Run("remove_user_role", func(t *testing.T) {
		a, userID, verifyBody := setup(t)
		if status, _ := doAdminRequest(t, a.Router, http.MethodPut, "/admin/users/"+userID.String()+"/roles", testAdminKey, map[string]any{
			"roles": []string{},
		}); status != http.StatusOK {
			t.Fatalf("PUT user roles status=%d want=%d", status, http.StatusOK)
		}
		allow, reason := a.Service.Verify(context.Background(), "eu-1", verifyBody)
		if allow || reason != service.DenyReasonPolicyDenied {
			t.Fatalf("cached allow survived user role removal: (%v, %q)", allow, reason)
		}
	})

	t.Run("delete_relay", func(t *testing.T) {
		a, _, verifyBody := setup(t)
		if status, _ := doAdminRequest(t, a.Router, http.MethodDelete, "/admin/relays/eu-1", testAdminKey, nil); status != http.StatusOK {
			t.Fatalf("DELETE relay status=%d want=%d", status, http.StatusOK)
		}
		if allow, _ := a.Service.Verify(context.Background(), "eu-1", verifyBody); allow {
			t.Fatalf("cached allow survived relay deletion")
		}
	})
}

func TestAccessAuditRowsAndSummaries(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)
	adminKey := insertAdminKey(t, gormDB, "d-auditor", actor.TierAdmin)
	user := createUser(t, gormDB, "audit-access-user")

	// Read routes write no audit rows.
	for _, path := range []string{"/admin/relays", "/admin/roles"} {
		if status, _ := doAdminRequest(t, router, http.MethodGet, path, adminKey, nil); status != http.StatusOK {
			t.Fatalf("GET %s status=%d want=%d", path, status, http.StatusOK)
		}
	}
	var count int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Count(&count).Error; err != nil {
		t.Fatalf("count audits after GET: %v", err)
	}
	if count != 0 {
		t.Fatalf("audit count after GET=%d want=0", count)
	}

	// Execute all 6 access writes.
	steps := []struct {
		method     string
		path       string
		payload    any
		wantStatus int
		wantAction string
		wantType   string
		wantTarget string
	}{
		{http.MethodPost, "/admin/relays", map[string]any{"name": "eu-1", "description": "EU"}, http.StatusCreated, "relay.create", "relay", "eu-1"},
		{http.MethodPost, "/admin/roles", map[string]any{"name": "ops", "relays": []string{"eu-1"}}, http.StatusCreated, "role.create", "role", "ops"},
		{http.MethodPut, "/admin/roles/ops/relays", map[string]any{"relays": []string{"default", "eu-1"}}, http.StatusOK, "role.grants.set", "role", "ops"},
		{http.MethodPut, "/admin/users/" + user.ID.String() + "/roles", map[string]any{"roles": []string{"ops"}}, http.StatusOK, "user.roles.set", "user", user.ID.String()},
		{http.MethodDelete, "/admin/roles/ops", nil, http.StatusOK, "role.delete", "role", "ops"},
		{http.MethodDelete, "/admin/relays/eu-1", nil, http.StatusOK, "relay.delete", "relay", "eu-1"},
	}

	for _, step := range steps {
		status, body := doAdminRequest(t, router, step.method, step.path, adminKey, step.payload)
		if status != step.wantStatus {
			t.Fatalf("%s %s status=%d want=%d body=%v", step.method, step.path, status, step.wantStatus, body)
		}
	}

	var rows []model.AdminAuditLog
	if err := gormDB.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("load admin_audit_logs: %v", err)
	}
	if len(rows) != len(steps) {
		t.Fatalf("audit row count=%d want=%d", len(rows), len(steps))
	}
	for i, step := range steps {
		row := rows[i]
		if row.Action != step.wantAction || row.TargetType != step.wantType || row.TargetID != step.wantTarget {
			t.Fatalf("row %d got action=%q type=%q target=%q want %q/%q/%q",
				i, row.Action, row.TargetType, row.TargetID, step.wantAction, step.wantType, step.wantTarget)
		}
		if row.Outcome != service.AuditOutcomeSuccess {
			t.Fatalf("row %d outcome=%q want=%q", i, row.Outcome, service.AuditOutcomeSuccess)
		}
		if row.HTTPStatus == nil || *row.HTTPStatus != step.wantStatus {
			t.Fatalf("row %d httpStatus=%v want=%d", i, row.HTTPStatus, step.wantStatus)
		}
		if strings.Contains(row.Summary, adminKey) {
			t.Fatalf("row %d summary leaked admin key", i)
		}
		var summary map[string]any
		if err := json.Unmarshal([]byte(row.Summary), &summary); err != nil {
			t.Fatalf("row %d invalid summary JSON %q: %v", i, row.Summary, err)
		}
		if len(summary) == 0 {
			t.Fatalf("row %d empty summary", i)
		}
	}
}
