package server_test

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestRegisterWritesNoPolicyRules(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	userID, token := provisionUserAndToken(t, router, "reg-no-rules")
	_ = userID

	var before []model.CasbinRule
	if err := gormDB.Order("id asc").Find(&before).Error; err != nil {
		t.Fatalf("snapshot casbin_rule before: %v", err)
	}

	nodeKey := newNodeKey(t)
	status, _ := doJSONRequest(t, router, "/register", map[string]any{
		"token":   token,
		"nodeKey": nodeKey,
		"label":   "laptop",
	})
	if status != http.StatusOK {
		t.Fatalf("register status=%d want=%d", status, http.StatusOK)
	}

	var after []model.CasbinRule
	if err := gormDB.Order("id asc").Find(&after).Error; err != nil {
		t.Fatalf("snapshot casbin_rule after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("casbin_rule changed during /register:\nbefore=%+v\nafter=%+v", before, after)
	}
}

func TestAdminCreateUserRolesDefaultExplicitAndUnknown(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Add a custom role with a grant on default so we can test explicit binding.
	if err := gormDB.Create(&model.Role{Name: "custom"}).Error; err != nil {
		t.Fatalf("create custom role: %v", err)
	}
	if err := gormDB.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "custom", []string{policy.BuiltinRelay})
	}); err != nil {
		t.Fatalf("grant custom on default: %v", err)
	}

	// 1. Omitted roles defaults to ["standard"].
	status, body := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "u-default",
	})
	if status != http.StatusCreated {
		t.Fatalf("default roles create status=%d want=%d", status, http.StatusCreated)
	}
	uDefaultID := uuid.MustParse(body["user"].(map[string]any)["id"].(string))
	rolesMap, err := policy.UserRoles(context.Background(), gormDB, []uuid.UUID{uDefaultID})
	if err != nil {
		t.Fatalf("UserRoles default: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[uDefaultID], []string{"standard"}) {
		t.Fatalf("default user roles=%v want=[standard]", rolesMap[uDefaultID])
	}

	// 2. Explicit roles: ["custom"] binds only ["custom"] and allows verify.
	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "u-explicit",
		"roles":    []string{"custom"},
	})
	if status != http.StatusCreated {
		t.Fatalf("explicit roles create status=%d want=%d", status, http.StatusCreated)
	}
	uExplicitID := uuid.MustParse(body["user"].(map[string]any)["id"].(string))
	rolesMap, err = policy.UserRoles(context.Background(), gormDB, []uuid.UUID{uExplicitID})
	if err != nil {
		t.Fatalf("UserRoles explicit: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[uExplicitID], []string{"custom"}) {
		t.Fatalf("explicit user roles=%v want=[custom]", rolesMap[uExplicitID])
	}
	nkExplicit := newNodeKey(t)
	createDevice(t, gormDB, uExplicitID, nkExplicit, "", nil)
	_, payload := doRawRequest(t, router, "/verify", buildVerifyBody(t, nkExplicit))
	if allow, _ := payload["Allow"].(bool); !allow {
		t.Fatalf("explicit role user expected allow, got deny reason=%q", denyReason(payload))
	}

	// 3. Explicit empty roles: [] binds no roles and verify denies with policy denied.
	status, body = doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "u-empty",
		"roles":    []string{},
	})
	if status != http.StatusCreated {
		t.Fatalf("empty roles create status=%d want=%d", status, http.StatusCreated)
	}
	uEmptyID := uuid.MustParse(body["user"].(map[string]any)["id"].(string))
	rolesMap, err = policy.UserRoles(context.Background(), gormDB, []uuid.UUID{uEmptyID})
	if err != nil {
		t.Fatalf("UserRoles empty: %v", err)
	}
	if len(rolesMap[uEmptyID]) != 0 {
		t.Fatalf("empty roles user got=%v want=[]", rolesMap[uEmptyID])
	}
	nkEmpty := newNodeKey(t)
	createDevice(t, gormDB, uEmptyID, nkEmpty, "", nil)
	_, payload = doRawRequest(t, router, "/verify", buildVerifyBody(t, nkEmpty))
	if reason := denyReason(payload); reason != service.DenyReasonPolicyDenied {
		t.Fatalf("empty roles user reason=%q want=%q", reason, service.DenyReasonPolicyDenied)
	}

	// 4. Unknown role returns 400 and creates no user.
	status, _ = doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{
		"username": "u-unknown-role",
		"roles":    []string{"does-not-exist"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("unknown role create status=%d want=%d", status, http.StatusBadRequest)
	}
	var count int64
	if err := gormDB.Model(&model.User{}).Where("username = ?", "u-unknown-role").Count(&count).Error; err != nil {
		t.Fatalf("count u-unknown-role: %v", err)
	}
	if count != 0 {
		t.Fatalf("u-unknown-role count=%d want=0", count)
	}
}
