package server_test

import (
	"net/http"
	"testing"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/service"
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
	if err := gormDB.Order("id asc").Find(&rows).Error; err != nil {
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
	if err := gormDB.Model(&model.AdminAuditLog{}).Count(&count).Error; err != nil {
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
	if err := gormDB.Model(&model.AdminAuditLog{}).Count(&count).Error; err != nil {
		t.Fatalf("count admin_audit_logs: %v", err)
	}
	if count != 0 {
		t.Fatalf("admin audit count=%d want=0 for GET requests", count)
	}
}
