package server_test

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
)

func eExtractInt64IDs(t *testing.T, body map[string]any) []int64 {
	t.Helper()
	rawEntries, ok := body["entries"].([]any)
	if !ok {
		t.Fatalf("expected entries []any, got %T (%v)", body["entries"], body["entries"])
	}
	ids := make([]int64, len(rawEntries))
	for i, raw := range rawEntries {
		m := raw.(map[string]any)
		ids[i] = int64(m["id"].(float64))
	}
	return ids
}

func TestAdminAuditQueryFilters(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// Startup creates the bootstrap key and writes exactly one system audit row.
	var startupRows []model.AdminAuditLog
	if err := gormDB.Where("actor_key_id IS NULL AND actor_name = ?", actor.System.Name).Find(&startupRows).Error; err != nil {
		t.Fatalf("query startup system audit: %v", err)
	}
	if len(startupRows) != 1 || startupRows[0].Action != "bootstrap.create" {
		t.Fatalf("startup system audits=%+v want 1 bootstrap.create row", startupRows)
	}
	startupRow := startupRows[0]

	actor1 := uuid.New()
	actor2 := uuid.New()
	status200 := http.StatusOK
	status201 := http.StatusCreated
	status403 := http.StatusForbidden

	t1 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 20, 11, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	t4 := time.Date(2026, 11, 20, 13, 0, 0, 0, time.UTC)

	seed := []model.AdminAuditLog{
		{
			TS:         t1,
			ActorKeyID: &actor1,
			ActorName:  "op-1",
			ActorTier:  model.AdminTierOperator,
			Action:     "user.create",
			TargetType: "user",
			TargetID:   "u-1",
			Outcome:    service.AuditOutcomeSuccess,
			HTTPStatus: &status201,
			ClientIP:   "192.0.2.1",
			Summary:    `{"username":"alice"}`,
		},
		{
			TS:         t2,
			ActorKeyID: &actor1,
			ActorName:  "op-1",
			ActorTier:  model.AdminTierOperator,
			Action:     "device.revoke",
			TargetType: "device",
			TargetID:   "d-1",
			Outcome:    service.AuditOutcomeSuccess,
			HTTPStatus: &status200,
			ClientIP:   "192.0.2.1",
			Summary:    `{"revoked":true}`,
		},
		{
			TS:         t3,
			ActorKeyID: &actor2,
			ActorName:  "viewer-1",
			ActorTier:  model.AdminTierViewer,
			Action:     "device.revoke",
			TargetType: "device",
			TargetID:   "d-2",
			Outcome:    service.AuditOutcomeFailure,
			HTTPStatus: &status403,
			ClientIP:   "198.51.100.2",
			Summary:    `{}`,
		},
		{
			TS:         t4,
			ActorKeyID: nil,
			ActorName:  "system",
			ActorTier:  model.AdminTierAdmin,
			Action:     "device.revoke",
			TargetType: "device",
			TargetID:   "d-1",
			Outcome:    service.AuditOutcomeSuccess,
			HTTPStatus: nil,
			ClientIP:   "",
			Summary:    `{"reason":"upgrade"}`,
		},
	}
	for i := range seed {
		if err := gormDB.Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed admin audit %d: %v", i, err)
		}
	}

	// Verify entry JSON shape on unfiltered query (newest first), accounting for the startup bootstrap row.
	allRows := append([]model.AdminAuditLog{startupRow}, seed...)
	sort.Slice(allRows, func(i, j int) bool {
		if !allRows[i].TS.Equal(allRows[j].TS) {
			return allRows[i].TS.After(allRows[j].TS)
		}
		return allRows[i].ID > allRows[j].ID
	})
	wantUnfiltered := make([]int64, len(allRows))
	for i, r := range allRows {
		wantUnfiltered[i] = r.ID
	}

	status, body := doAdminRequest(t, router, http.MethodGet, "/admin/audit/admin", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("unfiltered status=%d want=%d", status, http.StatusOK)
	}
	if got := eExtractInt64IDs(t, body); !reflect.DeepEqual(got, wantUnfiltered) {
		t.Fatalf("unfiltered order=%v want=%v", got, wantUnfiltered)
	}
	var seededSystemEntry map[string]any
	for _, raw := range body["entries"].([]any) {
		m := raw.(map[string]any)
		if int64(m["id"].(float64)) == seed[3].ID {
			seededSystemEntry = m
			break
		}
	}
	if seededSystemEntry == nil {
		t.Fatalf("seeded system entry id=%d not found in unfiltered response", seed[3].ID)
	}
	if seededSystemEntry["actorName"] != "system" || seededSystemEntry["actorKeyId"] != nil || seededSystemEntry["httpStatus"] != nil {
		t.Fatalf("unexpected system entry shape: %+v", seededSystemEntry)
	}
	summaryObj, ok := seededSystemEntry["summary"].(map[string]any)
	if !ok || summaryObj["reason"] != "upgrade" {
		t.Fatalf("expected parsed JSON summary object, got %#v", seededSystemEntry["summary"])
	}

	filterRangeIDs := func(since, until *time.Time) []int64 {
		var out []int64
		for _, r := range allRows {
			if since != nil && r.TS.Before(*since) {
				continue
			}
			if until != nil && r.TS.After(*until) {
				continue
			}
			out = append(out, r.ID)
		}
		return out
	}

	// Individual filters and combined AND filters.
	cases := []struct {
		name    string
		query   string
		wantIDs []int64
	}{
		{"actorKeyId", "actorKeyId=" + actor1.String(), []int64{seed[1].ID, seed[0].ID}},
		{"action", "action=user.create", []int64{seed[0].ID}},
		{"targetType", "targetType=device", []int64{seed[3].ID, seed[2].ID, seed[1].ID}},
		{"targetId", "targetId=d-1", []int64{seed[3].ID, seed[1].ID}},
		{"since", "since=" + url.QueryEscape(t3.Format(time.RFC3339)), filterRangeIDs(&t3, nil)},
		{"until", "until=" + url.QueryEscape(t2.Format(time.RFC3339)), filterRangeIDs(nil, &t2)},
		{
			"since_and_until_with_tz_offset",
			"since=" + url.QueryEscape("2026-11-20T19:00:00+08:00") + "&until=" + url.QueryEscape("2026-11-20T20:00:00+08:00"),
			filterRangeIDs(&t2, &t3),
		},
		{
			"combined_and",
			"actorKeyId=" + actor1.String() + "&action=device.revoke&targetType=device&targetId=d-1",
			[]int64{seed[1].ID},
		},
		{
			"combined_empty_match",
			"actorKeyId=" + actor2.String() + "&targetId=d-1",
			[]int64{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doAdminRequest(t, router, http.MethodGet, "/admin/audit/admin?"+tc.query, testAdminKey, nil)
			if status != http.StatusOK {
				t.Fatalf("query %s status=%d want=%d", tc.query, status, http.StatusOK)
			}
			got := eExtractInt64IDs(t, body)
			if !reflect.DeepEqual(got, tc.wantIDs) {
				t.Fatalf("query %s got=%v want=%v", tc.query, got, tc.wantIDs)
			}
		})
	}

	// Malformed filters -> 400.
	for _, bad := range []string{
		"actorKeyId=not-a-uuid",
		"since=not-a-timestamp",
		"until=2026-11-20",
	} {
		if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/admin?"+bad, testAdminKey, nil); status != http.StatusBadRequest {
			t.Fatalf("malformed %s status=%d want=%d", bad, status, http.StatusBadRequest)
		}
	}
}

func TestVerifyAuditQueryFilters(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	dev1 := uuid.New()
	dev2 := uuid.New()
	nk1 := newNodeKey(t)
	nk2 := newNodeKey(t)
	relayDefault := "default"
	relayEU := "eu-1"

	t1 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 21, 11, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	t4 := time.Date(2026, 11, 21, 13, 0, 0, 0, time.UTC)

	seed := []model.AuditLog{
		{
			DeviceID: &dev1,
			NodeKey:  nk1,
			Relay:    &relayDefault,
			Allowed:  true,
			Reason:   "",
			TS:       t1,
		},
		{
			DeviceID: &dev1,
			NodeKey:  nk1,
			Relay:    &relayEU,
			Allowed:  false,
			Reason:   service.DenyReasonPolicyDenied,
			TS:       t2,
		},
		{
			DeviceID: &dev2,
			NodeKey:  nk2,
			Relay:    &relayEU,
			Allowed:  true,
			Reason:   "",
			TS:       t3,
		},
		{
			DeviceID: nil,
			NodeKey:  nk2,
			Relay:    nil,
			Allowed:  false,
			Reason:   service.DenyReasonNotRegistered,
			TS:       t4,
		},
	}
	for i := range seed {
		if err := gormDB.Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed verify audit %d: %v", i, err)
		}
	}

	// Verify entry JSON shape on unfiltered query.
	status, body := doAdminRequest(t, router, http.MethodGet, "/admin/audit/verify", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("unfiltered verify audit status=%d want=%d", status, http.StatusOK)
	}
	entries := body["entries"].([]any)
	if len(entries) != 4 {
		t.Fatalf("entry count=%d want=4", len(entries))
	}
	newest := entries[0].(map[string]any)
	if newest["deviceId"] != nil || newest["relay"] != nil || newest["nodeKey"] != nk2 ||
		newest["allowed"] != false || newest["reason"] != service.DenyReasonNotRegistered {
		t.Fatalf("unexpected verify audit entry shape: %+v", newest)
	}

	cases := []struct {
		name    string
		query   string
		wantIDs []int64
	}{
		{"nodeKey", "nodeKey=" + url.QueryEscape(nk1), []int64{seed[1].ID, seed[0].ID}},
		{"deviceId", "deviceId=" + dev1.String(), []int64{seed[1].ID, seed[0].ID}},
		{"relay_exact_excludes_null", "relay=eu-1", []int64{seed[2].ID, seed[1].ID}},
		{"allowed_true", "allowed=true", []int64{seed[2].ID, seed[0].ID}},
		{"allowed_false", "allowed=false", []int64{seed[3].ID, seed[1].ID}},
		{"since", "since=" + url.QueryEscape(t3.Format(time.RFC3339)), []int64{seed[3].ID, seed[2].ID}},
		{"until", "until=" + url.QueryEscape(t2.Format(time.RFC3339)), []int64{seed[1].ID, seed[0].ID}},
		{"nodeKey_and_allowed_false", "nodeKey=" + url.QueryEscape(nk1) + "&allowed=false", []int64{seed[1].ID}},
		{"relay_and_allowed_true_and_range", "relay=eu-1&allowed=true&since=" + url.QueryEscape(t2.Format(time.RFC3339)) + "&until=" + url.QueryEscape(t4.Format(time.RFC3339)), []int64{seed[2].ID}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doAdminRequest(t, router, http.MethodGet, "/admin/audit/verify?"+tc.query, testAdminKey, nil)
			if status != http.StatusOK {
				t.Fatalf("query %s status=%d want=%d", tc.query, status, http.StatusOK)
			}
			got := eExtractInt64IDs(t, body)
			if !reflect.DeepEqual(got, tc.wantIDs) {
				t.Fatalf("query %s got=%v want=%v", tc.query, got, tc.wantIDs)
			}
		})
	}

	// Malformed filters -> 400.
	for _, bad := range []string{
		"deviceId=not-a-uuid",
		"allowed=yes",
		"allowed=1",
		"allowed=TRUE",
		"since=bad-time",
		"until=2026-11-21",
	} {
		if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/verify?"+bad, testAdminKey, nil); status != http.StatusBadRequest {
			t.Fatalf("malformed %s status=%d want=%d", bad, status, http.StatusBadRequest)
		}
	}
}

func TestAuditQueriesPaginateNewestFirst(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	const total = 55
	baseTime := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)

	type auditMeta struct {
		id int64
		ts time.Time
	}
	adminMetas := make([]auditMeta, 0, total+1)
	verifyMetas := make([]auditMeta, 0, total)

	// Account for the single startup system audit row created for bootstrap.
	var startupRows []model.AdminAuditLog
	if err := gormDB.Where("actor_key_id IS NULL AND actor_name = ?", actor.System.Name).Find(&startupRows).Error; err != nil {
		t.Fatalf("query startup system audit: %v", err)
	}
	if len(startupRows) != 1 || startupRows[0].Action != "bootstrap.create" {
		t.Fatalf("startup system audits=%+v want 1 bootstrap.create row", startupRows)
	}
	adminMetas = append(adminMetas, auditMeta{id: startupRows[0].ID, ts: startupRows[0].TS})

	statusOK := http.StatusOK
	relay := "default"
	for i := 0; i < total; i++ {
		// Groups of 5 share identical timestamps to test the id DESC tie-breaker.
		ts := baseTime.Add(time.Duration(i/5) * time.Second)
		a := model.AdminAuditLog{
			TS:         ts,
			ActorName:  "system",
			ActorTier:  model.AdminTierAdmin,
			Action:     "user.create",
			TargetType: "user",
			TargetID:   fmt.Sprintf("u-%03d", i),
			Outcome:    service.AuditOutcomeSuccess,
			HTTPStatus: &statusOK,
			Summary:    "{}",
		}
		if err := gormDB.Create(&a).Error; err != nil {
			t.Fatalf("seed admin audit %d: %v", i, err)
		}
		adminMetas = append(adminMetas, auditMeta{id: a.ID, ts: ts})

		v := model.AuditLog{
			NodeKey: fmt.Sprintf("nodekey:%064d", i),
			Relay:   &relay,
			Allowed: i%2 == 0,
			TS:      ts,
		}
		if err := gormDB.Create(&v).Error; err != nil {
			t.Fatalf("seed verify audit %d: %v", i, err)
		}
		verifyMetas = append(verifyMetas, auditMeta{id: v.ID, ts: ts})
	}

	sortDesc := func(metas []auditMeta) []int64 {
		cp := append([]auditMeta(nil), metas...)
		sort.Slice(cp, func(i, j int) bool {
			if !cp[i].ts.Equal(cp[j].ts) {
				return cp[i].ts.After(cp[j].ts)
			}
			return cp[i].id > cp[j].id
		})
		out := make([]int64, len(cp))
		for i, m := range cp {
			out[i] = m.id
		}
		return out
	}

	endpoints := []struct {
		name      string
		path      string
		listName  string
		wantOrder []int64
	}{
		{"admin_audit", "/admin/audit/admin", "admin_audit", sortDesc(adminMetas)},
		{"verify_audit", "/admin/audit/verify", "verify_audit", sortDesc(verifyMetas)},
	}

	sampleCursors := make(map[string]string, len(endpoints))

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			// Default limit 50.
			status, body := doAdminRequest(t, router, http.MethodGet, ep.path, testAdminKey, nil)
			if status != http.StatusOK {
				t.Fatalf("default page status=%d want=%d", status, http.StatusOK)
			}
			ids := eExtractInt64IDs(t, body)
			if len(ids) != page.DefaultLimit {
				t.Fatalf("default page len=%d want=%d", len(ids), page.DefaultLimit)
			}
			nextCursor, ok := body["nextCursor"].(string)
			if !ok || nextCursor == "" {
				t.Fatalf("expected non-empty nextCursor, got %#v", body["nextCursor"])
			}
			sampleCursors[ep.name] = nextCursor

			// Walk all pages with limit=7.
			var gotIDs []int64
			cur := ""
			for {
				q := ep.path + "?limit=7"
				if cur != "" {
					q += "&cursor=" + url.QueryEscape(cur)
				}
				status, body := doAdminRequest(t, router, http.MethodGet, q, testAdminKey, nil)
				if status != http.StatusOK {
					t.Fatalf("walk %s status=%d want=%d", q, status, http.StatusOK)
				}
				gotIDs = append(gotIDs, eExtractInt64IDs(t, body)...)
				if body["nextCursor"] == nil {
					break
				}
				cur = body["nextCursor"].(string)
			}
			if !reflect.DeepEqual(gotIDs, ep.wantOrder) {
				t.Fatalf("%s walked order mismatch: got len=%d want len=%d", ep.name, len(gotIDs), len(ep.wantOrder))
			}

			// Boundary limits and bad limits/cursors.
			if status, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?limit=1", testAdminKey, nil); status != http.StatusOK {
				t.Fatalf("limit=1 status=%d want=%d", status, http.StatusOK)
			}
			if status, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?limit=200", testAdminKey, nil); status != http.StatusOK {
				t.Fatalf("limit=200 status=%d want=%d", status, http.StatusOK)
			}
			for _, bad := range []string{"0", "201", "abc"} {
				if status, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?limit="+bad, testAdminKey, nil); status != http.StatusBadRequest {
					t.Fatalf("limit=%s status=%d want=%d", bad, status, http.StatusBadRequest)
				}
			}
			for _, bad := range []string{
				"not-base64!!!",
				eMakeCursor(ep.listName, baseTime, "not-an-int"),
				eMakeCursor("users", baseTime, uuid.New().String()),
			} {
				if status, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?cursor="+url.QueryEscape(bad), testAdminKey, nil); status != http.StatusBadRequest {
					t.Fatalf("bad cursor %q status=%d want=%d", bad, status, http.StatusBadRequest)
				}
			}
		})
	}

	// Cross-list audit cursor rejection.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/admin?cursor="+url.QueryEscape(sampleCursors["verify_audit"]), testAdminKey, nil); status != http.StatusBadRequest {
		t.Fatalf("admin audit accepted verify audit cursor: status=%d want=%d", status, http.StatusBadRequest)
	}
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/verify?cursor="+url.QueryEscape(sampleCursors["admin_audit"]), testAdminKey, nil); status != http.StatusBadRequest {
		t.Fatalf("verify audit accepted admin audit cursor: status=%d want=%d", status, http.StatusBadRequest)
	}
}

func TestAuditQueryTiers(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	viewerKey := insertAdminKey(t, gormDB, "e-audit-viewer", actor.TierViewer)
	opKey := insertAdminKey(t, gormDB, "e-audit-operator", actor.TierOperator)
	adminKey := insertAdminKey(t, gormDB, "e-audit-admin", actor.TierAdmin)

	// Viewer: 403 on admin audit, 200 on verify audit.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/admin", viewerKey, nil); status != http.StatusForbidden {
		t.Fatalf("viewer GET /admin/audit/admin status=%d want=%d", status, http.StatusForbidden)
	}
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/verify", viewerKey, nil); status != http.StatusOK {
		t.Fatalf("viewer GET /admin/audit/verify status=%d want=%d", status, http.StatusOK)
	}

	// Operator: 403 on admin audit, 200 on verify audit.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/admin", opKey, nil); status != http.StatusForbidden {
		t.Fatalf("operator GET /admin/audit/admin status=%d want=%d", status, http.StatusForbidden)
	}
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/verify", opKey, nil); status != http.StatusOK {
		t.Fatalf("operator GET /admin/audit/verify status=%d want=%d", status, http.StatusOK)
	}

	// Admin: 200 on both.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/admin", adminKey, nil); status != http.StatusOK {
		t.Fatalf("admin GET /admin/audit/admin status=%d want=%d", status, http.StatusOK)
	}
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/verify", adminKey, nil); status != http.StatusOK {
		t.Fatalf("admin GET /admin/audit/verify status=%d want=%d", status, http.StatusOK)
	}

	// GET requests (even 403 GETs) must never write admin audit rows; only the
	// startup bootstrap creation system row should exist.
	var sysCount int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Where("actor_key_id IS NULL AND actor_name = ?", actor.System.Name).Count(&sysCount).Error; err != nil {
		t.Fatalf("count startup system audit rows: %v", err)
	}
	if sysCount != 1 {
		t.Fatalf("startup system audit count=%d want=1", sysCount)
	}
	var auditCount int64
	if err := gormDB.Model(&model.AdminAuditLog{}).Where("NOT (actor_key_id IS NULL AND actor_name = ?)", actor.System.Name).Count(&auditCount).Error; err != nil {
		t.Fatalf("count admin audit rows: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("admin audit count=%d want=0 after GET requests", auditCount)
	}
}

func TestCursorRejectedUnderDifferentFilters(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	// 1. GET /admin/devices?userId=A cursor rejected for userId=B and for unfiltered.
	uA := createUser(t, gormDB, "cursor-filter-a")
	uB := createUser(t, gormDB, "cursor-filter-b")
	for i := 0; i < 3; i++ {
		createDevice(t, gormDB, uA.ID, newNodeKey(t), fmt.Sprintf("a-%d", i), nil)
		createDevice(t, gormDB, uB.ID, newNodeKey(t), fmt.Sprintf("b-%d", i), nil)
	}

	status, body := doAdminRequest(t, router, http.MethodGet, "/admin/devices?limit=1&userId="+uA.ID.String(), testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /admin/devices?userId=A status=%d want=200", status)
	}
	devCurA, ok := body["nextCursor"].(string)
	if !ok || devCurA == "" {
		t.Fatalf("expected non-empty nextCursor for userId=A, got %#v", body["nextCursor"])
	}

	// Same filter works.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/devices?limit=1&userId="+uA.ID.String()+"&cursor="+url.QueryEscape(devCurA), testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("same userId cursor status=%d want=200", status)
	}
	// Different userId rejected with 400.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/devices?limit=1&userId="+uB.ID.String()+"&cursor="+url.QueryEscape(devCurA), testAdminKey, nil); status != http.StatusBadRequest {
		t.Fatalf("different userId cursor status=%d want=400", status)
	}
	// Unfiltered rejected with 400.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/devices?limit=1&cursor="+url.QueryEscape(devCurA), testAdminKey, nil); status != http.StatusBadRequest {
		t.Fatalf("filtered cursor on unfiltered /admin/devices status=%d want=400", status)
	}
	// Unfiltered cursor rejected when userId is added.
	status, body = doAdminRequest(t, router, http.MethodGet, "/admin/devices?limit=1", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("unfiltered /admin/devices status=%d want=200", status)
	}
	devCurAll := body["nextCursor"].(string)
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/devices?limit=1&userId="+uA.ID.String()+"&cursor="+url.QueryEscape(devCurAll), testAdminKey, nil); status != http.StatusBadRequest {
		t.Fatalf("unfiltered cursor on filtered /admin/devices status=%d want=400", status)
	}

	// 2. GET /admin/audit/admin cursor bound to filters.
	base := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	statusOK := http.StatusOK
	for i := 0; i < 3; i++ {
		if err := gormDB.Create(&model.AdminAuditLog{
			TS:         base.Add(time.Duration(i) * time.Minute),
			ActorName:  "op",
			ActorTier:  model.AdminTierOperator,
			Action:     "user.create",
			TargetType: "user",
			TargetID:   fmt.Sprintf("u-%d", i),
			Outcome:    service.AuditOutcomeSuccess,
			HTTPStatus: &statusOK,
			Summary:    "{}",
		}).Error; err != nil {
			t.Fatalf("seed admin audit: %v", err)
		}
	}

	status, body = doAdminRequest(t, router, http.MethodGet, "/admin/audit/admin?limit=1&action=user.create", testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /admin/audit/admin?action=user.create status=%d want=200", status)
	}
	adminCur := body["nextCursor"].(string)
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/admin?limit=1&action=user.create&cursor="+url.QueryEscape(adminCur), testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("same admin audit filter status=%d want=200", status)
	}
	for _, mismatched := range []string{
		"/admin/audit/admin?limit=1&action=device.revoke&cursor=" + url.QueryEscape(adminCur),
		"/admin/audit/admin?limit=1&cursor=" + url.QueryEscape(adminCur),
		"/admin/audit/admin?limit=1&action=user.create&targetType=user&cursor=" + url.QueryEscape(adminCur),
	} {
		if status, _ := doAdminRequest(t, router, http.MethodGet, mismatched, testAdminKey, nil); status != http.StatusBadRequest {
			t.Fatalf("mismatched admin audit filter %s status=%d want=400", mismatched, status)
		}
	}

	// 3. GET /admin/audit/verify cursor bound to filters (and normalizes equivalent timestamps).
	relayDefault := "default"
	for i := 0; i < 3; i++ {
		if err := gormDB.Create(&model.AuditLog{
			NodeKey: fmt.Sprintf("nodekey:%064d", i),
			Relay:   &relayDefault,
			Allowed: true,
			TS:      base.Add(time.Duration(i) * time.Minute),
		}).Error; err != nil {
			t.Fatalf("seed verify audit: %v", err)
		}
	}

	sinceUTC := base.Format(time.RFC3339)
	sincePlus8 := base.In(time.FixedZone("+08", 8*3600)).Format(time.RFC3339)
	status, body = doAdminRequest(t, router, http.MethodGet, "/admin/audit/verify?limit=1&relay=default&allowed=true&since="+url.QueryEscape(sinceUTC), testAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /admin/audit/verify filtered status=%d want=200", status)
	}
	verifyCur := body["nextCursor"].(string)
	// Equivalent timestamp in a different timezone offset normalizes to the same fingerprint -> 200.
	if status, _ := doAdminRequest(t, router, http.MethodGet, "/admin/audit/verify?limit=1&relay=default&allowed=true&since="+url.QueryEscape(sincePlus8)+"&cursor="+url.QueryEscape(verifyCur), testAdminKey, nil); status != http.StatusOK {
		t.Fatalf("equivalent timezone verify audit filter status=%d want=200", status)
	}
	for _, mismatched := range []string{
		"/admin/audit/verify?limit=1&relay=eu-1&allowed=true&since=" + url.QueryEscape(sinceUTC) + "&cursor=" + url.QueryEscape(verifyCur),
		"/admin/audit/verify?limit=1&relay=default&allowed=false&since=" + url.QueryEscape(sinceUTC) + "&cursor=" + url.QueryEscape(verifyCur),
		"/admin/audit/verify?limit=1&relay=default&cursor=" + url.QueryEscape(verifyCur),
		"/admin/audit/verify?limit=1&cursor=" + url.QueryEscape(verifyCur),
	} {
		if status, _ := doAdminRequest(t, router, http.MethodGet, mismatched, testAdminKey, nil); status != http.StatusBadRequest {
			t.Fatalf("mismatched verify audit filter %s status=%d want=400", mismatched, status)
		}
	}
}
