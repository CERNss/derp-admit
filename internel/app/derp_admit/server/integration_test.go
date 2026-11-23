package server_test

import (
	"context"
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
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/service"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestPolicyVersionBumpedOnEachChange(t *testing.T) {
	type versionCase struct {
		name       string
		wantDelta  int64
		wantStatus int
		run        func(t *testing.T, router http.Handler, gormDB *gorm.DB) int
	}

	readVer := func(t *testing.T, gormDB *gorm.DB) int64 {
		t.Helper()
		v, err := policy.ReadVersion(context.Background(), gormDB)
		if err != nil {
			t.Fatalf("ReadVersion: %v", err)
		}
		return v
	}

	cases := []versionCase{
		// --- Decision-affecting changes (must bump by +1) ---
		{
			name: "relay_create_bumps", wantDelta: 1, wantStatus: http.StatusCreated,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/relays", testAdminKey, map[string]any{"name": "eu-1"})
				return st
			},
		},
		{
			name: "relay_delete_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/relays/pre-relay", testAdminKey, nil)
				return st
			},
		},
		{
			name: "role_create_bumps", wantDelta: 1, wantStatus: http.StatusCreated,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/roles", testAdminKey, map[string]any{"name": "ops", "relays": []string{"default"}})
				return st
			},
		},
		{
			name: "role_grants_change_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doAdminRequest(t, router, http.MethodPut, "/admin/roles/pre-role/relays", testAdminKey, map[string]any{"relays": []string{"*"}})
				return st
			},
		},
		{
			name: "role_delete_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/roles/pre-role", testAdminKey, nil)
				return st
			},
		},
		{
			name: "user_create_default_roles_bumps", wantDelta: 1, wantStatus: http.StatusCreated,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{"username": "v-user-default"})
				return st
			},
		},
		{
			name: "user_create_empty_roles_bumps", wantDelta: 1, wantStatus: http.StatusCreated,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users", testAdminKey, map[string]any{"username": "v-user-empty", "roles": []string{}})
				return st
			},
		},
		{
			name: "user_roles_change_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var u model.User
				if err := gormDB.Where("username = ?", "base-user").First(&u).Error; err != nil {
					t.Fatalf("find base-user: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPut, "/admin/users/"+u.ID.String()+"/roles", testAdminKey, map[string]any{"roles": []string{"pre-role"}})
				return st
			},
		},
		{
			name: "user_disable_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var u model.User
				if err := gormDB.Where("username = ?", "base-user").First(&u).Error; err != nil {
					t.Fatalf("find base-user: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users/"+u.ID.String()+"/disable", testAdminKey, nil)
				return st
			},
		},
		{
			name: "user_enable_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var u model.User
				if err := gormDB.Where("username = ?", "disabled-user").First(&u).Error; err != nil {
					t.Fatalf("find disabled-user: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users/"+u.ID.String()+"/enable", testAdminKey, nil)
				return st
			},
		},
		{
			name: "user_delete_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var u model.User
				if err := gormDB.Where("username = ?", "base-user").First(&u).Error; err != nil {
					t.Fatalf("find base-user: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/users/"+u.ID.String(), testAdminKey, nil)
				return st
			},
		},
		{
			name: "device_revoke_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var d model.Device
				if err := gormDB.Where("label = ?", "active-dev").First(&d).Error; err != nil {
					t.Fatalf("find active-dev: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+d.ID.String()+"/revoke", testAdminKey, nil)
				return st
			},
		},
		{
			name: "device_enable_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var d model.Device
				if err := gormDB.Where("label = ?", "revoked-dev").First(&d).Error; err != nil {
					t.Fatalf("find revoked-dev: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+d.ID.String()+"/enable", testAdminKey, nil)
				return st
			},
		},
		{
			name: "device_delete_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var d model.Device
				if err := gormDB.Where("label = ?", "active-dev").First(&d).Error; err != nil {
					t.Fatalf("find active-dev: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/devices/"+d.ID.String(), testAdminKey, nil)
				return st
			},
		},
		{
			name: "register_new_device_bumps", wantDelta: 1, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doJSONRequest(t, router, "/register", map[string]any{
					"token":   "base-enroll-token-plain",
					"nodeKey": newNodeKey(t),
					"label":   "brand-new",
				})
				return st
			},
		},

		// --- Non-decision changes (must NOT bump: delta 0) ---
		{
			name: "token_mint_no_bump", wantDelta: 0, wantStatus: http.StatusCreated,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var u model.User
				if err := gormDB.Where("username = ?", "base-user").First(&u).Error; err != nil {
					t.Fatalf("find base-user: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/tokens", testAdminKey, map[string]any{"userId": u.ID.String()})
				return st
			},
		},
		{
			name: "token_revoke_no_bump", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var tok model.EnrollToken
				if err := gormDB.Where("note = ?", "active-tok").First(&tok).Error; err != nil {
					t.Fatalf("find active-tok: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/tokens/"+tok.ID.String()+"/revoke", testAdminKey, nil)
				return st
			},
		},
		{
			name: "token_delete_no_bump", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var tok model.EnrollToken
				if err := gormDB.Where("note = ?", "active-tok").First(&tok).Error; err != nil {
					t.Fatalf("find active-tok: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodDelete, "/admin/tokens/"+tok.ID.String(), testAdminKey, nil)
				return st
			},
		},
		{
			name: "key_create_no_bump", wantDelta: 0, wantStatus: http.StatusCreated,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys", testAdminKey, map[string]any{"name": "v-viewer", "tier": "viewer"})
				return st
			},
		},
		{
			name: "key_revoke_no_bump", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var k model.AdminKey
				if err := gormDB.Where("name = ?", "active-viewer-key").First(&k).Error; err != nil {
					t.Fatalf("find active-viewer-key: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+k.ID.String()+"/revoke", testAdminKey, nil)
				return st
			},
		},
		{
			name: "register_label_only_reregister_no_bump", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var d model.Device
				if err := gormDB.Where("label = ?", "active-dev").First(&d).Error; err != nil {
					t.Fatalf("find active-dev: %v", err)
				}
				st, _ := doJSONRequest(t, router, "/register", map[string]any{
					"token":   "base-enroll-token-plain",
					"nodeKey": d.NodeKey,
					"label":   "renamed-label",
				})
				return st
			},
		},

		// --- Every idempotent no-op (must NOT bump: delta 0) ---
		{
			name: "noop_user_disable_already_disabled", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var u model.User
				if err := gormDB.Where("username = ?", "disabled-user").First(&u).Error; err != nil {
					t.Fatalf("find disabled-user: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users/"+u.ID.String()+"/disable", testAdminKey, nil)
				return st
			},
		},
		{
			name: "noop_user_enable_already_enabled", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var u model.User
				if err := gormDB.Where("username = ?", "base-user").First(&u).Error; err != nil {
					t.Fatalf("find base-user: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/users/"+u.ID.String()+"/enable", testAdminKey, nil)
				return st
			},
		},
		{
			name: "noop_device_revoke_already_revoked", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var d model.Device
				if err := gormDB.Where("label = ?", "revoked-dev").First(&d).Error; err != nil {
					t.Fatalf("find revoked-dev: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+d.ID.String()+"/revoke", testAdminKey, nil)
				return st
			},
		},
		{
			name: "noop_device_enable_already_enabled", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var d model.Device
				if err := gormDB.Where("label = ?", "active-dev").First(&d).Error; err != nil {
					t.Fatalf("find active-dev: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/devices/"+d.ID.String()+"/enable", testAdminKey, nil)
				return st
			},
		},
		{
			name: "noop_role_grants_same_relays", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, _ *gorm.DB) int {
				st, _ := doAdminRequest(t, router, http.MethodPut, "/admin/roles/pre-role/relays", testAdminKey, map[string]any{"relays": []string{"pre-relay"}})
				return st
			},
		},
		{
			name: "noop_user_roles_same_roles", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var u model.User
				if err := gormDB.Where("username = ?", "base-user").First(&u).Error; err != nil {
					t.Fatalf("find base-user: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPut, "/admin/users/"+u.ID.String()+"/roles", testAdminKey, map[string]any{"roles": []string{"standard"}})
				return st
			},
		},
		{
			name: "noop_token_revoke_already_revoked", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var tok model.EnrollToken
				if err := gormDB.Where("note = ?", "revoked-tok").First(&tok).Error; err != nil {
					t.Fatalf("find revoked-tok: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/tokens/"+tok.ID.String()+"/revoke", testAdminKey, nil)
				return st
			},
		},
		{
			name: "noop_key_revoke_already_revoked", wantDelta: 0, wantStatus: http.StatusOK,
			run: func(t *testing.T, router http.Handler, gormDB *gorm.DB) int {
				var k model.AdminKey
				if err := gormDB.Where("name = ?", "revoked-viewer-key").First(&k).Error; err != nil {
					t.Fatalf("find revoked-viewer-key: %v", err)
				}
				st, _ := doAdminRequest(t, router, http.MethodPost, "/admin/keys/"+k.ID.String()+"/revoke", testAdminKey, nil)
				return st
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, gormDB := newTestRouter(t, adminKeyOpt)

			// Seed consistent baseline fixtures directly via SQL so each case measures
			// only the exact delta of its own single operation.
			now := time.Now().UTC()
			baseUser := createUser(t, gormDB, "base-user")
			bindStandardRole(t, gormDB, baseUser.ID)

			disabledUser := model.User{ID: uuid.New(), Username: "disabled-user", DisabledAt: &now}
			if err := gormDB.Create(&disabledUser).Error; err != nil {
				t.Fatalf("seed disabled-user: %v", err)
			}

			tokActive := model.EnrollToken{
				ID:         uuid.New(),
				UserID:     baseUser.ID,
				TokenHash:  hashToken("base-enroll-token-plain", "test-pepper"),
				MaxDevices: 0,
				Note:       "active-tok",
			}
			if err := gormDB.Create(&tokActive).Error; err != nil {
				t.Fatalf("seed active-tok: %v", err)
			}
			tokRevoked := model.EnrollToken{
				ID:         uuid.New(),
				UserID:     baseUser.ID,
				TokenHash:  hashToken("revoked-enroll-token-plain", "test-pepper"),
				RevokedAt:  &now,
				MaxDevices: 1,
				Note:       "revoked-tok",
			}
			if err := gormDB.Create(&tokRevoked).Error; err != nil {
				t.Fatalf("seed revoked-tok: %v", err)
			}

			createDevice(t, gormDB, baseUser.ID, newNodeKey(t), "active-dev", nil)
			createDevice(t, gormDB, baseUser.ID, newNodeKey(t), "revoked-dev", &now)

			if err := gormDB.Create(&model.Relay{Name: "pre-relay"}).Error; err != nil {
				t.Fatalf("seed pre-relay: %v", err)
			}
			if err := gormDB.Create(&model.Role{Name: "pre-role"}).Error; err != nil {
				t.Fatalf("seed pre-role: %v", err)
			}
			if err := gormDB.Transaction(func(tx *gorm.DB) error {
				return policy.SetRoleGrants(tx, "pre-role", []string{"pre-relay"})
			}); err != nil {
				t.Fatalf("seed pre-role grants: %v", err)
			}

			insertAdminKey(t, gormDB, "active-viewer-key", actor.TierViewer)
			_ = insertAdminKey(t, gormDB, "revoked-viewer-key", actor.TierViewer)
			if err := gormDB.Model(&model.AdminKey{}).Where("name = ?", "revoked-viewer-key").Update("revoked_at", &now).Error; err != nil {
				t.Fatalf("revoke viewer key: %v", err)
			}

			vBefore := readVer(t, gormDB)
			gotStatus := tc.run(t, router, gormDB)
			if gotStatus != tc.wantStatus {
				t.Fatalf("%s status=%d want=%d", tc.name, gotStatus, tc.wantStatus)
			}
			vAfter := readVer(t, gormDB)
			if vAfter != vBefore+tc.wantDelta {
				t.Fatalf("%s policy version: before=%d after=%d delta=%d want delta=%d",
					tc.name, vBefore, vAfter, vAfter-vBefore, tc.wantDelta)
			}
		})
	}
}

func TestAdminListPagination(t *testing.T) {
	router, gormDB := newTestRouter(t, adminKeyOpt)

	const seedCount = 55
	base := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

	type rowKey struct {
		ts time.Time
		k  string
	}
	sortAscKeys := func(rows []rowKey) []string {
		cp := append([]rowKey(nil), rows...)
		sort.Slice(cp, func(i, j int) bool {
			if !cp[i].ts.Equal(cp[j].ts) {
				return cp[i].ts.Before(cp[j].ts)
			}
			return cp[i].k < cp[j].k
		})
		out := make([]string, len(cp))
		for i, r := range cp {
			out[i] = r.k
		}
		return out
	}
	type intRowKey struct {
		ts time.Time
		id int64
	}
	sortDescIntKeys := func(rows []intRowKey) []string {
		cp := append([]intRowKey(nil), rows...)
		sort.Slice(cp, func(i, j int) bool {
			if !cp[i].ts.Equal(cp[j].ts) {
				return cp[i].ts.After(cp[j].ts)
			}
			return cp[i].id > cp[j].id
		})
		out := make([]string, len(cp))
		for i, r := range cp {
			out[i] = fmt.Sprintf("%d", r.id)
		}
		return out
	}

	var (
		userKeys        []rowKey
		tokenKeys       []rowKey
		deviceKeys      []rowKey
		roleKeys        []rowKey
		relayKeys       []rowKey
		keyKeys         []rowKey
		adminAuditKeys  []intRowKey
		verifyAuditKeys []intRowKey
	)

	// Include pre-existing built-ins (default relay, standard role, bootstrap key, startup system audit row).
	var existingRoles []model.Role
	if err := gormDB.Find(&existingRoles).Error; err != nil {
		t.Fatalf("load existing roles: %v", err)
	}
	for _, r := range existingRoles {
		roleKeys = append(roleKeys, rowKey{ts: r.CreatedAt.UTC(), k: r.Name})
	}
	var existingRelays []model.Relay
	if err := gormDB.Find(&existingRelays).Error; err != nil {
		t.Fatalf("load existing relays: %v", err)
	}
	for _, r := range existingRelays {
		relayKeys = append(relayKeys, rowKey{ts: r.CreatedAt.UTC(), k: r.Name})
	}
	var existingAdminKeys []model.AdminKey
	if err := gormDB.Find(&existingAdminKeys).Error; err != nil {
		t.Fatalf("load existing admin keys: %v", err)
	}
	for _, k := range existingAdminKeys {
		keyKeys = append(keyKeys, rowKey{ts: k.CreatedAt.UTC(), k: k.ID.String()})
	}
	var existingAdminAudits []model.AdminAuditLog
	if err := gormDB.Find(&existingAdminAudits).Error; err != nil {
		t.Fatalf("load existing admin audits: %v", err)
	}
	for _, a := range existingAdminAudits {
		adminAuditKeys = append(adminAuditKeys, intRowKey{ts: a.TS.UTC(), id: a.ID})
	}

	statusOK := http.StatusOK
	relayDefault := "default"
	for i := 0; i < seedCount; i++ {
		// Groups of 5 share identical timestamps to exercise the tie-breaker across pages.
		ts := base.Add(time.Duration(i/5) * time.Second)

		u := model.User{ID: uuid.New(), Username: fmt.Sprintf("pg-user-%03d", i), CreatedAt: ts}
		if err := gormDB.Create(&u).Error; err != nil {
			t.Fatalf("seed user %d: %v", i, err)
		}
		userKeys = append(userKeys, rowKey{ts: ts, k: u.ID.String()})

		tok := model.EnrollToken{
			ID:         uuid.New(),
			UserID:     u.ID,
			TokenHash:  fmt.Sprintf("tokhash-%03d", i),
			MaxDevices: 1,
			CreatedAt:  ts,
		}
		if err := gormDB.Create(&tok).Error; err != nil {
			t.Fatalf("seed token %d: %v", i, err)
		}
		tokenKeys = append(tokenKeys, rowKey{ts: ts, k: tok.ID.String()})

		dev := model.Device{
			ID:        uuid.New(),
			UserID:    u.ID,
			NodeKey:   fmt.Sprintf("nodekey:%064d", i),
			Label:     fmt.Sprintf("dev-%03d", i),
			CreatedAt: ts,
		}
		if err := gormDB.Create(&dev).Error; err != nil {
			t.Fatalf("seed device %d: %v", i, err)
		}
		deviceKeys = append(deviceKeys, rowKey{ts: ts, k: dev.ID.String()})

		role := model.Role{Name: fmt.Sprintf("role-%03d", i), CreatedAt: ts}
		if err := gormDB.Create(&role).Error; err != nil {
			t.Fatalf("seed role %d: %v", i, err)
		}
		roleKeys = append(roleKeys, rowKey{ts: ts, k: role.Name})

		relay := model.Relay{Name: fmt.Sprintf("relay-%03d", i), CreatedAt: ts}
		if err := gormDB.Create(&relay).Error; err != nil {
			t.Fatalf("seed relay %d: %v", i, err)
		}
		relayKeys = append(relayKeys, rowKey{ts: ts, k: relay.Name})

		ak := model.AdminKey{
			ID:        uuid.New(),
			Name:      fmt.Sprintf("key-%03d", i),
			Tier:      model.AdminTierViewer,
			KeyHash:   fmt.Sprintf("akhash-%03d", i),
			CreatedAt: ts,
		}
		if err := gormDB.Create(&ak).Error; err != nil {
			t.Fatalf("seed key %d: %v", i, err)
		}
		keyKeys = append(keyKeys, rowKey{ts: ts, k: ak.ID.String()})

		aa := model.AdminAuditLog{
			TS:         ts,
			ActorName:  "op",
			ActorTier:  model.AdminTierOperator,
			Action:     "user.create",
			TargetType: "user",
			TargetID:   u.ID.String(),
			Outcome:    service.AuditOutcomeSuccess,
			HTTPStatus: &statusOK,
			Summary:    "{}",
		}
		if err := gormDB.Create(&aa).Error; err != nil {
			t.Fatalf("seed admin audit %d: %v", i, err)
		}
		adminAuditKeys = append(adminAuditKeys, intRowKey{ts: ts, id: aa.ID})

		va := model.AuditLog{
			NodeKey: fmt.Sprintf("nodekey:%064d", i),
			Relay:   &relayDefault,
			Allowed: i%2 == 0,
			TS:      ts,
		}
		if err := gormDB.Create(&va).Error; err != nil {
			t.Fatalf("seed verify audit %d: %v", i, err)
		}
		verifyAuditKeys = append(verifyAuditKeys, intRowKey{ts: ts, id: va.ID})
	}

	type listEndpoint struct {
		name      string
		path      string
		itemsKey  string
		idField   string
		wantOrder []string
	}
	endpoints := []listEndpoint{
		{"users", "/admin/users", "users", "id", sortAscKeys(userKeys)},
		{"tokens", "/admin/tokens", "tokens", "id", sortAscKeys(tokenKeys)},
		{"devices", "/admin/devices", "devices", "id", sortAscKeys(deviceKeys)},
		{"roles", "/admin/roles", "roles", "name", sortAscKeys(roleKeys)},
		{"relays", "/admin/relays", "relays", "name", sortAscKeys(relayKeys)},
		{"keys", "/admin/keys", "keys", "id", sortAscKeys(keyKeys)},
		{"admin_audit", "/admin/audit/admin", "entries", "id", sortDescIntKeys(adminAuditKeys)},
		{"verify_audit", "/admin/audit/verify", "entries", "id", sortDescIntKeys(verifyAuditKeys)},
	}

	extractKeys := func(t *testing.T, body map[string]any, itemsKey, idField string) []string {
		t.Helper()
		rawItems, ok := body[itemsKey].([]any)
		if !ok {
			t.Fatalf("missing array %q in response: %v", itemsKey, body)
		}
		out := make([]string, len(rawItems))
		for i, item := range rawItems {
			m := item.(map[string]any)
			switch v := m[idField].(type) {
			case string:
				out[i] = v
			case float64:
				out[i] = fmt.Sprintf("%d", int64(v))
			default:
				t.Fatalf("unexpected %s type %T", idField, v)
			}
		}
		return out
	}

	issuedCursors := make(map[string]string, len(endpoints))

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			// 1. Default limit = 50 with non-null nextCursor.
			status, body := doAdminRequest(t, router, http.MethodGet, ep.path, testAdminKey, nil)
			if status != http.StatusOK {
				t.Fatalf("default GET %s status=%d want=200", ep.path, status)
			}
			firstPage := extractKeys(t, body, ep.itemsKey, ep.idField)
			if len(firstPage) != page.DefaultLimit {
				t.Fatalf("default page len=%d want=%d", len(firstPage), page.DefaultLimit)
			}
			cur, ok := body["nextCursor"].(string)
			if !ok || cur == "" {
				t.Fatalf("expected non-empty nextCursor on first page, got %#v", body["nextCursor"])
			}
			issuedCursors[ep.name] = cur

			// 2. Boundary limits 1 and 200 accepted.
			if st, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?limit=1", testAdminKey, nil); st != http.StatusOK {
				t.Fatalf("limit=1 status=%d want=200", st)
			}
			if st, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?limit=200", testAdminKey, nil); st != http.StatusOK {
				t.Fatalf("limit=200 status=%d want=200", st)
			}

			// 3. Invalid limits rejected with 400.
			for _, badLimit := range []string{"0", "201", "-1", "notanumber"} {
				if st, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?limit="+badLimit, testAdminKey, nil); st != http.StatusBadRequest {
					t.Fatalf("limit=%s status=%d want=400", badLimit, st)
				}
			}

			// 4. Invalid cursor rejected with 400.
			if st, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?cursor=not-valid-base64!!!", testAdminKey, nil); st != http.StatusBadRequest {
				t.Fatalf("malformed cursor status=%d want=400", st)
			}

			// 5. Walk every page with limit=7: exact order, no repeats, no skips, null nextCursor at end.
			var walked []string
			next := ""
			for pages := 0; pages < 100; pages++ {
				q := ep.path + "?limit=7"
				if next != "" {
					q += "&cursor=" + url.QueryEscape(next)
				}
				st, pBody := doAdminRequest(t, router, http.MethodGet, q, testAdminKey, nil)
				if st != http.StatusOK {
					t.Fatalf("walk page %d (%s) status=%d want=200", pages, q, st)
				}
				walked = append(walked, extractKeys(t, pBody, ep.itemsKey, ep.idField)...)
				nextVal, hasField := pBody["nextCursor"]
				if !hasField {
					t.Fatalf("page %d missing nextCursor field", pages)
				}
				if nextVal == nil {
					break
				}
				next = nextVal.(string)
			}
			if !reflect.DeepEqual(walked, ep.wantOrder) {
				t.Fatalf("walked order mismatch: got len=%d want len=%d", len(walked), len(ep.wantOrder))
			}
		})
	}

	// 6. Cross-list cursor rejection for every list route.
	for i, ep := range endpoints {
		other := endpoints[(i+1)%len(endpoints)]
		foreign := issuedCursors[other.name]
		if st, _ := doAdminRequest(t, router, http.MethodGet, ep.path+"?cursor="+url.QueryEscape(foreign), testAdminKey, nil); st != http.StatusBadRequest {
			t.Fatalf("%s accepted cursor from %s: status=%d want=400", ep.name, other.name, st)
		}
	}
}
