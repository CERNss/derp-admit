package db_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type columnSpec struct {
	name     string
	nullable bool
}

var expectedNewSchema = map[string][]columnSpec{
	"casbin_rule": {
		{name: "id", nullable: false},
		{name: "ptype", nullable: false},
		{name: "v0", nullable: true},
		{name: "v1", nullable: true},
		{name: "v2", nullable: true},
		{name: "v3", nullable: true},
		{name: "v4", nullable: true},
		{name: "v5", nullable: true},
	},
	"roles": {
		{name: "name", nullable: false},
		{name: "description", nullable: false},
		{name: "all_relays", nullable: false},
		{name: "created_at", nullable: false},
	},
	"relays": {
		{name: "name", nullable: false},
		{name: "description", nullable: false},
		{name: "created_at", nullable: false},
	},
	"policy_state": {
		{name: "id", nullable: false},
		{name: "version", nullable: false},
		{name: "upgraded_at", nullable: true},
	},
	"admin_keys": {
		{name: "id", nullable: false},
		{name: "name", nullable: false},
		{name: "tier", nullable: false},
		{name: "key_hash", nullable: false},
		{name: "created_at", nullable: false},
		{name: "expires_at", nullable: true},
		{name: "revoked_at", nullable: true},
		{name: "last_used_at", nullable: true},
	},
	"admin_audit_logs": {
		{name: "id", nullable: false},
		{name: "ts", nullable: false},
		{name: "actor_key_id", nullable: true},
		{name: "actor_name", nullable: false},
		{name: "actor_tier", nullable: false},
		{name: "action", nullable: false},
		{name: "target_type", nullable: false},
		{name: "target_id", nullable: false},
		{name: "outcome", nullable: false},
		{name: "http_status", nullable: true},
		{name: "client_ip", nullable: false},
		{name: "summary", nullable: false},
	},
}

var expectedIndexes = map[string][]string{
	"casbin_rule": {
		"idx_casbin_rule_ptype",
		"idx_casbin_rule_v0",
		"idx_casbin_rule_v1",
		"idx_casbin_rule_v2",
	},
	"admin_keys": {
		"idx_admin_keys_tier",
		"idx_admin_keys_expires_at",
		"idx_admin_keys_revoked_at",
	},
	"admin_audit_logs": {
		"idx_admin_audit_logs_ts_id",
		"idx_admin_audit_logs_actor_key_ts_id",
		"idx_admin_audit_logs_action_ts_id",
		"idx_admin_audit_logs_target_ts_id",
	},
	"audit_logs": {
		"idx_audit_logs_ts",
		"idx_audit_logs_device_ts",
		"idx_audit_logs_relay_ts_id",
	},
}

func TestApplyMigrationsSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migrate.db")
	dbURL := "sqlite://" + dbPath

	conn, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	if err := db.ApplyMigrations(context.Background(), conn, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	expectTableExists(t, conn, "users")
	expectTableExists(t, conn, "enroll_tokens")
	expectTableExists(t, conn, "devices")
	expectTableExists(t, conn, "audit_logs")

	assertSchemaSQLite(t, conn)
	assertInitialPolicyState(t, conn)

	// Running ApplyMigrations a second time must be a no-op.
	if err := db.ApplyMigrations(context.Background(), conn, dbURL); err != nil {
		t.Fatalf("apply migrations second time: %v", err)
	}

	assertSchemaSQLite(t, conn)
	assertInitialPolicyState(t, conn)
	assertSchemaConstraints(t, conn)

	// Verify re-running ApplyMigrations preserves an updated policy_state row.
	upgradedAt := time.Now().UTC().Truncate(time.Second)
	if err := conn.Model(&model.PolicyState{}).
		Where("id = ?", model.PolicyStateRowID).
		Updates(map[string]any{"version": int64(7), "upgraded_at": upgradedAt}).Error; err != nil {
		t.Fatalf("update policy_state: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), conn, dbURL); err != nil {
		t.Fatalf("apply migrations third time: %v", err)
	}
	var state model.PolicyState
	if err := conn.First(&state, model.PolicyStateRowID).Error; err != nil {
		t.Fatalf("read policy_state: %v", err)
	}
	if state.Version != 7 {
		t.Fatalf("expected version 7 after re-running migrations, got %d", state.Version)
	}
	if state.UpgradedAt == nil || !state.UpgradedAt.UTC().Equal(upgradedAt) {
		t.Fatalf("expected upgraded_at %v preserved, got %v", upgradedAt, state.UpgradedAt)
	}
}

func TestApplyMigrationsPostgres(t *testing.T) {
	dbURL := os.Getenv("TEST_POSTGRES_URL")
	if dbURL == "" {
		t.Skip("TEST_POSTGRES_URL is not set")
	}

	conn, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open postgres db: %v", err)
	}

	if err := db.ApplyMigrations(context.Background(), conn, dbURL); err != nil {
		t.Fatalf("apply postgres migrations (first): %v", err)
	}

	assertSchemaPostgres(t, conn)
	assertInitialPolicyState(t, conn)

	if err := db.ApplyMigrations(context.Background(), conn, dbURL); err != nil {
		t.Fatalf("apply postgres migrations (second): %v", err)
	}

	assertSchemaPostgres(t, conn)
	assertInitialPolicyState(t, conn)
	assertSchemaConstraints(t, conn)
}

func assertSchemaSQLite(t *testing.T, conn *gorm.DB) {
	t.Helper()

	for _, table := range []string{"casbin_rule", "roles", "relays", "policy_state", "admin_keys", "admin_audit_logs"} {
		expectTableExists(t, conn, table)
	}

	for table, cols := range expectedNewSchema {
		got := sqliteTableColumns(t, conn, table)
		for _, want := range cols {
			actualNullable, ok := got[want.name]
			if !ok {
				t.Fatalf("sqlite table %s missing column %s", table, want.name)
			}
			if actualNullable != want.nullable {
				t.Fatalf("sqlite %s.%s nullable=%v, want %v", table, want.name, actualNullable, want.nullable)
			}
		}
	}

	auditCols := sqliteTableColumns(t, conn, "audit_logs")
	relayNullable, ok := auditCols["relay"]
	if !ok {
		t.Fatalf("sqlite table audit_logs missing column relay")
	}
	if !relayNullable {
		t.Fatalf("sqlite audit_logs.relay must be nullable")
	}

	for table, indexes := range expectedIndexes {
		for _, idx := range indexes {
			var count int64
			if err := conn.Raw(
				`SELECT COUNT(1) FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND name = ?`,
				table, idx,
			).Scan(&count).Error; err != nil {
				t.Fatalf("query sqlite_master index %s on %s: %v", idx, table, err)
			}
			if count != 1 {
				t.Fatalf("sqlite index %s on %s does not exist", idx, table)
			}
		}
	}
}

func assertSchemaPostgres(t *testing.T, conn *gorm.DB) {
	t.Helper()

	for _, table := range []string{
		"users", "enroll_tokens", "devices", "audit_logs", "casbin_rule",
		"roles", "relays", "policy_state", "admin_keys", "admin_audit_logs",
	} {
		var count int64
		if err := conn.Raw(
			`SELECT COUNT(1) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = ?`,
			table,
		).Scan(&count).Error; err != nil {
			t.Fatalf("query postgres table %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("postgres table %s does not exist", table)
		}
	}

	for table, cols := range expectedNewSchema {
		got := postgresTableColumns(t, conn, table)
		for _, want := range cols {
			actualNullable, ok := got[want.name]
			if !ok {
				t.Fatalf("postgres table %s missing column %s", table, want.name)
			}
			if actualNullable != want.nullable {
				t.Fatalf("postgres %s.%s nullable=%v, want %v", table, want.name, actualNullable, want.nullable)
			}
		}
	}

	auditCols := postgresTableColumns(t, conn, "audit_logs")
	relayNullable, ok := auditCols["relay"]
	if !ok {
		t.Fatalf("postgres table audit_logs missing column relay")
	}
	if !relayNullable {
		t.Fatalf("postgres audit_logs.relay must be nullable")
	}

	for table, indexes := range expectedIndexes {
		for _, idx := range indexes {
			var count int64
			if err := conn.Raw(
				`SELECT COUNT(1) FROM pg_indexes WHERE schemaname = current_schema() AND tablename = ? AND indexname = ?`,
				table, idx,
			).Scan(&count).Error; err != nil {
				t.Fatalf("query pg_indexes %s on %s: %v", idx, table, err)
			}
			if count != 1 {
				t.Fatalf("postgres index %s on %s does not exist", idx, table)
			}
		}
	}
}

func assertInitialPolicyState(t *testing.T, conn *gorm.DB) {
	t.Helper()

	var count int64
	if err := conn.Model(&model.PolicyState{}).Count(&count).Error; err != nil {
		t.Fatalf("count policy_state: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 policy_state row, got %d", count)
	}

	var state model.PolicyState
	if err := conn.First(&state, model.PolicyStateRowID).Error; err != nil {
		t.Fatalf("read policy_state: %v", err)
	}
	if state.Version != 0 {
		t.Fatalf("expected initial policy_state.version = 0, got %d", state.Version)
	}
	if state.UpgradedAt != nil {
		t.Fatalf("expected initial policy_state.upgraded_at to be nil, got %v", state.UpgradedAt)
	}
}

func assertSchemaConstraints(t *testing.T, conn *gorm.DB) {
	t.Helper()

	tx := conn.Begin()
	if tx.Error != nil {
		t.Fatalf("begin tx: %v", tx.Error)
	}
	defer tx.Rollback()

	// Role and Relay inserts succeed with BeforeCreate defaults.
	if err := tx.Create(&model.Role{Name: "ops", Description: "operators"}).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}
	var opsRole model.Role
	if err := tx.First(&opsRole, "name = ?", "ops").Error; err != nil {
		t.Fatalf("reload role ops: %v", err)
	}
	if opsRole.AllRelays {
		t.Fatalf("expected roles.all_relays default false, got true")
	}
	if err := tx.Create(&model.Role{Name: "global", AllRelays: true}).Error; err != nil {
		t.Fatalf("create all_relays role: %v", err)
	}
	if err := tx.Create(&model.Relay{Name: "eu-1", Description: "Europe 1"}).Error; err != nil {
		t.Fatalf("create relay: %v", err)
	}

	// policy_state enforces single row (id = 1).
	if err := tx.SavePoint("sp_ps").Error; err != nil {
		t.Fatalf("savepoint: %v", err)
	}
	if err := tx.Create(&model.PolicyState{ID: 2, Version: 0}).Error; err == nil {
		t.Fatalf("expected check constraint error inserting policy_state with id=2")
	}
	if err := tx.RollbackTo("sp_ps").Error; err != nil {
		t.Fatalf("rollback savepoint: %v", err)
	}

	// admin_keys: valid insert, unique name, unique key_hash, tier check.
	k1 := &model.AdminKey{
		Name:    "test-admin",
		Tier:    model.AdminTierAdmin,
		KeyHash: "hash-1",
	}
	if err := tx.Create(k1).Error; err != nil {
		t.Fatalf("create admin_key: %v", err)
	}
	if k1.ID == uuid.Nil {
		t.Fatalf("expected admin_key ID generated")
	}

	if err := tx.SavePoint("sp_name").Error; err != nil {
		t.Fatalf("savepoint: %v", err)
	}
	if err := tx.Create(&model.AdminKey{Name: "test-admin", Tier: model.AdminTierViewer, KeyHash: "hash-2"}).Error; err == nil {
		t.Fatalf("expected unique constraint error on duplicate admin_keys.name")
	}
	if err := tx.RollbackTo("sp_name").Error; err != nil {
		t.Fatalf("rollback savepoint: %v", err)
	}

	if err := tx.SavePoint("sp_hash").Error; err != nil {
		t.Fatalf("savepoint: %v", err)
	}
	if err := tx.Create(&model.AdminKey{Name: "test-viewer", Tier: model.AdminTierViewer, KeyHash: "hash-1"}).Error; err == nil {
		t.Fatalf("expected unique constraint error on duplicate admin_keys.key_hash")
	}
	if err := tx.RollbackTo("sp_hash").Error; err != nil {
		t.Fatalf("rollback savepoint: %v", err)
	}

	if err := tx.SavePoint("sp_tier").Error; err != nil {
		t.Fatalf("savepoint: %v", err)
	}
	if err := tx.Create(&model.AdminKey{Name: "bad-tier", Tier: "superuser", KeyHash: "hash-3"}).Error; err == nil {
		t.Fatalf("expected check constraint error on invalid admin_keys.tier")
	}
	if err := tx.RollbackTo("sp_tier").Error; err != nil {
		t.Fatalf("rollback savepoint: %v", err)
	}

	// admin_audit_logs: accepts system row with null actor_key_id and null http_status.
	sysAudit := &model.AdminAuditLog{
		ActorName:  "system",
		ActorTier:  "",
		Action:     "bootstrap.create",
		TargetType: "admin_key",
		TargetID:   k1.ID.String(),
		Outcome:    "success",
		Summary:    "created bootstrap key",
	}
	if err := tx.Create(sysAudit).Error; err != nil {
		t.Fatalf("create system admin_audit_log: %v", err)
	}
	if sysAudit.ID <= 0 {
		t.Fatalf("expected auto-increment admin_audit_log.id > 0, got %d", sysAudit.ID)
	}

	// audit_logs: accepts null relay and non-null relay.
	if err := tx.Create(&model.AuditLog{
		NodeKey: "nodekey:nullrelay",
		Allowed: false,
		Reason:  "unknown relay",
	}).Error; err != nil {
		t.Fatalf("create audit_log with null relay: %v", err)
	}
	relayName := "eu-1"
	if err := tx.Create(&model.AuditLog{
		NodeKey: "nodekey:withrelay",
		Relay:   &relayName,
		Allowed: true,
	}).Error; err != nil {
		t.Fatalf("create audit_log with relay: %v", err)
	}
}

func sqliteTableColumns(t *testing.T, conn *gorm.DB, table string) map[string]bool {
	t.Helper()

	type pragmaCol struct {
		Name    string `gorm:"column:name"`
		NotNull int    `gorm:"column:notnull"`
		PK      int    `gorm:"column:pk"`
	}
	var rows []pragmaCol
	if err := conn.Raw(`PRAGMA table_info("` + table + `")`).Scan(&rows).Error; err != nil {
		t.Fatalf("pragma table_info(%s): %v", table, err)
	}
	cols := make(map[string]bool, len(rows))
	for _, r := range rows {
		// In SQLite, an INTEGER PRIMARY KEY (rowid alias) is never NULL even if notnull == 0.
		notNull := r.NotNull != 0 || (r.PK > 0 && r.Name == "id")
		cols[r.Name] = !notNull
	}
	return cols
}

func postgresTableColumns(t *testing.T, conn *gorm.DB, table string) map[string]bool {
	t.Helper()

	type pgCol struct {
		Name       string `gorm:"column:column_name"`
		IsNullable string `gorm:"column:is_nullable"`
	}
	var rows []pgCol
	if err := conn.Raw(
		`SELECT column_name, is_nullable FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ?`,
		table,
	).Scan(&rows).Error; err != nil {
		t.Fatalf("query information_schema.columns for %s: %v", table, err)
	}
	cols := make(map[string]bool, len(rows))
	for _, r := range rows {
		cols[r.Name] = r.IsNullable == "YES"
	}
	return cols
}

func expectTableExists(t *testing.T, conn *gorm.DB, table string) {
	t.Helper()

	var count int64
	if err := conn.Raw(`SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count).Error; err != nil {
		t.Fatalf("query sqlite_master for %s: %v", table, err)
	}
	if count != 1 {
		t.Fatalf("table %s does not exist", table)
	}
}
