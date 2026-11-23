package policy_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestSeedBuiltinsIdempotent(t *testing.T) {
	dbConn := openPolicyTestDB(t)

	var created1, created2 bool
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		var err error
		created1, err = policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("SeedBuiltins #1: %v", err)
	}
	if !created1 {
		t.Fatalf("expected created=true on first seed")
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		var err error
		created2, err = policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("SeedBuiltins #2: %v", err)
	}
	if created2 {
		t.Fatalf("expected created=false on second seed")
	}

	var relayCount, roleCount, grantCount int64
	if err := dbConn.Model(&model.Relay{}).Where("name = ?", policy.BuiltinRelay).Count(&relayCount).Error; err != nil {
		t.Fatalf("count default relay: %v", err)
	}
	if err := dbConn.Model(&model.Role{}).Where("name = ?", policy.BuiltinRole).Count(&roleCount).Error; err != nil {
		t.Fatalf("count standard role: %v", err)
	}
	if err := dbConn.Model(&model.CasbinRule{}).
		Where("ptype = ? AND v0 = ? AND v1 = ? AND v2 = ?", "p", "role:standard", "derp:default", "connect").
		Count(&grantCount).Error; err != nil {
		t.Fatalf("count standard grant: %v", err)
	}
	if relayCount != 1 || roleCount != 1 || grantCount != 1 {
		t.Fatalf("counts relay=%d role=%d grant=%d want 1,1,1", relayCount, roleCount, grantCount)
	}
}

func TestSeedKeepsEditedStandardGrants(t *testing.T) {
	dbConn := openPolicyTestDB(t)

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("SeedBuiltins #1: %v", err)
	}

	if err := dbConn.Create(&model.Relay{Name: "eu-1"}).Error; err != nil {
		t.Fatalf("create relay eu-1: %v", err)
	}
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, policy.BuiltinRole, []string{"eu-1"})
	}); err != nil {
		t.Fatalf("SetRoleGrants standard -> [eu-1]: %v", err)
	}

	// Re-seeding on restart must not restore default onto standard.
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("SeedBuiltins #2: %v", err)
	}

	grants, err := policy.RoleGrants(context.Background(), dbConn, []string{policy.BuiltinRole})
	if err != nil {
		t.Fatalf("RoleGrants: %v", err)
	}
	if !reflect.DeepEqual(grants[policy.BuiltinRole], []string{"eu-1"}) {
		t.Fatalf("standard grants=%v want=[eu-1]", grants[policy.BuiltinRole])
	}
}

func TestEnforceRoleGrantOnRelay(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Relay{Name: "eu-1"}).Error; err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := dbConn.Create(&model.Role{Name: "ops"}).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}

	userID := uuid.New()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		if err := policy.SetRoleGrants(tx, "ops", []string{"eu-1"}); err != nil {
			return err
		}
		return policy.SetUserRoles(tx, userID, []string{"ops"})
	}); err != nil {
		t.Fatalf("setup grants/bindings: %v", err)
	}

	// Verify NewEngine ignores enabled=false and always enforces.
	engine, err := policy.NewEngine(dbConn)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	allowed, err := engine.Enforce(policy.Request{UserID: userID, Relay: "eu-1"})
	if err != nil || !allowed {
		t.Fatalf("enforce eu-1: allowed=%v err=%v want true, nil", allowed, err)
	}
	allowed, err = engine.Enforce(policy.Request{UserID: userID, Relay: "default"})
	if err != nil || allowed {
		t.Fatalf("enforce default: allowed=%v err=%v want false, nil", allowed, err)
	}
}

func TestEnforceWildcardGrant(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Role{Name: "global"}).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}
	userID := uuid.New()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		if err := policy.SetRoleGrants(tx, "global", []string{"*"}); err != nil {
			return err
		}
		return policy.SetUserRoles(tx, userID, []string{"global"})
	}); err != nil {
		t.Fatalf("set wildcard grant: %v", err)
	}

	engine, err := policy.NewEngine(dbConn)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Add a new relay AFTER the role was created and granted "*".
	if err := dbConn.Create(&model.Relay{Name: "ap-1"}).Error; err != nil {
		t.Fatalf("create relay ap-1: %v", err)
	}
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	for _, relay := range []string{"default", "ap-1"} {
		allowed, err := engine.Enforce(policy.Request{UserID: userID, Relay: relay})
		if err != nil || !allowed {
			t.Fatalf("enforce %s: allowed=%v err=%v want true, nil", relay, allowed, err)
		}
	}
	// An unregistered relay must still be denied.
	allowed, err := engine.Enforce(policy.Request{UserID: userID, Relay: "unknown-1"})
	if err != nil || allowed {
		t.Fatalf("enforce unregistered relay: allowed=%v err=%v want false, nil", allowed, err)
	}
}

func TestEnforceUserWithoutRoleDenied(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	engine, err := policy.NewEngine(dbConn)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	allowed, err := engine.Enforce(policy.Request{UserID: uuid.New(), Relay: "default"})
	if err != nil || allowed {
		t.Fatalf("unbound user enforce: allowed=%v err=%v want false, nil", allowed, err)
	}
}

func TestEnforceIgnoresDirectAndDeviceRules(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Role{Name: "role-a"}).Error; err != nil {
		t.Fatalf("create role-a: %v", err)
	}
	if err := dbConn.Create(&model.Role{Name: "role-b"}).Error; err != nil {
		t.Fatalf("create role-b: %v", err)
	}

	userDirect := uuid.New()
	userInherited := uuid.New()
	userWrongAct := uuid.New()
	nodeKey := "nodekey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Insert unmanaged rules directly into casbin_rule:
	unmanaged := []model.CasbinRule{
		// Direct p on user subject.
		{Ptype: "p", V0: policy.UserSubject(userDirect), V1: "derp:default", V2: "connect"},
		// Direct p on device subject + legacy device grouping.
		{Ptype: "p", V0: "device:" + nodeKey, V1: "derp:default", V2: "connect"},
		{Ptype: "g", V0: "device:" + nodeKey, V1: policy.UserSubject(userDirect)},
		// Role-to-role inheritance (role-a -> standard which has default).
		{Ptype: "g", V0: "role:role-a", V1: "role:standard"},
		{Ptype: "g", V0: policy.UserSubject(userInherited), V1: "role:role-a"},
		// Non-connect action on role-b.
		{Ptype: "p", V0: "role:role-b", V1: "derp:default", V2: "admin"},
		{Ptype: "g", V0: policy.UserSubject(userWrongAct), V1: "role:role-b"},
	}
	if err := dbConn.Create(&unmanaged).Error; err != nil {
		t.Fatalf("insert unmanaged rules: %v", err)
	}

	engine, err := policy.NewEngine(dbConn)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	for name, req := range map[string]policy.Request{
		"direct_user_and_device": {UserID: userDirect, NodeKey: nodeKey, Relay: "default"},
		"role_to_role_inherit":   {UserID: userInherited, Relay: "default"},
		"other_action":           {UserID: userWrongAct, Relay: "default"},
	} {
		allowed, err := engine.Enforce(req)
		if err != nil || allowed {
			t.Fatalf("%s: allowed=%v err=%v want false, nil", name, allowed, err)
		}
	}

	// All unmanaged rows remain untouched in casbin_rule.
	var count int64
	if err := dbConn.Model(&model.CasbinRule{}).Count(&count).Error; err != nil {
		t.Fatalf("count casbin_rule: %v", err)
	}
	if count != int64(len(unmanaged)+1) { // +1 for standard -> default seed
		t.Fatalf("casbin_rule count=%d want=%d", count, len(unmanaged)+1)
	}
}

func TestEnforceIgnoresStoredWildcardRule(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Role{Name: "legacy-wild", AllRelays: false}).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}
	userID := uuid.New()
	if err := dbConn.Create(&model.CasbinRule{
		Ptype: "p", V0: "role:legacy-wild", V1: "derp:*", V2: "connect",
	}).Error; err != nil {
		t.Fatalf("insert stored wildcard rule: %v", err)
	}
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetUserRoles(tx, userID, []string{"legacy-wild"})
	}); err != nil {
		t.Fatalf("bind user: %v", err)
	}

	engine, err := policy.NewEngine(dbConn)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	allowed, err := engine.Enforce(policy.Request{UserID: userID, Relay: "default"})
	if err != nil || allowed {
		t.Fatalf("stored derp:* rule allowed=%v err=%v want false, nil", allowed, err)
	}
}

func TestEnforceIgnoresNonCanonicalUserBinding(t *testing.T) {
	userID := uuid.MustParse("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
	canon := userID.String()
	spellings := []struct {
		name string
		raw  string
	}{
		{name: "uppercase", raw: strings.ToUpper(canon)},
		{name: "braces", raw: "{" + canon + "}"},
		{name: "urn", raw: "urn:uuid:" + canon},
		{name: "no_hyphens", raw: strings.ReplaceAll(canon, "-", "")},
	}

	for _, sp := range spellings {
		t.Run(sp.name, func(t *testing.T) {
			dbConn := openPolicyTestDB(t)
			seedBuiltins(t, dbConn)

			if err := dbConn.Create(&model.CasbinRule{
				Ptype: "g",
				V0:    "user:" + sp.raw,
				V1:    "role:standard",
			}).Error; err != nil {
				t.Fatalf("insert non-canonical g row: %v", err)
			}

			engine, err := policy.NewEngine(dbConn)
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			allowed, err := engine.Enforce(policy.Request{UserID: userID, Relay: "default"})
			if err != nil || allowed {
				t.Fatalf("non-canonical %s allowed=%v err=%v want false, nil", sp.name, allowed, err)
			}
			rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{userID})
			if err != nil {
				t.Fatalf("UserRoles: %v", err)
			}
			if len(rolesMap[userID]) != 0 {
				t.Fatalf("UserRoles reported %v for non-canonical binding, want []", rolesMap[userID])
			}

			// Canonical bind allows, then clearing via SetUserRoles(tx, id, nil) denies again.
			if err := dbConn.Transaction(func(tx *gorm.DB) error {
				return policy.SetUserRoles(tx, userID, []string{policy.BuiltinRole})
			}); err != nil {
				t.Fatalf("SetUserRoles standard: %v", err)
			}
			if err := engine.Reload(context.Background()); err != nil {
				t.Fatalf("Reload after bind: %v", err)
			}
			allowed, err = engine.Enforce(policy.Request{UserID: userID, Relay: "default"})
			if err != nil || !allowed {
				t.Fatalf("canonical bind allowed=%v err=%v want true, nil", allowed, err)
			}

			if err := dbConn.Transaction(func(tx *gorm.DB) error {
				return policy.SetUserRoles(tx, userID, nil)
			}); err != nil {
				t.Fatalf("SetUserRoles clear: %v", err)
			}
			if err := engine.Reload(context.Background()); err != nil {
				t.Fatalf("Reload after clear: %v", err)
			}
			allowed, err = engine.Enforce(policy.Request{UserID: userID, Relay: "default"})
			if err != nil || allowed {
				t.Fatalf("after clearing canonical binding allowed=%v err=%v want false, nil", allowed, err)
			}

			// The unmanaged non-canonical row remains untouched in casbin_rule.
			var nonCanonCount int64
			if err := dbConn.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ?", "g", "user:"+sp.raw).Count(&nonCanonCount).Error; err != nil {
				t.Fatalf("count non-canonical row: %v", err)
			}
			if nonCanonCount != 1 {
				t.Fatalf("non-canonical row count=%d want=1", nonCanonCount)
			}
		})
	}
}

func TestReloadSeesOneConsistentSnapshot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	dbURL := "sqlite://" + dbPath

	conn1, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open conn1: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), conn1, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	conn2, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open conn2: %v", err)
	}

	seedBuiltins(t, conn1)
	if err := conn1.Create(&model.Relay{Name: "eu-1"}).Error; err != nil {
		t.Fatalf("create relay eu-1: %v", err)
	}
	if err := conn1.Create(&model.Role{Name: "ops"}).Error; err != nil {
		t.Fatalf("create role ops: %v", err)
	}

	u1, u2 := uuid.New(), uuid.New()
	// OLD state: ops has all_relays=true, u1 bound to ops, u2 unbound.
	// Neither OLD nor NEW state ever allows (u2, eu-1).
	if err := conn1.Transaction(func(tx *gorm.DB) error {
		if err := policy.SetRoleGrants(tx, "ops", []string{"*"}); err != nil {
			return err
		}
		return policy.SetUserRoles(tx, u1, []string{"ops"})
	}); err != nil {
		t.Fatalf("seed old state: %v", err)
	}

	engine, err := policy.NewEngine(conn1)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Hook after the roles read inside Reload to race a competing transaction on
	// conn2 that atomically replaces ops=["*"] with ops=["default"] and binds u2->ops.
	// Without a single-snapshot read transaction, conn2 commits immediately during
	// the pause and Reload mixes old roles (all_relays=true) with new casbin_rule
	// (u2->ops), allowing (u2, eu-1).
	var fired atomic.Bool
	writerErrCh := make(chan error, 1)
	writerDone := make(chan struct{})
	if err := conn1.Callback().Query().After("gorm:query").Register("test_interleave_reload", func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Table != "roles" || !fired.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer close(writerDone)
			writerErrCh <- conn2.Transaction(func(wtx *gorm.DB) error {
				if err := policy.SetRoleGrants(wtx, "ops", []string{policy.BuiltinRelay}); err != nil {
					return err
				}
				return policy.SetUserRoles(wtx, u2, []string{"ops"})
			})
		}()
		select {
		case <-writerDone:
		case <-time.After(50 * time.Millisecond):
		}
	}); err != nil {
		t.Fatalf("register query callback: %v", err)
	}
	defer func() {
		_ = conn1.Callback().Query().Remove("test_interleave_reload")
	}()

	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !fired.Load() {
		t.Fatalf("interleaving hook did not fire")
	}

	// Wait for the competing write transaction to finish cleanly.
	<-writerDone
	if wErr := <-writerErrCh; wErr != nil {
		t.Fatalf("competing writer failed: %v", wErr)
	}

	// Snapshot published by Reload must be either the complete OLD state or the
	// complete NEW state — never a mix where (u2, eu-1) is allowed.
	type matrix [4]bool
	eval := func() matrix {
		reqs := [4]policy.Request{
			{UserID: u1, Relay: "default"},
			{UserID: u1, Relay: "eu-1"},
			{UserID: u2, Relay: "default"},
			{UserID: u2, Relay: "eu-1"},
		}
		var out matrix
		for i, r := range reqs {
			ok, err := engine.Enforce(r)
			if err != nil {
				t.Fatalf("Enforce(%+v): %v", r, err)
			}
			out[i] = ok
		}
		return out
	}

	oldState := matrix{true, true, false, false}
	newState := matrix{true, false, true, false}
	got := eval()
	if got != oldState && got != newState {
		t.Fatalf("Reload published inconsistent mixed snapshot: got=%v want old=%v or new=%v", got, oldState, newState)
	}

	// A follow-up Reload after the competing transaction committed must see newState.
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("second Reload: %v", err)
	}
	if got2 := eval(); got2 != newState {
		t.Fatalf("post-commit Reload got=%v want new=%v", got2, newState)
	}
}

func TestEngineVersionPublishedWithSnapshot(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Relay{Name: "eu-1"}).Error; err != nil {
		t.Fatalf("create relay eu-1: %v", err)
	}
	if err := dbConn.Create(&model.Role{Name: "ops"}).Error; err != nil {
		t.Fatalf("create role ops: %v", err)
	}
	u := uuid.New()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		if err := policy.SetRoleGrants(tx, "ops", []string{"eu-1"}); err != nil {
			return err
		}
		return policy.SetUserRoles(tx, u, []string{"ops"})
	}); err != nil {
		t.Fatalf("setup initial ops role: %v", err)
	}

	engine, err := policy.NewEngine(dbConn)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if engine.Version() != 0 {
		t.Fatalf("initial Version()=%d want=0", engine.Version())
	}

	// Alternate atomically between:
	//   odd version  -> ops granted ["default"]
	//   even version -> ops granted ["eu-1"]
	// Concurrent readers bracket Enforce with Version() before and after; whenever
	// vBefore == vAfter, the observed rules must match that version's parity.
	const rounds = 40
	stop := make(chan struct{})
	var oddMatched, evenMatched atomic.Int64
	errCh := make(chan error, 8)
	var wg sync.WaitGroup

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				vBefore := engine.Version()
				allowDef, err1 := engine.Enforce(policy.Request{UserID: u, Relay: "default"})
				allowEU, err2 := engine.Enforce(policy.Request{UserID: u, Relay: "eu-1"})
				vAfter := engine.Version()
				if err1 != nil || err2 != nil {
					select {
					case errCh <- errors.Join(err1, err2):
					default:
					}
					return
				}
				if vBefore != vAfter {
					continue
				}
				if vBefore%2 == 1 {
					if !allowDef || allowEU {
						select {
						case errCh <- errors.New("version/snapshot mismatch on odd version"):
						default:
						}
						return
					}
					oddMatched.Add(1)
				} else {
					if allowDef || !allowEU {
						select {
						case errCh <- errors.New("version/snapshot mismatch on even version"):
						default:
						}
						return
					}
					evenMatched.Add(1)
				}
			}
		}()
	}

	for i := 1; i <= rounds; i++ {
		target := []string{"eu-1"}
		if i%2 == 1 {
			target = []string{"default"}
		}
		var bumped int64
		if err := dbConn.Transaction(func(tx *gorm.DB) error {
			if err := policy.SetRoleGrants(tx, "ops", target); err != nil {
				return err
			}
			var err error
			bumped, err = policy.BumpVersion(tx)
			return err
		}); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("round %d commit: %v", i, err)
		}
		if err := engine.Reload(context.Background()); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("round %d reload: %v", i, err)
		}
		if got := engine.Version(); got != bumped {
			close(stop)
			wg.Wait()
			t.Fatalf("round %d Version()=%d want=%d", i, got, bumped)
		}
	}

	close(stop)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent reader observed error: %v", err)
	}
	if oddMatched.Load() == 0 || evenMatched.Load() == 0 {
		t.Fatalf("expected concurrent reads on both parities: odd=%d even=%d", oddMatched.Load(), evenMatched.Load())
	}
}

func TestRuleFunctionsRejectInvalidRegistryNames(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	// Insert registry rows that violate NamePattern directly via SQL/GORM.
	if err := dbConn.Create(&model.Role{Name: "Ops", AllRelays: true}).Error; err != nil {
		t.Fatalf("insert invalid role Ops: %v", err)
	}
	if err := dbConn.Create(&model.Relay{Name: "EU_1"}).Error; err != nil {
		t.Fatalf("insert invalid relay EU_1: %v", err)
	}

	u := uuid.New()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetUserRoles(tx, u, []string{"Ops"})
	}); !errors.Is(err, policy.ErrUnknownRole) {
		t.Fatalf("SetUserRoles invalid registry role err=%v want ErrUnknownRole", err)
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, policy.BuiltinRole, []string{"EU_1"})
	}); !errors.Is(err, policy.ErrUnknownRelay) {
		t.Fatalf("SetRoleGrants invalid registry relay err=%v want ErrUnknownRelay", err)
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "Ops", []string{policy.BuiltinRelay})
	}); !errors.Is(err, policy.ErrUnknownRole) {
		t.Fatalf("SetRoleGrants on invalid registry role err=%v want ErrUnknownRole", err)
	}

	// Even when raw rules exist in casbin_rule, UserRoles and RoleGrants report
	// only what the engine would honour.
	if err := dbConn.Create(&[]model.CasbinRule{
		{Ptype: "g", V0: policy.UserSubject(u), V1: "role:Ops"},
		{Ptype: "p", V0: "role:standard", V1: "derp:EU_1", V2: "connect"},
	}).Error; err != nil {
		t.Fatalf("insert raw rules with invalid names: %v", err)
	}

	rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{u})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if len(rolesMap[u]) != 0 {
		t.Fatalf("UserRoles reported invalid role: %v want []", rolesMap[u])
	}

	grantsMap, err := policy.RoleGrants(context.Background(), dbConn, []string{policy.BuiltinRole, "Ops"})
	if err != nil {
		t.Fatalf("RoleGrants: %v", err)
	}
	if !reflect.DeepEqual(grantsMap[policy.BuiltinRole], []string{policy.BuiltinRelay}) {
		t.Fatalf("RoleGrants standard=%v want=[default]", grantsMap[policy.BuiltinRole])
	}
	if len(grantsMap["Ops"]) != 0 {
		t.Fatalf("RoleGrants Ops=%v want=[]", grantsMap["Ops"])
	}
}

func TestRuleFunctions(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	for _, r := range []string{"eu-1", "us-1"} {
		if err := dbConn.Create(&model.Relay{Name: r}).Error; err != nil {
			t.Fatalf("create relay %s: %v", r, err)
		}
	}
	for _, r := range []string{"ops", "eng"} {
		if err := dbConn.Create(&model.Role{Name: r}).Error; err != nil {
			t.Fatalf("create role %s: %v", r, err)
		}
	}

	// SetRoleGrants: named relays, wildcard alone, wildcard mixed, unknown relay.
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "ops", []string{"us-1", "eu-1", "eu-1"})
	}); err != nil {
		t.Fatalf("SetRoleGrants named: %v", err)
	}
	grants, err := policy.RoleGrants(context.Background(), dbConn, []string{"ops"})
	if err != nil {
		t.Fatalf("RoleGrants named: %v", err)
	}
	if !reflect.DeepEqual(grants["ops"], []string{"eu-1", "us-1"}) {
		t.Fatalf("ops grants=%v want=[eu-1 us-1]", grants["ops"])
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "ops", []string{"*", "eu-1"})
	}); !errors.Is(err, policy.ErrInvalidGrant) {
		t.Fatalf("mixed wildcard err=%v want ErrInvalidGrant", err)
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "ops", []string{"no-such-relay"})
	}); !errors.Is(err, policy.ErrUnknownRelay) {
		t.Fatalf("unknown relay err=%v want ErrUnknownRelay", err)
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetRoleGrants(tx, "ops", []string{"*"})
	}); err != nil {
		t.Fatalf("SetRoleGrants wildcard: %v", err)
	}
	grants, err = policy.RoleGrants(context.Background(), dbConn, []string{"ops"})
	if err != nil {
		t.Fatalf("RoleGrants wildcard: %v", err)
	}
	if !reflect.DeepEqual(grants["ops"], []string{"*"}) {
		t.Fatalf("ops wildcard grants=%v want=[*]", grants["ops"])
	}

	// Switch ops back to named grants and also give eng grants on both eu-1 and default.
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		if err := policy.SetRoleGrants(tx, "ops", []string{"eu-1", "us-1"}); err != nil {
			return err
		}
		return policy.SetRoleGrants(tx, "eng", []string{"eu-1", policy.BuiltinRelay})
	}); err != nil {
		t.Fatalf("SetRoleGrants switch back: %v", err)
	}

	// SetUserRoles & UserRoles (including unknown role error).
	u1, u2 := uuid.New(), uuid.New()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.SetUserRoles(tx, u1, []string{"no-such-role"})
	}); !errors.Is(err, policy.ErrUnknownRole) {
		t.Fatalf("SetUserRoles unknown err=%v want ErrUnknownRole", err)
	}
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		if err := policy.SetUserRoles(tx, u1, []string{"ops", "eng"}); err != nil {
			return err
		}
		return policy.SetUserRoles(tx, u2, []string{"ops", "eng"})
	}); err != nil {
		t.Fatalf("SetUserRoles valid: %v", err)
	}
	rolesMap, err := policy.UserRoles(context.Background(), dbConn, []uuid.UUID{u1, u2})
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[u1], []string{"eng", "ops"}) || !reflect.DeepEqual(rolesMap[u2], []string{"eng", "ops"}) {
		t.Fatalf("UserRoles got=%v", rolesMap)
	}

	// DeleteRelayGrants refuses builtin, deletes eu-1 grants, and preserves grants on other relays.
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.DeleteRelayGrants(tx, policy.BuiltinRelay)
	}); !errors.Is(err, policy.ErrBuiltin) {
		t.Fatalf("DeleteRelayGrants builtin err=%v want ErrBuiltin", err)
	}
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.DeleteRelayGrants(tx, "eu-1")
	}); err != nil {
		t.Fatalf("DeleteRelayGrants eu-1: %v", err)
	}
	grants, err = policy.RoleGrants(context.Background(), dbConn, []string{"ops", "eng", policy.BuiltinRole})
	if err != nil {
		t.Fatalf("RoleGrants after DeleteRelayGrants: %v", err)
	}
	if !reflect.DeepEqual(grants["ops"], []string{"us-1"}) {
		t.Fatalf("ops grants after eu-1 delete=%v want=[us-1]", grants["ops"])
	}
	if !reflect.DeepEqual(grants["eng"], []string{policy.BuiltinRelay}) {
		t.Fatalf("eng grants after eu-1 delete=%v want=[default]", grants["eng"])
	}
	if !reflect.DeepEqual(grants[policy.BuiltinRole], []string{policy.BuiltinRelay}) {
		t.Fatalf("standard grants after eu-1 delete=%v want=[default]", grants[policy.BuiltinRole])
	}

	// DeleteRoleRules refuses builtin, returns binding count (2 users bound to ops),
	// and preserves eng's grants and user bindings.
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		_, err := policy.DeleteRoleRules(tx, policy.BuiltinRole)
		return err
	}); !errors.Is(err, policy.ErrBuiltin) {
		t.Fatalf("DeleteRoleRules builtin err=%v want ErrBuiltin", err)
	}
	// Seed non-user grouping rows naming role:ops; DeleteRoleRules must delete
	// them too while counting only the 2 user bindings in its return value.
	if err := dbConn.Create(&[]model.CasbinRule{
		{Ptype: "g", V0: "role:eng", V1: "role:ops"},
		{Ptype: "g", V0: "device:nodekey:stale-dev", V1: "role:ops"},
	}).Error; err != nil {
		t.Fatalf("seed non-user grouping rules for ops: %v", err)
	}

	var removed int64
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		var err error
		removed, err = policy.DeleteRoleRules(tx, "ops")
		return err
	}); err != nil {
		t.Fatalf("DeleteRoleRules ops: %v", err)
	}
	if removed != 2 {
		t.Fatalf("DeleteRoleRules removed=%d want=2", removed)
	}
	var leftoverOpsGroupings int64
	if err := dbConn.Model(&model.CasbinRule{}).Where("ptype = ? AND v1 = ?", "g", "role:ops").Count(&leftoverOpsGroupings).Error; err != nil {
		t.Fatalf("count leftover ops grouping rules: %v", err)
	}
	if leftoverOpsGroupings != 0 {
		t.Fatalf("leftover g,*,role:ops rows=%d want=0", leftoverOpsGroupings)
	}
	grants, err = policy.RoleGrants(context.Background(), dbConn, []string{"ops", "eng"})
	if err != nil {
		t.Fatalf("RoleGrants after DeleteRoleRules: %v", err)
	}
	if len(grants["ops"]) != 0 {
		t.Fatalf("ops grants after delete=%v want=[]", grants["ops"])
	}
	if !reflect.DeepEqual(grants["eng"], []string{policy.BuiltinRelay}) {
		t.Fatalf("eng grants damaged by DeleteRoleRules(ops): got=%v want=[default]", grants["eng"])
	}
	rolesMap, err = policy.UserRoles(context.Background(), dbConn, []uuid.UUID{u1, u2})
	if err != nil {
		t.Fatalf("UserRoles after DeleteRoleRules: %v", err)
	}
	if !reflect.DeepEqual(rolesMap[u1], []string{"eng"}) || !reflect.DeepEqual(rolesMap[u2], []string{"eng"}) {
		t.Fatalf("other role bindings damaged by DeleteRoleRules(ops): got=%v", rolesMap)
	}

	// DeleteLegacyDeviceRule & DeleteUserRules: verify isolation across devices and users.
	nk1 := "nodekey:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	nk2 := "nodekey:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	nk3 := "nodekey:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := dbConn.Create(&[]model.CasbinRule{
		{Ptype: "g", V0: "device:" + nk1, V1: policy.UserSubject(u1)},
		{Ptype: "g", V0: "device:" + nk2, V1: policy.UserSubject(u1)},
		{Ptype: "g", V0: "device:" + nk3, V1: policy.UserSubject(u2)},
	}).Error; err != nil {
		t.Fatalf("seed legacy device rules: %v", err)
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.DeleteLegacyDeviceRule(tx, nk1, u1)
	}); err != nil {
		t.Fatalf("DeleteLegacyDeviceRule: %v", err)
	}
	var legacyCount int64
	if err := dbConn.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ?", "g", "device:"+nk1).Count(&legacyCount).Error; err != nil {
		t.Fatalf("count legacy nk1: %v", err)
	}
	if legacyCount != 0 {
		t.Fatalf("legacy rule nk1 still exists")
	}
	// Other device of u1 (nk2) and device of u2 (nk3) must still exist.
	if err := dbConn.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ? AND v1 = ?", "g", "device:"+nk2, policy.UserSubject(u1)).Count(&legacyCount).Error; err != nil {
		t.Fatalf("count legacy nk2: %v", err)
	}
	if legacyCount != 1 {
		t.Fatalf("legacy rule nk2 count=%d want=1 (must not be deleted by DeleteLegacyDeviceRule(nk1))", legacyCount)
	}
	if err := dbConn.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ? AND v1 = ?", "g", "device:"+nk3, policy.UserSubject(u2)).Count(&legacyCount).Error; err != nil {
		t.Fatalf("count legacy nk3: %v", err)
	}
	if legacyCount != 1 {
		t.Fatalf("legacy rule nk3 count=%d want=1 (must not be deleted by DeleteLegacyDeviceRule(nk1))", legacyCount)
	}

	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		return policy.DeleteUserRules(tx, u1, []string{nk2})
	}); err != nil {
		t.Fatalf("DeleteUserRules: %v", err)
	}
	if err := dbConn.Model(&model.CasbinRule{}).
		Where("v0 = ? OR v0 = ?", policy.UserSubject(u1), "device:"+nk2).
		Count(&legacyCount).Error; err != nil {
		t.Fatalf("count remaining u1 rules: %v", err)
	}
	if legacyCount != 0 {
		t.Fatalf("remaining u1 rules=%d want=0", legacyCount)
	}
	// u2 must keep both its role bindings and its legacy device rule.
	rolesMap, err = policy.UserRoles(context.Background(), dbConn, []uuid.UUID{u1, u2})
	if err != nil {
		t.Fatalf("UserRoles after DeleteUserRules: %v", err)
	}
	if len(rolesMap[u1]) != 0 {
		t.Fatalf("u1 roles after delete=%v want=[]", rolesMap[u1])
	}
	if !reflect.DeepEqual(rolesMap[u2], []string{"eng"}) {
		t.Fatalf("u2 roles damaged by DeleteUserRules(u1): got=%v want=[eng]", rolesMap[u2])
	}
	if err := dbConn.Model(&model.CasbinRule{}).Where("ptype = ? AND v0 = ? AND v1 = ?", "g", "device:"+nk3, policy.UserSubject(u2)).Count(&legacyCount).Error; err != nil {
		t.Fatalf("count u2 legacy nk3: %v", err)
	}
	if legacyCount != 1 {
		t.Fatalf("u2 legacy rule nk3 count=%d want=1 (must not be deleted by DeleteUserRules(u1))", legacyCount)
	}
}

func TestRuleWritesIdempotentWithUniqueIndex(t *testing.T) {
	dbConn := openPolicyTestDB(t)
	seedBuiltins(t, dbConn)

	if err := dbConn.Create(&model.Role{Name: "ops"}).Error; err != nil {
		t.Fatalf("create role ops: %v", err)
	}
	if err := dbConn.Create(&model.Relay{Name: "eu-1"}).Error; err != nil {
		t.Fatalf("create relay eu-1: %v", err)
	}

	userID := uuid.New()

	// Write the same user binding twice (including duplicate entries in the slice).
	for i := 0; i < 2; i++ {
		if err := dbConn.Transaction(func(tx *gorm.DB) error {
			return policy.SetUserRoles(tx, userID, []string{"ops", "ops"})
		}); err != nil {
			t.Fatalf("SetUserRoles attempt %d: %v", i+1, err)
		}
	}
	var bindCount int64
	if err := dbConn.Model(&model.CasbinRule{}).
		Where("ptype = ? AND v0 = ? AND v1 = ?", "g", policy.UserSubject(userID), "role:ops").
		Count(&bindCount).Error; err != nil {
		t.Fatalf("count user role binding: %v", err)
	}
	if bindCount != 1 {
		t.Fatalf("user role binding count=%d want=1", bindCount)
	}

	// Write the same role grant twice (including duplicate entries in the slice).
	for i := 0; i < 2; i++ {
		if err := dbConn.Transaction(func(tx *gorm.DB) error {
			return policy.SetRoleGrants(tx, "ops", []string{"eu-1", "eu-1"})
		}); err != nil {
			t.Fatalf("SetRoleGrants attempt %d: %v", i+1, err)
		}
	}
	var grantCount int64
	if err := dbConn.Model(&model.CasbinRule{}).
		Where("ptype = ? AND v0 = ? AND v1 = ? AND v2 = ?", "p", "role:ops", "derp:eu-1", "connect").
		Count(&grantCount).Error; err != nil {
		t.Fatalf("count role grant: %v", err)
	}
	if grantCount != 1 {
		t.Fatalf("role grant count=%d want=1", grantCount)
	}
}

func seedBuiltins(t *testing.T, dbConn *gorm.DB) {
	t.Helper()
	if err := dbConn.Transaction(func(tx *gorm.DB) error {
		_, err := policy.SeedBuiltins(tx)
		return err
	}); err != nil {
		t.Fatalf("seed builtins: %v", err)
	}
}

func openPolicyTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "policy.db")
	dbURL := "sqlite://" + dbPath

	conn, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), conn, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	return conn
}
