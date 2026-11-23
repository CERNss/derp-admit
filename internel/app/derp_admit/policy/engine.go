package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"derp-admit/internel/app/derp_admit/model"

	"github.com/casbin/casbin/v3"
	casbinmodel "github.com/casbin/casbin/v3/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	connectAct   = "connect"
	userPrefix   = "user:"
	rolePrefix   = "role:"
	relayPrefix  = "derp:"
	devicePrefix = "device:"
)

const modelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

type Request struct {
	UserID  uuid.UUID
	NodeKey string
	Relay   string
}

type PolicyEngine interface {
	Enforce(Request) (bool, error)
	Reload(ctx context.Context) error
}

var _ PolicyEngine = (*Engine)(nil)

type Engine struct {
	db       *gorm.DB
	reloadMu sync.Mutex
	enforcer atomic.Pointer[casbin.SyncedEnforcer]
}

// NewEngine builds an always-enforcing Casbin policy engine backed by db and
// loads the initial snapshot. The second parameter is retained for signature
// compatibility until Track A removes ENABLE_CASBIN and is ignored.
func NewEngine(db *gorm.DB, _ bool) (*Engine, error) {
	e := &Engine{db: db}
	if err := e.Reload(context.Background()); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload reads the role/relay registries and casbin_rule rows from the database,
// filters them down to managed shapes, expands all_relays roles over registered
// relays in memory, and atomically swaps in a brand-new read-only enforcer.
func (e *Engine) Reload(ctx context.Context) error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()

	var roles []model.Role
	if err := e.db.WithContext(ctx).Find(&roles).Error; err != nil {
		return fmt.Errorf("load roles: %w", err)
	}
	var relays []model.Relay
	if err := e.db.WithContext(ctx).Find(&relays).Error; err != nil {
		return fmt.Errorf("load relays: %w", err)
	}
	var rules []model.CasbinRule
	if err := e.db.WithContext(ctx).Find(&rules).Error; err != nil {
		return fmt.Errorf("load casbin rules: %w", err)
	}

	validRoles := make(map[string]model.Role, len(roles))
	for _, r := range roles {
		if NamePattern.MatchString(r.Name) {
			validRoles[r.Name] = r
		}
	}
	validRelays := make(map[string]struct{}, len(relays))
	for _, r := range relays {
		if NamePattern.MatchString(r.Name) {
			validRelays[r.Name] = struct{}{}
		}
	}

	gSeen := make(map[[2]string]struct{})
	pSeen := make(map[[3]string]struct{})
	var gBatch [][]string
	var pBatch [][]string

	for _, rule := range rules {
		switch rule.Ptype {
		case "g":
			if rule.V2 != "" || rule.V3 != "" || rule.V4 != "" || rule.V5 != "" {
				continue
			}
			uidRaw, ok := strings.CutPrefix(rule.V0, userPrefix)
			if !ok {
				continue
			}
			uid, err := uuid.Parse(uidRaw)
			if err != nil {
				continue
			}
			roleName, ok := strings.CutPrefix(rule.V1, rolePrefix)
			if !ok {
				continue
			}
			if _, exists := validRoles[roleName]; !exists {
				continue
			}
			key := [2]string{UserSubject(uid), roleSubject(roleName)}
			if _, dup := gSeen[key]; dup {
				continue
			}
			gSeen[key] = struct{}{}
			gBatch = append(gBatch, []string{key[0], key[1]})

		case "p":
			if rule.V3 != "" || rule.V4 != "" || rule.V5 != "" {
				continue
			}
			if rule.V2 != connectAct {
				continue
			}
			roleName, ok := strings.CutPrefix(rule.V0, rolePrefix)
			if !ok {
				continue
			}
			if _, exists := validRoles[roleName]; !exists {
				continue
			}
			relayName, ok := strings.CutPrefix(rule.V1, relayPrefix)
			if !ok {
				continue
			}
			if _, exists := validRelays[relayName]; !exists {
				continue
			}
			key := [3]string{roleSubject(roleName), relayObject(relayName), connectAct}
			if _, dup := pSeen[key]; dup {
				continue
			}
			pSeen[key] = struct{}{}
			pBatch = append(pBatch, []string{key[0], key[1], key[2]})
		}
	}

	// Expand all_relays roles over every registered relay in memory (AM2).
	for _, r := range validRoles {
		if !r.AllRelays {
			continue
		}
		for relayName := range validRelays {
			key := [3]string{roleSubject(r.Name), relayObject(relayName), connectAct}
			if _, dup := pSeen[key]; dup {
				continue
			}
			pSeen[key] = struct{}{}
			pBatch = append(pBatch, []string{key[0], key[1], key[2]})
		}
	}

	m, err := casbinmodel.NewModelFromString(modelText)
	if err != nil {
		return fmt.Errorf("build casbin model: %w", err)
	}
	enforcer, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		return fmt.Errorf("new casbin enforcer: %w", err)
	}
	enforcer.EnableAutoSave(false)

	if len(gBatch) > 0 {
		if _, err := enforcer.AddGroupingPolicies(gBatch); err != nil {
			return fmt.Errorf("add grouping policies: %w", err)
		}
	}
	if len(pBatch) > 0 {
		if _, err := enforcer.AddPolicies(pBatch); err != nil {
			return fmt.Errorf("add policies: %w", err)
		}
	}

	e.enforcer.Store(enforcer)
	return nil
}

func (e *Engine) Enforce(req Request) (bool, error) {
	if req.UserID == uuid.Nil || !NamePattern.MatchString(req.Relay) {
		return false, nil
	}
	enforcer := e.enforcer.Load()
	if enforcer == nil {
		return false, fmt.Errorf("policy engine not initialized")
	}
	allowed, err := enforcer.Enforce(UserSubject(req.UserID), relayObject(req.Relay), connectAct)
	if err != nil {
		return false, fmt.Errorf("enforce policy: %w", err)
	}
	return allowed, nil
}

func UserSubject(userID uuid.UUID) string {
	return userPrefix + userID.String()
}

func roleSubject(role string) string {
	return rolePrefix + role
}

func relayObject(relay string) string {
	return relayPrefix + relay
}
