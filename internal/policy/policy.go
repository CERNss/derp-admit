package policy

import (
	"context"
	"fmt"
	"sync"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	roleStandard = "role:standard"
	derpObject   = "derp:default"
	connectAct   = "connect"
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
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

type Engine struct {
	enabled  bool
	enforcer *casbin.SyncedEnforcer
	mu       sync.Mutex
}

func NewEngine(db *gorm.DB, enabled bool) (*Engine, error) {
	if !enabled {
		return &Engine{enabled: false}, nil
	}

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("build model: %w", err)
	}

	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, fmt.Errorf("new gorm adapter: %w", err)
	}

	enforcer, err := casbin.NewSyncedEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("new enforcer: %w", err)
	}
	enforcer.EnableAutoSave(true)
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}

	return &Engine{
		enabled:  true,
		enforcer: enforcer,
	}, nil
}

func (e *Engine) Bootstrap(_ context.Context) error {
	if !e.enabled {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	exists, err := e.enforcer.HasPolicy(roleStandard, derpObject, connectAct)
	if err != nil {
		return fmt.Errorf("check standard role policy: %w", err)
	}
	if exists {
		return nil
	}

	ok, err := e.enforcer.AddPolicy(roleStandard, derpObject, connectAct)
	if err != nil {
		return fmt.Errorf("add standard role policy: %w", err)
	}
	if !ok {
		return fmt.Errorf("failed to add standard role policy")
	}
	return nil
}

func (e *Engine) EnsureDeviceForUser(nodeKey string, userID uuid.UUID) error {
	if !e.enabled {
		return nil
	}

	deviceSub := DeviceSubject(nodeKey)
	userSub := UserSubject(userID)

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.ensureGrouping(deviceSub, userSub); err != nil {
		return err
	}
	if err := e.ensureGrouping(userSub, roleStandard); err != nil {
		return err
	}
	return nil
}

func (e *Engine) EnforceConnect(nodeKey string) (bool, error) {
	if !e.enabled {
		return true, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	allowed, err := e.enforcer.Enforce(DeviceSubject(nodeKey), derpObject, connectAct)
	if err != nil {
		return false, fmt.Errorf("enforce policy: %w", err)
	}
	return allowed, nil
}

func DeviceSubject(nodeKey string) string {
	return "device:" + nodeKey
}

func UserSubject(userID uuid.UUID) string {
	return "user:" + userID.String()
}

func (e *Engine) ensureGrouping(child, parent string) error {
	exists, err := e.enforcer.HasGroupingPolicy(child, parent)
	if err != nil {
		return fmt.Errorf("check grouping policy %s -> %s: %w", child, parent, err)
	}
	if exists {
		return nil
	}
	ok, err := e.enforcer.AddGroupingPolicy(child, parent)
	if err != nil {
		return fmt.Errorf("add grouping policy %s -> %s: %w", child, parent, err)
	}
	if !ok {
		return fmt.Errorf("failed to add grouping policy %s -> %s", child, parent)
	}
	return nil
}
