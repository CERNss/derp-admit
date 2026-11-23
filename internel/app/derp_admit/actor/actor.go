package actor

import (
	"context"
	"sync/atomic"

	"derp-admit/internel/app/derp_admit/model"

	"github.com/google/uuid"
)

// Tier represents the authorization level of an admin caller.
// Tiers are ordered TierNone < TierViewer < TierOperator < TierAdmin.
type Tier uint8

const (
	TierNone Tier = iota
	TierViewer
	TierOperator
	TierAdmin
)

func ParseTier(s string) (Tier, bool) {
	switch s {
	case model.AdminTierViewer:
		return TierViewer, true
	case model.AdminTierOperator:
		return TierOperator, true
	case model.AdminTierAdmin:
		return TierAdmin, true
	default:
		return TierNone, false
	}
}

func (t Tier) String() string {
	switch t {
	case TierViewer:
		return model.AdminTierViewer
	case TierOperator:
		return model.AdminTierOperator
	case TierAdmin:
		return model.AdminTierAdmin
	default:
		return "none"
	}
}

// Actor identifies who invoked an admin or system operation.
type Actor struct {
	KeyID *uuid.UUID
	Name  string
	Tier  Tier
	IP    string
}

// System is the actor used for automated startup and upgrade actions.
var System = Actor{Name: "system", Tier: TierAdmin}

type ctxKey uint8

const (
	actorCtxKey ctxKey = iota + 1
	opCtxKey
)

func With(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorCtxKey, a)
}

func From(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorCtxKey).(Actor)
	return a, ok
}

// Op carries per-request audit metadata set from the route table and consumed
// by service.Mutate.
type Op struct {
	Action     string
	TargetType string
	TargetID   string
	recorded   atomic.Bool
}

func WithOp(ctx context.Context, op *Op) context.Context {
	return context.WithValue(ctx, opCtxKey, op)
}

func OpFrom(ctx context.Context) (*Op, bool) {
	op, ok := ctx.Value(opCtxKey).(*Op)
	return op, ok && op != nil
}

func (o *Op) MarkRecorded() {
	o.recorded.Store(true)
}

func (o *Op) Recorded() bool {
	return o.recorded.Load()
}
