package service

import (
	"context"
	"sync/atomic"
)

// syncer is the policy-sync stub until Track B replaces it with a poller.
type syncer struct {
	stale atomic.Bool
}

func newSyncer() *syncer {
	return &syncer{}
}

func (s *syncer) Stale() bool {
	return s.stale.Load()
}

func (s *syncer) MarkStale() {
	s.stale.Store(true)
}

func (s *syncer) ClearStale() {
	s.stale.Store(false)
}

func (s *syncer) Start(_ context.Context) {}

func (s *Service) StartSync(ctx context.Context) {
	s.sync.Start(ctx)
}

func (s *Service) SyncStale() bool {
	return s.sync.Stale()
}
