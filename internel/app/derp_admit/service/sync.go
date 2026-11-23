package service

import "context"

// syncer is the policy-sync stub until Track B replaces it with a poller.
type syncer struct{}

func newSyncer() *syncer {
	return &syncer{}
}

func (s *syncer) Stale() bool {
	return false
}

func (s *syncer) MarkStale() {}

func (s *syncer) Start(_ context.Context) {}

func (s *Service) StartSync(ctx context.Context) {
	s.sync.Start(ctx)
}

func (s *Service) SyncStale() bool {
	return s.sync.Stale()
}
