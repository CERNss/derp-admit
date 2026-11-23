package service

import "context"

// SyncBootstrapKey reconciles the bootstrap admin key at startup.
// Stub: does nothing until Track C implements bootstrap key management.
func (s *Service) SyncBootstrapKey(_ context.Context, _ string) error {
	return nil
}
