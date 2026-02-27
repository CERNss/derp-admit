package service

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

type verifyCacheEntry struct {
	Allow    bool
	Reason   string
	DeviceID *uuid.UUID
	Expires  time.Time
}

type VerifyCache struct {
	ttl     time.Duration
	enabled bool
	mu      sync.RWMutex
	items   map[string]verifyCacheEntry
}

func NewVerifyCache(ttl time.Duration) *VerifyCache {
	if ttl <= 0 {
		return &VerifyCache{
			ttl:     ttl,
			enabled: false,
			items:   map[string]verifyCacheEntry{},
		}
	}
	return &VerifyCache{
		ttl:     ttl,
		enabled: true,
		items:   map[string]verifyCacheEntry{},
	}
}

func (c *VerifyCache) Get(nodeKey string) (verifyCacheEntry, bool) {
	if !c.enabled {
		return verifyCacheEntry{}, false
	}

	c.mu.RLock()
	entry, ok := c.items[nodeKey]
	c.mu.RUnlock()

	if !ok || time.Now().UTC().After(entry.Expires) {
		return verifyCacheEntry{}, false
	}
	return entry, true
}

func (c *VerifyCache) Set(nodeKey string, allow bool, reason string, deviceID *uuid.UUID) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	var copiedID *uuid.UUID
	if deviceID != nil {
		id := *deviceID
		copiedID = &id
	}

	c.items[nodeKey] = verifyCacheEntry{
		Allow:    allow,
		Reason:   reason,
		DeviceID: copiedID,
		Expires:  time.Now().UTC().Add(c.ttl),
	}
}

func (c *VerifyCache) Invalidate(nodeKey string) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, nodeKey)
}
