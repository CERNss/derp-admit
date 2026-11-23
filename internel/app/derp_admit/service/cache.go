package service

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// defaultMaxCacheEntries bounds the verify decision cache so a flood of
// distinct (e.g. random/unregistered) node keys cannot grow it without limit.
const defaultMaxCacheEntries = 50000

// evictScanBatch caps how many entries a single eviction pass may touch, so
// Set never stalls concurrent verifies by scanning the whole map under c.mu.
const evictScanBatch = 512

type verifyCacheEntry struct {
	Allow    bool
	Reason   string
	DeviceID *uuid.UUID
	Expires  time.Time
}

type VerifyCache struct {
	ttl        time.Duration
	enabled    bool
	maxEntries int
	mu         sync.RWMutex
	// epoch increments on every Invalidate. Writers snapshot it via Epoch()
	// before reading the database and pass it to Set, which discards the
	// entry if any invalidation happened in between — otherwise a decision
	// computed from pre-invalidation state could be cached after the
	// invalidation and outlive it (stale allow after a revoke).
	epoch uint64
	items map[string]verifyCacheEntry
}

func NewVerifyCache(ttl time.Duration) *VerifyCache {
	return &VerifyCache{
		ttl:        ttl,
		enabled:    ttl > 0,
		maxEntries: defaultMaxCacheEntries,
		items:      map[string]verifyCacheEntry{},
	}
}

// Epoch returns a snapshot token to pass to Set. Take it before reading the
// state the cached decision is derived from.
func (c *VerifyCache) Epoch() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.epoch
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

func (c *VerifyCache) Set(nodeKey string, epoch uint64, allow bool, reason string, deviceID *uuid.UUID) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if epoch != c.epoch {
		// An invalidation raced this decision; it may be stale — drop it.
		return
	}

	if _, exists := c.items[nodeKey]; !exists && len(c.items) >= c.maxEntries {
		c.evictLocked()
	}

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
	c.epoch++
	delete(c.items, nodeKey)
}

// Purge clears all cached decisions and advances the epoch so decisions
// computed from pre-purge state cannot be stored afterwards.
func (c *VerifyCache) Purge() {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	clear(c.items)
}

// Enabled reports whether caching is active (TTL > 0).
func (c *VerifyCache) Enabled() bool {
	return c.enabled
}

// evictLocked reclaims space when the cache is full, touching at most a
// bounded batch of entries per call: expired entries in the batch are
// dropped; if none were expired the whole batch is shed so the map cannot
// grow past maxEntries. Callers must hold c.mu.
func (c *VerifyCache) evictLocked() {
	batch := c.maxEntries / 2
	if batch > evictScanBatch {
		batch = evictScanBatch
	}
	if batch < 1 {
		batch = 1
	}

	now := time.Now().UTC()
	live := make([]string, 0, batch)
	removed := 0
	for k, v := range c.items {
		if now.After(v.Expires) {
			delete(c.items, k)
			removed++
		} else {
			live = append(live, k)
		}
		if removed+len(live) >= batch {
			break
		}
	}
	if removed == 0 {
		for _, k := range live {
			delete(c.items, k)
		}
	}
}
