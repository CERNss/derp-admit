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

type verifyCacheKey struct {
	relay   string
	nodeKey string
}

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
	// epoch increments on every Invalidate or Purge. Writers snapshot it via
	// Epoch() before reading the database and pass it to Set, which discards
	// the entry if any invalidation happened in between — otherwise a decision
	// computed from pre-invalidation state could be cached after the
	// invalidation and outlive it (stale allow after a revoke).
	epoch  uint64
	items  map[verifyCacheKey]verifyCacheEntry
	byNode map[string]map[string]struct{}
}

func NewVerifyCache(ttl time.Duration) *VerifyCache {
	return &VerifyCache{
		ttl:        ttl,
		enabled:    ttl > 0,
		maxEntries: defaultMaxCacheEntries,
		items:      map[verifyCacheKey]verifyCacheEntry{},
		byNode:     map[string]map[string]struct{}{},
	}
}

// Epoch returns a snapshot token to pass to Set. Take it before reading the
// state the cached decision is derived from.
func (c *VerifyCache) Epoch() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.epoch
}

func (c *VerifyCache) Get(relay, nodeKey string) (verifyCacheEntry, bool) {
	if !c.enabled {
		return verifyCacheEntry{}, false
	}

	key := verifyCacheKey{relay: relay, nodeKey: nodeKey}
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok || time.Now().UTC().After(entry.Expires) {
		return verifyCacheEntry{}, false
	}
	return entry, true
}

func (c *VerifyCache) Set(relay, nodeKey string, epoch uint64, allow bool, reason string, deviceID *uuid.UUID) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if epoch != c.epoch {
		// An invalidation raced this decision; it may be stale — drop it.
		return
	}

	key := verifyCacheKey{relay: relay, nodeKey: nodeKey}
	if _, exists := c.items[key]; !exists && len(c.items) >= c.maxEntries {
		c.evictLocked()
	}

	var copiedID *uuid.UUID
	if deviceID != nil {
		id := *deviceID
		copiedID = &id
	}

	c.items[key] = verifyCacheEntry{
		Allow:    allow,
		Reason:   reason,
		DeviceID: copiedID,
		Expires:  time.Now().UTC().Add(c.ttl),
	}
	relays := c.byNode[nodeKey]
	if relays == nil {
		relays = map[string]struct{}{}
		c.byNode[nodeKey] = relays
	}
	relays[relay] = struct{}{}
}

// Invalidate drops all cached decisions for nodeKey across every relay and
// advances the epoch so pre-invalidation decisions cannot be stored afterwards.
func (c *VerifyCache) Invalidate(nodeKey string) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	if relays, ok := c.byNode[nodeKey]; ok {
		for relay := range relays {
			delete(c.items, verifyCacheKey{relay: relay, nodeKey: nodeKey})
		}
		delete(c.byNode, nodeKey)
	}
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
	clear(c.byNode)
}

// Enabled reports whether caching is active (TTL > 0).
func (c *VerifyCache) Enabled() bool {
	return c.enabled
}

func (c *VerifyCache) deleteLocked(k verifyCacheKey) {
	delete(c.items, k)
	if relays, ok := c.byNode[k.nodeKey]; ok {
		delete(relays, k.relay)
		if len(relays) == 0 {
			delete(c.byNode, k.nodeKey)
		}
	}
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
	live := make([]verifyCacheKey, 0, batch)
	removed := 0
	for k, v := range c.items {
		if now.After(v.Expires) {
			c.deleteLocked(k)
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
			c.deleteLocked(k)
		}
	}
}
