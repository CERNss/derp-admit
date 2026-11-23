package service

import (
	"strconv"
	"testing"
	"time"
)

func TestVerifyCacheDisabled(t *testing.T) {
	c := NewVerifyCache(0)
	c.Set("default", "node", c.Epoch(), true, "", nil)
	if _, ok := c.Get("default", "node"); ok {
		t.Fatalf("disabled cache should never return a hit")
	}
}

func TestVerifyCacheStoreAndExpire(t *testing.T) {
	c := NewVerifyCache(50 * time.Millisecond)

	c.Set("default", "node", c.Epoch(), false, DenyReasonNotRegistered, nil)
	entry, ok := c.Get("default", "node")
	if !ok {
		t.Fatalf("expected cache hit")
	}
	if entry.Allow || entry.Reason != DenyReasonNotRegistered {
		t.Fatalf("unexpected entry: %+v", entry)
	}

	time.Sleep(70 * time.Millisecond)
	if _, ok := c.Get("default", "node"); ok {
		t.Fatalf("expected entry to expire")
	}
}

func TestVerifyCacheBounded(t *testing.T) {
	c := NewVerifyCache(time.Hour)
	c.maxEntries = 100

	for i := 0; i < 1000; i++ {
		c.Set("default", "node-"+strconv.Itoa(i), c.Epoch(), false, DenyReasonNotRegistered, nil)
	}

	c.mu.RLock()
	size := len(c.items)
	c.mu.RUnlock()

	if size > c.maxEntries {
		t.Fatalf("cache grew past max: size=%d max=%d", size, c.maxEntries)
	}
}

// TestVerifyCacheInvalidateDropsStaleSet pins the epoch semantics: a decision
// computed from state read before an Invalidate must not be cached after it,
// otherwise a revoked device could keep a stale allow for the full TTL.
func TestVerifyCacheInvalidateDropsStaleSet(t *testing.T) {
	c := NewVerifyCache(time.Hour)

	epoch := c.Epoch()
	c.Invalidate("node")
	c.Set("default", "node", epoch, true, "", nil)
	if _, ok := c.Get("default", "node"); ok {
		t.Fatalf("set with a pre-invalidation epoch must be dropped")
	}

	c.Set("default", "node", c.Epoch(), true, "", nil)
	if _, ok := c.Get("default", "node"); !ok {
		t.Fatalf("set with a current epoch should be stored")
	}
}
