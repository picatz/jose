package dpop

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrReplayCacheFull is returned by [MemoryReplayCache] when it holds
// its maximum number of unexpired entries. Failing closed keeps an attacker
// from evicting a jti to replay it.
var ErrReplayCacheFull = errors.New("dpop: replay cache full")

// MemoryReplayCache is a bounded, in-process [ReplayCache]. It suits a
// single server instance; a fleet needs a shared store with an atomic
// insert-if-absent, so a proof accepted by one instance is rejected by the
// others.
//
// The zero value is not usable; call [NewMemoryReplayCache].
type MemoryReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	max     int
	now     func() time.Time
}

// NewMemoryReplayCache returns a cache holding at most max unexpired
// identifiers. now may be nil to use [time.Now].
func NewMemoryReplayCache(max int, now func() time.Time) *MemoryReplayCache {
	if max <= 0 {
		max = 1
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayCache{entries: make(map[string]time.Time), max: max, now: now}
}

// Seen implements [ReplayCache].
func (c *MemoryReplayCache) Seen(_ context.Context, jti string, expires time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current := c.now()
	if expiry, ok := c.entries[jti]; ok && current.Before(expiry) {
		return true, nil
	}
	if len(c.entries) >= c.max {
		for id, expiry := range c.entries {
			if !current.Before(expiry) {
				delete(c.entries, id)
			}
		}
		if len(c.entries) >= c.max {
			return false, ErrReplayCacheFull
		}
	}
	c.entries[jti] = expires
	return false, nil
}
