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
// DPoP proofs are self-signed, so anyone can mint proofs with fresh
// identifiers. An unauthenticated client of an endpoint that checks the
// replay cache before anything else can fill it with unexpired entries, and
// then every client gets [ErrReplayCacheFull] until they expire (MaxAge plus
// Leeway, 5.5 minutes by default). The cache fails closed on purpose, and a
// full cache refuses in constant time. Authenticate the client or check the
// access token ("ath", [Request.AccessToken]) before relying on the cache,
// rate-limit proofs per client ahead of [Verifier.Verify], or size one cache
// per client.
//
// The zero value is not usable; call [NewMemoryReplayCache].
type MemoryReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	// earliest is a lower bound on the expiry of every entry. While the
	// cache is full and now is before it, nothing can have expired, so a
	// check refuses without scanning; a scan resets it to the exact value.
	earliest time.Time
	max      int
	now      func() time.Time
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
		if current.Before(c.earliest) {
			return false, ErrReplayCacheFull
		}
		c.earliest = time.Time{}
		for id, expiry := range c.entries {
			if !current.Before(expiry) {
				delete(c.entries, id)
			} else if c.earliest.IsZero() || expiry.Before(c.earliest) {
				c.earliest = expiry
			}
		}
		if len(c.entries) >= c.max {
			return false, ErrReplayCacheFull
		}
	}
	if len(c.entries) == 0 || expires.Before(c.earliest) {
		c.earliest = expires
	}
	c.entries[jti] = expires
	return false, nil
}
