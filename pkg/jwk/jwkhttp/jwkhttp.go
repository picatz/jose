// Package jwkhttp fetches and caches JWK Sets over HTTP, such as an
// OpenID Connect provider's jwks_uri.
//
// It is separate from [jwk] so that programs which only parse and use keys
// do not link an HTTP client. Fetch keys only from URLs you configured
// yourself: never from a "jku" or "x5u" header in a token you are about to
// verify (RFC 8725 §3.10).
//
// https://www.rfc-editor.org/rfc/rfc8725.html#section-3.10
package jwkhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/picatz/jose/pkg/jwk"
)

// maxSetSize bounds the JWK Set response FetchSet reads. Published sets are
// a few kilobytes; the bound keeps a hostile or broken endpoint from
// exhausting memory.
const maxSetSize = 1 << 20

// FetchSet fetches a JWK set from the given URL and HTTP client. It reads
// at most 1 MiB of response body.
func FetchSet(ctx context.Context, url string, client *http.Client) (*jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK set request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWK set: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWK set: %s", resp.Status)
	}

	var set jwk.Set
	err = json.NewDecoder(io.LimitReader(resp.Body, maxSetSize)).Decode(&set)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK set: %w", err)
	}

	err = set.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate JWK set: %w", err)
	}

	return &set, nil
}

// URLSetCache is a cache of JWK sets keyed by URL that can be easily used to verify
// JWTs from multiple issuers. It handles refreshing the JWK sets when they expire,
// retrying failed fetches, and caching the JWK sets for a configurable amount of time.
type URLSetCache struct {
	mutex sync.RWMutex

	// sets is a map of JWK sets keyed by URL.
	sets map[string]*jwk.Set

	// cacheTimes is a map of JWK set cache times keyed by URL.
	cacheTimes map[string]time.Time

	// client is the HTTP client used to fetch JWK sets.
	client *http.Client

	// refreshInterval is the amount of time between refreshing JWK sets.
	refreshInterval time.Duration

	// cacheDuration is the amount of time to cache JWK sets.
	cacheDuration time.Duration
}

// NewURLSetCache returns a new JWK set cache.
func NewURLSetCache(client *http.Client, refreshInterval, cacheDuration time.Duration) *URLSetCache {
	return &URLSetCache{
		mutex:           sync.RWMutex{},
		sets:            make(map[string]*jwk.Set),
		cacheTimes:      make(map[string]time.Time),
		client:          client,
		refreshInterval: refreshInterval,
		cacheDuration:   cacheDuration,
	}
}

// Get returns the JWK set for the given URL, fetching it if it is not already cached.
func (c *URLSetCache) Get(ctx context.Context, url string) (*jwk.Set, error) {
	c.mutex.RLock()
	set, cached := c.sets[url]
	expiry := c.cacheTimes[url]
	c.mutex.RUnlock()

	// If there's no set or the set is expired, fetch a fresh copy.
	if !cached || time.Now().After(expiry) {
		return c.Fetch(ctx, url)
	}
	return set, nil
}

// GetKey returns the first key from the JWK set for the given URL that matches the given key id,
// fetching the JWK set if it is not already cached.
func (c *URLSetCache) GetKey(ctx context.Context, url string, keyID string) (jwk.Value, error) {
	c.mutex.RLock()
	set, ok := c.sets[url]
	urlCacheTime := c.cacheTimes[url]
	c.mutex.RUnlock()

	if !ok {
		var err error
		set, err = c.Fetch(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWK set: %w", err)
		}
	}

	if time.Now().After(urlCacheTime) {
		var err error
		set, err = c.Refresh(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh JWK set: %w", err)
		}
	}

	key, err := set.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %q from JWK set: %w", keyID, err)
	}

	return key, nil
}

// Range iterates over the JWK sets in the cache, calling the given function for each
// URL and key. If the function returns false, the iteration will stop.
func (c *URLSetCache) Range(fn func(url string, key jwk.Value) bool) {
	if fn == nil || c == nil {
		return
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for url, set := range c.sets {
		for _, key := range set.Keys {
			if !fn(url, key) {
				return
			}
		}
	}
}

// Fetch fetches the JWK set for the given URL.
func (c *URLSetCache) Fetch(ctx context.Context, url string) (*jwk.Set, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	set, err := FetchSet(ctx, url, c.client)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWK set: %w", err)
	}

	c.sets[url] = set
	c.cacheTimes[url] = time.Now().Add(c.cacheDuration)

	return set, nil
}

// Refresh refreshes the JWK set for the given URL.
func (c *URLSetCache) Refresh(ctx context.Context, url string) (*jwk.Set, error) {
	return c.Fetch(ctx, url)
}

// RefreshAll refreshes all JWK sets in the cache.
func (c *URLSetCache) RefreshAll(ctx context.Context) error {
	c.mutex.RLock()
	urls := make([]string, 0, len(c.sets))
	for url := range c.sets {
		urls = append(urls, url)
	}
	c.mutex.RUnlock()

	for _, url := range urls {
		if _, err := c.Refresh(ctx, url); err != nil {
			return fmt.Errorf("failed to refresh JWK set for %q: %w", url, err)
		}
	}
	return nil
}

// Start starts the JWK set cache, refreshing the JWK sets at the given interval.
// It will block until the context is canceled, and will only return an error if
// the refresh fails, possibly due to a network error.
//
// Most callers will want to call this in a goroutine after creating the cache.
func (c *URLSetCache) Start(ctx context.Context) error {
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := c.RefreshAll(ctx)
			if err != nil {
				return fmt.Errorf("failed to refresh JWK sets: %w", err)
			}
		}
	}
}
