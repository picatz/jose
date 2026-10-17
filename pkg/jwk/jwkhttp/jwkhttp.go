// Package jwkhttp fetches JWK Sets over HTTP, such as an OpenID Connect
// provider's jwks_uri, and serves them to a [jwt.Verifier] as a
// [jwt.KeySource].
//
// It is separate from [jwk] so that programs which only parse and use keys
// do not link an HTTP client. Fetch keys only from URLs you configured
// yourself: this package never follows a "jku" or "x5u" header from a token
// you are about to verify (RFC 8725 §3.10).
//
// https://www.rfc-editor.org/rfc/rfc8725.html#section-3.10
package jwkhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwt"
)

// maxSetSize bounds the JWK Set response read. Published sets are a few
// kilobytes; the bound keeps a hostile or broken endpoint from exhausting
// memory.
const maxSetSize = 1 << 20

// fetchTimeout bounds a single fetch, whatever the caller's client allows.
const fetchTimeout = 15 * time.Second

// Bounds and defaults for the [Keys] timing fields.
const (
	DefaultTTL             = time.Hour
	MinTTL                 = time.Minute
	MaxTTL                 = 24 * time.Hour
	DefaultRefetchInterval = time.Minute
	MinRefetchInterval     = 5 * time.Second
	MaxRefetchInterval     = time.Hour
	DefaultMaxStale        = 24 * time.Hour
	MaxMaxStale            = 7 * 24 * time.Hour
)

var (
	// ErrInsecureURL reports a JWK Set URL that is not https, or http to a
	// host other than a loopback address.
	ErrInsecureURL = errors.New("jwkhttp: URL must be https, or http to a loopback host")
	// ErrFetch reports a JWK Set that could not be retrieved: a transport
	// error, a status other than 200, or a body over 1 MiB.
	ErrFetch = errors.New("jwkhttp: fetching key set failed")
)

// checkURL accepts https URLs, and http URLs whose host is localhost or a
// loopback IP (for tests and local development).
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("%w: %q", ErrInsecureURL, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrInsecureURL, raw)
}

// FetchSet fetches and parses the JWK Set at rawURL once, with no caching.
// The URL must be https, or http to a loopback host; redirects are held to
// the same rule. A nil client means [http.DefaultClient]. The response is
// limited to 1 MiB, and the set is parsed with [jwk.ParseSet] and checked
// with [jwk.Set.Validate].
func FetchSet(ctx context.Context, rawURL string, client *http.Client) (*jwk.Set, error) {
	if err := checkURL(rawURL); err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	// Copy so the caller's client keeps its redirect policy.
	c := *client
	previous := c.CheckRedirect
	// Plain http (to loopback) is only followed when the configured URL is
	// itself http; a redirect from https must stay https.
	startedHTTP := strings.HasPrefix(strings.ToLower(rawURL), "http:")
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := checkURL(req.URL.String()); err != nil {
			return err
		}
		if req.URL.Scheme == "http" && !startedHTTP {
			return fmt.Errorf("%w: redirect from https to %q", ErrInsecureURL, req.URL.String())
		}
		if previous != nil {
			return previous(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", ErrFetch, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSetSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	if len(body) > maxSetSize {
		return nil, fmt.Errorf("%w: response is larger than %d bytes", ErrFetch, maxSetSize)
	}
	set, err := jwk.ParseSet(body)
	if err != nil {
		return nil, err
	}
	if err := set.Validate(); err != nil {
		return nil, err
	}
	return set, nil
}

// Keys is a [jwt.KeySource] backed by a JWK Set at a URL, such as an OpenID
// Connect provider's jwks_uri:
//
//	verifier := jwt.Verifier{
//		Keys:     &jwkhttp.Keys{URL: "https://issuer.example/jwks"},
//		Issuer:   "https://issuer.example",
//		Audience: "my-api",
//	}
//
// The set is fetched lazily on first use and cached for TTL. A token naming
// a "kid" the cached set lacks triggers one refetch, at most once per
// RefetchInterval, so rotated keys are picked up quickly while a flood of
// tokens with made-up kids cannot hammer the issuer. Concurrent callers
// share one fetch. If a refresh fails, the last good set keeps being served
// until it is MaxStale past its TTL. The fetched keys go through
// [jwt.KeysFromSet], so a set holding private or symmetric keys is refused.
//
// The response is limited to 1 MiB, the URL must be https (or http to a
// loopback host), and redirects are held to the same rule. A Keys must not
// be copied after first use. The zero value of every field except URL
// selects a safe default.
type Keys struct {
	// URL is the JWK Set location, configured by you and never taken from
	// a token.
	URL string
	// Client performs the fetch; nil means [http.DefaultClient]. Each
	// fetch is also bounded to 15 seconds.
	Client *http.Client
	// TTL is how long a fetched set is used before it is refreshed. Zero
	// means [DefaultTTL]; values are clamped to [MinTTL, MaxTTL].
	TTL time.Duration
	// RefetchInterval is the shortest time between fetches, so it bounds
	// the refetch an unknown "kid" can trigger and the retry rate after a
	// failure. Zero means [DefaultRefetchInterval]; values are clamped to
	// [MinRefetchInterval, MaxRefetchInterval].
	RefetchInterval time.Duration
	// MaxStale is how long past its TTL the last good set is still served
	// when refreshing fails. Zero means [DefaultMaxStale]; values are
	// clamped to [0, MaxMaxStale] (negative disables stale serving).
	MaxStale time.Duration

	mu        sync.Mutex
	keys      jwt.Keys
	fetched   time.Time // last successful fetch
	attempted time.Time // last attempt, successful or not
	lastErr   error
	inflight  chan struct{}    // closed when the in-flight fetch finishes
	now       func() time.Time // for tests
}

var _ jwt.KeySource = (*Keys)(nil)

func clamp(d, def, lo, hi time.Duration) time.Duration {
	if d == 0 {
		return def
	}
	return min(max(d, lo), hi)
}

// Keys implements [jwt.KeySource]. It returns the keys whose "kid" matches
// kid (or all keys when kid is empty), fetching or refreshing the set as
// described on [Keys].
func (k *Keys) Keys(ctx context.Context, kid string) ([]jwt.Key, error) {
	if err := checkURL(k.URL); err != nil {
		return nil, err
	}
	ttl := clamp(k.TTL, DefaultTTL, MinTTL, MaxTTL)
	interval := clamp(k.RefetchInterval, DefaultRefetchInterval, MinRefetchInterval, MaxRefetchInterval)
	maxStale := k.MaxStale
	switch {
	case maxStale == 0:
		maxStale = DefaultMaxStale
	case maxStale < 0:
		maxStale = 0
	default:
		maxStale = min(maxStale, MaxMaxStale)
	}

	// The mutex is never held across network I/O. A fetch runs in its own
	// goroutine on a context detached from any caller; callers that have a
	// usable cached set return it, the rest wait (honouring their ctx).
	waited := false
	for {
		k.mu.Lock()
		now := k.clock()
		have := k.keys != nil
		age := now.Sub(k.fetched)
		usable := have && age < ttl+maxStale
		var wait chan struct{}
		mine := false
		if k.inflight != nil {
			wait = k.inflight
		} else if !waited {
			var want bool
			switch {
			case !have || age >= ttl:
				// Expired or never fetched, unless a recent attempt failed
				// (or just succeeded and expired within the interval).
				want = k.attempted.IsZero() || now.Sub(k.attempted) >= interval
			case kid != "" && !k.hasKey(kid) && now.Sub(k.attempted) >= interval:
				want = true
			}
			if want {
				wait = make(chan struct{})
				mine = true
				k.inflight = wait
				k.attempted = now
				go k.refresh(context.WithoutCancel(ctx), now, wait)
			}
		}
		if wait != nil && (mine || !usable) {
			k.mu.Unlock()
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("jwkhttp: waiting for key set: %w", err)
			}
			select {
			case <-wait:
				waited = true
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("jwkhttp: waiting for key set: %w", ctx.Err())
			}
		}
		keys, lastErr := k.keys, k.lastErr
		k.mu.Unlock()

		if !have {
			if lastErr == nil {
				lastErr = ErrFetch
			}
			return nil, lastErr
		}
		if !usable {
			return nil, fmt.Errorf("jwkhttp: key set is stale and could not be refreshed: %w", lastErr)
		}
		return keys.Keys(ctx, kid)
	}
}

func (k *Keys) clock() time.Time {
	if k.now != nil {
		return k.now()
	}
	return time.Now()
}

func (k *Keys) hasKey(kid string) bool {
	return slices.ContainsFunc(k.keys, func(key jwt.Key) bool { return key.ID == kid })
}

// refresh fetches the set without holding mu and, on success, replaces the
// cache. On failure the previous keys stay. It always clears the in-flight
// marker and closes done.
func (k *Keys) refresh(ctx context.Context, now time.Time, done chan struct{}) {
	set, err := FetchSet(ctx, k.URL, k.Client)
	var keys jwt.Keys
	if err == nil {
		if keys, err = jwt.KeysFromSet(set); err == nil && keys == nil {
			keys = jwt.Keys{}
		}
	}
	k.mu.Lock()
	if err == nil {
		k.keys, k.fetched, k.lastErr = keys, now, nil
	} else {
		k.lastErr = err
	}
	k.inflight = nil
	k.mu.Unlock()
	close(done)
}
