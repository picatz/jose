package jwkhttp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/jwk"
)

// jwksServer serves a mutable body and counts requests.
type jwksServer struct {
	*httptest.Server
	mu     sync.Mutex
	body   string
	status int
	hits   atomic.Int32
}

func newJWKSServer(t *testing.T, kids ...string) *jwksServer {
	t.Helper()
	s := &jwksServer{status: http.StatusOK}
	s.setKeys(t, kids...)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		body, status := s.body, s.status
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) set(body string, status int) {
	s.mu.Lock()
	s.body, s.status = body, status
	s.mu.Unlock()
}

func (s *jwksServer) setKeys(t *testing.T, kids ...string) {
	t.Helper()
	set := jwk.Set{}
	for _, kid := range kids {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		v, err := jwk.PublicValue(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		v[jwk.KeyID] = kid
		v[jwk.Algorithm] = "ES256"
		set.Keys = append(set.Keys, v)
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	s.set(string(b), http.StatusOK)
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newKeys(s *jwksServer) (*Keys, *clock) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	return &Keys{URL: s.URL, Client: s.Client(), now: c.now}, c
}

func TestKeysFetchesLazilyAndCaches(t *testing.T) {
	s := newJWKSServer(t, "a", "b")
	k, c := newKeys(s)
	if s.hits.Load() != 0 {
		t.Fatal("fetched before first use")
	}
	for range 3 {
		keys, err := k.Keys(t.Context(), "a")
		if err != nil || len(keys) != 1 || keys[0].ID != "a" {
			t.Fatalf("Keys(a) = %v, %v", keys, err)
		}
	}
	all, err := k.Keys(t.Context(), "")
	if err != nil || len(all) != 2 {
		t.Fatalf("Keys(\"\") = %v, %v", all, err)
	}
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}

	c.advance(DefaultTTL + time.Second)
	if _, err := k.Keys(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	if got := s.hits.Load(); got != 2 {
		t.Fatalf("hits after TTL = %d, want 2", got)
	}
}

func TestKeysTTLBounds(t *testing.T) {
	s := newJWKSServer(t, "a")
	k, c := newKeys(s)
	k.TTL = time.Nanosecond // clamps to MinTTL
	k.Keys(t.Context(), "a")
	c.advance(MinTTL - time.Second)
	k.Keys(t.Context(), "a")
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("hits before MinTTL = %d, want 1", got)
	}
	k2, c2 := newKeys(s)
	k2.TTL = 1000 * time.Hour // clamps to MaxTTL
	k2.Keys(t.Context(), "a")
	c2.advance(MaxTTL + time.Second)
	k2.Keys(t.Context(), "a")
	if got := s.hits.Load(); got != 3 {
		t.Fatalf("hits = %d, want 3", got)
	}
}

func TestKeysUnknownKidRefetchesOncePerInterval(t *testing.T) {
	s := newJWKSServer(t, "a")
	k, c := newKeys(s)
	if _, err := k.Keys(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}

	// Key rotation: the unknown kid triggers a refetch once the interval passed.
	s.setKeys(t, "a", "b")
	c.advance(DefaultRefetchInterval)
	keys, err := k.Keys(t.Context(), "b")
	if err != nil || len(keys) != 1 || keys[0].ID != "b" {
		t.Fatalf("Keys(b) = %v, %v", keys, err)
	}
	if got := s.hits.Load(); got != 2 {
		t.Fatalf("hits = %d, want 2", got)
	}

	// A made-up kid refetches once, then is throttled.
	c.advance(DefaultRefetchInterval)
	for range 10 {
		keys, err := k.Keys(t.Context(), "nope")
		if err != nil || len(keys) != 0 {
			t.Fatalf("Keys(nope) = %v, %v", keys, err)
		}
	}
	if got := s.hits.Load(); got != 3 {
		t.Fatalf("hits = %d, want 3 (one refetch for the unknown kid)", got)
	}
}

func TestKeysSingleFlight(t *testing.T) {
	s := newJWKSServer(t, "a")
	k := &Keys{URL: s.URL, Client: s.Client()}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := k.Keys(t.Context(), "a"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}
}

func TestKeysServesLastGoodSetWhenRefreshFails(t *testing.T) {
	s := newJWKSServer(t, "a")
	k, c := newKeys(s)
	if _, err := k.Keys(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	s.set("oops", http.StatusInternalServerError)

	c.advance(DefaultTTL + time.Second)
	keys, err := k.Keys(t.Context(), "a")
	if err != nil || len(keys) != 1 {
		t.Fatalf("stale Keys = %v, %v", keys, err)
	}
	hits := s.hits.Load()
	// Failed attempts are throttled too.
	for range 5 {
		k.Keys(t.Context(), "a")
	}
	if s.hits.Load() != hits {
		t.Fatalf("hits grew from %d to %d within the interval", hits, s.hits.Load())
	}

	// Recovery.
	s.setKeys(t, "a", "c")
	c.advance(DefaultRefetchInterval)
	keys, err = k.Keys(t.Context(), "c")
	if err != nil || len(keys) != 1 {
		t.Fatalf("recovered Keys(c) = %v, %v", keys, err)
	}

	// Past the maximum staleness the failure surfaces.
	s.set("oops", http.StatusBadGateway)
	c.advance(DefaultTTL + DefaultMaxStale + time.Second)
	if _, err := k.Keys(t.Context(), "a"); !errors.Is(err, ErrFetch) {
		t.Fatalf("Keys past MaxStale error = %v, want ErrFetch", err)
	}
}

func TestKeysBadRefreshKeepsGoodSet(t *testing.T) {
	s := newJWKSServer(t, "a")
	k, c := newKeys(s)
	k.Keys(t.Context(), "a")
	// 200 but a symmetric key: KeysFromSet refuses it.
	s.set(`{"keys":[{"kty":"oct","kid":"x","k":"c2VjcmV0"}]}`, http.StatusOK)
	c.advance(DefaultTTL + time.Second)
	keys, err := k.Keys(t.Context(), "a")
	if err != nil || len(keys) != 1 || keys[0].ID != "a" {
		t.Fatalf("Keys = %v, %v", keys, err)
	}
}

func TestKeysFirstFetchFailure(t *testing.T) {
	s := newJWKSServer(t, "a")
	s.set("", http.StatusServiceUnavailable)
	k, c := newKeys(s)
	if _, err := k.Keys(t.Context(), "a"); !errors.Is(err, ErrFetch) {
		t.Fatalf("error = %v, want ErrFetch", err)
	}
	hits := s.hits.Load()
	if _, err := k.Keys(t.Context(), "a"); !errors.Is(err, ErrFetch) || s.hits.Load() != hits {
		t.Fatalf("retry inside interval: err = %v, hits %d -> %d", err, hits, s.hits.Load())
	}
	s.setKeys(t, "a")
	c.advance(DefaultRefetchInterval)
	if keys, err := k.Keys(t.Context(), "a"); err != nil || len(keys) != 1 {
		t.Fatalf("after recovery: %v, %v", keys, err)
	}
}

func TestKeysCanceledContextDoesNotThrottle(t *testing.T) {
	s := newJWKSServer(t, "a")
	k, _ := newKeys(s)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := k.Keys(ctx, "a"); err == nil {
		t.Fatal("canceled context succeeded")
	}
	if keys, err := k.Keys(t.Context(), "a"); err != nil || len(keys) != 1 {
		t.Fatalf("next call: %v, %v", keys, err)
	}
}

func TestKeysResponseSizeCap(t *testing.T) {
	s := newJWKSServer(t)
	s.set(`{"keys":[],"pad":"`+strings.Repeat("a", maxSetSize)+`"}`, http.StatusOK)
	k, _ := newKeys(s)
	if _, err := k.Keys(t.Context(), ""); !errors.Is(err, ErrFetch) || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("error = %v, want size ErrFetch", err)
	}
}

func TestKeysRefusesInsecureURL(t *testing.T) {
	for _, u := range []string{
		"http://example.com/jwks",
		"http://10.0.0.1/jwks",
		"ftp://example.com/jwks",
		"https://user:pw@example.com/jwks",
		"https:///jwks",
		"",
	} {
		k := &Keys{URL: u}
		if _, err := k.Keys(t.Context(), "a"); !errors.Is(err, ErrInsecureURL) {
			t.Errorf("Keys with URL %q error = %v, want ErrInsecureURL", u, err)
		}
	}
	for _, u := range []string{"https://example.com/jwks", "http://localhost:1/x", "http://127.0.0.1/x", "http://[::1]/x"} {
		if err := checkURL(u); err != nil {
			t.Errorf("checkURL(%q) = %v", u, err)
		}
	}
}

func TestKeysHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	// An empty set is refused by Validate.
	k := &Keys{URL: srv.URL, Client: srv.Client()}
	if _, err := k.Keys(t.Context(), ""); !errors.Is(err, jwk.ErrFormat) {
		t.Fatalf("error = %v, want jwk.ErrFormat", err)
	}
	// Without trusting the certificate the fetch fails.
	k = &Keys{URL: srv.URL}
	if _, err := k.Keys(t.Context(), ""); !errors.Is(err, ErrFetch) {
		t.Fatalf("untrusted cert error = %v, want ErrFetch", err)
	}
}

func TestFetchSetRefusesInsecureRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/jwks", http.StatusFound)
	}))
	defer redirect.Close()
	if _, err := FetchSet(t.Context(), redirect.URL, nil); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("error = %v, want ErrInsecureURL", err)
	}
}

func TestFetchSetRejectsBadSets(t *testing.T) {
	s := newJWKSServer(t)
	for name, body := range map[string]string{
		"duplicate kid":    `{"keys":[{"kty":"oct","kid":"a","k":"AAAA"},{"kty":"oct","kid":"a","k":"AAAA"}]}`,
		"duplicate member": `{"keys":[],"keys":[]}`,
		"not json":         `<html>`,
		"invalid key":      `{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`,
	} {
		s.set(body, http.StatusOK)
		if _, err := FetchSet(t.Context(), s.URL, s.Client()); err == nil {
			t.Errorf("%s: FetchSet succeeded", name)
		}
	}
	s.set(`{"keys":[{"kty":"oct","kid":"a","k":"AAAA"}]}`, http.StatusOK)
	set, err := FetchSet(t.Context(), s.URL, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set.Get("a"); !ok {
		t.Fatal("kid a not found")
	}
}

// blockingServer serves a valid set, but holds each request until released.
type blockingServer struct {
	*httptest.Server
	hits    atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func newBlockingServer(t *testing.T, kids ...string) *blockingServer {
	t.Helper()
	inner := newJWKSServer(t, kids...)
	b := &blockingServer{entered: make(chan struct{}, 64), release: make(chan struct{})}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		b.entered <- struct{}{}
		select {
		case <-b.release:
		case <-r.Context().Done():
			return
		}
		inner.mu.Lock()
		body := inner.body
		inner.mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(func() {
		select {
		case <-b.release:
		default:
			close(b.release)
		}
		b.Close()
	})
	return b
}

func within(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("call blocked")
	}
}

func TestKeysSlowRefetchDoesNotBlockCachedKid(t *testing.T) {
	inner := newJWKSServer(t, "a")
	k := &Keys{URL: inner.URL, Client: inner.Client(), RefetchInterval: MinRefetchInterval}
	if _, err := k.Keys(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	// Swap to a blocking server for the refetch.
	slow := newBlockingServer(t, "a", "b")
	k.URL, k.Client = slow.URL, slow.Client()
	c := &clock{t: time.Now().Add(2 * MinRefetchInterval)}
	k.now = c.now

	go k.Keys(t.Context(), "unknown") // kid miss: starts the slow refetch
	<-slow.entered

	within(t, 2*time.Second, func() {
		keys, err := k.Keys(t.Context(), "a")
		if err != nil || len(keys) != 1 {
			t.Errorf("Keys(a) = %v, %v", keys, err)
		}
	})
	// A second unknown kid does not start another fetch or wait.
	within(t, 2*time.Second, func() { k.Keys(t.Context(), "other") })
	if got := slow.hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}
	close(slow.release)
}

func TestKeysFirstFetchWaitersCoalesce(t *testing.T) {
	slow := newBlockingServer(t, "a")
	k := &Keys{URL: slow.URL, Client: slow.Client()}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if keys, err := k.Keys(t.Context(), "a"); err != nil || len(keys) != 1 {
				t.Errorf("Keys = %v, %v", keys, err)
			}
		}()
	}
	<-slow.entered
	time.Sleep(50 * time.Millisecond) // let the others queue up
	close(slow.release)
	wg.Wait()
	if got := slow.hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}
}

func TestKeysCanceledWaiterDoesNotCancelFetch(t *testing.T) {
	slow := newBlockingServer(t, "a")
	k := &Keys{URL: slow.URL, Client: slow.Client()}
	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() { _, err := k.Keys(ctx, "a"); errc <- err }()
	<-slow.entered
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	// Another waiter joins the same fetch, which still completes.
	res := make(chan error, 1)
	go func() { _, err := k.Keys(t.Context(), "a"); res <- err }()
	time.Sleep(50 * time.Millisecond)
	close(slow.release)
	if err := <-res; err != nil {
		t.Fatal(err)
	}
	if got := slow.hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}
}

func TestFetchSetRedirectSchemes(t *testing.T) {
	plain := newJWKSServer(t, "a") // http loopback
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tlsSrv.Close()
	// https -> http loopback is refused.
	if _, err := FetchSet(t.Context(), tlsSrv.URL, tlsSrv.Client()); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("https->http error = %v, want ErrInsecureURL", err)
	}
	// http loopback -> http loopback is allowed.
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer hop.Close()
	if set, err := FetchSet(t.Context(), hop.URL, nil); err != nil || len(set.Keys) != 1 {
		t.Fatalf("http->http loopback: %v, %v", set, err)
	}
}
