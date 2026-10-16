package jwkhttp

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/jwk"
)

// createTestHTTPContext creates a context and HTTP client for testing external
// JWK endpoints. These tests reach the internet, so they are skipped under
// go test -short.
func createTestHTTPContext(t *testing.T, timeout time.Duration) (context.Context, *http.Client) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping test that fetches a public JWK Set in -short mode")
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   timeout,
	}
	t.Cleanup(cancel)
	return ctx, client
}

func TestGoogleWellKnownCertsV3(t *testing.T) {
	ctx, httpClient := createTestHTTPContext(t, 5*time.Second)

	// https://accounts.google.com/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/certs", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("httpClient.Do() error = %v", err)
	}

	set := jwk.Set{}
	err = json.NewDecoder(resp.Body).Decode(&set)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if set.Keys == nil {
		t.Fatal("decoded jwk.Set is empty")
	}
	if len(set.Keys) == 0 {
		t.Fatal("len(set.Keys) = 0, want non-zero")
	}
	for _, key := range set.Keys {
		if key[jwk.KeyType] == nil || key[jwk.KeyType] == "" {
			t.Fatal("key[jwk.KeyType] is empty")
		}
		if key[jwk.KeyID] == nil || key[jwk.KeyID] == "" {
			t.Fatal("key[jwk.KeyID] is empty")
		}
		if key[jwk.PublicKeyUse] == nil || key[jwk.PublicKeyUse] == "" {
			t.Fatal("key[jwk.PublicKeyUse] is empty")
		}

		if key[jwk.KeyType] == "RSA" {
			n, e, _, err := jwk.RSAValues(key)
			if err != nil {
				t.Fatalf("jwk.RSAValues() error = %v", err)
			}
			if len(n) == 0 {
				t.Fatal("n is empty")
			}
			if len(e) == 0 {
				t.Fatal("e is empty")
			}
			// d is optional, used for RSA key blinding https://datatracker.ietf.org/doc/html/rfc7517#ref-Kocher

			public, err := jwk.PublicKey(key)
			if err != nil {
				t.Fatalf("jwk.PublicKey() error = %v", err)
			}
			pkey, ok := public.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("public type = %T, want *rsa.PublicKey", public)
			}
			if pkey.N == nil {
				t.Fatal("pkey.N = nil, want non-nil")
			}
			if pkey.Size() == 0 {
				t.Fatal("pkey.Size() = 0, want non-zero")
			}
		}
	}
}

func TestMicrosoftLoginWellKnownKeys(t *testing.T) {
	ctx, httpClient := createTestHTTPContext(t, 5*time.Second)

	// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://login.microsoftonline.com/common/discovery/v2.0/keys", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("httpClient.Do() error = %v", err)
	}

	set := jwk.Set{}
	err = json.NewDecoder(resp.Body).Decode(&set)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if set.Keys == nil {
		t.Fatal("decoded jwk.Set is empty")
	}
	if len(set.Keys) == 0 {
		t.Fatal("len(set.Keys) = 0, want non-zero")
	}
	for _, key := range set.Keys {
		if key[jwk.KeyType] == nil || key[jwk.KeyType] == "" {
			t.Fatal("key[jwk.KeyType] is empty")
		}
		if key[jwk.KeyID] == nil || key[jwk.KeyID] == "" {
			t.Fatal("key[jwk.KeyID] is empty")
		}
		if key[jwk.PublicKeyUse] == nil || key[jwk.PublicKeyUse] == "" {
			t.Fatal("key[jwk.PublicKeyUse] is empty")
		}

		if key[jwk.KeyType] == "RSA" {
			n, e, _, err := jwk.RSAValues(key)
			if err != nil {
				t.Fatalf("jwk.RSAValues() error = %v", err)
			}
			if len(n) == 0 {
				t.Fatal("n is empty")
			}
			if len(e) == 0 {
				t.Fatal("e is empty")
			}
			// d is optional, used for RSA key blinding https://datatracker.ietf.org/doc/html/rfc7517#ref-Kocher

			public, err := jwk.PublicKey(key)
			if err != nil {
				t.Fatalf("jwk.PublicKey() error = %v", err)
			}
			pkey, ok := public.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("public type = %T, want *rsa.PublicKey", public)
			}
			if pkey.N == nil {
				t.Fatal("pkey.N = nil, want non-nil")
			}
			if pkey.Size() == 0 {
				t.Fatal("pkey.Size() = 0, want non-zero")
			}
		}
	}
}

func TestGitHubActionsWellKnownKeys(t *testing.T) {
	ctx, httpClient := createTestHTTPContext(t, 5*time.Second)

	// https://token.actions.githubusercontent.com/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://token.actions.githubusercontent.com/.well-known/jwks", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("httpClient.Do() error = %v", err)
	}

	set := jwk.Set{}
	err = json.NewDecoder(resp.Body).Decode(&set)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(set.Keys) == 0 {
		t.Fatal("set.Keys is empty")
	}
}

func TestURLSetCache(t *testing.T) {
	const body = `{"keys":[{"kty":"oct","kid":"k1","k":"c2VjcmV0LWtleS1vZi1hdC1sZWFzdC0zMi1ieXRlcyE"}]}`
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	cache := NewURLSetCache(srv.Client(), 24*time.Hour, 6*time.Hour)

	set, err := cache.Get(ctx, srv.URL)
	if err != nil {
		t.Fatalf("cache.Get() error = %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("len(set.Keys) = %d, want 1", len(set.Keys))
	}

	key, err := cache.GetKey(ctx, srv.URL, "k1")
	if err != nil {
		t.Fatalf("cache.GetKey() error = %v", err)
	}
	if len(key) == 0 {
		t.Fatal("key is empty")
	}
	if hits != 1 {
		t.Fatalf("server hits = %d, want 1 (second lookup should come from the cache)", hits)
	}
}
