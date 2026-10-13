package jwkhttp

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/jwk"
)

// createTestHTTPContext creates a context and HTTP client for testing external JWK endpoints.
func createTestHTTPContext(t *testing.T, timeout time.Duration) (context.Context, *http.Client) {
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
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	cache := NewURLSetCache(http.DefaultClient, 24*time.Hour, 6*time.Hour)

	go func() {
		err := cache.Start(ctx)
		if err != nil {
			panic(err)
		}
	}()

	ghaJWKsURL := "https://token.actions.githubusercontent.com/.well-known/jwks"

	set, err := cache.Get(ctx, ghaJWKsURL)
	if err != nil {
		t.Fatalf("cache.Get() error = %v", err)
	}
	if len(set.Keys) == 0 {
		t.Fatal("set.Keys is empty")
	}

	firstKeyID := set.Keys[0][jwk.KeyID].(string)

	firstKey, err := cache.GetKey(ctx, ghaJWKsURL, firstKeyID)
	if err != nil {
		t.Fatalf("cache.GetKey() error = %v", err)
	}
	if len(firstKey) == 0 {
		t.Fatal("firstKey is empty")
	}
}
