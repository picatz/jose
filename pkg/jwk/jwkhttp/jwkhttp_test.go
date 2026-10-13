package jwkhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/jwk"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	set := jwk.Set{}
	err = json.NewDecoder(resp.Body).Decode(&set)
	require.NoError(t, err)
	require.NotEmpty(t, set)
	require.NotZero(t, len(set.Keys))
	for _, key := range set.Keys {
		require.NotEmpty(t, key[jwk.KeyType])
		require.NotEmpty(t, key[jwk.KeyID])
		require.NotEmpty(t, key[jwk.PublicKeyUse])

		if key[jwk.KeyType] == "RSA" {
			n, e, _, err := jwk.RSAValues(key)
			require.NoError(t, err)
			require.NotEmpty(t, n)
			require.NotEmpty(t, e)
			// d is optional, used for RSA key blinding https://datatracker.ietf.org/doc/html/rfc7517#ref-Kocher

			pkey, _, err := jwk.RSAPublicKey(key)
			require.NoError(t, err)
			require.NotNil(t, pkey)
			require.NotNil(t, pkey.E)
			require.NotNil(t, pkey.N)
			require.NotZero(t, pkey.Size())
		}
	}
}

func TestMicrosoftLoginWellKnownKeys(t *testing.T) {
	ctx, httpClient := createTestHTTPContext(t, 5*time.Second)

	// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://login.microsoftonline.com/common/discovery/v2.0/keys", nil)
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	set := jwk.Set{}
	err = json.NewDecoder(resp.Body).Decode(&set)
	require.NoError(t, err)
	require.NotEmpty(t, set)
	require.NotZero(t, len(set.Keys))
	for _, key := range set.Keys {
		require.NotEmpty(t, key[jwk.KeyType])
		require.NotEmpty(t, key[jwk.KeyID])
		require.NotEmpty(t, key[jwk.PublicKeyUse])

		if key[jwk.KeyType] == "RSA" {
			n, e, _, err := jwk.RSAValues(key)
			require.NoError(t, err)
			require.NotEmpty(t, n)
			require.NotEmpty(t, e)
			// d is optional, used for RSA key blinding https://datatracker.ietf.org/doc/html/rfc7517#ref-Kocher

			pkey, _, err := jwk.RSAPublicKey(key)
			require.NoError(t, err)
			require.NotNil(t, pkey)
			require.NotNil(t, pkey.E)
			require.NotNil(t, pkey.N)
			require.NotZero(t, pkey.Size())
		}
	}
}

func TestGitHubActionsWellKnownKeys(t *testing.T) {
	ctx, httpClient := createTestHTTPContext(t, 5*time.Second)

	// https://token.actions.githubusercontent.com/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://token.actions.githubusercontent.com/.well-known/jwks", nil)
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	set := jwk.Set{}
	err = json.NewDecoder(resp.Body).Decode(&set)
	require.NoError(t, err)
	require.NotEmpty(t, set.Keys)
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
	require.NoError(t, err)
	require.NotEmpty(t, set.Keys)

	firstKeyID := set.Keys[0][jwk.KeyID].(string)

	firstKey, err := cache.GetKey(ctx, ghaJWKsURL, firstKeyID)
	require.NoError(t, err)
	require.NotEmpty(t, firstKey)
}
