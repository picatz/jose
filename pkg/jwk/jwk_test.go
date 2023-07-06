package jwk

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValueECDSA(t *testing.T) {
	input := `
	{
		"kty":"EC",
		"crv":"P-256",
		"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		"kid":"Public key used in JWS spec Appendix A.3 example"
   	}`

	value := Value{}
	err := json.NewDecoder(strings.NewReader(input)).Decode(&value)
	require.NoError(t, err)
	require.NotEmpty(t, value)

	require.Equal(t, "EC", value[KeyType])
	require.Equal(t, "P-256", value[Curve])
	require.Equal(t, "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", value[X])
	require.Equal(t, "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", value[Y])
	require.Equal(t, "Public key used in JWS spec Appendix A.3 example", value[KeyID])
}

func TestValueRSA(t *testing.T) {
	input := `
		{
			"kty":"RSA",
			"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			"e":"AQAB",
			"alg":"RS256",
			"kid":"2011-04-29"
		}`

	value := Value{}
	err := json.NewDecoder(strings.NewReader(input)).Decode(&value)
	require.NoError(t, err)
	require.NotEmpty(t, value)
	require.Equal(t, "2011-04-29", value[KeyID])

	pkey, blindingValue, err := RSAPublicKey(value)
	require.NoError(t, err)
	require.Nil(t, blindingValue)
	require.NotNil(t, pkey)
	require.NotNil(t, pkey.N)
	require.Equal(t, 65537, pkey.E)
}

func TestSet(t *testing.T) {
	input := `
	{
		"keys":[
			{
				"kty":"oct",
				"alg":"A128KW",
				"k":"GawgguFyGrWKav7AX4VKUg"
			},
			{
				"kty":"oct",
				"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
				"kid":"HMAC key used in JWS spec Appendix A.1 example"
			},
			{
				"kty":"EC",
				"crv":"P-256",
				"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
				"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
				"use":"enc",
				"kid":"1"
			}
		]
	}`

	set := Set{}
	err := json.NewDecoder(strings.NewReader(input)).Decode(&set)
	require.NoError(t, err)
	require.NotEmpty(t, set)

	require.NotZero(t, len(set.Keys))
	for _, key := range set.Keys {
		require.NotEmpty(t, key[KeyType])

		if key[KeyType] == "oct" {
			k, err := SymmetricKey(key)
			require.NoError(t, err)
			require.NotEmpty(t, k)

			sk, err := HMACSecretKey(key)
			require.NoError(t, err)
			require.NotEmpty(t, sk)
		}

		if key[KeyType] == "EC" {
			crv, x, y, err := ECDSAValues(key)
			require.NoError(t, err)
			require.NotEmpty(t, crv)
			require.NotEmpty(t, x)
			require.NotEmpty(t, y)

			pkey, _, err := ECDSAPublicKey(key)
			require.NoError(t, err)
			require.NotNil(t, pkey)
			require.NotNil(t, pkey.X)
			require.NotNil(t, pkey.Y)
			require.Equal(t, pkey.Curve, elliptic.P256())
		}
	}
}

func TestGoogleWellKnownCertsV3(t *testing.T) {
	timeout := 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   timeout,
	}

	// https://accounts.google.com/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/certs", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	set := Set{}
	err = json.NewDecoder(resp.Body).Decode(&set)
	require.NoError(t, err)
	require.NotEmpty(t, set)
	require.NotZero(t, len(set.Keys))
	for _, key := range set.Keys {
		require.NotEmpty(t, key[KeyType])
		require.NotEmpty(t, key[KeyID])
		require.NotEmpty(t, key[PublicKeyUse])

		if key[KeyType] == "RSA" {
			n, e, _, err := RSAValues(key)
			require.NoError(t, err)
			require.NotEmpty(t, n)
			require.NotEmpty(t, e)
			// d is optional, used for RSA key blinding https://datatracker.ietf.org/doc/html/rfc7517#ref-Kocher

			pkey, _, err := RSAPublicKey(key)
			require.NoError(t, err)
			require.NotNil(t, pkey)
			require.NotNil(t, pkey.E)
			require.NotNil(t, pkey.N)
			require.NotZero(t, pkey.Size())
		}
	}
}

func TestMicrosoftLoginWellKnownKeys(t *testing.T) {
	timeout := 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   timeout,
	}

	// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://login.microsoftonline.com/common/discovery/v2.0/keys", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	set := Set{}
	err = json.NewDecoder(resp.Body).Decode(&set)
	require.NoError(t, err)
	require.NotEmpty(t, set)
	require.NotZero(t, len(set.Keys))
	for _, key := range set.Keys {
		require.NotEmpty(t, key[KeyType])
		require.NotEmpty(t, key[KeyID])
		require.NotEmpty(t, key[PublicKeyUse])

		if key[KeyType] == "RSA" {
			n, e, _, err := RSAValues(key)
			require.NoError(t, err)
			require.NotEmpty(t, n)
			require.NotEmpty(t, e)
			// d is optional, used for RSA key blinding https://datatracker.ietf.org/doc/html/rfc7517#ref-Kocher

			pkey, _, err := RSAPublicKey(key)
			require.NoError(t, err)
			require.NotNil(t, pkey)
			require.NotNil(t, pkey.E)
			require.NotNil(t, pkey.N)
			require.NotZero(t, pkey.Size())
		}
	}
}

func TestGitHubActionsWellKnownKeys(t *testing.T) {
	timeout := 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   timeout,
	}

	// https://token.actions.githubusercontent.com/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://token.actions.githubusercontent.com/.well-known/jwks", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	set := Set{}
	err = json.NewDecoder(resp.Body).Decode(&set)
	require.NoError(t, err)
	require.NotEmpty(t, set.Keys)
}
