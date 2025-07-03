package jwk

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/base64"
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

func TestValueEd25519(t *testing.T) {
	input := `
	{
		"kty":"OKP",
		"crv":"Ed25519",
		"x":"3pP2u1u8vI1qT5Z0Xq5bZ7MfCqE8pYzX1VXU5Y7w8XU",
		"use":"sig",
		"kid":"test"
	}`

	value := Value{}
	err := json.NewDecoder(strings.NewReader(input)).Decode(&value)
	require.NoError(t, err)

	x, err := Ed25519Values(value)
	require.NoError(t, err)
	require.NotEmpty(t, x)
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
	ctx, httpClient := createTestHTTPContext(t, 5*time.Second)

	// https://accounts.google.com/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/certs", nil)
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
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
	ctx, httpClient := createTestHTTPContext(t, 5*time.Second)

	// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://login.microsoftonline.com/common/discovery/v2.0/keys", nil)
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
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
	ctx, httpClient := createTestHTTPContext(t, 5*time.Second)

	// https://token.actions.githubusercontent.com/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://token.actions.githubusercontent.com/.well-known/jwks", nil)
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	set := Set{}
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

	firstKeyID := set.Keys[0][KeyID].(string)

	firstKey, err := cache.GetKey(ctx, ghaJWKsURL, firstKeyID)
	require.NoError(t, err)
	require.NotEmpty(t, firstKey)
}

func TestErrorMessages(t *testing.T) {
	t.Run("ECDSAValues with non-EC key type", func(t *testing.T) {
		value := Value{
			KeyType: "RSA",
		}
		_, _, _, err := ECDSAValues(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK value is not EC")
	})

	t.Run("RSAValues with non-RSA key type", func(t *testing.T) {
		value := Value{
			KeyType: "EC",
		}
		_, _, _, err := RSAValues(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWK value is not RSA")
	})

	t.Run("SymmetricKey with no key value", func(t *testing.T) {
		value := Value{
			K: "",
		}
		_, err := SymmetricKey(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no symmetric key value set")
	})

	t.Run("Set.Get with non-existent key", func(t *testing.T) {
		set := &Set{
			Keys: []Value{
				{
					KeyID: "key1",
				},
			},
		}
		_, err := set.Get("nonexistent")
		require.Error(t, err)
		require.Contains(t, err.Error(), "key \"nonexistent\" not found in set")
	})

	t.Run("RSAPublicKey with large exponent", func(t *testing.T) {
		input := `{
                       "kty":"RSA",
                       "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                       "e":"AQAAAAAAAAAA",
                       "alg":"RS256",
                       "kid":"large-exp"
               }`

		value := Value{}
		err := json.NewDecoder(strings.NewReader(input)).Decode(&value)
		require.NoError(t, err)

		_, _, err = RSAPublicKey(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exponent")
	})
}

func TestValidate(t *testing.T) {
	t.Run("valid EC key with P-256 curve", func(t *testing.T) {
		value := Value{
			KeyType: "EC",
			Curve:   "P-256",
			X:       "dGVzdA", // base64 encoded "test"
			Y:       "dGVzdA", // base64 encoded "test"
		}
		err := Validate(value)
		require.NoError(t, err)
	})

	t.Run("invalid EC key with unsupported curve", func(t *testing.T) {
		value := Value{
			KeyType: "EC",
			Curve:   "secp256k1", // unsupported curve
			X:       "dGVzdA",
			Y:       "dGVzdA",
		}
		err := Validate(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid curve")
	})
}

// TestRSAModulusSizeValidation ensures RSAPublicKey enforces a minimum
// modulus size of 2048 bits, rejecting smaller RSA moduli.
func TestRSAModulusSizeValidation(t *testing.T) {
	const validInput = `{
               "kty":"RSA",
               "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
               "e":"AQAB",
               "alg":"RS256",
               "kid":"2011-04-29"
       }`

	t.Run("valid modulus", func(t *testing.T) {
		var value Value
		err := json.NewDecoder(strings.NewReader(validInput)).Decode(&value)
		require.NoError(t, err)

		pkey, _, err := RSAPublicKey(value)
		require.NoError(t, err)
		require.Equal(t, 2048, pkey.N.BitLen())
	})

	t.Run("modulus too small", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)

		nEnc, err := base64.Encode(key.N.Bytes())
		require.NoError(t, err)

		input := fmt.Sprintf(`{"kty":"RSA","n":"%s","e":"AQAB"}`, nEnc)
		var value Value
		err = json.NewDecoder(strings.NewReader(input)).Decode(&value)
		require.NoError(t, err)

		_, _, err = RSAPublicKey(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "modulus too small")
	})
}

// TestRSAPublicKeyExponentValidation exercises RSAPublicKey with a variety of
// exponent values, ensuring that invalid exponents are rejected and valid ones
// are accepted.
func TestRSAPublicKeyExponentValidation(t *testing.T) {
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

	encodeInt := func(i *big.Int) string {
		b := i.Bytes()
		if len(b) == 0 {
			b = []byte{0}
		}
		s, err := base64.Encode(b)
		require.NoError(t, err, "failed to encode integer to base64")
		return s
	}

	tests := []struct {
		name    string
		exp     *big.Int
		wantErr bool
	}{
		{"zero", big.NewInt(0), true},
		{"one", big.NewInt(1), true},
		{"typical", big.NewInt(65537), false},
		{"max-int32", big.NewInt(math.MaxInt32), false},
		{"overflow", new(big.Int).Add(big.NewInt(math.MaxInt32), big.NewInt(1)), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eEnc := encodeInt(tc.exp)
			input := fmt.Sprintf(`{"kty":"RSA","n":"%s","e":"%s"}`, n, eEnc)
			var value Value
			err := json.NewDecoder(strings.NewReader(input)).Decode(&value)
			require.NoError(t, err)

			_, _, err = RSAPublicKey(value)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
