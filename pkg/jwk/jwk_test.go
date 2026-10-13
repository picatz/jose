package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

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

	public, err := PublicKey(value)
	require.NoError(t, err)
	pkey, ok := public.(*rsa.PublicKey)
	require.True(t, ok)
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

			public, err := PublicKey(key)
			require.NoError(t, err)
			pkey, ok := public.(*ecdsa.PublicKey)
			require.True(t, ok)
			require.NotNil(t, pkey.X)
			require.NotNil(t, pkey.Y)
			require.Equal(t, pkey.Curve, elliptic.P256())
		}
	}
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
