package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
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
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(value) == 0 {
		t.Fatal("value is empty")
	}

	if value[KeyType] != "EC" {
		t.Fatalf("value[KeyType] = %q, want %q", value[KeyType], "EC")
	}
	if value[Curve] != "P-256" {
		t.Fatalf("value[Curve] = %q, want %q", value[Curve], "P-256")
	}
	if value[X] != "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU" {
		t.Fatalf("value[X] = %q, want %q", value[X], "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
	}
	if value[Y] != "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" {
		t.Fatalf("value[Y] = %q, want %q", value[Y], "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
	}
	if value[KeyID] != "Public key used in JWS spec Appendix A.3 example" {
		t.Fatalf("value[KeyID] = %q, want %q", value[KeyID], "Public key used in JWS spec Appendix A.3 example")
	}
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
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(value) == 0 {
		t.Fatal("value is empty")
	}
	if value[KeyID] != "2011-04-29" {
		t.Fatalf("value[KeyID] = %q, want %q", value[KeyID], "2011-04-29")
	}

	public, err := PublicKey(value)
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	pkey, ok := public.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public type = %T, want *rsa.PublicKey", public)
	}
	if pkey.N == nil {
		t.Fatal("pkey.N = nil, want non-nil")
	}
	if pkey.E != 65537 {
		t.Fatalf("pkey.E = %v, want %v", pkey.E, 65537)
	}
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
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	x, err := Ed25519Values(value)
	if err != nil {
		t.Fatalf("Ed25519Values() error = %v", err)
	}
	if len(x) == 0 {
		t.Fatal("x is empty")
	}
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
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if set.Keys == nil {
		t.Fatal("decoded Set is empty")
	}

	if len(set.Keys) == 0 {
		t.Fatal("len(set.Keys) = 0, want non-zero")
	}
	for _, key := range set.Keys {
		if key[KeyType] == nil || key[KeyType] == "" {
			t.Fatal("key[KeyType] is empty")
		}

		if key[KeyType] == "oct" {
			k, err := SymmetricKey(key)
			if err != nil {
				t.Fatalf("SymmetricKey() error = %v", err)
			}
			if len(k) == 0 {
				t.Fatal("k is empty")
			}

			sk, err := HMACSecretKey(key)
			if err != nil {
				t.Fatalf("HMACSecretKey() error = %v", err)
			}
			if len(sk) == 0 {
				t.Fatal("sk is empty")
			}
		}

		if key[KeyType] == "EC" {
			crv, x, y, err := ECDSAValues(key)
			if err != nil {
				t.Fatalf("ECDSAValues() error = %v", err)
			}
			if len(crv) == 0 {
				t.Fatal("crv is empty")
			}
			if len(x) == 0 {
				t.Fatal("x is empty")
			}
			if len(y) == 0 {
				t.Fatal("y is empty")
			}

			public, err := PublicKey(key)
			if err != nil {
				t.Fatalf("PublicKey() error = %v", err)
			}
			pkey, ok := public.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("public type = %T, want *ecdsa.PublicKey", public)
			}
			if pkey.X == nil {
				t.Fatal("pkey.X = nil, want non-nil")
			}
			if pkey.Y == nil {
				t.Fatal("pkey.Y = nil, want non-nil")
			}
			if pkey.Curve != elliptic.P256() {
				t.Fatalf("pkey.Curve = %v, want P-256", pkey.Curve.Params().Name)
			}
		}
	}
}

func TestErrorMessages(t *testing.T) {
	t.Run("ECDSAValues with non-EC key type", func(t *testing.T) {
		value := Value{
			KeyType: "RSA",
		}
		_, _, _, err := ECDSAValues(value)
		if err == nil || !strings.Contains(err.Error(), "JWK value is not EC") {
			t.Fatalf("ECDSAValues() error = %v, want error containing %q", err, "JWK value is not EC")
		}
	})

	t.Run("RSAValues with non-RSA key type", func(t *testing.T) {
		value := Value{
			KeyType: "EC",
		}
		_, _, _, err := RSAValues(value)
		if err == nil || !strings.Contains(err.Error(), "JWK value is not RSA") {
			t.Fatalf("RSAValues() error = %v, want error containing %q", err, "JWK value is not RSA")
		}
	})

	t.Run("SymmetricKey with no key value", func(t *testing.T) {
		value := Value{
			K: "",
		}
		_, err := SymmetricKey(value)
		if err == nil || !strings.Contains(err.Error(), "no symmetric key value set") {
			t.Fatalf("SymmetricKey() error = %v, want error containing %q", err, "no symmetric key value set")
		}
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
		if err == nil || !strings.Contains(err.Error(), "key \"nonexistent\" not found in set") {
			t.Fatalf("set.Get() error = %v, want error containing %q", err, "key \"nonexistent\" not found in set")
		}
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
		if err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("invalid EC key with unsupported curve", func(t *testing.T) {
		value := Value{
			KeyType: "EC",
			Curve:   "secp256k1", // unsupported curve
			X:       "dGVzdA",
			Y:       "dGVzdA",
		}
		err := Validate(value)
		if err == nil || !strings.Contains(err.Error(), "invalid curve") {
			t.Fatalf("Validate() error = %v, want error containing %q", err, "invalid curve")
		}
	})
}
