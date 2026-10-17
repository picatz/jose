package thumbprint_test

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
)

var seeds = []string{
	`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`,
	`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
	`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`,
	`{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`,
}

// FuzzGenerate checks that Generate never panics, is deterministic, ignores
// members outside the required set, and yields a full-length digest.
func FuzzGenerate(f *testing.F) {
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var key jwk.Key
		if json.Unmarshal(data, &key) != nil {
			return
		}
		sum, err := thumbprint.Generate(key, crypto.SHA256)
		if err != nil {
			return
		}
		if len(sum) != 32 {
			t.Fatalf("len(sum) = %d, want 32", len(sum))
		}
		again, err := thumbprint.Generate(key, 0)
		if err != nil || string(again) != string(sum) {
			t.Fatalf("zero hash differs from SHA-256: %v", err)
		}
		extended := jwk.Key{"kid": "x", "use": "sig", "d": "AAAA"}
		for name, v := range key {
			extended[name] = v
		}
		extended["kid"], extended["use"] = "x", "sig"
		if other, err := thumbprint.Generate(extended, crypto.SHA256); err != nil || string(other) != string(sum) {
			t.Fatalf("optional members changed the thumbprint: %v", err)
		}
	})
}

// FuzzFromPublicKey checks that FromPublicKey never panics on any key a JWK
// can describe, and agrees with the thumbprint of the key's canonical JWK.
func FuzzFromPublicKey(f *testing.F) {
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var key jwk.Key
		if json.Unmarshal(data, &key) != nil {
			return
		}
		public, err := jwk.PublicKey(key)
		if err != nil {
			return
		}
		got, err := thumbprint.FromPublicKey(public)
		if err != nil {
			t.Fatalf("FromPublicKey(%T) error = %v", public, err)
		}
		canonical, err := jwk.PublicValue(public)
		if err != nil {
			t.Fatal(err)
		}
		want, err := thumbprint.GenerateString(canonical, crypto.SHA256)
		if err != nil || got != want {
			t.Fatalf("FromPublicKey = %q, canonical thumbprint = %q, %v", got, want, err)
		}
		urn, err := thumbprint.URN(public)
		if err != nil || urn != thumbprint.URNPrefix+got {
			t.Fatalf("URN = %q, %v", urn, err)
		}
	})
}
