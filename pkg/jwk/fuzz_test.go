package jwk_test

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/picatz/jose/pkg/jwk"
)

// FuzzPublicKey checks that PublicKey never panics and that a key it
// accepts survives PublicValue and PublicKey again unchanged.
func FuzzPublicKey(f *testing.F) {
	for _, seed := range []string{
		`{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`,
		`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		`{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}`,
		`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`,
		`{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var value jwk.Value
		if json.Unmarshal(data, &value) != nil {
			return
		}
		key, err := jwk.PublicKey(value)
		if err != nil {
			return
		}
		again, err := jwk.PublicValue(key)
		if err != nil {
			t.Fatalf("PublicValue(%T) error = %v", key, err)
		}
		roundTrip, err := jwk.PublicKey(again)
		if err != nil {
			t.Fatalf("PublicKey(PublicValue()) error = %v", err)
		}
		if equal, ok := key.(interface{ Equal(crypto.PublicKey) bool }); ok && !equal.Equal(roundTrip) {
			t.Fatalf("round trip changed the %T key", key)
		}
	})
}
