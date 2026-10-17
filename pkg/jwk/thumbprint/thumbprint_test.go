package thumbprint

import (
	"crypto"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
)

func TestGenerate_EC(t *testing.T) {
	value := jwk.Key{
		jwk.KeyType: "EC",
		jwk.Curve:   "P-256",
		jwk.X:       "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		jwk.Y:       "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	}

	// {"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}

	thumbprint, err := Generate(value, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	thumbprintString := base64url.Encode(thumbprint)

	if thumbprintString != "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s" {
		t.Fatalf("thumbprintString = %q, want %q", thumbprintString, "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s")
	}
}

func TestGenerate_RSA(t *testing.T) {
	value := jwk.Key{
		jwk.KeyType:   "RSA",
		jwk.N:         "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		jwk.E:         "AQAB",
		jwk.Algorithm: jwa.RS256,
		jwk.KeyID:     "2011-04-29",
	}

	// {"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}

	thumbprint, err := Generate(value, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	thumbprintString := base64url.Encode(thumbprint)

	if thumbprintString != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprintString = %q, want %q", thumbprintString, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
	}
}

// RFC 9278 §3 names the RFC 7638 example key with this URI.
//
// https://www.rfc-editor.org/rfc/rfc9278.html#section-3
func TestURN(t *testing.T) {
	key, err := jwk.PublicKey(jwk.Key{
		jwk.KeyType: "RSA",
		jwk.N:       "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		jwk.E:       "AQAB",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := URN(key)
	if err != nil {
		t.Fatal(err)
	}
	if want := "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Fatalf("URN() = %q, want %q", got, want)
	}
}
