package jws_test

import (
	"strings"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
)

// The RFC 7797 §4 examples sign the payload "$.02" with the HMAC key from
// RFC 7515 Appendix A.1.
const (
	rfc7797Key     = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
	rfc7797Payload = "$.02"
	// https://www.rfc-editor.org/rfc/rfc7797#section-4.1
	rfc7797Encoded = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ"
	// https://www.rfc-editor.org/rfc/rfc7797#section-4.2
	rfc7797Unencoded = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
)

func rfc7797HMACKey(t *testing.T) []byte {
	t.Helper()
	key, err := base64url.Decode(rfc7797Key)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDetachedEncodedPayload(t *testing.T) {
	key := rfc7797HMACKey(t)

	attached, err := jws.Parse(rfc7797Encoded)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	detached, err := attached.Detached()
	if err != nil {
		t.Fatalf("Detached() error = %v", err)
	}
	if want := "eyJhbGciOiJIUzI1NiJ9..5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ"; detached != want {
		t.Fatalf("Detached() = %q, want %q", detached, want)
	}

	parsed, err := jws.ParseDetached(detached, []byte(rfc7797Payload))
	if err != nil {
		t.Fatalf("ParseDetached() error = %v", err)
	}
	if err := parsed.Verify(key); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	tampered, err := jws.ParseDetached(detached, []byte("$.03"))
	if err != nil {
		t.Fatalf("ParseDetached() error = %v", err)
	}
	if err := tampered.Verify(key); err == nil {
		t.Fatal("Verify() accepted a different detached payload")
	}
}

func TestDetachedUnencodedPayload(t *testing.T) {
	key := rfc7797HMACKey(t)

	parsed, err := jws.ParseDetached(rfc7797Unencoded, []byte(rfc7797Payload))
	if err != nil {
		t.Fatalf("ParseDetached() error = %v", err)
	}
	if err := parsed.Verify(key); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got := parsed.String(); got != rfc7797Unencoded {
		t.Fatalf("String() = %q, want the detached form %q", got, rfc7797Unencoded)
	}

	tampered, err := jws.ParseDetached(rfc7797Unencoded, []byte("$.03"))
	if err != nil {
		t.Fatalf("ParseDetached() error = %v", err)
	}
	if err := tampered.Verify(key); err == nil {
		t.Fatal("Verify() accepted a different unencoded payload")
	}

	// Signing from scratch reproduces the RFC example byte for byte.
	signed, err := jws.New(jws.Header{
		header.Algorithm:              jwa.HS256,
		header.Base64URLEncodePayload: false,
		header.Critical:               []string{header.Base64URLEncodePayload},
	}, []byte(rfc7797Payload), key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got, err := signed.Detached()
	if err != nil {
		t.Fatalf("Detached() error = %v", err)
	}
	if got != rfc7797Unencoded {
		t.Fatalf("Detached() = %q, want %q", got, rfc7797Unencoded)
	}
}

func TestUnencodedPayloadRefusals(t *testing.T) {
	encode := func(t *testing.T, h string) string {
		t.Helper()
		s := base64url.Encode([]byte(h))
		return s
	}
	const sig = "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"

	t.Run("Parse needs the opt-in", func(t *testing.T) {
		h := encode(t, `{"alg":"HS256","b64":false,"crit":["b64"]}`)
		if _, err := jws.Parse(h + ".JC4wMg." + sig); err == nil || !strings.Contains(err.Error(), "ParseDetached") {
			t.Fatalf("Parse() error = %v, want a pointer to ParseDetached", err)
		}
	})

	for name, h := range map[string]string{
		"b64 not in crit": `{"alg":"HS256","b64":false}`,
		"b64 not boolean": `{"alg":"HS256","b64":"false","crit":["b64"]}`,
		"unknown crit":    `{"alg":"HS256","b64":false,"crit":["b64","exp-ext"],"exp-ext":1}`,
		"no alg":          `{"b64":false,"crit":["b64"]}`,
		"invalid UTF-8":   "{\"alg\":\"HS256\",\"b64\":false,\"crit\":[\"b64\"],\"x\":\"\xff\"}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := jws.ParseDetached(encode(t, h)+".."+sig, []byte(rfc7797Payload)); err == nil {
				t.Fatalf("ParseDetached(%s) succeeded", h)
			}
		})
	}

	t.Run("b64 needs crit when signing", func(t *testing.T) {
		_, err := jws.New(jws.Header{
			header.Algorithm:              jwa.HS256,
			header.Base64URLEncodePayload: false,
		}, []byte(rfc7797Payload), rfc7797HMACKey(t))
		if err == nil {
			t.Fatal("New() signed b64 false without crit")
		}
	})

	t.Run("unsecured", func(t *testing.T) {
		h := encode(t, `{"alg":"none","b64":false,"crit":["b64"]}`)
		if _, err := jws.ParseDetached(h+"..", []byte(rfc7797Payload)); err == nil {
			t.Fatal("ParseDetached() accepted an unsigned unencoded JWS")
		}
	})

	for name, input := range map[string]string{
		"attached":       rfc7797Encoded,
		"no header":      ".." + sig,
		"no signature":   "eyJhbGciOiJIUzI1NiJ9..",
		"extra segments": "eyJhbGciOiJIUzI1NiJ9..a.b",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := jws.ParseDetached(input, []byte(rfc7797Payload)); err == nil {
				t.Fatalf("ParseDetached(%q) succeeded", input)
			}
		})
	}
}
