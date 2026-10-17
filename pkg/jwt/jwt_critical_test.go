package jwt_test

import (
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/keyutil"
)

// TestCriticalHeaderValidation tests RFC 7515 section 4.1.11 critical header
// validation through the Verifier: a "crit" it does not list in
// [jwt.Verifier.Critical], or that is malformed, is refused before any
// signature is checked.
func TestCriticalHeaderValidation(t *testing.T) {
	keys := testNewKeyPair(t, keyutil.NewECDSAKeyPair)
	claims := jwt.ClaimsSet{jwt.Subject: "test"}

	// signed returns a validly signed token with extra header parameters.
	signed := func(t *testing.T, extra jws.Header) string {
		t.Helper()
		h := jws.Header{header.Type: jwt.Type, header.Algorithm: jwa.ES256}
		for name, value := range extra {
			h[name] = value
		}
		return sign(t, h, claims, keys.private)
	}
	// forged is the same shape with a signature nobody checked: if the
	// refusal is ErrFormat, it came before signature verification.
	forged := func(t *testing.T, extra map[string]any) string {
		t.Helper()
		h := map[string]any{"typ": "JWT", "alg": "ES256"}
		for name, value := range extra {
			h[name] = value
		}
		return rawToken(t, h, claims, []byte("signature"))
	}
	verifier := func(critical ...string) *jwt.Verifier {
		v := sigOnlyVerifier(keys.public, jwa.ES256)
		v.Critical = critical
		return v
	}

	t.Run("No Critical Header", func(t *testing.T) {
		if err := verifyToken(verifier(), signed(t, nil)); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("Valid Critical Header", func(t *testing.T) {
		token := signed(t, jws.Header{
			header.Critical: []any{"custom-ext", "another-ext"},
			"custom-ext":    "some-value",
			"another-ext":   "another-value",
		})
		if err := verifyToken(verifier("custom-ext", "another-ext"), token); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		// Understood extensions are the caller's to check: not listing one
		// refuses the token, however valid its signature.
		requireRefused(t, verifier("custom-ext"), token, jwt.ErrFormat)
		requireRefused(t, verifier(), token, jwt.ErrFormat)
	})

	t.Run("Unsupported Critical Header", func(t *testing.T) {
		token := signed(t, jws.Header{
			header.Critical:   []any{"unsupported-ext"},
			"unsupported-ext": "some-value",
		})
		requireRefused(t, verifier("custom-ext"), token, jwt.ErrFormat)
	})

	t.Run("Critical Header Not Present", func(t *testing.T) {
		// "crit" names a parameter the header does not carry.
		token := forged(t, map[string]any{"crit": []any{"missing-ext"}})
		requireRefused(t, verifier("missing-ext"), token, jwt.ErrFormat)
	})

	t.Run("Empty Critical Header Array", func(t *testing.T) {
		// RFC 7515 section 4.1.11: The "crit" header parameter MUST NOT be empty
		token := forged(t, map[string]any{"crit": []any{}})
		requireRefused(t, verifier(), token, jwt.ErrFormat)
	})

	t.Run("Critical Header Wrong Type", func(t *testing.T) {
		token := forged(t, map[string]any{"crit": "not-an-array"})
		requireRefused(t, verifier(), token, jwt.ErrFormat)
	})

	t.Run("Critical Header Non-String Elements", func(t *testing.T) {
		token := forged(t, map[string]any{"crit": []any{"valid-ext", 123}, "valid-ext": "some-value"})
		requireRefused(t, verifier("valid-ext"), token, jwt.ErrFormat)
	})

	t.Run("Standard Header in Critical List", func(t *testing.T) {
		// RFC 7515 section 4.1.11: Standard headers cannot be marked as critical
		token := forged(t, map[string]any{"crit": []any{"alg"}})
		requireRefused(t, verifier("alg"), token, jwt.ErrFormat)
	})

	t.Run("Multiple Standard Headers in Critical List", func(t *testing.T) {
		standardHeaders := []string{"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"}

		for _, stdHeader := range standardHeaders {
			t.Run("Standard_"+stdHeader, func(t *testing.T) {
				token := forged(t, map[string]any{"crit": []any{stdHeader}})
				requireRefused(t, verifier(stdHeader), token, jwt.ErrFormat)
			})
		}
	})

	t.Run("Complex Valid Critical Header Scenario", func(t *testing.T) {
		token := signed(t, jws.Header{
			header.Critical:    []any{"custom-auth", "rate-limit", "version"},
			"custom-auth":      "bearer-extended",
			"rate-limit":       "100/minute",
			"version":          "v2.0",
			"non-critical-ext": "this-is-ok", // Non-critical extension
		})
		if err := verifyToken(verifier("custom-auth", "rate-limit", "version", "other-ext"), token); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})
}
