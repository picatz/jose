package jwt_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
)

// rawToken assembles a compact token from arbitrary header, claims and
// signature bytes, with no validation, so tests can build tokens that no
// honest signer would produce.
func rawToken(t testing.TB, h, claims any, signature []byte) string {
	t.Helper()
	enc := func(v any) string {
		var b []byte
		switch v := v.(type) {
		case string:
			b = []byte(v)
		default:
			var err error
			if b, err = json.Marshal(v); err != nil {
				t.Fatal(err)
			}
		}
		return base64url.Encode(b)
	}
	sig := base64url.Encode(signature)
	return enc(h) + "." + enc(claims) + "." + sig
}

// requireRefused fails unless Verify refused token with ErrInvalidToken and
// the given sentinel, and returned no token.
func requireRefused(t testing.TB, v *jwt.Verifier, token string, sentinel error) {
	t.Helper()
	got, err := v.Verify(context.Background(), token)
	if err == nil {
		t.Fatalf("Verify() accepted token, want %v", sentinel)
	}
	if got != nil {
		t.Fatalf("Verify() returned token %v alongside error %v", got, err)
	}
	if !errors.Is(err, jwt.ErrInvalidToken) || !errors.Is(err, sentinel) {
		t.Fatalf("Verify() error = %v, want %v and %v", err, jwt.ErrInvalidToken, sentinel)
	}
}

// TestSecurityVulnerabilities tests various security vulnerabilities and attack vectors
func TestSecurityVulnerabilities(t *testing.T) {
	t.Run("Algorithm Confusion Attack", func(t *testing.T) {
		// An RSA public key must not be usable as an HMAC secret.
		rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)

		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
			jwt.ClaimsSet{jwt.Subject: "test"},
			rsaKeyPair.private,
		)

		// The verifier is told to expect HS256 and holds the RSA public key.
		requireRefused(t, sigOnlyVerifier(rsaKeyPair.public, jwa.HS256), token.String(), jwt.ErrFormat)

		// An attacker's HS256 token, MACed with the PEM-ish bytes of the
		// public key, is refused too: by default HMAC is not accepted at all.
		forged := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.HS256},
			jwt.ClaimsSet{jwt.Subject: "admin"},
			[]byte("0123456789abcdef0123456789abcdef"),
		)
		requireRefused(t, sigOnlyVerifier(rsaKeyPair.public), forged.String(), jwt.ErrFormat)

		// Even if HS256 is listed, an RSA key is not an HMAC secret.
		requireRefused(t, sigOnlyVerifier(rsaKeyPair.public, jwa.HS256), forged.String(), jwt.ErrSignature)
	})

	t.Run("Weak HMAC Key", func(t *testing.T) {
		// Test that weak HMAC keys are rejected
		weakKey := []byte("weak") // Only 4 bytes, much less than SHA256's 32 bytes

		_, err := jwt.New(
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.HS256},
			jwt.ClaimsSet{jwt.Subject: "test"},
			weakKey,
		)
		if err == nil || !strings.Contains(err.Error(), "HMAC key must be at least 32 bytes") {
			t.Fatalf("jwt.New() error = %v, want error containing %q", err, "HMAC key must be at least 32 bytes")
		}

		// A weak key held by the verifier cannot verify a token either.
		strong := []byte("0123456789abcdef0123456789abcdef")
		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.HS256},
			jwt.ClaimsSet{jwt.Subject: "test"}, strong)
		requireRefused(t, sigOnlyVerifier(weakKey, jwa.HS256), token.String(), jwt.ErrSignature)
	})

	t.Run("None Algorithm Security", func(t *testing.T) {
		// The Verifier never accepts "none", whatever the signature
		// segment holds and however the algorithm list is configured.
		h := header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.None}
		claims := jwt.ClaimsSet{jwt.Subject: "test"}
		rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)

		for name, token := range map[string]string{
			"empty signature":     rawToken(t, h, claims, nil),
			"non-empty signature": rawToken(t, h, claims, []byte("not-empty")),
		} {
			t.Run(name, func(t *testing.T) {
				requireRefused(t, sigOnlyVerifier(rsaKeyPair.public), token, jwt.ErrFormat)
				// Listing "none" explicitly changes nothing.
				requireRefused(t, sigOnlyVerifier(rsaKeyPair.public, jwa.None), token, jwt.ErrFormat)
				requireRefused(t, sigOnlyVerifier(rsaKeyPair.public, jwa.None, jwa.RS256), token, jwt.ErrFormat)
			})
		}

		// Case variants of the name are not "none" to a lenient parser.
		for _, alg := range []string{"None", "NONE", "nOnE"} {
			token := rawToken(t, map[string]any{"typ": "JWT", "alg": alg}, claims, nil)
			requireRefused(t, sigOnlyVerifier(rsaKeyPair.public), token, jwt.ErrFormat)
		}
	})

	t.Run("Missing Algorithm Header", func(t *testing.T) {
		token := rawToken(t, map[string]any{"typ": "JWT"}, jwt.ClaimsSet{jwt.Subject: "test"}, []byte("sig"))
		requireRefused(t, sigOnlyVerifier(testHMACSecretKey, jwa.HS256), token, jwt.ErrFormat)
	})

	t.Run("Empty Algorithm Header", func(t *testing.T) {
		token := rawToken(t, map[string]any{"typ": "JWT", "alg": ""}, jwt.ClaimsSet{jwt.Subject: "test"}, []byte("sig"))
		requireRefused(t, sigOnlyVerifier(testHMACSecretKey, jwa.HS256), token, jwt.ErrFormat)
	})
}

func TestTimingAttackResistance(t *testing.T) {
	t.Run("HMAC Key Iteration", func(t *testing.T) {
		// Several candidate keys: the one that matches verifies, and a set
		// with no match is refused with a signature error.
		key1 := make([]byte, 32)
		key2 := make([]byte, 32)
		key3 := make([]byte, 32)
		for i := range key1 {
			key1[i] = byte(i)
			key2[i] = byte(i + 1)
			key3[i] = byte(i + 2)
		}

		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.HS256},
			jwt.ClaimsSet{jwt.Subject: "test"},
			key2,
		)

		verifier := sigOnlyVerifier(nil, jwa.HS256)
		verifier.Keys = jwt.Keys{{Public: key1}, {Public: key2}, {Public: key3}}
		if err := verifyToken(verifier, token.String()); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}

		verifier.Keys = jwt.Keys{{Public: key1}, {Public: key3}}
		requireRefused(t, verifier, token.String(), jwt.ErrSignature)
	})
}

func TestClockSkewTolerance(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)
	now := time.Now()

	t.Run("Expiration with Leeway", func(t *testing.T) {
		// A token that expired 30 seconds ago.
		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
			jwt.ClaimsSet{jwt.Subject: "test", jwt.ExpirationTime: now.Add(-30 * time.Second).Unix()},
			rsaKeyPair.private,
		)

		verifier := sigOnlyVerifier(rsaKeyPair.public)
		verifier.Now = func() time.Time { return now }

		// Refused when the leeway is smaller than the age.
		verifier.Leeway = 10 * time.Second
		requireRefused(t, verifier, token.String(), jwt.ErrExpired)

		// Accepted with sufficient leeway.
		verifier.Leeway = time.Minute
		if err := verifyToken(verifier, token.String()); err != nil {
			t.Fatalf("Verify() with 1m leeway error = %v", err)
		}

		// The zero value is the 30s default, which has just run out.
		verifier.Leeway = 0
		requireRefused(t, verifier, token.String(), jwt.ErrExpired)
	})

	t.Run("NotBefore with Leeway", func(t *testing.T) {
		// A token that is not valid for another 45 seconds.
		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
			jwt.ClaimsSet{jwt.Subject: "test", jwt.NotBefore: now.Add(45 * time.Second).Unix()},
			rsaKeyPair.private,
		)

		verifier := sigOnlyVerifier(rsaKeyPair.public)
		verifier.Now = func() time.Time { return now }

		verifier.Leeway = 10 * time.Second
		requireRefused(t, verifier, token.String(), jwt.ErrNotYetValid)

		verifier.Leeway = time.Minute
		if err := verifyToken(verifier, token.String()); err != nil {
			t.Fatalf("Verify() with 1m leeway error = %v", err)
		}
	})
}

func TestInvalidSignatures(t *testing.T) {
	t.Run("Tampered Signature", func(t *testing.T) {
		rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)

		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
			jwt.ClaimsSet{jwt.Subject: "test"},
			rsaKeyPair.private,
		)

		// Flip all bits in the first byte of the signature.
		sig := append([]byte(nil), token.Signature...)
		sig[0] ^= 0xFF
		parts := strings.Split(token.String(), ".")
		sigB64 := base64url.Encode(sig)
		tampered := parts[0] + "." + parts[1] + "." + sigB64

		requireRefused(t, sigOnlyVerifier(rsaKeyPair.public), tampered, jwt.ErrSignature)
		// The untouched token still verifies.
		if err := verifyToken(sigOnlyVerifier(rsaKeyPair.public), token.String()); err != nil {
			t.Fatalf("Verify() of the original error = %v", err)
		}
	})

	t.Run("Tampered Claims", func(t *testing.T) {
		rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)

		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
			jwt.ClaimsSet{jwt.Subject: "test"},
			rsaKeyPair.private,
		)

		parts := strings.Split(token.String(), ".")
		claims := base64url.Encode([]byte(`{"sub":"admin"}`))
		requireRefused(t, sigOnlyVerifier(rsaKeyPair.public), parts[0]+"."+claims+"."+parts[2], jwt.ErrSignature)
	})

	t.Run("Wrong Key Type for Algorithm", func(t *testing.T) {
		rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)
		ecdsaKeyPair := testNewKeyPair(t, testNewECDSAKeyPair)

		rsaToken := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
			jwt.ClaimsSet{jwt.Subject: "test"},
			rsaKeyPair.private,
		)

		// An ECDSA key cannot verify an RSA signature.
		requireRefused(t, sigOnlyVerifier(ecdsaKeyPair.public), rsaToken.String(), jwt.ErrSignature)
	})

	t.Run("ECDSA Signature Length Validation", func(t *testing.T) {
		ecdsaKeyPair := testNewKeyPair(t, testNewECDSAKeyPair)

		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.ES256},
			jwt.ClaimsSet{jwt.Subject: "test"},
			ecdsaKeyPair.private,
		)

		parts := strings.Split(token.String(), ".")
		sig := base64url.Encode([]byte("invalid-length-signature"))
		requireRefused(t, sigOnlyVerifier(ecdsaKeyPair.public), parts[0]+"."+parts[1]+"."+sig, jwt.ErrSignature)
	})
}

func TestKeyValidation(t *testing.T) {
	t.Run("HMAC Key Length Validation", func(t *testing.T) {
		tests := []struct {
			algorithm jwa.Algorithm
			keySize   int
			shouldErr bool
		}{
			{jwa.HS256, 32, false}, // Valid: exactly hash size
			{jwa.HS256, 64, false}, // Valid: larger than hash size
			{jwa.HS256, 16, true},  // Invalid: smaller than hash size
			{jwa.HS384, 48, false}, // Valid: exactly hash size
			{jwa.HS384, 32, true},  // Invalid: smaller than hash size
			{jwa.HS512, 64, false}, // Valid: exactly hash size
			{jwa.HS512, 32, true},  // Invalid: smaller than hash size
		}

		for _, test := range tests {
			t.Run(string(test.algorithm), func(t *testing.T) {
				key := make([]byte, test.keySize)
				for i := range key {
					key[i] = byte(i)
				}

				_, err := jwt.New(
					header.Parameters{header.Type: jwt.Type, header.Algorithm: test.algorithm},
					jwt.ClaimsSet{jwt.Subject: "test"},
					key,
				)

				if test.shouldErr {
					if err == nil || !strings.Contains(err.Error(), "HMAC key must be at least") {
						t.Fatalf("jwt.New() error = %v, want error containing %q", err, "HMAC key must be at least")
					}
				} else if err != nil {
					t.Fatalf("jwt.New() error = %v", err)
				}
			})
		}
	})

	t.Run("EdDSA Key Size Validation", func(t *testing.T) {
		// A 16-byte "public key" never verifies an EdDSA token.
		eddsaKeyPair := testNewKeyPair(t, testNewEdDSAKeyPair)
		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.EdDSA},
			jwt.ClaimsSet{jwt.Subject: "test"},
			eddsaKeyPair.private,
		)
		requireRefused(t, sigOnlyVerifier(make([]byte, 16), jwa.EdDSA), token.String(), jwt.ErrSignature)
	})
}

func TestParsingVulnerabilities(t *testing.T) {
	verifier := sigOnlyVerifier(testHMACSecretKey, jwa.HS256)

	t.Run("Malformed JWT Structure", func(t *testing.T) {
		malformedTokens := []string{
			"",                   // Empty
			".",                  // Just a dot
			"..",                 // Two dots
			"a.b",                // Only two parts
			"a.b.c.d",            // Too many parts
			"invalid-base64.b.c", // Invalid base64 in header
			"a.invalid-base64.c", // Invalid base64 in payload
			"a.b.invalid-base64", // Invalid base64 in signature
		}

		for _, malformed := range malformedTokens {
			t.Run("malformed_"+malformed, func(t *testing.T) {
				if _, err := jwt.Parse(malformed); err == nil {
					t.Fatal("jwt.Parse() error = nil, want non-nil")
				}
				requireRefused(t, verifier, malformed, jwt.ErrFormat)
			})
		}
	})

	t.Run("Invalid JSON in Header", func(t *testing.T) {
		malformedToken := rawToken(t, "not-json", `{"sub":"test"}`, []byte("signature"))

		_, err := jwt.Parse(malformedToken)
		if err == nil || !strings.Contains(err.Error(), "failed to decode JOSE header JSON") {
			t.Fatalf("jwt.Parse() error = %v, want error containing %q", err, "failed to decode JOSE header JSON")
		}
		requireRefused(t, verifier, malformedToken, jwt.ErrFormat)
	})

	t.Run("Invalid JSON in Claims", func(t *testing.T) {
		malformedToken := rawToken(t, `{"alg":"HS256","typ":"JWT"}`, "not-json", []byte("signature"))

		_, err := jwt.Parse(malformedToken)
		if err == nil || !strings.Contains(err.Error(), "failed to decode claims JSON") {
			t.Fatalf("jwt.Parse() error = %v, want error containing %q", err, "failed to decode claims JSON")
		}
		requireRefused(t, verifier, malformedToken, jwt.ErrFormat)
	})

	t.Run("Invalid Time Claims", func(t *testing.T) {
		// String values for time claims, which should be numeric.
		malformedToken := rawToken(t, `{"alg":"HS256","typ":"JWT"}`, `{"exp":"not-a-number","iat":"also-not-a-number"}`, []byte("signature"))

		_, err := jwt.Parse(malformedToken)
		if err == nil || !strings.Contains(err.Error(), "invalid type") {
			t.Fatalf("jwt.Parse() error = %v, want error containing %q", err, "invalid type")
		}
		// The token is not validly signed, and claims are judged only after
		// the signature (see TestVerifierChecksSignatureBeforeTime).
		requireRefused(t, verifier, malformedToken, jwt.ErrSignature)
	})
}

func TestAudienceValidation(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)

	audienceVerifier := func(audience string) *jwt.Verifier {
		v := sigOnlyVerifier(rsaKeyPair.public)
		v.AnyAudience = false
		v.Audience = audience
		return v
	}

	t.Run("String Audience", func(t *testing.T) {
		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
			jwt.ClaimsSet{jwt.Subject: "test", jwt.Audience: "expected-audience"},
			rsaKeyPair.private,
		)

		if err := verifyToken(audienceVerifier("expected-audience"), token.String()); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		requireRefused(t, audienceVerifier("wrong-audience"), token.String(), jwt.ErrClaims)
	})

	t.Run("Array Audience", func(t *testing.T) {
		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
			jwt.ClaimsSet{jwt.Subject: "test", jwt.Audience: []string{"aud1", "aud2", "aud3"}},
			rsaKeyPair.private,
		)

		// Accepted when this verifier is one of the audiences.
		if err := verifyToken(audienceVerifier("aud2"), token.String()); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		requireRefused(t, audienceVerifier("aud4"), token.String(), jwt.ErrClaims)
	})

	t.Run("Missing Audience", func(t *testing.T) {
		token := testToken(t,
			header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
			jwt.ClaimsSet{jwt.Subject: "test"},
			rsaKeyPair.private,
		)
		requireRefused(t, audienceVerifier("expected-audience"), token.String(), jwt.ErrClaims)
	})

	t.Run("Invalid Audience Type", func(t *testing.T) {
		// A validly signed token whose "aud" is neither a string nor an
		// array of strings. Mint it with jws, since jwt.New refuses it.
		token := sign(t,
			jws.Header{header.Algorithm: jwa.RS256, header.Type: jwt.Type},
			map[string]any{"sub": "test", "aud": 123},
			rsaKeyPair.private,
		)
		requireRefused(t, audienceVerifier("any"), token, jwt.ErrClaims)
		// Not even a verifier that skips the audience check accepts it.
		requireRefused(t, sigOnlyVerifier(rsaKeyPair.public), token, jwt.ErrClaims)
	})
}

// RFC 7519 §4: a JWT whose header or claims repeat a name is refused, so
// two verifiers cannot read different values from the same token.
func TestDuplicateNamesRefused(t *testing.T) {
	encode := func(s string) string { out := base64url.Encode([]byte(s)); return out }
	verifier := sigOnlyVerifier(testHMACSecretKey, jwa.HS256)
	for name, token := range map[string]string{
		"header": encode(`{"alg":"none","alg":"HS256","typ":"JWT"}`) + "." + encode(`{"sub":"alice"}`) + ".c2ln",
		"claims": encode(`{"alg":"HS256","typ":"JWT"}`) + "." + encode(`{"sub":"alice","sub":"admin"}`) + ".c2ln",
	} {
		if _, err := jwt.Parse(token); err == nil {
			t.Errorf("%s: Parse accepted duplicate names", name)
		}
		requireRefused(t, verifier, token, jwt.ErrFormat)
	}
}
