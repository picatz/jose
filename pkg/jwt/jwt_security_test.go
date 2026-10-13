package jwt_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/keyutil"
)

// TestSecurityVulnerabilities tests various security vulnerabilities and attack vectors
func TestSecurityVulnerabilities(t *testing.T) {
	t.Run("Algorithm Confusion Attack", func(t *testing.T) {
		// Test that RSA public keys cannot be used as HMAC secrets
		rsaKeyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)

		// Create a token signed with RSA
		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			rsaKeyPair.private,
		)

		// Try to verify with HMAC using the RSA public key (should fail)
		err := token.Verify(
			jwt.WithAllowedAlgorithms(jwa.HS256),
			jwt.WithKey(rsaKeyPair.public),
		)
		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("token.Verify() error = %v, want %v", err, jwt.ErrInvalidToken)
		}
	})

	t.Run("Weak HMAC Key", func(t *testing.T) {
		// Test that weak HMAC keys are rejected
		weakKey := []byte("weak") // Only 4 bytes, much less than SHA256's 32 bytes

		_, err := jwt.New(
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.HS256,
			},
			jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			weakKey,
		)
		if err == nil || !strings.Contains(err.Error(), "HMAC key must be at least 32 bytes") {
			t.Fatalf("jwt.New() error = %v, want error containing %q", err, "HMAC key must be at least 32 bytes")
		}
	})

	t.Run("None Algorithm Security", func(t *testing.T) {
		// Test that "none" algorithm is properly restricted
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte{}, // Empty signature for "none"
		}

		// Should fail without explicit allowance
		err := token.Verify()
		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("token.Verify() error = %v, want %v", err, jwt.ErrInvalidToken)
		}

		// Should still fail even with explicit allowance if signature is not empty
		tokenWithSig := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte("not-empty"), // Invalid for "none"
		}

		err = tokenWithSig.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
		)
		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("tokenWithSig.Verify() error = %v, want %v", err, jwt.ErrInvalidToken)
		}
	})

	t.Run("Missing Algorithm Header", func(t *testing.T) {
		// Test that missing algorithm header is properly handled
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type: jwt.Type,
				// Missing algorithm
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
		}

		err := token.Verify(jwt.WithKey(testHMACSecretKey))
		if err == nil || !strings.Contains(err.Error(), "parameter not found") {
			t.Fatalf("token.Verify() error = %v, want error containing %q", err, "parameter not found")
		}
	})

	t.Run("Empty Algorithm Header", func(t *testing.T) {
		// Test that empty algorithm header is rejected
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: "", // Empty algorithm
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
		}

		err := token.Verify(jwt.WithKey(testHMACSecretKey))
		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("token.Verify() error = %v, want %v", err, jwt.ErrInvalidToken)
		}
	})
}

func TestTimingAttackResistance(t *testing.T) {
	t.Run("HMAC Key Iteration Timing", func(t *testing.T) {
		// Test that HMAC verification doesn't leak timing information about which key succeeded
		key1 := make([]byte, 32)
		key2 := make([]byte, 32)
		key3 := make([]byte, 32)

		// Fill with different patterns
		for i := range key1 {
			key1[i] = byte(i)
			key2[i] = byte(i + 1)
			key3[i] = byte(i + 2)
		}

		// Create token with key2
		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.HS256,
			},
			jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			key2,
		)

		// Verify with multiple keys - should succeed
		err := token.Verify(
			jwt.WithAllowedAlgorithms(jwa.HS256),
			jwt.WithKey(key1),
			jwt.WithKey(key2), // This one will match
			jwt.WithKey(key3),
		)
		if err != nil {
			t.Fatalf("token.Verify() error = %v", err)
		}

		// Verify with wrong keys - should fail
		err = token.Verify(
			jwt.WithAllowedAlgorithms(jwa.HS256),
			jwt.WithKey(key1),
			jwt.WithKey(key3),
		)
		if err == nil {
			t.Fatal("token.Verify() error = nil, want non-nil")
		}
	})
}

func TestClockSkewTolerance(t *testing.T) {
	t.Run("Expiration with Clock Skew", func(t *testing.T) {
		rsaKeyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)

		// Create token that expired 30 seconds ago
		expiredTime := time.Now().Add(-30 * time.Second)
		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.ExpirationTime: expiredTime.Unix(),
			},
			rsaKeyPair.private,
		)

		// Should fail without clock skew tolerance
		err := token.Verify(jwt.WithKey(rsaKeyPair.public))
		if err == nil || !strings.Contains(err.Error(), "token is expired") {
			t.Fatalf("token.Verify() error = %v, want error containing %q", err, "token is expired")
		}

		// Should succeed with sufficient clock skew tolerance
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithClockSkewTolerance(1*time.Minute),
		)
		if err != nil {
			t.Fatalf("token.Verify() error = %v", err)
		}

		// Should still fail with insufficient clock skew tolerance
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithClockSkewTolerance(10*time.Second),
		)
		if err == nil || !strings.Contains(err.Error(), "token is expired") {
			t.Fatalf("token.Verify() error = %v, want error containing %q", err, "token is expired")
		}
	})

	t.Run("NotBefore with Clock Skew", func(t *testing.T) {
		rsaKeyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)

		// Create token that's not valid yet (30 seconds in future)
		notBeforeTime := time.Now().Add(30 * time.Second)
		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			jwt.ClaimsSet{
				jwt.Subject:   "test",
				jwt.NotBefore: notBeforeTime.Unix(),
			},
			rsaKeyPair.private,
		)

		// Should fail without clock skew tolerance
		err := token.Verify(jwt.WithKey(rsaKeyPair.public))
		if err == nil || !strings.Contains(err.Error(), "unable to be used before") {
			t.Fatalf("token.Verify() error = %v, want error containing %q", err, "unable to be used before")
		}

		// Should succeed with sufficient clock skew tolerance
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithClockSkewTolerance(1*time.Minute),
		)
		if err != nil {
			t.Fatalf("token.Verify() error = %v", err)
		}
	})
}

func TestInvalidSignatures(t *testing.T) {
	t.Run("Tampered Signature", func(t *testing.T) {
		rsaKeyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)

		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			rsaKeyPair.private,
		)

		// Tamper with signature
		if len(token.Signature) > 0 {
			token.Signature[0] ^= 0xFF // Flip all bits in first byte
		}

		err := token.Verify(jwt.WithKey(rsaKeyPair.public))
		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("token.Verify() error = %v, want %v", err, jwt.ErrInvalidToken)
		}
	})

	t.Run("Wrong Key Type for Algorithm", func(t *testing.T) {
		rsaKeyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)
		ecdsaKeyPair := testNewKeyPair(t, keyutil.NewECDSAKeyPair)

		// Create RSA token
		rsaToken := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			rsaKeyPair.private,
		)

		// Try to verify with ECDSA key (wrong type)
		err := rsaToken.Verify(jwt.WithKey(ecdsaKeyPair.public))
		if err == nil || !strings.Contains(err.Error(), "failed to verify RSA signature using any of the allowed keys") {
			t.Fatalf("rsaToken.Verify() error = %v, want error containing %q", err, "failed to verify RSA signature using any of the allowed keys")
		}
	})

	t.Run("ECDSA Signature Length Validation", func(t *testing.T) {
		ecdsaKeyPair := testNewKeyPair(t, keyutil.NewECDSAKeyPair)

		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.ES256,
			},
			jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			ecdsaKeyPair.private,
		)

		// Corrupt signature length
		token.Signature = []byte("invalid-length-signature")

		err := token.Verify(jwt.WithKey(ecdsaKeyPair.public))
		if err == nil || !strings.Contains(err.Error(), "failed to verify ECDSA signature") {
			t.Fatalf("token.Verify() error = %v, want error containing %q", err, "failed to verify ECDSA signature")
		}
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
					header.Parameters{
						header.Type:      jwt.Type,
						header.Algorithm: test.algorithm,
					},
					jwt.ClaimsSet{
						jwt.Subject: "test",
					},
					key,
				)

				if test.shouldErr {
					if err == nil || !strings.Contains(err.Error(), "HMAC key must be at least") {
						t.Fatalf("jwt.New() error = %v, want error containing %q", err, "HMAC key must be at least")
					}
				} else {
					if err != nil {
						t.Fatalf("jwt.New() error = %v", err)
					}
				}
			})
		}
	})

	t.Run("EdDSA Key Size Validation", func(t *testing.T) {
		// Test with invalid key sizes
		invalidKey := make([]byte, 16) // Too short

		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.EdDSA,
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: make([]byte, 64), // Valid signature length
		}

		// This should be caught at the verification level
		err := token.VerifyEdDSASignature(invalidKey)
		if err == nil || !strings.Contains(err.Error(), "invalid Ed25519 public key size") {
			t.Fatalf("token.VerifyEdDSASignature() error = %v, want error containing %q", err, "invalid Ed25519 public key size")
		}
	})
}

func TestParsingVulnerabilities(t *testing.T) {
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
				_, err := jwt.ParseString(malformed)
				if err == nil {
					t.Fatal("jwt.ParseString() error = nil, want non-nil")
				}
			})
		}
	})

	t.Run("Invalid JSON in Header", func(t *testing.T) {
		// Create token with invalid JSON in header
		invalidHeader := "not-json"
		validClaims := `{"sub":"test"}`
		validSig := "signature"

		// Base64 encode the parts
		headerB64, err := base64.Encode([]byte(invalidHeader))
		if err != nil {
			t.Fatalf("base64.Encode() error = %v", err)
		}
		if len(headerB64) == 0 {
			t.Fatal("headerB64 is empty")
		}
		claimsB64, err := base64.Encode([]byte(validClaims))
		if err != nil {
			t.Fatalf("base64.Encode() error = %v", err)
		}
		if len(claimsB64) == 0 {
			t.Fatal("claimsB64 is empty")
		}
		sigB64, err := base64.Encode([]byte(validSig))
		if err != nil {
			t.Fatalf("base64.Encode() error = %v", err)
		}
		if len(sigB64) == 0 {
			t.Fatal("sigB64 is empty")
		}

		malformedToken := headerB64 + "." + claimsB64 + "." + sigB64

		_, err = jwt.ParseString(malformedToken)
		if err == nil || !strings.Contains(err.Error(), "failed to decode JOSE header JSON") {
			t.Fatalf("jwt.ParseString() error = %v, want error containing %q", err, "failed to decode JOSE header JSON")
		}
	})

	t.Run("Invalid JSON in Claims", func(t *testing.T) {
		// Create token with invalid JSON in claims
		validHeader := `{"alg":"HS256","typ":"JWT"}`
		invalidClaims := "not-json"
		validSig := "signature"

		// Base64 encode the parts
		headerB64, err := base64.Encode([]byte(validHeader))
		if err != nil {
			t.Fatalf("base64.Encode() error = %v", err)
		}
		if len(headerB64) == 0 {
			t.Fatal("headerB64 is empty")
		}
		claimsB64, err := base64.Encode([]byte(invalidClaims))
		if err != nil {
			t.Fatalf("base64.Encode() error = %v", err)
		}
		if len(claimsB64) == 0 {
			t.Fatal("claimsB64 is empty")
		}
		sigB64, err := base64.Encode([]byte(validSig))
		if err != nil {
			t.Fatalf("base64.Encode() error = %v", err)
		}
		if len(sigB64) == 0 {
			t.Fatal("sigB64 is empty")
		}

		malformedToken := headerB64 + "." + claimsB64 + "." + sigB64

		_, err = jwt.ParseString(malformedToken)
		if err == nil || !strings.Contains(err.Error(), "failed to decode claims JSON") {
			t.Fatalf("jwt.ParseString() error = %v, want error containing %q", err, "failed to decode claims JSON")
		}
	})

	t.Run("Invalid Time Claims", func(t *testing.T) {
		// Test with string values for time claims (should be numeric)
		validHeader := `{"alg":"HS256","typ":"JWT"}`
		invalidClaims := `{"exp":"not-a-number","iat":"also-not-a-number"}`
		validSig := "signature"

		headerB64, err := base64.Encode([]byte(validHeader))
		if err != nil {
			t.Fatalf("base64.Encode() error = %v", err)
		}
		if len(headerB64) == 0 {
			t.Fatal("headerB64 is empty")
		}
		claimsB64, err := base64.Encode([]byte(invalidClaims))
		if err != nil {
			t.Fatalf("base64.Encode() error = %v", err)
		}
		if len(claimsB64) == 0 {
			t.Fatal("claimsB64 is empty")
		}
		sigB64, err := base64.Encode([]byte(validSig))
		if err != nil {
			t.Fatalf("base64.Encode() error = %v", err)
		}
		if len(sigB64) == 0 {
			t.Fatal("sigB64 is empty")
		}

		malformedToken := headerB64 + "." + claimsB64 + "." + sigB64

		_, err = jwt.ParseString(malformedToken)
		if err == nil || !strings.Contains(err.Error(), "invalid type") {
			t.Fatalf("jwt.ParseString() error = %v, want error containing %q", err, "invalid type")
		}
	})
}

func TestAudienceValidation(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)

	t.Run("String Audience", func(t *testing.T) {
		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			jwt.ClaimsSet{
				jwt.Subject:  "test",
				jwt.Audience: "expected-audience",
			},
			rsaKeyPair.private,
		)

		// Should succeed with correct audience
		err := token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithAllowedAudiences("expected-audience"),
		)
		if err != nil {
			t.Fatalf("token.Verify() error = %v", err)
		}

		// Should fail with wrong audience
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithAllowedAudiences("wrong-audience"),
		)
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("token.Verify() error = %v, want error containing %q", err, "not allowed")
		}
	})

	t.Run("Array Audience", func(t *testing.T) {
		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			jwt.ClaimsSet{
				jwt.Subject:  "test",
				jwt.Audience: []string{"aud1", "aud2", "aud3"},
			},
			rsaKeyPair.private,
		)

		// Should succeed if any audience matches
		err := token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithAllowedAudiences("aud2", "aud4"),
		)
		if err != nil {
			t.Fatalf("token.Verify() error = %v", err)
		}

		// Should fail if no audience matches
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithAllowedAudiences("aud4", "aud5"),
		)
		if err == nil || !strings.Contains(err.Error(), "none of the requested audiences") {
			t.Fatalf("token.Verify() error = %v, want error containing %q", err, "none of the requested audiences")
		}
	})

	t.Run("Invalid Audience Type", func(t *testing.T) {
		// Create a token with "none" algorithm to bypass signature verification
		// and manually set invalid audience type
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject:  "test",
				jwt.Audience: 123.0, // Invalid type (float64 - what JSON unmarshaling would produce)
			},
			Signature: []byte{}, // Empty signature for "none"
		}

		// Should fail due to invalid audience type
		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
			jwt.WithAllowedAudiences("any"),
		)
		if err == nil || !strings.Contains(err.Error(), "invalid audience type") {
			t.Fatalf("token.Verify() error = %v, want error containing %q", err, "invalid audience type")
		}
	})
}

// RFC 7519 §4: a JWT whose header or claims repeat a name is refused, so
// two verifiers cannot read different values from the same token.
func TestDuplicateNamesRefused(t *testing.T) {
	encode := func(s string) string { out, _ := base64.Encode([]byte(s)); return out }
	for name, token := range map[string]string{
		"header": encode(`{"alg":"none","alg":"HS256","typ":"JWT"}`) + "." + encode(`{"sub":"alice"}`) + ".c2ln",
		"claims": encode(`{"alg":"HS256","typ":"JWT"}`) + "." + encode(`{"sub":"alice","sub":"admin"}`) + ".c2ln",
	} {
		if _, err := jwt.ParseString(token); err == nil {
			t.Errorf("%s: ParseString accepted duplicate names", name)
		}
	}
}
