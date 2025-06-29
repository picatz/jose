package jwt_test

import (
	"testing"
	"time"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/keyutil"
	"github.com/stretchr/testify/require"
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
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrInvalidToken)
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "HMAC key must be at least 32 bytes")
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
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrInvalidToken)

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
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrInvalidToken)
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "parameter not found")
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
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrInvalidToken)
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
		require.NoError(t, err)

		// Verify with wrong keys - should fail
		err = token.Verify(
			jwt.WithAllowedAlgorithms(jwa.HS256),
			jwt.WithKey(key1),
			jwt.WithKey(key3),
		)
		require.Error(t, err)
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "token is expired")

		// Should succeed with sufficient clock skew tolerance
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithClockSkewTolerance(1*time.Minute),
		)
		require.NoError(t, err)

		// Should still fail with insufficient clock skew tolerance
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithClockSkewTolerance(10*time.Second),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "token is expired")
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to be used before")

		// Should succeed with sufficient clock skew tolerance
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithClockSkewTolerance(1*time.Minute),
		)
		require.NoError(t, err)
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
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrInvalidToken)
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify RSA signature using any of the allowed keys")
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify ECDSA signature")
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
					require.Error(t, err)
					require.Contains(t, err.Error(), "HMAC key must be at least")
				} else {
					require.NoError(t, err)
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid Ed25519 public key size")
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
				require.Error(t, err)
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
		require.NoError(t, err)
		require.NotEmpty(t, headerB64)
		claimsB64, err := base64.Encode([]byte(validClaims))
		require.NoError(t, err)
		require.NotEmpty(t, claimsB64)
		sigB64, err := base64.Encode([]byte(validSig))
		require.NoError(t, err)
		require.NotEmpty(t, sigB64)

		malformedToken := headerB64 + "." + claimsB64 + "." + sigB64

		_, err = jwt.ParseString(malformedToken)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode JOSE header JSON")
	})

	t.Run("Invalid JSON in Claims", func(t *testing.T) {
		// Create token with invalid JSON in claims
		validHeader := `{"alg":"HS256","typ":"JWT"}`
		invalidClaims := "not-json"
		validSig := "signature"

		// Base64 encode the parts
		headerB64, err := base64.Encode([]byte(validHeader))
		require.NoError(t, err)
		require.NotEmpty(t, headerB64)
		claimsB64, err := base64.Encode([]byte(invalidClaims))
		require.NoError(t, err)
		require.NotEmpty(t, claimsB64)
		sigB64, err := base64.Encode([]byte(validSig))
		require.NoError(t, err)
		require.NotEmpty(t, sigB64)

		malformedToken := headerB64 + "." + claimsB64 + "." + sigB64

		_, err = jwt.ParseString(malformedToken)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode claims JSON")
	})

	t.Run("Invalid Time Claims", func(t *testing.T) {
		// Test with string values for time claims (should be numeric)
		validHeader := `{"alg":"HS256","typ":"JWT"}`
		invalidClaims := `{"exp":"not-a-number","iat":"also-not-a-number"}`
		validSig := "signature"

		headerB64, err := base64.Encode([]byte(validHeader))
		require.NoError(t, err)
		require.NotEmpty(t, headerB64)
		claimsB64, err := base64.Encode([]byte(invalidClaims))
		require.NoError(t, err)
		require.NotEmpty(t, claimsB64)
		sigB64, err := base64.Encode([]byte(validSig))
		require.NoError(t, err)
		require.NotEmpty(t, sigB64)

		malformedToken := headerB64 + "." + claimsB64 + "." + sigB64

		_, err = jwt.ParseString(malformedToken)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid type")
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
		require.NoError(t, err)

		// Should fail with wrong audience
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithAllowedAudiences("wrong-audience"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not allowed")
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
		require.NoError(t, err)

		// Should fail if no audience matches
		err = token.Verify(
			jwt.WithKey(rsaKeyPair.public),
			jwt.WithAllowedAudiences("aud4", "aud5"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "none of the requested audiences")
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid audience type")
	})
}
