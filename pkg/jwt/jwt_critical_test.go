package jwt_test

import (
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/stretchr/testify/require"
)

// TestCriticalHeaderValidation tests RFC 7515 section 4.1.11 critical header validation
func TestCriticalHeaderValidation(t *testing.T) {
	t.Run("No Critical Header", func(t *testing.T) {
		// Token without "crit" header should pass validation
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte{}, // Empty for "none" algorithm
		}

		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
		)
		require.NoError(t, err)
	})

	t.Run("Valid Critical Header", func(t *testing.T) {
		// Token with valid critical header that we support
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
				header.Critical:  []any{"custom-ext", "another-ext"},
				"custom-ext":     "some-value",
				"another-ext":    "another-value",
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte{}, // Empty for "none" algorithm
		}

		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
			jwt.WithSupportedCriticalHeaders("custom-ext", "another-ext"),
		)
		require.NoError(t, err)
	})

	t.Run("Unsupported Critical Header", func(t *testing.T) {
		// Token with critical header that we don't support
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:       jwt.Type,
				header.Algorithm:  jwa.None,
				header.Critical:   []any{"unsupported-ext"},
				"unsupported-ext": "some-value",
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte{}, // Empty for "none" algorithm
		}

		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
			jwt.WithSupportedCriticalHeaders("custom-ext"), // Different from what's in token
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported critical header parameter: \"unsupported-ext\"")
	})

	t.Run("Critical Header Not Present", func(t *testing.T) {
		// Token with critical header that references missing header parameter
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
				header.Critical:  []any{"missing-ext"},
				// "missing-ext" is NOT present in header
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte{}, // Empty for "none" algorithm
		}

		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
			jwt.WithSupportedCriticalHeaders("missing-ext"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "critical header parameter \"missing-ext\" is missing from header")
	})

	t.Run("Empty Critical Header Array", func(t *testing.T) {
		// RFC 7515 section 4.1.11: The "crit" header parameter MUST NOT be empty
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
				header.Critical:  []any{}, // Empty array
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte{}, // Empty for "none" algorithm
		}

		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "critical header parameter \"crit\" must not be empty")
	})

	t.Run("Critical Header Wrong Type", func(t *testing.T) {
		// Critical header must be an array
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
				header.Critical:  "not-an-array", // Wrong type
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte{}, // Empty for "none" algorithm
		}

		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "critical header parameter \"crit\" must be an array")
	})

	t.Run("Critical Header Non-String Elements", func(t *testing.T) {
		// Critical header array elements must be strings
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
				header.Critical:  []any{"valid-ext", 123}, // Non-string element
				"valid-ext":      "some-value",
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte{}, // Empty for "none" algorithm
		}

		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
			jwt.WithSupportedCriticalHeaders("valid-ext"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "critical header parameter names must be strings")
	})

	t.Run("Standard Header in Critical List", func(t *testing.T) {
		// RFC 7515 section 4.1.11: Standard headers cannot be marked as critical
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.None,
				header.Critical:  []any{"alg"}, // Standard header
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			Signature: []byte{}, // Empty for "none" algorithm
		}

		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
			jwt.WithSupportedCriticalHeaders("alg"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "critical header parameter \"alg\" is a standard header and cannot be marked as critical")
	})

	t.Run("Multiple Standard Headers in Critical List", func(t *testing.T) {
		// Test various standard headers that cannot be critical
		standardHeaders := []string{"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"}

		for _, stdHeader := range standardHeaders {
			t.Run("Standard_"+stdHeader, func(t *testing.T) {
				token := &jwt.Token{
					Header: header.Parameters{
						header.Type:      jwt.Type,
						header.Algorithm: jwa.None,
						header.Critical:  []any{stdHeader},
					},
					Claims: jwt.ClaimsSet{
						jwt.Subject: "test",
					},
					Signature: []byte{}, // Empty for "none" algorithm
				}

				err := token.Verify(
					jwt.WithAllowInsecureNoneAlgorithm(true),
					jwt.WithAllowedAlgorithms(jwa.None),
					jwt.WithSupportedCriticalHeaders(stdHeader),
				)
				require.Error(t, err)
				require.Contains(t, err.Error(), "is a standard header and cannot be marked as critical")
			})
		}
	})

	t.Run("Complex Valid Critical Header Scenario", func(t *testing.T) {
		// More complex scenario with multiple valid critical headers
		token := &jwt.Token{
			Header: header.Parameters{
				header.Type:        jwt.Type,
				header.Algorithm:   jwa.None,
				header.Critical:    []any{"custom-auth", "rate-limit", "version"},
				"custom-auth":      "bearer-extended",
				"rate-limit":       "100/minute",
				"version":          "v2.0",
				"non-critical-ext": "this-is-ok", // Non-critical extension
			},
			Claims: jwt.ClaimsSet{
				jwt.Subject: "test",
				jwt.Issuer:  "test-issuer",
			},
			Signature: []byte{}, // Empty for "none" algorithm
		}

		err := token.Verify(
			jwt.WithAllowInsecureNoneAlgorithm(true),
			jwt.WithAllowedAlgorithms(jwa.None),
			jwt.WithSupportedCriticalHeaders("custom-auth", "rate-limit", "version", "other-ext"),
		)
		require.NoError(t, err)
	})
}
