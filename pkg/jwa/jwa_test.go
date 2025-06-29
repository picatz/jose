package jwa_test

import (
	"errors"
	"testing"

	"github.com/picatz/jose/pkg/jwa"
	"github.com/stretchr/testify/require"
)

func TestValidateAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   jwa.Algorithm
		allowedAlgs []jwa.Algorithm
		expectError bool
		expectedErr error
		description string
	}{
		{
			name:        "Valid known algorithm in allowed list",
			algorithm:   jwa.RS256,
			allowedAlgs: []jwa.Algorithm{jwa.RS256, jwa.HS256},
			expectError: false,
			description: "Should pass when algorithm is known and in allowed list",
		},
		{
			name:        "Valid known algorithm with empty allowed list",
			algorithm:   jwa.ES256,
			allowedAlgs: []jwa.Algorithm{},
			expectError: true,
			expectedErr: jwa.ErrAlgorithmNotAllowed,
			description: "Should fail when allowed list is empty (algorithm not in empty list)",
		},
		{
			name:        "Valid known algorithm with nil allowed list",
			algorithm:   jwa.PS256,
			allowedAlgs: nil,
			expectError: true,
			expectedErr: jwa.ErrAlgorithmNotAllowed,
			description: "Should fail when allowed list is nil (algorithm not in nil list)",
		},
		{
			name:        "Unknown algorithm",
			algorithm:   "UNKNOWN",
			allowedAlgs: []jwa.Algorithm{"UNKNOWN"},
			expectError: true,
			expectedErr: jwa.ErrUnknownAlgorithm,
			description: "Should fail with unknown algorithm error even if in allowed list",
		},
		{
			name:        "Empty algorithm string",
			algorithm:   "",
			allowedAlgs: []jwa.Algorithm{""},
			expectError: true,
			expectedErr: jwa.ErrUnknownAlgorithm,
			description: "Should fail with unknown algorithm error for empty string",
		},
		{
			name:        "Known algorithm not in allowed list",
			algorithm:   jwa.HS256,
			allowedAlgs: []jwa.Algorithm{jwa.RS256, jwa.ES256},
			expectError: true,
			expectedErr: jwa.ErrAlgorithmNotAllowed,
			description: "Should fail when known algorithm is not in allowed list",
		},
		{
			name:        "None algorithm is known",
			algorithm:   jwa.None,
			allowedAlgs: []jwa.Algorithm{jwa.None},
			expectError: false,
			description: "None algorithm should be considered known (though insecure)",
		},
		{
			name:        "None algorithm not in allowed list",
			algorithm:   jwa.None,
			allowedAlgs: []jwa.Algorithm{jwa.RS256, jwa.HS256},
			expectError: true,
			expectedErr: jwa.ErrAlgorithmNotAllowed,
			description: "None algorithm should fail if not explicitly allowed",
		},
		{
			name:        "All HMAC algorithms",
			algorithm:   jwa.HS384,
			allowedAlgs: []jwa.Algorithm{jwa.HS256, jwa.HS384, jwa.HS512},
			expectError: false,
			description: "HMAC algorithms should be validated correctly",
		},
		{
			name:        "All RSA algorithms",
			algorithm:   jwa.RS384,
			allowedAlgs: []jwa.Algorithm{jwa.RS256, jwa.RS384, jwa.RS512},
			expectError: false,
			description: "RSA algorithms should be validated correctly",
		},
		{
			name:        "All RSA-PSS algorithms",
			algorithm:   jwa.PS512,
			allowedAlgs: []jwa.Algorithm{jwa.PS256, jwa.PS384, jwa.PS512},
			expectError: false,
			description: "RSA-PSS algorithms should be validated correctly",
		},
		{
			name:        "All ECDSA algorithms",
			algorithm:   jwa.ES512,
			allowedAlgs: []jwa.Algorithm{jwa.ES256, jwa.ES384, jwa.ES512},
			expectError: false,
			description: "ECDSA algorithms should be validated correctly",
		},
		{
			name:        "EdDSA algorithm",
			algorithm:   jwa.EdDSA,
			allowedAlgs: []jwa.Algorithm{jwa.EdDSA},
			expectError: false,
			description: "EdDSA algorithm should be validated correctly",
		},
		{
			name:        "Case sensitive algorithm check",
			algorithm:   "rs256", // lowercase
			allowedAlgs: []jwa.Algorithm{"rs256"},
			expectError: true,
			expectedErr: jwa.ErrUnknownAlgorithm,
			description: "Algorithm validation should be case sensitive",
		},
		{
			name:        "Mixed case in allowed list",
			algorithm:   jwa.RS256,
			allowedAlgs: []jwa.Algorithm{"rs256", jwa.RS256, "RS256"},
			expectError: false,
			description: "Should find exact match in allowed list regardless of other case variants",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := jwa.ValidateAlgorithm(tt.algorithm, tt.allowedAlgs)

			if tt.expectError {
				require.Error(t, err, tt.description)
				if tt.expectedErr != nil {
					require.True(t, errors.Is(err, tt.expectedErr),
						"Expected error type %v, got %v", tt.expectedErr, err)
				}
			} else {
				require.NoError(t, err, tt.description)
			}
		})
	}
}

func TestValidateAlgorithm_AllKnownAlgorithms(t *testing.T) {
	knownAlgs := []jwa.Algorithm{
		jwa.HS256, jwa.HS384, jwa.HS512,
		jwa.RS256, jwa.RS384, jwa.RS512,
		jwa.PS256, jwa.PS384, jwa.PS512,
		jwa.ES256, jwa.ES384, jwa.ES512,
		jwa.EdDSA, jwa.None,
	}

	for _, alg := range knownAlgs {
		t.Run(string(alg), func(t *testing.T) {
			err := jwa.ValidateAlgorithm(alg, []jwa.Algorithm{alg})
			require.NoError(t, err, "Known algorithm %s should pass validation", alg)
		})
	}
}

func TestValidateAlgorithm_ErrorWrapping(t *testing.T) {
	t.Run("Unknown algorithm error message", func(t *testing.T) {
		err := jwa.ValidateAlgorithm("FAKE_ALG", []jwa.Algorithm{"FAKE_ALG"})
		require.Error(t, err)
		require.True(t, errors.Is(err, jwa.ErrUnknownAlgorithm))
		require.Contains(t, err.Error(), "FAKE_ALG")
		require.Contains(t, err.Error(), "is not a known algorithm")
	})

	t.Run("Algorithm not allowed error message", func(t *testing.T) {
		err := jwa.ValidateAlgorithm(jwa.RS256, []jwa.Algorithm{jwa.HS256})
		require.Error(t, err)
		require.True(t, errors.Is(err, jwa.ErrAlgorithmNotAllowed))
		require.Contains(t, err.Error(), "RS256")
		require.Contains(t, err.Error(), "is not allowed")
	})
}

func BenchmarkValidateAlgorithm(b *testing.B) {
	allowedAlgs := []jwa.Algorithm{
		jwa.RS256, jwa.RS384, jwa.RS512,
		jwa.ES256, jwa.ES384, jwa.ES512,
		jwa.HS256, jwa.HS384, jwa.HS512,
	}

	b.Run("Valid algorithm", func(b *testing.B) {
		for b.Loop() {
			_ = jwa.ValidateAlgorithm(jwa.RS256, allowedAlgs)
		}
	})

	b.Run("Invalid algorithm", func(b *testing.B) {
		for b.Loop() {
			_ = jwa.ValidateAlgorithm("UNKNOWN", allowedAlgs)
		}
	})

	b.Run("Algorithm not in allowed list", func(b *testing.B) {
		for b.Loop() {
			_ = jwa.ValidateAlgorithm(jwa.EdDSA, allowedAlgs)
		}
	})
}
