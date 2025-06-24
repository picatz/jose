package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/stretchr/testify/require"
)

// newRSAKeyPairWithSize generates an RSA key pair with the specified bit size
func newRSAKeyPairWithSize(t *testing.T, bits int) (*rsa.PublicKey, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return &privateKey.PublicKey, privateKey
}

// TestRSAKeySizeValidation tests that RSA key size validation is enforced per RFC 7518
func TestRSAKeySizeValidation(t *testing.T) {
	t.Run("RSA Key Size Validation Function", func(t *testing.T) {
		// Test keys below minimum (should fail)
		t.Run("1024 bit key should be rejected", func(t *testing.T) {
			_, private1024 := newRSAKeyPairWithSize(t, 1024)
			err := validateRSAKeySize(private1024)
			require.Error(t, err)
			require.Contains(t, err.Error(), "RSA key size 128 bytes (1024 bits) is below minimum required 256 bytes (2048 bits)")
		})

		// Test keys at minimum (should pass)
		t.Run("2048 bit key should be accepted", func(t *testing.T) {
			_, private2048 := newRSAKeyPairWithSize(t, 2048)
			err := validateRSAKeySize(private2048)
			require.NoError(t, err)
		})

		// Test keys above minimum (should pass)
		t.Run("3072 bit key should be accepted", func(t *testing.T) {
			_, private3072 := newRSAKeyPairWithSize(t, 3072)
			err := validateRSAKeySize(private3072)
			require.NoError(t, err)
		})

		t.Run("4096 bit key should be accepted", func(t *testing.T) {
			_, private4096 := newRSAKeyPairWithSize(t, 4096)
			err := validateRSAKeySize(private4096)
			require.NoError(t, err)
		})

		// Test with public keys as well
		t.Run("Public key validation", func(t *testing.T) {
			public1024, _ := newRSAKeyPairWithSize(t, 1024)
			err := validateRSAKeySize(public1024)
			require.Error(t, err)
			require.Contains(t, err.Error(), "RSA key size 128 bytes (1024 bits) is below minimum required 256 bytes (2048 bits)")

			public2048, _ := newRSAKeyPairWithSize(t, 2048)
			err = validateRSAKeySize(public2048)
			require.NoError(t, err)
		})

		// Test invalid key types
		t.Run("Invalid key type", func(t *testing.T) {
			err := validateRSAKeySize("not-an-rsa-key")
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid RSA key type: string")
		})
	})

	t.Run("RS256 Algorithm Validation", func(t *testing.T) {
		public1024, private1024 := newRSAKeyPairWithSize(t, 1024)
		public2048, private2048 := newRSAKeyPairWithSize(t, 2048)

		claims := ClaimsSet{
			Subject: "test",
		}

		// Test signing with weak key (should fail)
		t.Run("Signing with 1024-bit key should fail", func(t *testing.T) {
			_, err := New(
				header.Parameters{
					header.Type:      Type,
					header.Algorithm: jwa.RS256,
				},
				claims,
				private1024,
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "RSA key validation failed")
			require.Contains(t, err.Error(), "RSA key size 128 bytes (1024 bits) is below minimum required 256 bytes (2048 bits)")
		})

		// Test signing with strong key (should pass)
		t.Run("Signing with 2048-bit key should succeed", func(t *testing.T) {
			token, err := New(
				header.Parameters{
					header.Type:      Type,
					header.Algorithm: jwa.RS256,
				},
				claims,
				private2048,
			)
			require.NoError(t, err)
			require.NotNil(t, token)
		})

		// Test verification with weak key (should fail)
		t.Run("Verification with 1024-bit key should fail", func(t *testing.T) {
			// Create token with strong key first
			token, err := New(
				header.Parameters{
					header.Type:      Type,
					header.Algorithm: jwa.RS256,
				},
				claims,
				private2048,
			)
			require.NoError(t, err)

			// Try to verify with weak key (should fail due to key size, not signature mismatch)
			err = token.VerifyRSASignature(algHash[jwa.RS256], public1024)
			require.Error(t, err)
			require.Contains(t, err.Error(), "RSA key validation failed")
			require.Contains(t, err.Error(), "RSA key size 128 bytes (1024 bits) is below minimum required 256 bytes (2048 bits)")
		})

		// Test verification with strong key (should pass)
		t.Run("Verification with 2048-bit key should succeed", func(t *testing.T) {
			token, err := New(
				header.Parameters{
					header.Type:      Type,
					header.Algorithm: jwa.RS256,
				},
				claims,
				private2048,
			)
			require.NoError(t, err)

			err = token.VerifyRSASignature(algHash[jwa.RS256], public2048)
			require.NoError(t, err)
		})
	})

	t.Run("PS256 Algorithm Validation", func(t *testing.T) {
		public1024, private1024 := newRSAKeyPairWithSize(t, 1024)
		public2048, private2048 := newRSAKeyPairWithSize(t, 2048)

		claims := ClaimsSet{
			Subject: "test",
		}

		// Test signing with weak key (should fail)
		t.Run("Signing with 1024-bit key should fail", func(t *testing.T) {
			_, err := New(
				header.Parameters{
					header.Type:      Type,
					header.Algorithm: jwa.PS256,
				},
				claims,
				private1024,
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "RSA key validation failed")
			require.Contains(t, err.Error(), "RSA key size 128 bytes (1024 bits) is below minimum required 256 bytes (2048 bits)")
		})

		// Test signing with strong key (should pass)
		t.Run("Signing with 2048-bit key should succeed", func(t *testing.T) {
			token, err := New(
				header.Parameters{
					header.Type:      Type,
					header.Algorithm: jwa.PS256,
				},
				claims,
				private2048,
			)
			require.NoError(t, err)
			require.NotNil(t, token)
		})

		// Test verification with weak key (should fail)
		t.Run("Verification with 1024-bit key should fail", func(t *testing.T) {
			// Create token with strong key first
			token, err := New(
				header.Parameters{
					header.Type:      Type,
					header.Algorithm: jwa.PS256,
				},
				claims,
				private2048,
			)
			require.NoError(t, err)

			// Try to verify with weak key (should fail due to key size, not signature mismatch)
			err = token.VerifyRSAPSSSignature(algHash[jwa.PS256], public1024)
			require.Error(t, err)
			require.Contains(t, err.Error(), "RSA key validation failed")
			require.Contains(t, err.Error(), "RSA key size 128 bytes (1024 bits) is below minimum required 256 bytes (2048 bits)")
		})

		// Test verification with strong key (should pass)
		t.Run("Verification with 2048-bit key should succeed", func(t *testing.T) {
			token, err := New(
				header.Parameters{
					header.Type:      Type,
					header.Algorithm: jwa.PS256,
				},
				claims,
				private2048,
			)
			require.NoError(t, err)

			err = token.VerifyRSAPSSSignature(algHash[jwa.PS256], public2048)
			require.NoError(t, err)
		})
	})

	t.Run("All RSA Algorithms", func(t *testing.T) {
		_, private1024 := newRSAKeyPairWithSize(t, 1024)
		public2048, private2048 := newRSAKeyPairWithSize(t, 2048)
		public3072, private3072 := newRSAKeyPairWithSize(t, 3072)

		rsaAlgorithms := []jwa.Algorithm{
			jwa.RS256, jwa.RS384, jwa.RS512,
			jwa.PS256, jwa.PS384, jwa.PS512,
		}

		claims := ClaimsSet{
			Subject: "test",
		}

		for _, alg := range rsaAlgorithms {
			t.Run(string(alg), func(t *testing.T) {
				// Weak key should fail
				t.Run("1024-bit key rejected", func(t *testing.T) {
					_, err := New(
						header.Parameters{
							header.Type:      Type,
							header.Algorithm: alg,
						},
						claims,
						private1024,
					)
					require.Error(t, err)
					require.Contains(t, err.Error(), "RSA key validation failed")
					require.Contains(t, err.Error(), "1024 bits) is below minimum required")
				})

				// Strong keys should pass
				for _, keySize := range []struct {
					bits    int
					public  *rsa.PublicKey
					private *rsa.PrivateKey
				}{
					{2048, public2048, private2048},
					{3072, public3072, private3072},
				} {
					t.Run(fmt.Sprintf("%d-bit key accepted", keySize.bits), func(t *testing.T) {
						token, err := New(
							header.Parameters{
								header.Type:      Type,
								header.Algorithm: alg,
							},
							claims,
							keySize.private,
						)
						require.NoError(t, err)
						require.NotNil(t, token)

						// Test verification through the high-level Verify method
						err = token.Verify(WithKey(keySize.public))
						require.NoError(t, err)
					})
				}
			})
		}
	})

	t.Run("High-level JWT Verify with Weak Keys", func(t *testing.T) {
		public1024, _ := newRSAKeyPairWithSize(t, 1024)
		public2048, private2048 := newRSAKeyPairWithSize(t, 2048)

		// Create a valid token with strong key
		token, err := New(
			header.Parameters{
				header.Type:      Type,
				header.Algorithm: jwa.RS256,
			},
			ClaimsSet{
				Subject: "test",
			},
			private2048,
		)
		require.NoError(t, err)

		// High-level verification should also catch weak keys
		t.Run("Verify with weak key should fail", func(t *testing.T) {
			err = token.Verify(WithKey(public1024))
			require.Error(t, err)
			require.Contains(t, err.Error(), "RSA key validation failed")
		})

		t.Run("Verify with strong key should succeed", func(t *testing.T) {
			err = token.Verify(WithKey(public2048))
			require.NoError(t, err)
		})
	})
}
