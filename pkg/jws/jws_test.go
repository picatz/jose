package jws

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/stretchr/testify/require"
)

func TestJWSBasicFlow(t *testing.T) {
	tests := []struct {
		name      string
		algorithm jwa.Algorithm
		keyGen    func() (signing any, verification any)
	}{
		{
			name:      "HMAC SHA-256",
			algorithm: jwa.HS256,
			keyGen: func() (any, any) {
				key := []byte("test-secret-key-that-is-long-enough-for-hmac-256")
				return key, key
			},
		},
		{
			name:      "RSA SHA-256",
			algorithm: jwa.RS256,
			keyGen: func() (any, any) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return key, &key.PublicKey
			},
		},
		{
			name:      "ECDSA P-256 SHA-256",
			algorithm: jwa.ES256,
			keyGen: func() (any, any) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return key, &key.PublicKey
			},
		},
		{
			name:      "EdDSA",
			algorithm: jwa.EdDSA,
			keyGen: func() (any, any) {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return priv, pub
			},
		},
		{
			name:      "None algorithm",
			algorithm: jwa.None,
			keyGen: func() (any, any) {
				return nil, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signingKey, verificationKey := tt.keyGen()

			// Create header
			h := Header{
				header.Algorithm: tt.algorithm,
				header.Type:      "JWS",
			}

			// Test payload
			payload := []byte("Hello, JWS World!")

			// Create and sign JWS signature
			signature, err := New(h, payload, signingKey)
			require.NoError(t, err)
			require.NotNil(t, signature)

			// Verify the structure
			require.Equal(t, h, signature.Header)
			require.Equal(t, payload, signature.Payload)

			// For "none" algorithm, signature should be empty
			if tt.algorithm == jwa.None {
				require.Empty(t, signature.Signature)
			} else {
				require.NotEmpty(t, signature.Signature)
			}

			// Test string representation
			signatureStr := signature.String()
			require.NotEmpty(t, signatureStr)

			// Count periods - should be exactly 2
			periods := 0
			for _, char := range signatureStr {
				if char == '.' {
					periods++
				}
			}
			require.Equal(t, 2, periods, "JWS should have exactly 2 periods")

			// Parse the signature back
			parsedSignature, err := Parse(signatureStr)
			require.NoError(t, err)
			require.NotNil(t, parsedSignature)

			// Verify parsed signature matches original
			require.Equal(t, signature.Header, parsedSignature.Header)
			require.Equal(t, signature.Payload, parsedSignature.Payload)
			require.Equal(t, signature.Signature, parsedSignature.Signature)

			// Verify signature
			err = parsedSignature.Verify(verificationKey)
			require.NoError(t, err)

			// Test signature verification with original signature
			err = signature.Verify(verificationKey)
			require.NoError(t, err)
		})
	}
}

func TestJWSParsing(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		_, err := Parse("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty JWS string")
	})

	t.Run("invalid format - too few parts", func(t *testing.T) {
		_, err := Parse("header.payload")
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected 2 dots, got 1")
	})

	t.Run("invalid format - too many parts", func(t *testing.T) {
		_, err := Parse("header.payload.signature.extra")
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected 2 dots, got 3")
	})

	t.Run("invalid base64 header", func(t *testing.T) {
		_, err := Parse("invalid-base64!.payload.signature")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode header")
	})

	t.Run("invalid JSON header", func(t *testing.T) {
		invalidHeader := "eyJpbnZhbGlkIGpzb24=" // {"invalid json
		_, err := Parse(invalidHeader + ".payload.signature")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse header")
	})
}

func TestJWSSignatureVerification(t *testing.T) {
	// Generate test key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	h := Header{
		header.Algorithm: jwa.RS256,
	}
	payload := []byte("test payload")

	token, err := New(h, payload, key)
	require.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		err := token.Verify(&key.PublicKey)
		require.NoError(t, err)
	})

	t.Run("tampered signature", func(t *testing.T) {
		// Create a copy and tamper with signature
		tamperedToken := *token
		if len(tamperedToken.Signature) > 0 {
			tamperedToken.Signature[0] ^= 0xFF // Flip bits
		}

		err := tamperedToken.Verify(&key.PublicKey)
		require.Error(t, err)
	})

	t.Run("wrong key", func(t *testing.T) {
		wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		err = token.Verify(&wrongKey.PublicKey)
		require.Error(t, err)
	})

	t.Run("missing algorithm", func(t *testing.T) {
		tokenWithoutAlg := &Signature{
			Header:  Header{},
			Payload: payload,
		}

		err := tokenWithoutAlg.Verify(&key.PublicKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing or invalid algorithm")
	})
}

func TestJWSAlgorithmSupport(t *testing.T) {
	payload := []byte("test")

	t.Run("unsupported algorithm", func(t *testing.T) {
		h := Header{
			header.Algorithm: "UNSUPPORTED",
		}

		token := &Signature{
			Header:  h,
			Payload: payload,
		}

		_, err := token.Sign([]byte("key"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported algorithm")

		err = token.Verify([]byte("key"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported algorithm")
	})
}

func TestJWSPayloadFlexibility(t *testing.T) {
	h := Header{
		header.Algorithm: jwa.HS256,
	}
	key := []byte("test-secret-key-that-is-long-enough")

	testCases := []struct {
		name    string
		payload []byte
	}{
		{"empty payload", []byte{}},
		{"text payload", []byte("Hello, World!")},
		{"json payload", []byte(`{"message": "Hello, JWS!", "timestamp": 1234567890}`)},
		{"binary payload", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := New(h, tc.payload, key)
			require.NoError(t, err)

			// Verify roundtrip
			tokenStr := token.String()
			parsedToken, err := Parse(tokenStr)
			require.NoError(t, err)
			require.Equal(t, tc.payload, parsedToken.Payload)

			// Verify signature
			err = parsedToken.Verify(key)
			require.NoError(t, err)
		})
	}
}
