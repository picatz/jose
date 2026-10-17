package jws

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
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
				if err != nil {
					t.Fatalf("rsa.GenerateKey() error = %v", err)
				}
				return key, &key.PublicKey
			},
		},
		{
			name:      "ECDSA P-256 SHA-256",
			algorithm: jwa.ES256,
			keyGen: func() (any, any) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("ecdsa.GenerateKey() error = %v", err)
				}
				return key, &key.PublicKey
			},
		},
		{
			name:      "EdDSA",
			algorithm: jwa.EdDSA,
			keyGen: func() (any, any) {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("ed25519.GenerateKey() error = %v", err)
				}
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
				header.Algorithm: string(tt.algorithm),
				header.Type:      "JWS",
			}

			// Test payload
			payload := []byte("Hello, JWS World!")

			// Create and sign JWS signature
			signature, err := New(h, payload, signingKey)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if signature == nil {
				t.Fatal("signature = nil, want non-nil")
			}

			// Verify the structure
			if !reflect.DeepEqual(signature.Header, h) {
				t.Fatalf("signature.Header = %v, want %v", signature.Header, h)
			}
			if !bytes.Equal(signature.Payload, payload) {
				t.Fatalf("signature.Payload = %x, want %x", signature.Payload, payload)
			}

			// For "none" algorithm, signature should be empty
			if tt.algorithm == jwa.None {
				if len(signature.Signature) != 0 {
					t.Fatalf("signature.Signature = %v, want empty", signature.Signature)
				}
			} else {
				if len(signature.Signature) == 0 {
					t.Fatal("signature.Signature is empty")
				}
			}

			// Test string representation
			signatureStr := signature.String()
			if len(signatureStr) == 0 {
				t.Fatal("signatureStr is empty")
			}

			// Count periods - should be exactly 2
			periods := 0
			for _, char := range signatureStr {
				if char == '.' {
					periods++
				}
			}
			if periods != 2 {
				t.Fatalf("JWS %q has %d periods, want 2", signatureStr, periods)
			}

			// Parse the signature back
			parsedSignature, err := Parse(signatureStr)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if parsedSignature == nil {
				t.Fatal("parsedSignature = nil, want non-nil")
			}

			// Verify parsed signature matches original
			if !reflect.DeepEqual(parsedSignature.Header, signature.Header) {
				t.Fatalf("parsedSignature.Header = %v, want %v", parsedSignature.Header, signature.Header)
			}
			if !bytes.Equal(parsedSignature.Payload, signature.Payload) {
				t.Fatalf("parsedSignature.Payload = %x, want %x", parsedSignature.Payload, signature.Payload)
			}
			if !bytes.Equal(parsedSignature.Signature, signature.Signature) {
				t.Fatalf("parsedSignature.Signature = %x, want %x", parsedSignature.Signature, signature.Signature)
			}

			// An unsecured JWS never verifies (RFC 8725 §3.1).
			if tt.algorithm == jwa.None {
				if err := parsedSignature.Verify(verificationKey); err == nil {
					t.Fatal("parsedSignature.Verify() accepted alg none")
				}
				return
			}

			// Verify signature
			err = parsedSignature.Verify(verificationKey)
			if err != nil {
				t.Fatalf("parsedSignature.Verify() error = %v", err)
			}

			// Test signature verification with original signature
			err = signature.Verify(verificationKey)
			if err != nil {
				t.Fatalf("signature.Verify() error = %v", err)
			}
		})
	}
}

func TestJWSParsing(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		_, err := Parse("")
		if err == nil || !strings.Contains(err.Error(), "empty JWS string") {
			t.Fatalf("Parse() error = %v, want error containing %q", err, "empty JWS string")
		}
	})

	t.Run("invalid format - too few parts", func(t *testing.T) {
		_, err := Parse("header.payload")
		if err == nil || !strings.Contains(err.Error(), "expected 2 dots, got 1") {
			t.Fatalf("Parse() error = %v, want error containing %q", err, "expected 2 dots, got 1")
		}
	})

	t.Run("invalid format - too many parts", func(t *testing.T) {
		_, err := Parse("header.payload.signature.extra")
		if err == nil || !strings.Contains(err.Error(), "expected 2 dots, got 3") {
			t.Fatalf("Parse() error = %v, want error containing %q", err, "expected 2 dots, got 3")
		}
	})

	t.Run("invalid base64 header", func(t *testing.T) {
		_, err := Parse("invalid-base64!.payload.signature")
		if err == nil || !strings.Contains(err.Error(), "failed to decode header") {
			t.Fatalf("Parse() error = %v, want error containing %q", err, "failed to decode header")
		}
	})

	t.Run("invalid JSON header", func(t *testing.T) {
		invalidHeader := "eyJpbnZhbGlkIGpzb24" // {"invalid json
		_, err := Parse(invalidHeader + ".payload.signature")
		if err == nil || !strings.Contains(err.Error(), "failed to parse header") {
			t.Fatalf("Parse() error = %v, want error containing %q", err, "failed to parse header")
		}
	})
}

func TestJWSSignatureVerification(t *testing.T) {
	// Generate test key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	h := Header{
		header.Algorithm: jwa.RS256,
	}
	payload := []byte("test payload")

	token, err := New(h, payload, key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Run("valid signature", func(t *testing.T) {
		err := token.Verify(&key.PublicKey)
		if err != nil {
			t.Fatalf("token.Verify() error = %v", err)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		// Create a copy and tamper with signature
		tamperedToken := *token
		if len(tamperedToken.Signature) > 0 {
			tamperedToken.Signature[0] ^= 0xFF // Flip bits
		}

		err := tamperedToken.Verify(&key.PublicKey)
		if err == nil {
			t.Fatal("tamperedToken.Verify() error = nil, want non-nil")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}

		err = token.Verify(&wrongKey.PublicKey)
		if err == nil {
			t.Fatal("token.Verify() error = nil, want non-nil")
		}
	})

	t.Run("missing algorithm", func(t *testing.T) {
		tokenWithoutAlg := &Signature{
			Header:  Header{},
			Payload: payload,
		}

		err := tokenWithoutAlg.Verify(&key.PublicKey)
		if err == nil || !strings.Contains(err.Error(), "missing or invalid algorithm") {
			t.Fatalf("tokenWithoutAlg.Verify() error = %v, want error containing %q", err, "missing or invalid algorithm")
		}
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
		if err == nil || !strings.Contains(err.Error(), "unsupported algorithm") {
			t.Fatalf("token.Sign() error = %v, want error containing %q", err, "unsupported algorithm")
		}

		err = token.Verify([]byte("key"))
		if err == nil || !strings.Contains(err.Error(), "unsupported algorithm") {
			t.Fatalf("token.Verify() error = %v, want error containing %q", err, "unsupported algorithm")
		}
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
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			// Verify roundtrip
			tokenStr := token.String()
			parsedToken, err := Parse(tokenStr)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if !bytes.Equal(parsedToken.Payload, tc.payload) {
				t.Fatalf("parsedToken.Payload = %x, want %x", parsedToken.Payload, tc.payload)
			}

			// Verify signature
			err = parsedToken.Verify(key)
			if err != nil {
				t.Fatalf("parsedToken.Verify() error = %v", err)
			}
		})
	}
}
