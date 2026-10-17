package jwt_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

// TestRFC7519Compliance tests compliance with RFC 7519 validation requirements
func TestRFC7519Compliance(t *testing.T) {
	t.Run("JWT Structure Validation", func(t *testing.T) {
		tests := []struct {
			name        string
			input       string
			shouldError bool
			errorCheck  func(error) bool
		}{
			{
				name:        "No periods - invalid JWT structure",
				input:       "invalidjwtnoperiods",
				shouldError: true,
				errorCheck:  func(err error) bool { return errors.Is(err, jwt.ErrInvalidToken) },
			},
			{
				name:        "One period only - invalid JWT structure",
				input:       "header.payload",
				shouldError: true,
				errorCheck:  func(err error) bool { return errors.Is(err, jwt.ErrInvalidToken) },
			},
			{
				name:        "Empty string - invalid JWT",
				input:       "",
				shouldError: true,
				errorCheck:  func(err error) bool { return errors.Is(err, jwt.ErrInvalidToken) },
			},
			{
				name:        "Too many periods - extra content treated as part of signature",
				input:       "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.extra.periods.here",
				shouldError: true, // This should fail because "extra.periods.here" is not valid base64
				errorCheck:  func(err error) bool { return errors.Is(err, jwt.ErrInvalidToken) },
			},
			{
				name:        "Empty header - decodes to empty JSON",
				input:       ".eyJzdWIiOiJ0ZXN0In0.",
				shouldError: true,
				errorCheck: func(err error) bool {
					return strings.Contains(err.Error(), "failed to decode JOSE header JSON") ||
						strings.Contains(err.Error(), "failed to decode JOSE header base64")
				},
			},
			{
				name:        "Empty payload - decodes to empty JSON",
				input:       "eyJhbGciOiJub25lIn0..",
				shouldError: true,
				errorCheck: func(err error) bool {
					return strings.Contains(err.Error(), "failed to decode claims JSON") ||
						strings.Contains(err.Error(), "failed to decode claims base64")
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := jwt.Parse(tt.input)
				if tt.shouldError {
					if err == nil {
						t.Fatal("jwt.Parse() error = nil, want non-nil")
					}
					if tt.errorCheck != nil {
						if !tt.errorCheck(err) {
							t.Fatalf("error check failed for: %v", err)
						}
					}
				} else {
					if err != nil {
						t.Fatalf("jwt.Parse() error = %v", err)
					}
				}
			})
		}
	})

	t.Run("Invalid Base64 Content", func(t *testing.T) {
		tests := []struct {
			name        string
			header      string
			payload     string
			signature   string
			expectedErr string
		}{
			{
				name:        "Invalid base64 in header",
				header:      "invalid_base64!@#",
				payload:     base64url.Encode([]byte(`{"sub":"test"}`)),
				signature:   "",
				expectedErr: "failed to decode JOSE header base64",
			},
			{
				name:        "Invalid base64 in payload",
				header:      base64url.Encode([]byte(`{"alg":"none"}`)),
				payload:     "invalid_base64!@#",
				signature:   "",
				expectedErr: "failed to decode claims base64",
			},
			{
				name:        "Invalid base64 in signature",
				header:      base64url.Encode([]byte(`{"alg":"none"}`)),
				payload:     base64url.Encode([]byte(`{"sub":"test"}`)),
				signature:   "invalid_base64!@#",
				expectedErr: "failed to decode signature base64",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				jwtString := tt.header + "." + tt.payload + "." + tt.signature
				_, err := jwt.Parse(jwtString)
				if err == nil || !strings.Contains(err.Error(), tt.expectedErr) {
					t.Fatalf("jwt.Parse() error = %v, want error containing %q", err, tt.expectedErr)
				}
			})
		}
	})

	t.Run("Invalid JSON Content", func(t *testing.T) {
		tests := []struct {
			name        string
			header      string
			payload     string
			expectedErr string
		}{
			{
				name:        "Invalid JSON in header",
				header:      base64url.Encode([]byte(`{invalid json}`)),
				payload:     base64url.Encode([]byte(`{"sub":"test"}`)),
				expectedErr: "failed to decode JOSE header JSON",
			},
			{
				name:        "Invalid JSON in payload",
				header:      base64url.Encode([]byte(`{"alg":"none"}`)),
				payload:     base64url.Encode([]byte(`{invalid json}`)),
				expectedErr: "failed to decode claims JSON",
			},
			{
				name:        "Non-object JSON in header (array)",
				header:      base64url.Encode([]byte(`["alg", "none"]`)),
				payload:     base64url.Encode([]byte(`{"sub":"test"}`)),
				expectedErr: "failed to decode JOSE header JSON",
			},
			{
				name:        "Non-object JSON in payload (string)",
				header:      base64url.Encode([]byte(`{"alg":"none"}`)),
				payload:     base64url.Encode([]byte(`"just a string"`)),
				expectedErr: "failed to decode claims JSON",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				jwtString := tt.header + "." + tt.payload + "."
				_, err := jwt.Parse(jwtString)
				if err == nil || !strings.Contains(err.Error(), tt.expectedErr) {
					t.Fatalf("jwt.Parse() error = %v, want error containing %q", err, tt.expectedErr)
				}
			})
		}
	})

	t.Run("Registered Claim Type Validation", func(t *testing.T) {
		tests := []struct {
			name        string
			claims      string
			expectedErr string
		}{
			{
				name:        "Invalid exp type (string)",
				claims:      `{"exp":"not-a-number"}`,
				expectedErr: "invalid type string used for \"exp\"",
			},
			{
				name:        "Invalid nbf type (boolean)",
				claims:      `{"nbf":true}`,
				expectedErr: "invalid type bool used for \"nbf\"",
			},
			{
				name:        "Invalid iat type (object)",
				claims:      `{"iat":{"not":"number"}}`,
				expectedErr: "invalid type map[string]interface {} used for \"iat\"",
			},
			{
				name:        "Valid exp as float64",
				claims:      `{"exp":1234567890.5}`,
				expectedErr: "", // Should not error
			},
			{
				name:        "Valid nbf as int64",
				claims:      `{"nbf":1234567890}`,
				expectedErr: "", // Should not error
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				header := base64url.Encode([]byte(`{"alg":"none"}`))
				payload := base64url.Encode([]byte(test.claims))
				jwtString := header + "." + payload + "."

				_, err := jwt.Parse(jwtString)
				if test.expectedErr != "" {
					if err == nil || !strings.Contains(err.Error(), test.expectedErr) {
						t.Fatalf("jwt.Parse() error = %v, want error containing %q", err, test.expectedErr)
					}
				} else {
					if err != nil {
						t.Fatalf("jwt.Parse() error = %v", err)
					}
				}
			})
		}
	})
}

// TestSecurityEdgeCases tests additional security edge cases not covered in the main security test
func TestSecurityEdgeCases(t *testing.T) {
	t.Run("Header Parameter Security", func(t *testing.T) {
		// Test critical header parameter edge cases
		tests := []struct {
			name        string
			headerJson  string
			shouldError bool
			errorCheck  func(*testing.T, error)
		}{
			{
				name:        "Missing algorithm header",
				headerJson:  `{"typ":"JWT"}`,
				shouldError: true,
				errorCheck: func(t *testing.T, err error) {
					if !errors.Is(err, jwt.ErrInvalidToken) {
						t.Fatalf("error = %v, want %v", err, jwt.ErrInvalidToken)
					}
				},
			},
			{
				name:        "Null algorithm header",
				headerJson:  `{"alg":null,"typ":"JWT"}`,
				shouldError: true,
				errorCheck: func(t *testing.T, err error) {
					if !errors.Is(err, jwt.ErrInvalidToken) {
						t.Fatalf("error = %v, want %v", err, jwt.ErrInvalidToken)
					}
				},
			},
			{
				name:        "Case sensitivity in algorithm",
				headerJson:  `{"alg":"none","typ":"jwt"}`, // Use "none" algorithm for empty signature
				shouldError: false,                        // typ case shouldn't matter for parsing
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				header := base64url.Encode([]byte(tt.headerJson))
				payload := base64url.Encode([]byte(`{"sub":"test"}`))
				jwtString := header + "." + payload + "."

				// Whatever Parse makes of the header, a Verifier refuses it:
				// there is no usable algorithm, or it is "none".
				requireRefused(t, sigOnlyVerifier(testHMACSecretKey, jwa.HS256, jwa.None), jwtString, jwt.ErrFormat)

				_, parseErr := jwt.Parse(jwtString)
				// Parse only decodes, so it may well accept what the Verifier
				// refuses; when it does refuse, it must say so with ErrInvalidToken.
				if parseErr != nil && tt.shouldError {
					tt.errorCheck(t, parseErr)
				} else if parseErr != nil {
					t.Fatalf("jwt.Parse() error = %v", parseErr)
				}
			})
		}
	})

	t.Run("Large Payload Handling", func(t *testing.T) {
		// Test with a reasonably large payload to ensure no buffer overflows
		largeClaims := make(jwt.ClaimsSet)
		for i := 0; i < 1000; i++ {
			largeClaims[string(rune('a'+i%26))+string(rune('a'+(i/26)%26))] = strings.Repeat("x", 100)
		}

		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.HS256,
			},
			largeClaims,
			testHMACSecretKey,
		)

		// Parse the large token
		parsed, err := jwt.Parse(token.String())
		if err != nil {
			t.Fatalf("jwt.Parse() error = %v", err)
		}
		if parsed == nil {
			t.Fatal("parsed = nil, want non-nil")
		}

		// The default size bound refuses it; a raised bound accepts it.
		verifier := sigOnlyVerifier(testHMACSecretKey, jwa.HS256)
		requireRefused(t, verifier, token.String(), jwt.ErrFormat)
		verifier.MaxSize = 1 << 20
		if err := verifyToken(verifier, token.String()); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("Unicode and Special Characters", func(t *testing.T) {
		// Test with unicode and special characters in claims
		claims := jwt.ClaimsSet{
			jwt.Subject: "test-用户-🔐",
			jwt.Issuer:  "https://example.com/测试",
			"custom":    "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?",
			"unicode":   "emoji: 🚀🔒🛡️ chinese: 你好世界 arabic: مرحبا بالعالم",
		}

		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.HS256,
			},
			claims,
			testHMACSecretKey,
		)

		// Parse and verify
		parsed, err := jwt.Parse(token.String())
		if err != nil {
			t.Fatalf("jwt.Parse() error = %v", err)
		}
		if parsed.Claims[jwt.Subject] != claims[jwt.Subject] {
			t.Fatalf("parsed.Claims[jwt.Subject] = %v, want %v", parsed.Claims[jwt.Subject], claims[jwt.Subject])
		}
		if parsed.Claims[jwt.Issuer] != claims[jwt.Issuer] {
			t.Fatalf("parsed.Claims[jwt.Issuer] = %v, want %v", parsed.Claims[jwt.Issuer], claims[jwt.Issuer])
		}

		if err := verifyToken(sigOnlyVerifier(testHMACSecretKey, jwa.HS256), token.String()); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("Empty and Whitespace Claims", func(t *testing.T) {
		claims := jwt.ClaimsSet{
			jwt.Subject:  "",          // Empty string
			jwt.Issuer:   "   ",       // Whitespace only
			"empty":      "",          // Empty custom claim
			"whitespace": "\t\n\r   ", // Various whitespace
		}

		token := testToken(t,
			header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.HS256,
			},
			claims,
			testHMACSecretKey,
		)

		parsed, err := jwt.Parse(token.String())
		if err != nil {
			t.Fatalf("jwt.Parse() error = %v", err)
		}
		if parsed.Claims[jwt.Subject] != "" {
			t.Fatalf("parsed.Claims[jwt.Subject] = %q, want %q", parsed.Claims[jwt.Subject], "")
		}
		if parsed.Claims[jwt.Issuer] != "   " {
			t.Fatalf("parsed.Claims[jwt.Issuer] = %q, want %q", parsed.Claims[jwt.Issuer], "   ")
		}

		if err := verifyToken(sigOnlyVerifier(testHMACSecretKey, jwa.HS256), token.String()); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})
}

// TestNoneAlgorithmCompliance tests that the "none" algorithm is refused.
// The Verifier has no switch to allow it, so every shape of unsecured JWT
// (RFC 7519 §6) is refused, with or without "none" in the algorithm list.
func TestNoneAlgorithmCompliance(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)
	tests := []struct {
		name      string
		signature []byte
	}{
		{"None with empty signature", nil},
		{"None with non-empty signature", []byte("signature")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := rawToken(t,
				header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.None},
				jwt.ClaimsSet{jwt.Subject: "test"}, tt.signature)

			requireRefused(t, sigOnlyVerifier(rsaKeyPair.public), token, jwt.ErrFormat)
			requireRefused(t, sigOnlyVerifier(rsaKeyPair.public, jwa.None), token, jwt.ErrFormat)
			requireRefused(t, sigOnlyVerifier(nil, jwa.None), token, jwt.ErrFormat)
		})
	}
}
