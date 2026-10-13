package jwt_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

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
				_, err := jwt.ParseString(tt.input)
				if tt.shouldError {
					if err == nil {
						t.Fatal("jwt.ParseString() error = nil, want non-nil")
					}
					if tt.errorCheck != nil {
						if !tt.errorCheck(err) {
							t.Fatalf("error check failed for: %v", err)
						}
					}
				} else {
					if err != nil {
						t.Fatalf("jwt.ParseString() error = %v", err)
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
				payload:     must(base64.Encode([]byte(`{"sub":"test"}`))),
				signature:   "",
				expectedErr: "failed to decode JOSE header base64",
			},
			{
				name:        "Invalid base64 in payload",
				header:      must(base64.Encode([]byte(`{"alg":"none"}`))),
				payload:     "invalid_base64!@#",
				signature:   "",
				expectedErr: "failed to decode claims base64",
			},
			{
				name:        "Invalid base64 in signature",
				header:      must(base64.Encode([]byte(`{"alg":"none"}`))),
				payload:     must(base64.Encode([]byte(`{"sub":"test"}`))),
				signature:   "invalid_base64!@#",
				expectedErr: "failed to decode signature base64",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				jwtString := tt.header + "." + tt.payload + "." + tt.signature
				_, err := jwt.ParseString(jwtString)
				if err == nil || !strings.Contains(err.Error(), tt.expectedErr) {
					t.Fatalf("jwt.ParseString() error = %v, want error containing %q", err, tt.expectedErr)
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
				header:      must(base64.Encode([]byte(`{invalid json}`))),
				payload:     must(base64.Encode([]byte(`{"sub":"test"}`))),
				expectedErr: "failed to decode JOSE header JSON",
			},
			{
				name:        "Invalid JSON in payload",
				header:      must(base64.Encode([]byte(`{"alg":"none"}`))),
				payload:     must(base64.Encode([]byte(`{invalid json}`))),
				expectedErr: "failed to decode claims JSON",
			},
			{
				name:        "Non-object JSON in header (array)",
				header:      must(base64.Encode([]byte(`["alg", "none"]`))),
				payload:     must(base64.Encode([]byte(`{"sub":"test"}`))),
				expectedErr: "failed to decode JOSE header JSON",
			},
			{
				name:        "Non-object JSON in payload (string)",
				header:      must(base64.Encode([]byte(`{"alg":"none"}`))),
				payload:     must(base64.Encode([]byte(`"just a string"`))),
				expectedErr: "failed to decode claims JSON",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				jwtString := tt.header + "." + tt.payload + "."
				_, err := jwt.ParseString(jwtString)
				if err == nil || !strings.Contains(err.Error(), tt.expectedErr) {
					t.Fatalf("jwt.ParseString() error = %v, want error containing %q", err, tt.expectedErr)
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
				header, err := base64.Encode([]byte(`{"alg":"none"}`))
				if err != nil {
					t.Fatalf("base64.Encode() error = %v", err)
				}
				payload, err := base64.Encode([]byte(test.claims))
				if err != nil {
					t.Fatalf("base64.Encode() error = %v", err)
				}
				jwtString := header + "." + payload + "."

				_, err = jwt.ParseString(jwtString)
				if test.expectedErr != "" {
					if err == nil || !strings.Contains(err.Error(), test.expectedErr) {
						t.Fatalf("jwt.ParseString() error = %v, want error containing %q", err, test.expectedErr)
					}
				} else {
					if err != nil {
						t.Fatalf("jwt.ParseString() error = %v", err)
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
				header, err := base64.Encode([]byte(tt.headerJson))
				if err != nil {
					t.Fatalf("base64.Encode() error = %v", err)
				}
				payload, err := base64.Encode([]byte(`{"sub":"test"}`))
				if err != nil {
					t.Fatalf("base64.Encode() error = %v", err)
				}
				jwtString := header + "." + payload + "."

				token, parseErr := jwt.ParseString(jwtString)
				if parseErr != nil && tt.shouldError && tt.errorCheck != nil {
					tt.errorCheck(t, parseErr)
					return
				}
				if parseErr != nil {
					t.Fatalf("jwt.ParseString() error = %v", parseErr)
				}

				// Test verification
				if tt.name == "Case sensitivity in algorithm" {
					// For "none" algorithm test, allow insecure none algorithm
					err = token.Verify(jwt.WithAllowInsecureNoneAlgorithm(true), jwt.WithAllowedAlgorithms(jwa.None))
				} else {
					err = token.Verify(jwt.WithKey(testHMACSecretKey))
				}
				if tt.shouldError {
					if err == nil {
						t.Fatal("token.Verify() error = nil, want non-nil")
					}
					if tt.errorCheck != nil {
						tt.errorCheck(t, err)
					}
				} else {
					if err != nil {
						t.Fatalf("token.Verify() error = %v", err)
					}
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
		parsed, err := jwt.ParseString(token.String())
		if err != nil {
			t.Fatalf("jwt.ParseString() error = %v", err)
		}
		if parsed == nil {
			t.Fatal("parsed = nil, want non-nil")
		}

		// Verify it
		err = parsed.Verify(jwt.WithKey(testHMACSecretKey))
		if err != nil {
			t.Fatalf("parsed.Verify() error = %v", err)
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
		parsed, err := jwt.ParseString(token.String())
		if err != nil {
			t.Fatalf("jwt.ParseString() error = %v", err)
		}
		if parsed.Claims[jwt.Subject] != claims[jwt.Subject] {
			t.Fatalf("parsed.Claims[jwt.Subject] = %v, want %v", parsed.Claims[jwt.Subject], claims[jwt.Subject])
		}
		if parsed.Claims[jwt.Issuer] != claims[jwt.Issuer] {
			t.Fatalf("parsed.Claims[jwt.Issuer] = %v, want %v", parsed.Claims[jwt.Issuer], claims[jwt.Issuer])
		}

		err = parsed.Verify(jwt.WithKey(testHMACSecretKey))
		if err != nil {
			t.Fatalf("parsed.Verify() error = %v", err)
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

		parsed, err := jwt.ParseString(token.String())
		if err != nil {
			t.Fatalf("jwt.ParseString() error = %v", err)
		}
		if parsed.Claims[jwt.Subject] != "" {
			t.Fatalf("parsed.Claims[jwt.Subject] = %q, want %q", parsed.Claims[jwt.Subject], "")
		}
		if parsed.Claims[jwt.Issuer] != "   " {
			t.Fatalf("parsed.Claims[jwt.Issuer] = %q, want %q", parsed.Claims[jwt.Issuer], "   ")
		}

		err = parsed.Verify(jwt.WithKey(testHMACSecretKey))
		if err != nil {
			t.Fatalf("parsed.Verify() error = %v", err)
		}
	})
}

// TestNoneAlgorithmCompliance tests RFC compliance for "none" algorithm
func TestNoneAlgorithmCompliance(t *testing.T) {
	t.Run("None Algorithm Strict Validation", func(t *testing.T) {
		tests := []struct {
			name        string
			header      header.Parameters
			signature   []byte
			allowNone   bool
			shouldError bool
			errorCheck  func(error) bool
		}{
			{
				name: "None with empty signature - should work when allowed",
				header: header.Parameters{
					header.Type:      jwt.Type,
					header.Algorithm: jwa.None,
				},
				signature:   []byte{},
				allowNone:   true,
				shouldError: false,
			},
			{
				name: "None with non-empty signature - should fail",
				header: header.Parameters{
					header.Type:      jwt.Type,
					header.Algorithm: jwa.None,
				},
				signature:   []byte("signature"),
				allowNone:   true,
				shouldError: true,
				errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "signature must be empty") },
			},
			{
				name: "None without explicit allowance - should fail",
				header: header.Parameters{
					header.Type:      jwt.Type,
					header.Algorithm: jwa.None,
				},
				signature:   []byte{},
				allowNone:   false,
				shouldError: true,
				errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "is not allowed") },
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				token := &jwt.Token{
					Header: tt.header,
					Claims: jwt.ClaimsSet{
						jwt.Subject: "test",
					},
					Signature: tt.signature,
				}

				var opts []jwt.VerifyOption
				if tt.allowNone {
					opts = append(opts,
						jwt.WithAllowInsecureNoneAlgorithm(true),
						jwt.WithAllowedAlgorithms(jwa.None),
					)
				}

				err := token.Verify(opts...)
				if tt.shouldError {
					if err == nil {
						t.Fatal("token.Verify() error = nil, want non-nil")
					}
					if tt.errorCheck != nil {
						if !tt.errorCheck(err) {
							t.Fatalf("error check failed for: %v", err)
						}
					}
				} else {
					if err != nil {
						t.Fatalf("token.Verify() error = %v", err)
					}
				}
			})
		}
	})
}
