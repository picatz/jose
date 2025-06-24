package jwt_test

import (
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/stretchr/testify/require"
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
				errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "incorrect number of JWT parts") },
			},
			{
				name:        "One period only - invalid JWT structure",
				input:       "header.payload",
				shouldError: true,
				errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "incorrect number of JWT parts") },
			},
			{
				name:        "Empty string - invalid JWT",
				input:       "",
				shouldError: true,
				errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "incorrect number of JWT parts") },
			},
			{
				name:        "Too many periods - extra content treated as part of signature",
				input:       "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.extra.periods.here",
				shouldError: true, // This should fail because "extra.periods.here" is not valid base64
				errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "failed to decode signature base64") },
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
					require.Error(t, err)
					if tt.errorCheck != nil {
						require.True(t, tt.errorCheck(err), "Error check failed for: %v", err)
					}
				} else {
					require.NoError(t, err)
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
				payload:     base64.Encode([]byte(`{"sub":"test"}`)),
				signature:   "",
				expectedErr: "failed to decode JOSE header base64",
			},
			{
				name:        "Invalid base64 in payload",
				header:      base64.Encode([]byte(`{"alg":"none"}`)),
				payload:     "invalid_base64!@#",
				signature:   "",
				expectedErr: "failed to decode claims base64",
			},
			{
				name:        "Invalid base64 in signature",
				header:      base64.Encode([]byte(`{"alg":"none"}`)),
				payload:     base64.Encode([]byte(`{"sub":"test"}`)),
				signature:   "invalid_base64!@#",
				expectedErr: "failed to decode signature base64",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				jwtString := tt.header + "." + tt.payload + "." + tt.signature
				_, err := jwt.ParseString(jwtString)
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
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
				header:      base64.Encode([]byte(`{invalid json}`)),
				payload:     base64.Encode([]byte(`{"sub":"test"}`)),
				expectedErr: "failed to decode JOSE header JSON",
			},
			{
				name:        "Invalid JSON in payload",
				header:      base64.Encode([]byte(`{"alg":"none"}`)),
				payload:     base64.Encode([]byte(`{invalid json}`)),
				expectedErr: "failed to decode claims JSON",
			},
			{
				name:        "Non-object JSON in header (array)",
				header:      base64.Encode([]byte(`["alg", "none"]`)),
				payload:     base64.Encode([]byte(`{"sub":"test"}`)),
				expectedErr: "failed to decode JOSE header JSON",
			},
			{
				name:        "Non-object JSON in payload (string)",
				header:      base64.Encode([]byte(`{"alg":"none"}`)),
				payload:     base64.Encode([]byte(`"just a string"`)),
				expectedErr: "failed to decode claims JSON",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				jwtString := tt.header + "." + tt.payload + "."
				_, err := jwt.ParseString(jwtString)
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
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

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				header := base64.Encode([]byte(`{"alg":"none"}`))
				payload := base64.Encode([]byte(tt.claims))
				jwtString := header + "." + payload + "."

				_, err := jwt.ParseString(jwtString)
				if tt.expectedErr != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tt.expectedErr)
				} else {
					require.NoError(t, err)
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
			errorCheck  func(error) bool
		}{
			{
				name:        "Missing algorithm header",
				headerJson:  `{"typ":"JWT"}`,
				shouldError: true,
				errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "paramater not found") },
			},
			{
				name:        "Null algorithm header",
				headerJson:  `{"alg":null,"typ":"JWT"}`,
				shouldError: true,
				errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "is not allowed") },
			},
			{
				name:        "Case sensitivity in algorithm",
				headerJson:  `{"alg":"HS256","typ":"jwt"}`, // lowercase typ
				shouldError: false,                         // typ case shouldn't matter for parsing
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				header := base64.Encode([]byte(tt.headerJson))
				payload := base64.Encode([]byte(`{"sub":"test"}`))
				jwtString := header + "." + payload + "."

				token, parseErr := jwt.ParseString(jwtString)
				if parseErr != nil && tt.shouldError && tt.errorCheck != nil {
					require.True(t, tt.errorCheck(parseErr))
					return
				}
				require.NoError(t, parseErr)

				// Test verification
				err := token.Verify(jwt.WithKey(testHMACSecretKey))
				if tt.shouldError {
					require.Error(t, err)
					if tt.errorCheck != nil {
						require.True(t, tt.errorCheck(err))
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
		require.NoError(t, err)
		require.NotNil(t, parsed)

		// Verify it
		err = parsed.Verify(jwt.WithKey(testHMACSecretKey))
		require.NoError(t, err)
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
		require.NoError(t, err)
		require.Equal(t, claims[jwt.Subject], parsed.Claims[jwt.Subject])
		require.Equal(t, claims[jwt.Issuer], parsed.Claims[jwt.Issuer])

		err = parsed.Verify(jwt.WithKey(testHMACSecretKey))
		require.NoError(t, err)
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
		require.NoError(t, err)
		require.Equal(t, "", parsed.Claims[jwt.Subject])
		require.Equal(t, "   ", parsed.Claims[jwt.Issuer])

		err = parsed.Verify(jwt.WithKey(testHMACSecretKey))
		require.NoError(t, err)
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
					require.Error(t, err)
					if tt.errorCheck != nil {
						require.True(t, tt.errorCheck(err), "Error check failed for: %v", err)
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})
}
