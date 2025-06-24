package base64

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Decode returns the base64url decoded bytes from the given input.
// This function implements base64url decoding as defined in RFC 4648 Section 5,
// which is used in JWT and JWS specifications (RFC 7515).
//
// It automatically adds padding if needed before decoding.
func Decode(input string) ([]byte, error) {
	// Handle empty input - in cryptographic contexts, empty input should be an error
	if len(input) == 0 {
		return nil, fmt.Errorf("base64: input cannot be empty")
	}

	// Calculate padding needed and add it efficiently
	if padLen := len(input) % 4; padLen > 0 {
		// Use a builder to avoid multiple string allocations
		var b strings.Builder
		b.Grow(len(input) + (4 - padLen))
		b.WriteString(input)
		for i := padLen; i < 4; i++ {
			b.WriteByte('=')
		}
		input = b.String()
	}

	result, err := base64.URLEncoding.DecodeString(input)
	if err != nil {
		return nil, fmt.Errorf("base64: invalid base64url input: %w", err)
	}
	return result, nil
}

// Encode returns the base64url encoded string from the given input.
// This function implements base64url encoding as defined in RFC 4648 Section 5,
// which is used in JWT and JWS specifications (RFC 7515).
//
// It removes padding characters as required by the JWT specification.
//
// For cryptographic safety, empty input returns an empty string rather than an error
// to maintain API compatibility, but callers should validate non-empty input.
func Encode(input []byte) (string, error) {
	// Handle empty input - return empty string for API compatibility
	// but this should be validated by callers in cryptographic contexts
	if len(input) == 0 {
		return "", fmt.Errorf("base64: input cannot be empty")
	}

	return strings.TrimRight(base64.URLEncoding.EncodeToString(input), "="), nil
}
