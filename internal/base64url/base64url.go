// Package base64url encodes and decodes the unpadded base64url form used
// throughout JOSE, as defined in RFC 4648 Section 5 and RFC 7515 Section 2.
//
// It is a thin wrapper over [encoding/base64.RawURLEncoding] in strict mode:
// padding is rejected and the unused trailing bits of the final character
// must be zero, and the CR and LF that [encoding/base64] otherwise skips are
// rejected, so every value has exactly one valid encoding.
//
// http://www.rfc-editor.org/rfc/rfc4648#section-5
package base64url

import (
	"encoding/base64"
	"fmt"
	"strings"
)

var enc = base64.RawURLEncoding.Strict()

// Encode returns the unpadded base64url encoding of b. Empty input yields an
// empty string.
func Encode(b []byte) string {
	return enc.EncodeToString(b)
}

// Decode returns the bytes encoded by the unpadded base64url string s.
// Empty input yields empty output. A CR or LF anywhere is an error.
func Decode(s string) ([]byte, error) {
	// The standard decoder silently skips these, so one value would have
	// several valid strings.
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("base64url: line break in input")
	}
	b, err := enc.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return b, nil
}
