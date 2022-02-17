package base64

import (
	"encoding/base64"
	"strings"
)

// Decode returns the base64 decoded bytes from the given input.
func Decode(input string) ([]byte, error) {
	if l := len(input) % 4; l > 0 {
		input += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(input)
}

// Encode returns the base64 encoded string from the given input.
func Encode(input []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(input), "=")
}
