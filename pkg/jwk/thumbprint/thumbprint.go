package thumbprint

import (
	"bytes"
	"crypto"
	"errors"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/jwk"
)

var (
	ErrInvalidKey = errors.New("thumbprint: invalid key")
)

var requiredLexicographically = []string{"crv", "e", "kty", "n", "x", "y"}

// Generate returns the JWK Thumbprint for the given JWK following
// the steps defined in RFC 7638.
func Generate(value jwk.Value, h crypto.Hash) ([]byte, error) {
	// 1. Construct a JSON object [RFC7159] containing only the required
	// members of a JWK representing the key and with no whitespace or
	// line breaks before or after any syntactic elements and with the
	// required members ordered lexicographically by the Unicode
	// [UNICODE] code points of the member names.
	//
	// (This JSON object is itself a legal JWK representation of the key.)
	subset := jwk.Value{}

	for _, key := range requiredLexicographically {
		if _, ok := value[key]; ok {
			subset[key] = value[key]
		}
	}

	// Ensure the key type is included.
	if _, ok := subset["kty"]; !ok {
		return nil, ErrInvalidKey
	}

	// Ensure the key type is valid.
	switch subset["kty"] {
	case "RSA":
		// Ensure the modulus is included.
		if _, ok := subset["n"]; !ok {
			return nil, ErrInvalidKey
		}

		// Ensure the exponent is included.
		if _, ok := subset["e"]; !ok {
			return nil, ErrInvalidKey
		}

		// Do not allow any other values.
		if len(subset) > 3 {
			return nil, ErrInvalidKey
		}
	case "EC":
		// Ensure the curve is included.
		if _, ok := subset["crv"]; !ok {
			return nil, ErrInvalidKey
		}

		// Ensure the x coordinate is included.
		if _, ok := subset["x"]; !ok {
			return nil, ErrInvalidKey
		}

		// Ensure the y coordinate is included.
		if _, ok := subset["y"]; !ok {
			return nil, ErrInvalidKey
		}

		// Do not allow any other values.
		if len(subset) > 4 {
			return nil, ErrInvalidKey
		}
	default:
		return nil, ErrInvalidKey
	}

	// Get a lexical representation of the JSON object, we cannot
	// use the standard library's json.Marshal because it does not
	// guarantee the order of the keys.
	b := bytes.NewBuffer(nil)

	b.WriteRune('{')

	for i, key := range requiredLexicographically {
		if _, ok := subset[key]; ok {
			if i > 0 && b.Len() > 1 {
				b.WriteRune(',')
			}

			b.WriteRune('"')
			b.WriteString(key)
			b.WriteRune('"')
			b.WriteRune(':')

			switch v := subset[key].(type) {
			case string:
				b.WriteRune('"')
				b.WriteString(v)
				b.WriteRune('"')
			default:
				b.WriteString(v.(string))
			}
		}
	}

	b.WriteRune('}')

	// 2. Hash the octets of the UTF-8 representation of this JSON object
	// with a cryptographic hash function H.
	//
	// For example, SHA-256 might be used as H. If none is specified,
	// SHA-256 is used; this is indicated in the algorithm header parameter
	// of the resulting JWK Thumbprint by the value "SHA-256".
	if h == 0 {
		h = crypto.SHA256
	}

	hash := h.New()

	_, err := hash.Write(b.Bytes())
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// GenerateString returns the JWK Thumbprint for the given JWK following
// the steps defined in RFC 7638 as a base64 encoded string.
func GenerateString(value jwk.Value, h crypto.Hash) (string, error) {
	thumbprint, err := Generate(value, h)
	if err != nil {
		return "", err
	}

	return base64.Encode(thumbprint)
}
