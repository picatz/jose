// Package thumbprint computes JSON Web Key (JWK) Thumbprints as defined in
// RFC 7638, including OKP keys from RFC 8037.
//
// A thumbprint is a stable identifier for a public key. It is commonly used
// as a "kid" value and as the DPoP "jkt" confirmation (RFC 9449 §6.1).
package thumbprint

import (
	"crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/jwk"
)

var (
	ErrInvalidKey = errors.New("thumbprint: invalid key")
)

// requiredMembers lists, per key type, the members that make up the
// thumbprint input, already in lexicographic order.
//
// https://www.rfc-editor.org/rfc/rfc7638.html#section-3.2
// https://www.rfc-editor.org/rfc/rfc8037.html#section-2
var requiredMembers = map[string][]string{
	jwk.KeyTypeEC:  {jwk.Curve, jwk.KeyType, jwk.X, jwk.Y},
	jwk.KeyTypeRSA: {jwk.E, jwk.KeyType, jwk.N},
	jwk.KeyTypeOKP: {jwk.Curve, jwk.KeyType, jwk.X},
	jwk.KeyTypeOct: {jwk.K, jwk.KeyType},
}

// Generate returns the JWK Thumbprint for the given JWK following
// the steps defined in RFC 7638. A zero hash selects SHA-256.
//
// Only the required members for the key's type contribute; all others,
// including private members, are ignored. Each required member must be a
// string that needs no JSON escaping, which holds for every valid JWK.
//
// https://www.rfc-editor.org/rfc/rfc7638.html#section-3
func Generate(value jwk.Value, h crypto.Hash) ([]byte, error) {
	kty, ok := value[jwk.KeyType].(string)
	if !ok {
		return nil, ErrInvalidKey
	}
	members, ok := requiredMembers[kty]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported key type %q", ErrInvalidKey, kty)
	}

	// 1. Construct a JSON object [RFC7159] containing only the required
	// members of a JWK representing the key and with no whitespace or
	// line breaks before or after any syntactic elements and with the
	// required members ordered lexicographically by the Unicode
	// [UNICODE] code points of the member names.
	var b strings.Builder
	b.WriteByte('{')
	for i, name := range members {
		v, ok := value[name].(string)
		if !ok || v == "" {
			return nil, fmt.Errorf("%w: missing or non-string %q", ErrInvalidKey, name)
		}
		if needsEscape(v) {
			return nil, fmt.Errorf("%w: %q contains characters that need JSON escaping", ErrInvalidKey, name)
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(name)
		b.WriteString(`":"`)
		b.WriteString(v)
		b.WriteByte('"')
	}
	b.WriteByte('}')

	// 2. Hash the octets of the UTF-8 representation of this JSON object
	// with a cryptographic hash function H. If none is specified, SHA-256
	// is used.
	if h == 0 {
		h = crypto.SHA256
	}
	if !h.Available() {
		return nil, fmt.Errorf("thumbprint: hash %v is not available", h)
	}
	hash := h.New()
	hash.Write([]byte(b.String()))
	return hash.Sum(nil), nil
}

// needsEscape reports whether s would be altered by JSON string encoding.
// Required members are base64url values or short ASCII names, so any such
// character means the JWK is malformed.
func needsEscape(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == '"' || r == '\\' || r > 0x7e {
			return true
		}
	}
	return false
}

// GenerateString returns the JWK Thumbprint for the given JWK following
// the steps defined in RFC 7638 as a base64url string.
func GenerateString(value jwk.Value, h crypto.Hash) (string, error) {
	thumbprint, err := Generate(value, h)
	if err != nil {
		return "", err
	}

	return base64.Encode(thumbprint)
}

// FromPublicKey returns the base64url SHA-256 JWK Thumbprint of a public
// key, a private key or a [crypto.Signer]. It canonicalizes the key with
// [jwk.PublicValue] first, so the result does not depend on how a JWK was
// spelled. This is the value DPoP calls "jkt".
//
// https://www.rfc-editor.org/rfc/rfc7638.html#section-3
// https://www.rfc-editor.org/rfc/rfc9449.html#section-6.1
func FromPublicKey(key any) (string, error) {
	value, err := jwk.PublicValue(key)
	if err != nil {
		return "", err
	}
	return GenerateString(value, crypto.SHA256)
}

// URNPrefix starts a SHA-256 JWK Thumbprint URI (RFC 9278), the form a JWT
// uses to name a key in a string claim such as "iss" or "sub".
//
// https://www.rfc-editor.org/rfc/rfc9278.html#section-3
const URNPrefix = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"

// URN returns the SHA-256 JWK Thumbprint URI of a public key, a private key
// or a [crypto.Signer], such as
// "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".
//
// https://www.rfc-editor.org/rfc/rfc9278.html
func URN(key any) (string, error) {
	jkt, err := FromPublicKey(key)
	if err != nil {
		return "", err
	}
	return URNPrefix + jkt, nil
}
