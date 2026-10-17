package jwk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/picatz/jose/internal/strictjson"
)

// JWK member names.
//
// https://www.rfc-editor.org/rfc/rfc7517.html#section-4
const (
	KeyType                         = "kty"      // RFC 7517 §4.1
	PublicKeyUse                    = "use"      // RFC 7517 §4.2
	KeyOperations                   = "key_ops"  // RFC 7517 §4.3
	Algorithm                       = "alg"      // RFC 7517 §4.4
	KeyID                           = "kid"      // RFC 7517 §4.5
	X509URL                         = "x5u"      // RFC 7517 §4.6
	X509CertificateChain            = "x5c"      // RFC 7517 §4.7
	X509CertificateSHA1Thumbprint   = "x5t"      // RFC 7517 §4.8
	X509CertificateSHA256Thumbprint = "x5t#S256" // RFC 7517 §4.9
)

// Key type specific member names.
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6
const (
	// K is the symmetric key value of an "oct" key.
	K = "k"

	// Curve is the "crv" member of "EC" and "OKP" keys, such as "P-256".
	Curve = "crv"
	// X is the x-coordinate of an "EC" point, or the public key of an "OKP" key.
	X = "x"
	// Y is the y-coordinate of an "EC" point.
	Y = "y"

	// N is the RSA public modulus.
	N = "n"
	// E is the RSA public exponent.
	E = "e"
	// D is the private value: the RSA private exponent, the "EC" private
	// scalar or the "OKP" private key.
	D = "d"
)

// ErrFormat reports a JWK Set that is not a well-formed JSON object with a
// "keys" array, repeats a member name, or repeats a "kid".
var ErrFormat = errors.New("jwk: malformed key set")

// Key is a JSON Web Key: a JSON object holding the parameters of a
// cryptographic key. Index it with the member name constants, such as
// key[jwk.KeyID]. Use [PublicKey] and [PrivateKey] to turn one into a
// [crypto.PublicKey] or [crypto.PrivateKey], and [PublicValue] for the reverse.
//
// https://www.rfc-editor.org/rfc/rfc7517.html#section-4
type Key map[string]any

// Validate checks that k is a well-formed key of a supported type: a key
// with private members must be a valid private key, and any other must be a
// valid public key, with the same checks as [PrivateKey] and [PublicKey]
// (points on the curve, bounded RSA sizes). An "oct" key must hold a
// non-empty base64url "k".
//
// Errors wrap [ErrInvalidKey].
func Validate(k Key) error {
	kty, err := stringMember(k, KeyType)
	if err != nil {
		return err
	}
	if kty == KeyTypeOct {
		b, err := member(k, K)
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return invalid("%q is empty", K)
		}
		return nil
	}
	if IsPrivate(k) {
		_, err = PrivateKey(k)
	} else {
		_, err = PublicKey(k)
	}
	return err
}

// Set is a JWK Set.
//
// https://www.rfc-editor.org/rfc/rfc7517.html#section-5
type Set struct {
	// Keys is the "keys" array.
	//
	// https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1
	Keys []Key `json:"keys"`
}

// ParseSet parses a JWK Set. It refuses JSON that repeats a member name at
// any depth, and a set in which two keys share a "kid", since either would
// let two parsers select different keys from the same bytes. It does not
// validate the keys themselves; see [Set.Validate].
//
// Errors wrap [ErrFormat].
func ParseSet(data []byte) (*Set, error) {
	if err := strictjson.CheckDuplicates(data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	var raw struct {
		Keys *[]Key `json:"keys"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if raw.Keys == nil {
		return nil, fmt.Errorf("%w: missing %q", ErrFormat, "keys")
	}
	set := &Set{Keys: *raw.Keys}
	if err := set.checkKeyIDs(); err != nil {
		return nil, err
	}
	return set, nil
}

func (s *Set) checkKeyIDs() error {
	seen := map[string]bool{}
	for _, key := range s.Keys {
		kid, ok := key[KeyID].(string)
		if !ok {
			continue
		}
		if seen[kid] {
			return fmt.Errorf("%w: duplicate kid %q", ErrFormat, kid)
		}
		seen[kid] = true
	}
	return nil
}

// Validate checks that the set has at least one key, that no "kid" repeats,
// and that every key passes [Validate].
func (s *Set) Validate() error {
	if len(s.Keys) == 0 {
		return fmt.Errorf("%w: no keys", ErrFormat)
	}
	if err := s.checkKeyIDs(); err != nil {
		return err
	}
	for i, key := range s.Keys {
		if err := Validate(key); err != nil {
			return fmt.Errorf("jwk: key %d: %w", i, err)
		}
	}
	return nil
}

// Get returns the key whose "kid" is kid.
func (s *Set) Get(kid string) (Key, bool) {
	for _, key := range s.Keys {
		if id, ok := key[KeyID].(string); ok && id == kid {
			return key, true
		}
	}
	return nil, false
}
