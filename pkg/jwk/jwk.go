package jwk

import (
	"crypto/ed25519"
	"fmt"

	"github.com/picatz/jose/internal/base64url"
)

// https://datatracker.ietf.org/doc/html/rfc7517#section-4
type (
	ParameterName = string

	RSA       = ParameterName
	ECDSA     = ParameterName
	Symmetric = ParameterName
)

const (
	KeyType              ParameterName = "kty"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
	PublicKeyUse         ParameterName = "use"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
	KeyOperations        ParameterName = "key_ops"  // https://datatracker.ietf.org/doc/html/rfc7517#section-4.3
	Algorithm            ParameterName = "alg"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
	KeyID                ParameterName = "kid"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.5
	X509URL              ParameterName = "x5u"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.6
	X509CertificateChain ParameterName = "x5c"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
	X509SHA1Thumbprint   ParameterName = "x5t"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.8
	X509SHA256Thumbprint ParameterName = "x5t#S256" // https://datatracker.ietf.org/doc/html/rfc7517#section-4.9

	// K is the symmetric key value within a JWK.
	// https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.3
	K Symmetric = "k"

	// Curve is the curve value within an ECDSA JWK, such as "P-256".
	// https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.3
	Curve ECDSA = "crv"
	X     ECDSA = "x" // X is the x-coordinate for the elliptic curve point.
	Y     ECDSA = "y" // Y is the y-coordinate for the elliptic curve point.

	N RSA = "n" // N is the RSA public modulus value.
	E RSA = "e" // E is the RSA public exponent value.
	D RSA = "d" // D is the RSA private exponent value.
)

// Value is a JSON object containing the parameters describing
// the cryptographic operations and parameters employed.
//
// https://datatracker.ietf.org/doc/html/rfc7517#section-4
type Value = map[ParameterName]any

// Validate checks that the required parameters are present for
// the given key type, and that the values are valid. It accepts "EC", "RSA",
// "OKP" (RFC 8037) and "oct" keys.
func Validate(v Value) error {
	_, ok := v[KeyType]
	if !ok {
		return fmt.Errorf("missing required parameter %q", KeyType)
	}

	switch v[KeyType] {
	case "EC":
		curveValue, ok := v[Curve]
		if !ok {
			return fmt.Errorf("missing required parameter %q", Curve)
		}

		if curve, ok := curveValue.(string); ok {
			switch curve {
			case "P-256":
				// ok
			case "P-384":
				// ok
			case "P-521":
				// ok
			default:
				return fmt.Errorf("invalid curve %q", curve)
			}
		} else {
			return fmt.Errorf("invalid curve type %T", curveValue)
		}

		xValue, ok := v[X]
		if !ok {
			return fmt.Errorf("missing required parameter %q", X)
		}

		if x, ok := xValue.(string); ok {
			_, err := base64url.Decode(x)
			if err != nil {
				return fmt.Errorf("invalid base64 encoding for %q: %w", X, err)
			}
		} else {
			return fmt.Errorf("invalid type for %q", X)
		}

		yValue, ok := v[Y]
		if !ok {
			return fmt.Errorf("missing required parameter %q", Y)
		}

		if y, ok := yValue.(string); ok {
			_, err := base64url.Decode(y)
			if err != nil {
				return fmt.Errorf("invalid base64 encoding for %q: %w", Y, err)
			}
		} else {
			return fmt.Errorf("invalid type for %q", Y)
		}
	case "RSA":
		nValue, ok := v[N]
		if !ok {
			return fmt.Errorf("missing required parameter %q", N)
		}

		if n, ok := nValue.(string); ok {
			_, err := base64url.Decode(n)
			if err != nil {
				return fmt.Errorf("invalid base64 encoding for %q: %w", N, err)
			}
		} else {
			return fmt.Errorf("invalid type for %q", N)
		}

		eValue, ok := v[E]
		if !ok {
			return fmt.Errorf("missing required parameter %q", E)
		}

		if e, ok := eValue.(string); ok {
			_, err := base64url.Decode(e)
			if err != nil {
				return fmt.Errorf("invalid base64 encoding for %q: %w", E, err)
			}
		} else {
			return fmt.Errorf("invalid type for %q", E)
		}

		dValue, ok := v[D]
		if ok { // optional
			if d, ok := dValue.(string); ok {
				_, err := base64url.Decode(d)
				if err != nil {
					return fmt.Errorf("invalid base64 encoding for %q: %w", D, err)
				}
			} else {
				return fmt.Errorf("invalid type for %q", D)
			}
		}
	case KeyTypeOKP:
		if IsPrivate(v) {
			if _, err := PrivateKey(v); err != nil {
				return err
			}
		} else if _, err := PublicKey(v); err != nil {
			return err
		}
	case KeyTypeOct:
		if _, err := member(v, K); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown key type %q", v[KeyType])
	}

	return nil
}

// RSAValues returns the values for the RSA key type.
func RSAValues(v Value) (n, e, d string, err error) {
	if v[KeyType] != "RSA" {
		err = fmt.Errorf("JWK value is not RSA")
		return
	}

	if nValue, ok := v[N]; ok {
		n = fmt.Sprintf("%v", nValue)
	} else {
		err = fmt.Errorf("no %q set", N)
		return
	}

	if eValue, ok := v[E]; ok {
		e = fmt.Sprintf("%v", eValue)
	} else {
		err = fmt.Errorf("no %q set", E)
		return
	}

	if dValue, ok := v[D]; ok {
		d = fmt.Sprintf("%v", dValue)
	}
	// d can be empty

	return
}

// ECDSAValues returns the values for the ECDSA key type.
func ECDSAValues(v Value) (crv, x, y string, err error) {
	if v[KeyType] != "EC" {
		err = fmt.Errorf("JWK value is not EC")
		return
	}

	crv = fmt.Sprintf("%v", v[Curve])
	if crv == "" {
		err = fmt.Errorf("no %q set", Curve)
		return
	}

	x = fmt.Sprintf("%v", v[X])
	if x == "" {
		err = fmt.Errorf("no %q set", X)
		return
	}

	y = fmt.Sprintf("%v", v[Y])
	if y == "" {
		err = fmt.Errorf("no %q set", Y)
		return
	}

	return
}

// Ed25519Values returns the values for the Ed25519 key type.
func Ed25519Values(v Value) (x string, err error) {
	if v[KeyType] != "OKP" {
		err = fmt.Errorf("JWK value is not OKP")
		return
	}

	if v[Curve] != "Ed25519" {
		err = fmt.Errorf("JWK value is not Ed25519")
		return
	}

	x = fmt.Sprintf("%v", v[X])
	if x == "" {
		err = fmt.Errorf("no %q set", X)
		return
	}

	return
}

// SymmetricKey returns the symmetric key.
func SymmetricKey(v Value) (k string, err error) {
	k = fmt.Sprintf("%v", v[K])

	if k == "" {
		err = fmt.Errorf("no symmetric key value set")
	}

	return
}

// HMACSecretKey returns the HMAC secret key (symmetric key).
func HMACSecretKey(v Value) ([]byte, error) {
	key, err := SymmetricKey(v)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric key: %w", err)
	}
	return base64url.Decode(key)
}

// Ed25519PublicKey returns the Ed25519 public key, or an error if the
// key is not an Ed25519 public key.
func Ed25519PublicKey(v Value) (pkey ed25519.PublicKey, err error) {
	x, err := Ed25519Values(v)
	if err != nil {
		err = fmt.Errorf("failed to get Ed25519 values for public key: %w", err)
		return
	}

	xBytes, err := base64url.Decode(x)
	if err != nil {
		err = fmt.Errorf("failed to decode Ed25519 public key X: %w", err)
		return
	}

	// check the length of the key to make sure it is 32 bytes
	if len(xBytes) != ed25519.PublicKeySize {
		err = fmt.Errorf("invalid Ed25519 public key X length: %d", len(xBytes))
		return
	}

	pkey = xBytes

	return
}

// Set is a JWK set as defined in RFC 7517.
//
// https://datatracker.ietf.org/doc/html/rfc7517#section-5
type Set struct {
	// Keys is a list of JWK values.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-5.1
	Keys []Value `json:"keys"`
}

// Validate validates the JWK set, returning an error if any
// of the keys are invalid.
func (s *Set) Validate() error {
	if len(s.Keys) == 0 {
		return fmt.Errorf("no key values in JWK set")
	}

	for _, key := range s.Keys {
		err := Validate(key)
		if err != nil {
			return fmt.Errorf("key set validation error: %w", err)
		}
	}

	return nil
}

// Get returns the key that matches the given key id.
func (s *Set) Get(keyID string) (Value, error) {
	for _, key := range s.Keys {
		if key[KeyID] == keyID {
			return key, nil
		}
	}

	return nil, fmt.Errorf("key %q not found in set", keyID)
}
