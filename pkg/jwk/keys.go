package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/picatz/jose/pkg/base64"
)

// Key type ("kty") values.
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1
// https://www.rfc-editor.org/rfc/rfc8037.html#section-2
const (
	KeyTypeEC    = "EC"
	KeyTypeRSA   = "RSA"
	KeyTypeOct   = "oct"
	KeyTypeOKP   = "OKP"
	CurveP256    = "P-256"
	CurveP384    = "P-384"
	CurveP521    = "P-521"
	CurveEd25519 = "Ed25519"
	CurveX25519  = "X25519"
)

// Private and supplementary RSA members.
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2
const (
	P  RSA = "p"
	Q  RSA = "q"
	DP RSA = "dp"
	DQ RSA = "dq"
	QI RSA = "qi"
	// OtherPrimes ("oth") describes multi-prime RSA keys, which this package
	// rejects.
	OtherPrimes RSA = "oth"
)

// ErrInvalidKey reports a JWK that is malformed, uses an unsupported key type
// or curve, or encodes a point or key that is not valid for its type.
var ErrInvalidKey = errors.New("jwk: invalid key")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidKey, fmt.Sprintf(format, args...))
}

// member returns the decoded base64url member name of v. Missing members,
// non-string values and empty strings are errors.
func member(v Value, name string) ([]byte, error) {
	raw, ok := v[name]
	if !ok {
		return nil, invalid("missing %q", name)
	}
	s, ok := raw.(string)
	if !ok {
		return nil, invalid("%q is %T, not a string", name, raw)
	}
	b, err := base64.Decode(s)
	if err != nil {
		return nil, invalid("%q is not base64url: %v", name, err)
	}
	return b, nil
}

func stringMember(v Value, name string) (string, error) {
	raw, ok := v[name]
	if !ok {
		return "", invalid("missing %q", name)
	}
	s, ok := raw.(string)
	if !ok {
		return "", invalid("%q is %T, not a string", name, raw)
	}
	return s, nil
}

// ellipticCurve maps a JOSE curve name to its NIST curve and the matching
// crypto/ecdh curve, which validates points.
func ellipticCurve(name string) (elliptic.Curve, ecdh.Curve, error) {
	switch name {
	case CurveP256:
		return elliptic.P256(), ecdh.P256(), nil
	case CurveP384:
		return elliptic.P384(), ecdh.P384(), nil
	case CurveP521:
		return elliptic.P521(), ecdh.P521(), nil
	default:
		return nil, nil, invalid("unsupported EC curve %q", name)
	}
}

// curveNameOf returns the JOSE name for a NIST curve.
func curveNameOf(curve elliptic.Curve) (string, error) {
	switch curve {
	case elliptic.P256():
		return CurveP256, nil
	case elliptic.P384():
		return CurveP384, nil
	case elliptic.P521():
		return CurveP521, nil
	default:
		return "", invalid("unsupported EC curve")
	}
}

// coordinate left-pads b to size bytes. Producers must emit full-length
// coordinates (RFC 7518 §6.2.1.2); older ones sometimes trimmed leading zero
// bytes, which is accepted on input but never produced.
func coordinate(b []byte, size int, name string) ([]byte, error) {
	if len(b) > size {
		return nil, invalid("%q is %d bytes, longer than the %d-byte coordinate", name, len(b), size)
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out, nil
}

// ecPoint decodes and validates the uncompressed point of an EC JWK.
func ecPoint(v Value) (elliptic.Curve, ecdh.Curve, []byte, error) {
	crv, err := stringMember(v, Curve)
	if err != nil {
		return nil, nil, nil, err
	}
	curve, ecdhCurve, err := ellipticCurve(crv)
	if err != nil {
		return nil, nil, nil, err
	}
	size := (curve.Params().BitSize + 7) / 8
	x, err := member(v, X)
	if err != nil {
		return nil, nil, nil, err
	}
	if x, err = coordinate(x, size, X); err != nil {
		return nil, nil, nil, err
	}
	y, err := member(v, Y)
	if err != nil {
		return nil, nil, nil, err
	}
	if y, err = coordinate(y, size, Y); err != nil {
		return nil, nil, nil, err
	}
	point := make([]byte, 0, 1+2*size)
	point = append(point, 4)
	point = append(point, x...)
	point = append(point, y...)
	// crypto/ecdh rejects the identity and points that are not on the curve.
	if _, err := ecdhCurve.NewPublicKey(point); err != nil {
		return nil, nil, nil, invalid("point is not on %s", crv)
	}
	return curve, ecdhCurve, point, nil
}

func ecdsaFromPoint(curve elliptic.Curve, point []byte) *ecdsa.PublicKey {
	size := (len(point) - 1) / 2
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(point[1 : 1+size]),
		Y:     new(big.Int).SetBytes(point[1+size:]),
	}
}

// MaxRSAModulusBytes bounds the RSA modulus a JWK may carry: 8192 bits.
const MaxRSAModulusBytes = 1024

// rsaPublic decodes and bounds the public members of an RSA JWK.
func rsaPublic(v Value) (*rsa.PublicKey, error) {
	n, err := member(v, N)
	if err != nil {
		return nil, err
	}
	if n[0] == 0 {
		return nil, invalid("%q has a leading zero byte", N)
	}
	// Verification cost grows with the modulus, and a key from a token
	// header is attacker-chosen, so absurd sizes are refused.
	if len(n) > MaxRSAModulusBytes {
		return nil, invalid("RSA modulus is larger than %d bits", MaxRSAModulusBytes*8)
	}
	e, err := member(v, E)
	if err != nil {
		return nil, err
	}
	if len(e) > 4 || e[0] == 0 {
		return nil, invalid("%q is not a minimal exponent of at most 32 bits", E)
	}
	exponent := new(big.Int).SetBytes(e)
	if exponent.Int64() < 3 || exponent.Int64() > 1<<31-1 || exponent.Bit(0) == 0 {
		return nil, invalid("%q must be an odd exponent between 3 and 2^31-1", E)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent.Int64())}, nil
}

// PublicKey returns the public key a JWK describes:
//
//   - kty "EC" with crv "P-256", "P-384" or "P-521": *[ecdsa.PublicKey]
//   - kty "RSA": *[rsa.PublicKey]
//   - kty "OKP" with crv "Ed25519": [ed25519.PublicKey]
//   - kty "OKP" with crv "X25519": *[ecdh.PublicKey]
//
// EC points must lie on their curve. Private members, if present, are
// ignored; use [PrivateKey] to read them. Symmetric ("oct") keys have no
// public half and return [ErrInvalidKey].
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6
// https://www.rfc-editor.org/rfc/rfc8037.html#section-2
func PublicKey(v Value) (crypto.PublicKey, error) {
	kty, err := stringMember(v, KeyType)
	if err != nil {
		return nil, err
	}
	switch kty {
	case KeyTypeEC:
		curve, _, point, err := ecPoint(v)
		if err != nil {
			return nil, err
		}
		return ecdsaFromPoint(curve, point), nil
	case KeyTypeRSA:
		return rsaPublic(v)
	case KeyTypeOKP:
		crv, err := stringMember(v, Curve)
		if err != nil {
			return nil, err
		}
		x, err := member(v, X)
		if err != nil {
			return nil, err
		}
		switch crv {
		case CurveEd25519:
			if len(x) != ed25519.PublicKeySize {
				return nil, invalid("Ed25519 %q is %d bytes, want %d", X, len(x), ed25519.PublicKeySize)
			}
			return ed25519.PublicKey(x), nil
		case CurveX25519:
			key, err := ecdh.X25519().NewPublicKey(x)
			if err != nil {
				return nil, invalid("X25519 %q: %v", X, err)
			}
			return key, nil
		default:
			return nil, invalid("unsupported OKP curve %q", crv)
		}
	case KeyTypeOct:
		return nil, invalid("symmetric keys have no public key")
	default:
		return nil, invalid("unsupported key type %q", kty)
	}
}

// PrivateKey returns the private key a JWK describes:
//
//   - kty "EC": *[ecdsa.PrivateKey]
//   - kty "RSA": *[rsa.PrivateKey], with two primes only
//   - kty "OKP" with crv "Ed25519": [ed25519.PrivateKey]
//   - kty "OKP" with crv "X25519": *[ecdh.PrivateKey]
//
// The public members must match the private ones. The returned keys are
// [crypto.Signer] values (or, for X25519, usable with ECDH), so they plug
// into [jws.Signature.Sign] and JWE decryption directly.
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.2
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2
// https://www.rfc-editor.org/rfc/rfc8037.html#section-2
func PrivateKey(v Value) (crypto.PrivateKey, error) {
	kty, err := stringMember(v, KeyType)
	if err != nil {
		return nil, err
	}
	d, err := member(v, D)
	if err != nil {
		return nil, err
	}
	switch kty {
	case KeyTypeEC:
		curve, ecdhCurve, point, err := ecPoint(v)
		if err != nil {
			return nil, err
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(d) != size {
			return nil, invalid("EC %q is %d bytes, want %d", D, len(d), size)
		}
		private, err := ecdhCurve.NewPrivateKey(d)
		if err != nil {
			return nil, invalid("EC %q is out of range", D)
		}
		if string(private.PublicKey().Bytes()) != string(point) {
			return nil, invalid("EC private key does not match its public point")
		}
		return &ecdsa.PrivateKey{PublicKey: *ecdsaFromPoint(curve, point), D: new(big.Int).SetBytes(d)}, nil
	case KeyTypeRSA:
		public, err := rsaPublic(v)
		if err != nil {
			return nil, err
		}
		if _, ok := v[OtherPrimes]; ok {
			return nil, invalid("multi-prime RSA keys are not supported")
		}
		p, err := member(v, P)
		if err != nil {
			return nil, err
		}
		q, err := member(v, Q)
		if err != nil {
			return nil, err
		}
		key := &rsa.PrivateKey{
			PublicKey: *public,
			D:         new(big.Int).SetBytes(d),
			Primes:    []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)},
		}
		if err := key.Validate(); err != nil {
			return nil, invalid("RSA private key: %v", err)
		}
		key.Precompute()
		return key, nil
	case KeyTypeOKP:
		crv, err := stringMember(v, Curve)
		if err != nil {
			return nil, err
		}
		x, err := member(v, X)
		if err != nil {
			return nil, err
		}
		switch crv {
		case CurveEd25519:
			if len(d) != ed25519.SeedSize {
				return nil, invalid("Ed25519 %q is %d bytes, want %d", D, len(d), ed25519.SeedSize)
			}
			key := ed25519.NewKeyFromSeed(d)
			if string(key.Public().(ed25519.PublicKey)) != string(x) {
				return nil, invalid("Ed25519 private key does not match %q", X)
			}
			return key, nil
		case CurveX25519:
			key, err := ecdh.X25519().NewPrivateKey(d)
			if err != nil {
				return nil, invalid("X25519 %q: %v", D, err)
			}
			if string(key.PublicKey().Bytes()) != string(x) {
				return nil, invalid("X25519 private key does not match %q", X)
			}
			return key, nil
		default:
			return nil, invalid("unsupported OKP curve %q", crv)
		}
	default:
		return nil, invalid("unsupported private key type %q", kty)
	}
}

// encode base64url-encodes b, which callers guarantee is non-empty.
func encode(b []byte) string {
	s, _ := base64.Encode(b)
	return s
}

// PublicValue returns the minimal public JWK for key: only the members
// RFC 7518 and RFC 8037 require for its type, with EC coordinates at their
// full fixed width. It sets no "use", "alg" or "kid", so callers choose
// them deliberately.
//
// key may be *[ecdsa.PublicKey], *[rsa.PublicKey], [ed25519.PublicKey] or
// *[ecdh.PublicKey] (X25519, P-256, P-384 or P-521), or a private key or
// [crypto.Signer] whose Public method returns one of those.
func PublicValue(key any) (Value, error) {
	if signer, ok := key.(crypto.Signer); ok {
		key = signer.Public()
	}
	if private, ok := key.(*ecdh.PrivateKey); ok {
		key = private.PublicKey()
	}
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		crv, err := curveNameOf(key.Curve)
		if err != nil {
			return nil, err
		}
		ecdhKey, err := key.ECDH()
		if err != nil {
			return nil, invalid("EC public key: %v", err)
		}
		return ecValue(crv, ecdhKey.Bytes()), nil
	case *rsa.PublicKey:
		if key.N == nil || key.N.Sign() <= 0 || key.E < 3 {
			return nil, invalid("RSA public key is empty")
		}
		return Value{
			KeyType: KeyTypeRSA,
			N:       encode(key.N.Bytes()),
			E:       encode(big.NewInt(int64(key.E)).Bytes()),
		}, nil
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, invalid("Ed25519 public key is %d bytes", len(key))
		}
		return Value{KeyType: KeyTypeOKP, Curve: CurveEd25519, X: encode(key)}, nil
	case *ecdh.PublicKey:
		switch key.Curve() {
		case ecdh.X25519():
			return Value{KeyType: KeyTypeOKP, Curve: CurveX25519, X: encode(key.Bytes())}, nil
		case ecdh.P256():
			return ecValue(CurveP256, key.Bytes()), nil
		case ecdh.P384():
			return ecValue(CurveP384, key.Bytes()), nil
		case ecdh.P521():
			return ecValue(CurveP521, key.Bytes()), nil
		}
		return nil, invalid("unsupported ECDH curve")
	default:
		return nil, invalid("unsupported public key type %T", key)
	}
}

// ecValue builds an EC JWK from an uncompressed point.
func ecValue(crv string, point []byte) Value {
	size := (len(point) - 1) / 2
	return Value{
		KeyType: KeyTypeEC,
		Curve:   crv,
		X:       encode(point[1 : 1+size]),
		Y:       encode(point[1+size:]),
	}
}

// IsPrivate reports whether v carries private or symmetric key material:
// "d" for EC, OKP and RSA keys (plus the RSA CRT members), or "k" for "oct".
// A JWK published as a verification key, or embedded in a JWS "jwk" header,
// must not carry any of these.
//
// https://www.rfc-editor.org/rfc/rfc7517.html#section-9.2
func IsPrivate(v Value) bool {
	for _, name := range []string{D, P, Q, DP, DQ, QI, OtherPrimes, K} {
		if _, ok := v[name]; ok {
			return true
		}
	}
	return false
}
