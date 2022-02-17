package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/picatz/jose/pkg/base64"
)

// https://datatracker.ietf.org/doc/html/rfc7517#section-4
type (
	ParamaterName string

	RSA       = ParamaterName
	ECDSA     = ParamaterName
	Symmetric = ParamaterName
)

const (
	KeyType              ParamaterName = "kty"
	PublicKeyUse         ParamaterName = "use"
	KeyOperations        ParamaterName = "key_ops"
	Algorithm            ParamaterName = "alg"
	KeyID                ParamaterName = "kid"
	X509URL              ParamaterName = "x5u"
	X509CertificateChain ParamaterName = "x5c"
	X509SHA1Thumbprint   ParamaterName = "x5t"
	X509SHA256Thumbprint ParamaterName = "x5t#S256"

	K Symmetric = "k"

	Curve ECDSA = "crv"
	X     ECDSA = "x"
	Y     ECDSA = "y"

	N RSA = "n"
	E RSA = "e"
	D RSA = "d" // used for RSA key blinding operation (https://datatracker.ietf.org/doc/html/rfc7517#ref-Kocher)
)

type Value = map[ParamaterName]interface{}

func Validate(v Value) error {
	_, ok := v[KeyType]
	if !ok {
		return fmt.Errorf("missing required paramater %q", KeyType)
	}
	// TOOD: add more validation
	return nil
}

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

func ECDSAValues(v Value) (crv, x, y string, err error) {
	if v[KeyType] != "EC" {
		err = fmt.Errorf("JWK value is not RSA")
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

func SymmetricKey(v Value) (k string, err error) {
	k = fmt.Sprintf("%v", v[K])

	if k == "" {
		err = fmt.Errorf("not symmetric key")
	}

	return
}

func HMACSecretKey(v Value) ([]byte, error) {
	key, err := SymmetricKey(v)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric key: %w", err)
	}
	return base64.Decode(key)
}

func RSAPublicKey(v Value) (pkey *rsa.PublicKey, blindingValue []byte, err error) {
	nEnc, eEnc, dEnc, err := RSAValues(v)
	if err != nil {
		err = fmt.Errorf("failed to get RSA public key: %w", err)
		return
	}

	var (
		n = new(big.Int)
		e = new(big.Int)
		d []byte
	)

	if pkey == nil {
		pkey = &rsa.PublicKey{}
	}

	nBytes, err := base64.Decode(nEnc)
	if err != nil {
		err = fmt.Errorf("failed to decode RSA public key N: %w", err)
		return
	}
	n.SetBytes(nBytes)

	pkey.N = n

	eBytes, err := base64.Decode(eEnc)
	if err != nil {
		err = fmt.Errorf("failed to decode RSA public key E: %w", err)
		return
	}
	e.SetBytes(eBytes)

	pkey.E = int(e.Int64())

	if len(dEnc) > 0 {
		d, err = base64.Decode(dEnc)
		if err != nil {
			err = fmt.Errorf("failed to decode RSA public key D: %w", err)
			return
		}
		blindingValue = d
	}

	return
}

func ECDSAPublicKey(v Value) (pkey *ecdsa.PublicKey, blindingValue []byte, err error) {
	crv, xEnc, yEnc, err := ECDSAValues(v)
	if err != nil {
		err = fmt.Errorf("failed to get ECDSA values for public key: %w", err)
		return
	}

	pkey = &ecdsa.PublicKey{}

	switch crv {
	case "P-224":
		pkey.Curve = elliptic.P224()
	case "P-256":
		pkey.Curve = elliptic.P256()
	case "P-384":
		pkey.Curve = elliptic.P384()
	case "P-521":
		pkey.Curve = elliptic.P521()
	default:
		err = fmt.Errorf("invalid curve %q while getting ECDSA values for public key", crv)
		return
	}

	var (
		x = new(big.Int)
		y = new(big.Int)
	)

	xBytes, err := base64.Decode(xEnc)
	if err != nil {
		err = fmt.Errorf("failed to decode ECDSA public key X: %w", err)
		return
	}
	x.SetBytes(xBytes)

	pkey.X = x

	yBytes, err := base64.Decode(yEnc)
	if err != nil {
		err = fmt.Errorf("failed to decode ECDSA public key X: %w", err)
		return
	}
	y.SetBytes(yBytes)

	pkey.Y = y

	return
}

// https://datatracker.ietf.org/doc/html/rfc7517#section-5
type Set struct {
	Keys []Value `json:"keys"`
}

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
