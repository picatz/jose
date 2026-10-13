package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
)

// ForKey returns the conventional JWS algorithm for a public key, a private
// key or a [crypto.Signer]:
//
//   - ECDSA P-256, P-384, P-521: ES256, ES384, ES512 (the only algorithm
//     each curve may use, https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)
//   - Ed25519: EdDSA (https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1)
//   - RSA, at least 2048 bits: PS256 (RSASSA-PSS, preferred over PKCS #1 v1.5
//     by modern profiles such as FAPI 2.0)
//
// Callers that need RS256 for compatibility must set it explicitly.
func ForKey(key any) (Algorithm, error) {
	if signer, ok := key.(crypto.Signer); ok {
		key = signer.Public()
	}
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return ES256, nil
		case elliptic.P384():
			return ES384, nil
		case elliptic.P521():
			return ES512, nil
		}
		return "", fmt.Errorf("%w: no JWS algorithm for this ECDSA curve", ErrUnknownAlgorithm)
	case ed25519.PublicKey:
		return EdDSA, nil
	case *rsa.PublicKey:
		if key.Size() < 256 {
			return "", fmt.Errorf("%w: RSA keys must be at least 2048 bits", ErrAlgorithmNotAllowed)
		}
		return PS256, nil
	default:
		return "", fmt.Errorf("%w: no JWS algorithm for key type %T", ErrUnknownAlgorithm, key)
	}
}

// IsAsymmetricSignature reports whether alg is a registered asymmetric JWS
// algorithm this package implements. It is false for "none" and for HMAC.
func IsAsymmetricSignature(alg Algorithm) bool {
	switch alg {
	case RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA:
		return true
	}
	return false
}
