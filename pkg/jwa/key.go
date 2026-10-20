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
	// A typed nil key, such as the result of a failed GenerateKey, would
	// panic in Public or Size; refuse it like any other unusable key.
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k == nil {
			return "", fmt.Errorf("%w: nil RSA key", ErrUnknownAlgorithm)
		}
	case *ecdsa.PrivateKey:
		if k == nil {
			return "", fmt.Errorf("%w: nil ECDSA key", ErrUnknownAlgorithm)
		}
	case *rsa.PublicKey:
		if k == nil {
			return "", fmt.Errorf("%w: nil RSA key", ErrUnknownAlgorithm)
		}
	case *ecdsa.PublicKey:
		if k == nil {
			return "", fmt.Errorf("%w: nil ECDSA key", ErrUnknownAlgorithm)
		}
	}
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
// algorithm this package implements
// (https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1). It is false for "none" and for HMAC.
func IsAsymmetricSignature(alg Algorithm) bool {
	switch alg {
	case RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA:
		return true
	}
	return false
}

// IsSymmetric reports whether alg uses a shared secret rather than a key pair:
// the HMAC signature algorithms (HS256, HS384, HS512,
// https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2) and the symmetric
// key management algorithms (A128KW, A192KW, A256KW and "dir",
// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.4 and
// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.5).
func (alg Algorithm) IsSymmetric() bool {
	switch alg {
	case HS256, HS384, HS512, A128KW, A192KW, A256KW, Direct:
		return true
	}
	return false
}

// IsKeyManagement reports whether alg is a JWE key management algorithm
// ("alg" in a JWE header) this package names:
// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1
func (alg Algorithm) IsKeyManagement() bool {
	switch alg {
	case RSAOAEP, RSAOAEP256, A128KW, A192KW, A256KW, Direct,
		ECDHES, ECDHESA128KW, ECDHESA192KW, ECDHESA256KW:
		return true
	}
	return false
}

// IsContentEncryption reports whether enc is a JWE content encryption
// algorithm ("enc" in a JWE header) this package names:
// https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1
func (enc ContentEncryption) IsContentEncryption() bool {
	switch enc {
	case A128CBCHS256, A192CBCHS384, A256CBCHS512, A128GCM, A192GCM, A256GCM:
		return true
	}
	return false
}
