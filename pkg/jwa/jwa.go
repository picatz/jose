package jwa

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
)

// PrivateKey is a type that can be used to sign JOSE objects (JWS, JWT),
// such as a *[crypto/rsa.PrivateKey] or *[crypto/ecdsa.PrivateKey].
//
// This may be a shared secret key, such as a []byte or string, but
// this is not recommended.
type PrivateKey interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey | []byte | string
}

// PublicKey is a type that can be used to verify JOSE objects (JWS, JWT) using
// an asymmetric algorithm, such as *[crypto/rsa.PublicKey] or *[crypto/ecdsa.PublicKey]
// or [crypto/ed25519.PublicKey].
type PublicKey interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

// SymmetricKey is a type that can be used to sign or verify JOSE objects (JWS, JWT) using
// a symmetric algorithm, such as HMAC.
type SymmetricKey interface {
	[]byte | string
}

// VerifyKey is a type that can be used to verify JOSE objects (JWS, JWT) using
// either a symmetric or asymmetric algorithm.
type VerifyKey interface {
	PublicKey | SymmetricKey
}

// SigningKey is a type that can be used to sign JOSE objects (JWS, JWT) using
// either a symmetric or asymmetric algorithm.
type SigningKey interface {
	PrivateKey | SymmetricKey
}

// Algorithm represents a cryptographic algorithm used for signing or
// encrypting a JWS or JWE object respectively.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
type Algorithm = string

// HMAC with SHA-2 Functions
//
// These algorithms are used to construct a MAC using a shared secret
// and the Hash-based Message Authentication Code (HMAC) construction
// [RFC2104] employing SHA-2 [SHS] hash functions.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
//
// [RFC2104]: https://datatracker.ietf.org/doc/html/rfc2104
// [SHS]: https://datatracker.ietf.org/doc/html/rfc6234
const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
)

// RSASSA-PKCS1-v1_5
//
// These algorithms are used to digitally sign a JWS and produce a
// JWS Signature using PKCS #1 v1.5 methods.
//
// # RSA Key Size
//
// A key of size 2048 bits or larger MUST be used with these algorithms.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
const (
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
)

// ECDSA
//
// These algorithms are used to digitally sign a JWS and produce a
// JWS Signature using ECDSA algorithms.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
const (
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
)

// RSASSA-PSS
//
// These algorithms are used to digitally sign a JWS and produce a
// JWS Signature using the RSASSA-PSS algorithms.
//
// # RSA Key Size
//
// A key of size 2048 bits or larger MUST be used with these algorithms.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
const (
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
)

// No signature or MAC performed (unprotected JWS). This algorithm is
// intended to be used to create a JWS that is not integrity protected.
//
// # Warning
//
// The use of this algorithm is considered dangerous. Do NOT use this
// algorithm, it's only implemented for completeness.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.6
const None Algorithm = "none"

// EdDSA algorithms using Ed25519 (and Ed448, which is not implemented).
//
// https://datatracker.ietf.org/doc/html/rfc8037#section-3.1
const EdDSA Algorithm = "EdDSA"

//	ECDSA with secp256k1 and SHA-256 (used in Bitcoin and Ethereum).
//
// # Warning
//
// This algorithm is not implemented in this library, but is included
// for completeness and documentation purposes.
//
// https://datatracker.ietf.org/doc/html/draft-jones-webauthn-secp256k1
// https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-04#section-3.2
const ES256K Algorithm = "ES256K"
