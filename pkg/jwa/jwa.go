package jwa

// https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
type Algorithm = string

// HMAC with SHA-2 Functions
//
// These algorithms are used to construct a MAC using a shared secret
// and the Hash-based Message Authentication Code (HMAC) construction
// [RFC2104] employing SHA-2 [SHS] hash functions.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
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

// I have no idea where these are documented, but other libraries implement them?
const (
	ES256K Algorithm = "ES256K"
	EdDSA  Algorithm = "EdDSA"
)

// DefaultAllowedAlgorithms returns a list of algorithms that are allowed to be used.
func DefaultAllowedAlgorithms() []Algorithm {
	return []Algorithm{
		RS256, ES256,
	}
}
