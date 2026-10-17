// Package jwk implements JSON Web Keys and JWK Sets (RFC 7517) with the key
// representations of RFC 7518 §6 and RFC 8037.
//
// A [Key] is the JSON object itself, a map indexed by member name. [PublicKey]
// and [PrivateKey] turn one into a standard library key (and check that it is
// valid: points on the curve, bounded RSA sizes), and [PublicValue] turns a
// key back into a minimal public JWK. [ParseSet] reads a JWK Set strictly.
//
// Fetching sets over HTTP lives in package jwkhttp, so that programs which
// only parse keys do not link an HTTP client. Thumbprints (RFC 7638) live in
// package thumbprint.
//
// https://www.rfc-editor.org/rfc/rfc7517.html
package jwk
