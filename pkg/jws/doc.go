// Package jws implements JSON Web Signature (JWS) as defined in RFC 7515.
//
// [New], [Parse] and [Signature] handle the compact serialization, one
// signature in three dot-separated parts. [SignJSON], [ParseJSON] and
// [JSON] handle the JSON serialization, in its general syntax (several
// signatures, each with its own header) and its flattened syntax (one
// signature, as ACME uses).
//
// Signing takes any [crypto.Signer] for asymmetric algorithms, so keys held
// in hardware sign like in-memory keys. Verification checks the key type
// and curve against the algorithm, and an unsecured JWS ("alg" "none")
// never verifies.
//
// https://www.rfc-editor.org/rfc/rfc7515.html
package jws
