// Package jws implements JSON Web Signature (JWS) as defined in RFC 7515.
//
// [New], [Parse] and [Signature] handle the compact serialization, one
// signature in three dot-separated parts. [SignJSON], [ParseJSON] and
// [JSON] handle the JSON serialization, in its general syntax (several
// signatures, each with its own header) and its flattened syntax (one
// signature, as ACME uses).
//
// [ParseDetached] and [Signature.Detached] handle a detached payload
// ("header..signature", RFC 7515 Appendix F), including the unencoded
// payload option ("b64": false, RFC 7797) that only ParseDetached accepts.
//
// Signing takes any [crypto.Signer] for asymmetric algorithms, so keys held
// in hardware sign like in-memory keys. Verification checks the key type
// and curve against the algorithm, and an unsecured JWS ("alg" "none")
// never verifies.
//
// https://www.rfc-editor.org/rfc/rfc7515.html
package jws
