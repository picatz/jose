// Package jose is the overview of a JOSE (JavaScript Object Signing and
// Encryption) toolkit built on the standard library alone. The code lives in
// the packages below this directory; this package documents how they fit
// together.
//
// The packages follow the RFCs, and their defaults follow the RFC 8725 best
// current practices: a verifier takes the algorithm from an allowlist and never
// from the token, never accepts "alg": "none", and refuses keys that are the
// wrong type, too small or not on their curve.
//
// # Choosing a package
//
// To mint or verify a JSON Web Token, use package jwt: jwt.New signs a claims
// set and jwt.Verifier checks the signature, the "typ", the algorithm and the
// registered claims in one call. This is the right choice for access tokens,
// ID tokens and most application tokens. Header parameters come from package
// header and algorithm names from package jwa. Read bearer tokens out of an
// HTTP request with package jwt/jwthttp.
//
// To sign or encrypt arbitrary bytes, use the raw layers: package jws for
// signed content (compact, flattened and general JSON, detached and unencoded
// payloads) and package jwe for encrypted content (compact and JSON, with
// several recipients).
//
// For keys, use package jwk to read and write JSON Web Keys and JWK Sets, and
// jwk/thumbprint to name a key by its RFC 7638 thumbprint. To verify tokens
// against a remote issuer's key set, such as an OpenID Connect jwks_uri, use
// jwk/jwkhttp, a jwt.KeySource that caches and refreshes safely.
//
// To bind a token to a client's key so a stolen token is useless, use package
// dpop to mint and verify DPoP proofs, and dpop/dpophttp for the net/http
// client transport and server helpers.
//
// To pass narrowed authority from holder to holder without asking the issuer,
// use package jwtchain: attenuation chains of ordinary JWTs, linked by package
// ni digests and re-issued with RFC 8693 "act" lineage.
//
// To write tests against any of the above, use package josetest, which makes
// fresh keys, signed tokens and a JWKS server.
//
// # RFCs
//
// Package to specification, with the sections that define the behaviour:
//
//   - jws: [RFC 7515] JSON Web Signature, with the compact serialization
//     ([RFC 7515 §7.1]), the JSON serialization ([RFC 7515 §7.2]) and detached
//     content ([RFC 7515 Appendix F]); [RFC 7797] JWS Unencoded Payload Option
//     ("b64": false); the Ed25519 signatures of [RFC 8037].
//   - jwe: [RFC 7516] JSON Web Encryption ([RFC 7516 §7.1] compact,
//     [RFC 7516 §7.2] JSON), with the key management and content encryption
//     algorithms of [RFC 7518] ([RFC 7518 §4], [RFC 7518 §5]) and the X25519
//     key agreement of [RFC 8037] ([RFC 8037 §3.2]).
//   - jwk: [RFC 7517] JSON Web Key and JWK Set ([RFC 7517 §4], [RFC 7517 §5]),
//     with the key parameters of [RFC 7518 §6] and [RFC 8037 §2].
//   - jwk/thumbprint: [RFC 7638] JWK Thumbprint ([RFC 7638 §3]) and [RFC 9278]
//     JWK Thumbprint URI.
//   - jwa: [RFC 7518] JSON Web Algorithms (signatures in [RFC 7518 §3]).
//   - jwt: [RFC 7519] JSON Web Token (claims in [RFC 7519 §4], validation in
//     [RFC 7519 §7.2]), the [RFC 8725] best current practices, [RFC 7800]
//     proof-of-possession "cnf" claims ([RFC 7800 §3.1]) and [RFC 8693] "act"
//     and "may_act" claims ([RFC 8693 §4]).
//   - jwt/jwthttp: [RFC 6750] bearer tokens in the Authorization header
//     ([RFC 6750 §2.1]).
//   - jwk/jwkhttp: fetches [RFC 7517] sets and, following [RFC 8725 §3.10],
//     never trusts a "jku" or "x5u" from a token.
//   - dpop, dpop/dpophttp: [RFC 9449] OAuth 2.0 Demonstrating Proof of
//     Possession (proofs in [RFC 9449 §4], nonces in [RFC 9449 §8] and
//     [RFC 9449 §9], replay in [RFC 9449 §11.1]).
//   - jwtchain: composes [RFC 7519], [RFC 7800], [RFC 7638], [RFC 9278] and
//     [RFC 8693] with [RFC 6920] digests into attenuation chains.
//   - ni: [RFC 6920] Named Information URIs.
//
// Related information: the IETF JOSE working group charter,
// https://datatracker.ietf.org/wg/jose/charter/.
//
// [RFC 6750]: https://www.rfc-editor.org/rfc/rfc6750.html
// [RFC 6920]: https://www.rfc-editor.org/rfc/rfc6920.html
// [RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515.html
// [RFC 7516]: https://www.rfc-editor.org/rfc/rfc7516.html
// [RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517.html
// [RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518.html
// [RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519.html
// [RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638.html
// [RFC 7797]: https://www.rfc-editor.org/rfc/rfc7797.html
// [RFC 7800]: https://www.rfc-editor.org/rfc/rfc7800.html
// [RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037.html
// [RFC 8693]: https://www.rfc-editor.org/rfc/rfc8693.html
// [RFC 8725]: https://www.rfc-editor.org/rfc/rfc8725.html
// [RFC 9278]: https://www.rfc-editor.org/rfc/rfc9278.html
// [RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449.html
// [RFC 7515 §7.1]: https://www.rfc-editor.org/rfc/rfc7515.html#section-7.1
// [RFC 7515 §7.2]: https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2
// [RFC 7516 §7.1]: https://www.rfc-editor.org/rfc/rfc7516.html#section-7.1
// [RFC 7516 §7.2]: https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2
// [RFC 7518 §4]: https://www.rfc-editor.org/rfc/rfc7518.html#section-4
// [RFC 7518 §5]: https://www.rfc-editor.org/rfc/rfc7518.html#section-5
// [RFC 7518 §6]: https://www.rfc-editor.org/rfc/rfc7518.html#section-6
// [RFC 7518 §3]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3
// [RFC 8037 §3.2]: https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2
// [RFC 8037 §2]: https://www.rfc-editor.org/rfc/rfc8037.html#section-2
// [RFC 7517 §4]: https://www.rfc-editor.org/rfc/rfc7517.html#section-4
// [RFC 7517 §5]: https://www.rfc-editor.org/rfc/rfc7517.html#section-5
// [RFC 7638 §3]: https://www.rfc-editor.org/rfc/rfc7638.html#section-3
// [RFC 7519 §4]: https://www.rfc-editor.org/rfc/rfc7519.html#section-4
// [RFC 7519 §7.2]: https://www.rfc-editor.org/rfc/rfc7519.html#section-7.2
// [RFC 7800 §3.1]: https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1
// [RFC 8693 §4]: https://www.rfc-editor.org/rfc/rfc8693.html#section-4
// [RFC 6750 §2.1]: https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
// [RFC 8725 §3.10]: https://www.rfc-editor.org/rfc/rfc8725.html#section-3.10
// [RFC 9449 §4]: https://www.rfc-editor.org/rfc/rfc9449.html#section-4
// [RFC 9449 §8]: https://www.rfc-editor.org/rfc/rfc9449.html#section-8
// [RFC 9449 §9]: https://www.rfc-editor.org/rfc/rfc9449.html#section-9
// [RFC 9449 §11.1]: https://www.rfc-editor.org/rfc/rfc9449.html#section-11.1
// [RFC 7515 Appendix F]: https://www.rfc-editor.org/rfc/rfc7515.html#appendix-F
package jose
