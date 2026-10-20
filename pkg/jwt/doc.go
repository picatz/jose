// Package jwt mints, decodes and verifies JSON Web Tokens as defined by
// [RFC 7519], following the [RFC 8725] best current practices.
//
// Only signed tokens (a JWS in compact serialization) are supported.
//
// # Minting
//
// [New] signs a claims set with a key and returns a [*Token]. The key is
// anything [jws.New] accepts, including any [crypto.Signer]. New copies the
// header parameters and claims it is given, adds "typ": "JWT", checks the
// types of the registered claims, and never produces an unsecured token
// (alg "none", [RFC 7519 §6]).
//
//	token, err := jwt.New(
//		header.Parameters{header.Algorithm: jwa.EdDSA, header.KeyID: "k1"},
//		jwt.ClaimsSet{
//			jwt.Issuer:         "https://issuer.example",
//			jwt.Audience:       "https://api.example",
//			jwt.Subject:        "alice",
//			jwt.ExpirationTime: time.Now().Add(time.Hour),
//		},
//		privateKey,
//	)
//	compact := token.String()
//
// Claim names are untyped string constants and a [ClaimsSet] is a plain
// map, so claims are read by indexing: claims[jwt.Subject].(string).
//
// # Decoding
//
// [Parse] decodes a compact JWT without verifying it. Nothing it returns is
// trustworthy: use it to look at a token (for example to read the "kid"),
// never to make an authorization decision. The structure it checks is that of
// [RFC 7519 §7.2].
//
// # Verifying
//
// Key replay and revocation caches on the "jti" claim, never on the raw
// token string: ECDSA signatures are malleable, so the holder of a valid
// ES256, ES384 or ES512 token can derive another valid string for it.
//
// A [Verifier] checks the signature and the claims in one call, and is the
// only safe way to accept a token. Following [RFC 8725 §3], it takes the
// algorithm from an allowlist and never from the token alone, checks "typ",
// requires the issuer, audience and expiry to be checked unless the caller
// opts out by name, and bounds the token's size. A refused token gives an
// error wrapping [ErrInvalidToken] and one of [ErrFormat], [ErrSignature],
// [ErrExpired], [ErrNotYetValid] or [ErrClaims]. A failed key source gives
// [ErrKeysUnavailable], which is not a refusal and does not wrap
// [ErrInvalidToken], so a server can retry rather than answer 401.
//
//	v := &jwt.Verifier{
//		Keys:     jwt.Keys{{ID: "k1", Public: publicKey}},
//		Issuer:   "https://issuer.example",
//		Audience: "https://api.example",
//	}
//	token, err := v.Verify(ctx, compact)
//
// # Keys
//
// A Verifier gets its keys from a [KeySource]: [Keys] for a fixed list,
// [KeysFromSet] for a parsed JWK Set, or a refreshing source such as
// jwkhttp.Keys, which serves a remote JWKS URL.
//
// # Confirmation
//
// [ConfirmationFor] builds a "cnf" claim that binds a token to a holder's
// key by its JWK Thumbprint ([RFC 7800 §3.1]), as used by DPoP; see
// [ClaimsSet.ConfirmedThumbprint] to read it back.
//
// # Actors
//
// [ClaimsSet.Actors], [ClaimsSet.SetActors] and [ClaimsSet.AllowedActor]
// read and write the delegation chain in the "act" and "may_act" claims
// ([RFC 8693 §4.1], [RFC 8693 §4.4]).
//
// # Scope
//
// Nested JWTs (a JWT carried as the payload of a JWS or JWE, with "cty":
// "JWT", [RFC 7519 §5.2]) are out of scope: this package neither creates nor
// unwraps them, and a [Verifier] does not decrypt.
//
// [RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519.html
// [RFC 7519 §5.2]: https://www.rfc-editor.org/rfc/rfc7519.html#section-5.2
// [RFC 7519 §6]: https://www.rfc-editor.org/rfc/rfc7519.html#section-6
// [RFC 7519 §7.2]: https://www.rfc-editor.org/rfc/rfc7519.html#section-7.2
// [RFC 8725]: https://www.rfc-editor.org/rfc/rfc8725.html
// [RFC 8725 §3]: https://www.rfc-editor.org/rfc/rfc8725.html#section-3
// [RFC 7800 §3.1]: https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1
// [RFC 8693 §4.1]: https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
// [RFC 8693 §4.4]: https://www.rfc-editor.org/rfc/rfc8693.html#section-4.4
package jwt
