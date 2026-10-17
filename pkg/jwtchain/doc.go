// Package jwtchain builds attenuation chains: capability tokens that any
// holder can narrow and hand on offline, in plain JOSE.
//
// An issuer signs an ordinary JWT, the root, and binds it to a holder key
// with a "cnf" claim (RFC 7800). The holder can [Derive] a link: a JWT it
// signs itself that names its parent by digest and can only narrow what
// the parent allows. A link can drop audiences, drop scopes, end sooner,
// start later, add caveats, and name the next holder. That holder can
// derive again. Nobody calls the issuer, and a verifier that trusts only
// the issuer can check every step with a [Policy].
//
// The model comes from macaroons and Biscuit; the mechanics are standards:
// JWS (RFC 7515) and JWT (RFC 7519) for every token, JWK Thumbprints
// (RFC 7638) and their URIs (RFC 9278) to name keys, "cnf" (RFC 7800) to
// bind holders, Named Information URIs (RFC 6920) to link a token to its
// parent, and "act" (RFC 8693) to record lineage when a chain is re-issued.
//
// # Three ways to carry lineage
//
// A link always names its parent by digest. How the parent travels is up
// to the holder:
//
//   - By reference: the presenter sends the tokens joined with "~", root
//     first, like "root~link1~link2". This is the default and the smallest.
//   - Embedded: [Embed] puts the parent inside the link's header, so the
//     link alone is one ordinary three-segment JWS that carries its whole
//     history. Each embedding grows the token by about a third.
//   - Re-issued: an issuer verifies a chain and mints a fresh, short root,
//     recording who held the chain in an RFC 8693 "act" claim with
//     [Grant.Actors] and [jwt.ClaimsSet.SetActors]. The new token is as
//     small as any other, and the history survives as identity claims.
//
// # Wire format
//
// A link is a compact JWS whose protected header holds:
//
//   - "typ": "chain+jwt" ([Type]), so it is never mistaken for another JWT
//     (RFC 8725 §3.11);
//   - "alg": an asymmetric algorithm, and "jwk": the signer's public key;
//   - "prh": the ni URI of the parent token's exact bytes, listed in "crit"
//     so that a verifier that does not understand chains rejects the link
//     instead of reading it as a standalone token (RFC 7515 §4.1.11);
//   - "prt": optionally, the parent token itself (see [Embed]).
//
// Its claims are "iss" (the signer's thumbprint URI), "exp" (required),
// "iat", "jti", and any of "aud", "scope", "nbf", "cav" (caveats, an array
// of strings) and "cnf" (the next holder, {"jkt": ...} or {"jwk": ...}). A
// link may hold no other claim and cannot change "sub".
//
// # Narrowing rules
//
// A link's "aud", when present, must be a subset of what its parent allows
// (if the parent names any audience). Its "scope", when present, must be a
// subset of the parent's, and a parent without "scope" grants none to add.
// Its "exp" may not be later than the parent's. "nbf" and caveats only
// accumulate. Omitted claims inherit. A link without "cnf" is a bearer
// leaf: nobody can derive from it, and whoever holds it can use it.
//
// # Composing
//
// [Policy.Root] verifies the root however the application already does,
// so a chain can grow from any JWT: an OAuth access token, a token minted
// with package jwt, or one checked against a JWKS. [RootVerifier] reuses
// the application's [jwt.Verifier], so the root passes the same issuer,
// type, algorithm and key-set checks as any other token; [RootKey] covers
// the simplest case of one issuer key. [Grant.Holder] is the key thumbprint a
// DPoP proof must match (pass it as dpop.Request.Thumbprint), and
// [Policy.Caveat] is where an application evaluates caveats in whatever
// language it likes, with the request's context.
//
// # Limits
//
// [Limits] bounds the number of links, the size in bytes and the accepted
// link algorithms. Its zero value applies [DefaultMaxLinks],
// [DefaultMaxSize] and [DefaultAlgorithms]. A [Policy] carries one, and
// [WithLimits], [Limits.Parse] and [Limits.Inspect] apply the same bounds
// when deriving, parsing and inspecting.
//
// # Usage
//
// The issuer mints a root bound to the holder, using [jwt.ConfirmationFor]
// for the "cnf" claim. The holder narrows it, and a verifier checks it:
//
//	parent, err := jwtchain.Parse(rootToken)
//	chain, err := jwtchain.Derive(parent, holderKey, jwtchain.Restriction{
//		Expiry: time.Now().Add(5 * time.Minute),
//		Scope:  []string{"read"},
//		Holder: nextHolderKey.Public(),
//	})
//
//	policy := &jwtchain.Policy{
//		Root:     jwtchain.RootKey(issuerPublicKey),
//		Audience: "https://api.example",
//	}
//	grant, err := policy.Verify(ctx, chain.String())
//
// # Security
//
// Verify with [Policy] only; [Chain.Inspect] does not check the root. The
// package follows the JWT best current practices (RFC 8725): links carry an
// explicit "typ" (§3.11), algorithms are allowlisted and never symmetric
// or "none" (§3.1, §3.2), and a verifier names its audience (§3.9).
//
// # References
//
//   - RFC 6920, Naming Things with Hashes: https://www.rfc-editor.org/rfc/rfc6920.html
//   - RFC 7515, JSON Web Signature: https://www.rfc-editor.org/rfc/rfc7515.html
//   - RFC 7519, JSON Web Token: https://www.rfc-editor.org/rfc/rfc7519.html
//   - RFC 7638, JWK Thumbprint: https://www.rfc-editor.org/rfc/rfc7638.html
//   - RFC 7800, Proof-of-Possession Key Semantics ("cnf"): https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1
//   - RFC 8693, OAuth 2.0 Token Exchange ("act"): https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
//   - RFC 8725, JWT Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725.html
//   - RFC 9278, JWK Thumbprint URI: https://www.rfc-editor.org/rfc/rfc9278.html
package jwtchain
