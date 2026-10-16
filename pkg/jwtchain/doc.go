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
//     [Verified.Actors] and [jwt.ClaimsSet.SetActors]. The new token is as
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
// with package jwt, or one checked against a JWKS. [RootKey] covers the
// common case of one issuer key. [Verified.Holder] is the key thumbprint a
// DPoP proof must match (pass it as dpop.Request.Thumbprint), and
// [Policy.Caveat] is where an application evaluates caveats in whatever
// language it likes.
package jwtchain
