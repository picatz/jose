# Changelog

The module has no tagged release yet, so everything below is unreleased.
Until v1, minor versions may change the API; every change is listed here.

## Unreleased

### One way to verify a JWT

`jwt.Verifier` is the single path for verifying a JWT. It checks the JOSE
layer (size, canonical encoding, `typ`, `alg`, `crit`, signature) and the
registered claims (`iss`, `aud`, `exp`, `nbf`, `iat`), and returns typed
errors: refusals (`ErrFormat`, `ErrSignature`, `ErrExpired`,
`ErrNotYetValid`, `ErrClaims`) wrap `ErrInvalidToken`, while a failed key
source gives `ErrKeysUnavailable`, so a server can retry instead of
answering 401. Keys come
from a `KeySource`: `jwt.Keys` for fixed keys, `jwt.KeysFromSet` for a JWK
Set, or your own source for a fetched JWKS.

Its defaults are secure: asymmetric algorithms only unless HMAC is listed,
`none` never accepted, `exp`, `iss` and `aud` required unless waived by name
(`AllowNoExpiry`, `AnyIssuer`, `AnyAudience`), `typ` checked (RFC 8725
§3.11), `crit` limited to what the caller lists (and `b64` refused), and
bounded token size and key trials. `jwt.New` refuses `alg: none`.

**Removed, not deprecated:** `ParseAndVerify`, `Token.Verify` and the
`VerifyOption` family (`WithKey`, `WithAllowedIssuers`,
`WithAllowInsecureNoneAlgorithm` and the rest), `VerifyConfig`, `Clock`,
`DefaultAllowedAlgorithms`, `Token.Sign`, the per-algorithm
`*Signature`/`Verify*Signature` methods, `Token.Expired`/`Expires`, and
`ParseString`. Mint tokens with `jwt.New` or `jwt.NewWithSigner`, decode
without verifying with `jwt.Parse`, and verify with `jwt.Verifier`.

Why remove instead of deprecate: no release has been tagged and no known
consumer calls the old API, so no compatibility promise is broken. Keeping it
would ship v0.1.0 with two verifiers, one of which can be configured to
accept `alg: none` and can emit unsigned tokens, which is exactly the
baggage a security library should not carry into its first release.

### Attenuation chains and lineage

- `jwtchain`: capability tokens that any holder can narrow offline (fewer
  audiences and scopes, sooner expiry, caveats, a new holder key), linked to
  their parent by an RFC 6920 digest or embedded, verified back to the
  issuer, and re-issued with RFC 8693 `act` lineage. A link issued in the
  future (beyond the leeway) is refused.
  `Policy.Verify` and `VerifyChain` take a context, which reaches
  `Policy.Root` (a `RootFunc`) and `Policy.Caveat` (a `CaveatFunc`).
  `RootVerifier` verifies the root with a `jwt.Verifier`, so it passes the
  same issuer, type, algorithm and key-set checks as any other token.
- `ni`: RFC 6920 Named Information URIs.
- `jwt`: RFC 8693 `act` and `may_act` helpers (`Actors`, `SetActors`,
  `AllowedActor`).
- `jwk/thumbprint`: RFC 9278 thumbprint URIs (`URN`).
- `jws.ParseCritical` for callers that understand extra `crit` parameters.
- `jwk` refuses RSA moduli over 8192 bits.

**Moved:** the HTTP helpers of `jwt` (`FromHTTPAuthorizationHeader`,
`HTTPHeaderValue`, `SetHTTPAuthorizationHeader`) are now
`jwthttp.BearerToken` and `jwthttp.SetBearerToken`, so the core packages do
not import `net/http`.
