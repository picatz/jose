# Changelog

The module has no tagged release yet, so everything below is unreleased.
Until v1, minor versions may change the API; every change is listed here.

## Unreleased

### Security fixes

- `jws`: `Verify` on a parsed compact JWS now covers the current `Payload`,
  not only the payload that was parsed.
- `jwe`: a compact JWE whose `epk` header has a foreign `kty` no longer
  panics; `epk` must be `EC` or `OKP`.
- `jwk`: `PublicKey` no longer panics on an RSA key with an empty `n` or `e`
  (found by fuzzing).
- `dpop`: `TargetURI` refuses empty hostnames, malformed IPv6 hosts and IPv6
  zones (found by fuzzing); `BoundThumbprint` refuses a `cnf` with members
  besides `jkt`; the verifier requires canonical base64url and strict claims
  (UTF-8, no duplicate members, no trailing data).
- `jwkhttp`: a slow or failing refetch no longer blocks verifiers of keys that
  are already cached, and a fetch refuses an `https` to `http` redirect.
- `jwtchain`: a root `cnf` with `jkt` plus another member binds no holder.

### Testing helpers and documentation

- New `josetest` (in the spirit of `net/http/httptest`): `Key` (a fresh key
  for a signature algorithm), `Secret`, `Token` (a signed JWT) and `JWKS` (a
  server publishing a JWK Set, with RFC 7638 thumbprint `kid`s), plus `KeyID`.
- `pkg/doc.go` maps every package to its RFC sections (adds RFC 7797, 8725
  and 6750); the README is rewritten around a tested quickstart, a package
  table and the security defaults.
- README: the Go Report badge is replaced.
- `examples/http` no longer shares one token variable across requests, and
  `examples/pprof` verifies the subject claim instead of checking the token
  for nil.

### `jws`

- `ErrFormat`, `ErrSignature` and `ErrAlgorithm` wrap every error;
  `ErrNoValidSignature` matches `ErrSignature`. Parsed headers hold `alg` as a
  `jwa.Algorithm`.
- Tested against the RFC 7515 A.2 to A.6, RFC 8037 A.4 and RFC 7520 4.5 vectors.

**Removed, not deprecated:** `Signature.SignHMAC`, `VerifyHMAC`, `SignRSA`,
`VerifyRSA`, `SignRSAPSS`, `VerifyRSAPSS`, `SignECDSA`, `VerifyECDSA`,
`SignEdDSA` and `VerifyEdDSA`. Use `jws.New` with a key and `Signature.Verify`.

### `jwt` core

- `ClaimsSet` is a plain `map[string]any`; claim names are untyped string
  constants, so read claims by indexing (`claims[jwt.Subject]`).
- `New(params, claims, key)` is the one constructor: it copies its inputs,
  refuses `none` and a nil key, and takes any key `jws.New` takes.
  `Parse(string)` decodes without verifying, refuses a non-string `alg`, and
  wraps `ErrFormat`. `Token.String` returns the serialization fixed at signing
  or decoding, and `""` otherwise.
- `JWTID` is now `ID`; `WithContext` is now `NewContext` and `ContextKey` is
  unexported; `ConfirmedThumbprint` reads a nested `ClaimsSet`.
- New `ConfirmationFor(key)` builds a `cnf` claim and
  `ClaimsSet.ConfirmedThumbprint()` reads it back.

**Removed, not deprecated:** `ClaimName`, `Registered`, `Public`, `Private`,
`ClaimValue`, `ClaimsSet.Get`, `Set`, `Names` and `Base64URLString`,
`GetClaimValue`, `Parseable`, the generic `New[T]` and `Parse[T]`, and
`NewWithSigner` (the one `New` takes a `crypto.Signer` directly).

### `jwk`, `thumbprint` and `jwkhttp`

- `jwk.Value` is now `jwk.Key`, a defined type `map[string]any`.
  `X509SHA1Thumbprint` and `X509SHA256Thumbprint` are now
  `X509CertificateSHA1Thumbprint` and `X509CertificateSHA256Thumbprint`.
- `jwk.ParseSet` reads a set strictly (`ErrFormat`); `Set.Get` returns
  `(Key, bool)`; `Validate` is built on `PublicKey` and `PrivateKey`, and
  `Set.Validate` refuses duplicate `kid`s.
- `jwkhttp.Keys` is a `jwt.KeySource` for a JWKS URL, with `ErrInsecureURL`
  and `ErrFetch`. `FetchSet` is https only (http to a loopback host is
  allowed), refuses an https to http redirect, and caps the body at 1 MiB.

**Removed, not deprecated:** `jwk.ParameterName`, the `RSA`, `ECDSA` and
`Symmetric` aliases, `RSAValues`, `ECDSAValues`, `Ed25519Values`,
`SymmetricKey`, `HMACSecretKey`, `Ed25519PublicKey`, and `jwkhttp.URLSetCache`.
Member names are untyped constants.

### `jwe`

- New `Decrypter{Key, Algorithms, Encryptions, Critical}` with `Decrypt`,
  `DecryptMessage` and `DecryptJSON`: the key travels with its policy, as with
  `jwt.Verifier`. A `[]byte` key with nil `Algorithms` is `ErrNotAllowed`, so
  list the symmetric algorithms you accept.
- Compact `Parse` refuses duplicate header members.
- Tested against RFC 7516 A.1 and A.3, RFC 7518 B.1 to B.3 and RFC 7520 5.10
  to 5.13, and fuzzed with `FuzzDecrypt`.

**Removed, not deprecated:** the free `Decrypt`, `DecryptOptions`,
`Message.Decrypt`, `JSON.Decrypt`, and the jwe header-name constants (use the
`header` package; `CompressionAlgorithm` is `header.Zip`).

### `header`, `jwa`, and internal packages

- `jwa.Algorithm` and `jwa.ContentEncryption` are defined string types, so
  `header.Parameters{"alg": 42}`-style mistakes are caught where algorithms
  are compared. Added `Algorithm.IsSymmetric`, `Algorithm.IsKeyManagement` and
  `ContentEncryption.IsContentEncryption`.
- `header.Encryption` is now `header.EncryptionAlgorithm`, with
  `Parameters.EncryptionAlgorithm()`; `Algorithm()` accepts a `jwa.Algorithm`
  or a string; `ValidateCriticalHeaders` wraps `ErrCriticalHeaderValidation`.

**Removed, not deprecated:** `header.ParameterName`, `Registered`, `Public`,
`Private`, `Parameters.SymmetricAlgorithm` and `AsymmetricAlgorithm`,
`ErrFailedToEncodeHeader`, `jwa.ValidateAlgorithm`, `pkg/base64` (now
`internal/base64url`; use `encoding/base64.RawURLEncoding`) and `pkg/keyutil`
(use `crypto/ecdsa`, `rsa`, `ed25519`, `x509`, or `josetest` in tests).

### `dpop` and confirmation

**Removed, not deprecated:** `dpop.ClaimJWTID`, `ClaimIssuedAt`,
`ClaimConfirmation`, `ConfirmationThumbprint` and `Confirmation(jkt)`. Use
`jwt.JWTID`'s successor `jwt.ID`, `jwt.IssuedAt`, `jwt.Confirmation` and
`jwt.ConfirmationFor(key)`.

### `jwtchain` and `ni`

- `Limits{MaxLinks, MaxSize, Algorithms}` replaces `Policy.MaxLinks`,
  `MaxSize` and `Algorithms` with `Policy.Limits`; added the `WithLimits`
  derive option and `Limits.Parse` and `Limits.Inspect`.

**Removed, not deprecated:** `jwtchain.Confirmation` (use
`jwt.ConfirmationFor`).

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
`ParseString`. Mint tokens with `jwt.New`, decode
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
