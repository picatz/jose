# JOSE

[![Go Reference](https://pkg.go.dev/badge/github.com/picatz/jose.svg)](https://pkg.go.dev/github.com/picatz/jose)
[![Test](https://github.com/picatz/jose/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/picatz/jose/actions/workflows/test.yml)
[![Scan](https://github.com/picatz/jose/actions/workflows/scan.yml/badge.svg?branch=main)](https://github.com/picatz/jose/actions/workflows/scan.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/picatz/jose)](go.mod)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)

A JOSE toolkit for Go that is secure by default, built on the standard
library alone, and organized around the RFCs: JWS, JWE, JWK and JWT
([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html),
[7516](https://www.rfc-editor.org/rfc/rfc7516.html),
[7517](https://www.rfc-editor.org/rfc/rfc7517.html),
[7519](https://www.rfc-editor.org/rfc/rfc7519.html)), the
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) best current practices,
DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)), and
attenuation chains built from them. A verifier takes the algorithm from your
allowlist and never from the token, refuses `alg: none`, and checks issuer,
audience and expiry unless you waive them by name. Package documentation cites
the RFC section behind each behaviour.

## Install

```console
$ go get github.com/picatz/jose@latest
```

There are no dependencies beyond the Go standard library.

## Quickstart

Mint a token with `jwt.New` and verify it with a `jwt.Verifier`. The
packages live under `pkg/`:

```go
import (
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)
```

```go
// The issuer signs with a private key...
public, private, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
	panic(err)
}

token, err := jwt.New(
	header.Parameters{header.Algorithm: jwa.EdDSA, header.KeyID: "key-1"},
	jwt.ClaimsSet{
		jwt.Issuer:         "https://issuer.example",
		jwt.Audience:       "https://api.example",
		jwt.Subject:        "alice",
		jwt.ExpirationTime: time.Now().Add(time.Hour),
	},
	private,
)
if err != nil {
	panic(err)
}

// ...and the API verifies with the public key. Issuer, audience and
// expiry are required, and the algorithm comes from the verifier.
verifier := &jwt.Verifier{
	Keys:       jwt.Keys{{ID: "key-1", Public: public}},
	Algorithms: []jwa.Algorithm{jwa.EdDSA},
	Issuer:     "https://issuer.example",
	Audience:   "https://api.example",
}

verified, err := verifier.Verify(context.Background(), token.String())
if err != nil {
	panic(err)
}
fmt.Println(verified.Claims[jwt.Subject]) // alice
```

Claims are a plain `map[string]any`, read by indexing. To verify tokens from
a remote issuer, swap the key source for a cached JWK Set (the URL is yours,
never taken from a token):

```go
verifier := &jwt.Verifier{
	Keys:     &jwkhttp.Keys{URL: "https://issuer.example/jwks"},
	Issuer:   "https://issuer.example",
	Audience: "https://api.example",
}
```

A runnable HTTP server is in [`examples/http`](examples/http).

## Packages

| Package | What it does |
| --- | --- |
| [`jwt`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwt) | Mint, decode and verify JSON Web Tokens; `Verifier` enforces algorithm allow-lists, `typ` and claim checks |
| [`jwt/jwthttp`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwt/jwthttp) | Read and set bearer tokens in HTTP Authorization headers |
| [`jws`](https://pkg.go.dev/github.com/picatz/jose/pkg/jws) | Sign and verify JWS with any `crypto.Signer`, compact or JSON (general and flattened), with detached and unencoded (RFC 7797) payloads |
| [`jwe`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwe) | Encrypt and decrypt compact and JSON (general/flattened, multi-recipient) JWE: ECDH-ES, RSA-OAEP, AES key wrap, `dir`; GCM and CBC-HS; `Decrypter` carries the key and policy |
| [`jwk`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwk) | Parse and emit JWKs and JWK Sets strictly; [`thumbprint`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwk/thumbprint) computes RFC 7638 thumbprints and RFC 9278 URIs |
| [`jwk/jwkhttp`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwk/jwkhttp) | A `jwt.KeySource` that fetches and caches a JWK Set from a URL you trust, https only |
| [`dpop`](https://pkg.go.dev/github.com/picatz/jose/pkg/dpop) | Mint DPoP proofs and verify them, with replay, nonce and token binding checks |
| [`dpop/dpophttp`](https://pkg.go.dev/github.com/picatz/jose/pkg/dpop/dpophttp) | An `http.RoundTripper` that adds proofs and retries on `use_dpop_nonce`, and server helpers |
| [`jwtchain`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwtchain) | Attenuation chains: capability tokens any holder can narrow offline (fewer audiences and scopes, sooner expiry, caveats, a new holder key), linked by digest or embedded, verified back to the issuer, and re-issued with RFC 8693 `act` lineage |
| [`ni`](https://pkg.go.dev/github.com/picatz/jose/pkg/ni) | Named Information URIs (RFC 6920), digests that name content, such as one token referring to another |
| [`jwa`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwa), [`header`](https://pkg.go.dev/github.com/picatz/jose/pkg/header) | Algorithm identifiers and header parameters |
| [`josetest`](https://pkg.go.dev/github.com/picatz/jose/pkg/josetest) | Test helpers in the spirit of `httptest`: fresh keys, signed tokens and a JWKS server |

Only the `*http` packages import `net/http`, so offline programs link no HTTP
code. Asymmetric signing accepts any `crypto.Signer`, so keys held in
hardware (PIV, TPM, Secure Enclave) or a remote KMS sign like in-memory keys;
JWE decryption accepts `jwe.KeyAgreement` and `crypto.Decrypter` likewise.

## Security defaults

- The algorithm comes from an allowlist, never from the token alone; `none` is never accepted and `jwt.New` will not mint it.
- HMAC is off unless listed, so a public key cannot be replayed as a secret.
- `iss`, `aud` and `exp` are required unless waived by name (`AnyIssuer`, `AnyAudience`, `AllowNoExpiry`); `typ` is checked.
- `crit` is limited to what you list; `b64` is refused in JWTs.
- Token size, key trials, RSA modulus size (8192 bits) and chain length are all bounded.
- Encodings are canonical and strict: no padding, duplicate members or trailing data.
- JWE failures return one error, so decryption is no oracle; RSA1_5, PBES2 and `zip` are not implemented.
- Key sets are fetched only from URLs you configure (https, or loopback http), never from `jku` or `x5u`, with a 1 MiB cap, no https-to-http redirect, and a fetch that never blocks verifiers of cached keys.
- JWK Sets that publish private or symmetric keys are refused.
- JWE and JWS JSON serializations carry at most 16 recipients or signatures.
- FIPS 140-only mode (`GODEBUG=fips140=only`) is not supported: JWE needs
  AES-GCM with a caller-chosen IV, which that mode refuses.

## Stability

The module is at the **reviewed** rung of the
[Keyblade stability ladder](https://github.com/picatz/go-keyblade/blob/main/docs/stability.md#gates):
a second-reader security review, a fuzz target for every parser and verifier,
and a fresh-clone run by a non-author. See
[docs/evidence/reviewed.md](docs/evidence/reviewed.md). It is not tagged yet.

See [SECURITY.md](SECURITY.md) to report a vulnerability and
[CHANGELOG.md](CHANGELOG.md) for every API change.

## RFCs

- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) (**JWS**) JSON Web Signature
- [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516) (**JWE**) JSON Web Encryption
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) (**JWK**) JSON Web Key
- [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) (**JWA**) JSON Web Algorithms
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) (**JWT**) JSON Web Token
- [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) Bearer Token Usage
- [RFC 6920](https://datatracker.ietf.org/doc/html/rfc6920) Naming Things with Hashes (`ni` URIs)
- [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) JSON Web Key (JWK) Thumbprint
- [RFC 7797](https://datatracker.ietf.org/doc/html/rfc7797) JWS Unencoded Payload Option
- [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800) Proof-of-Possession Key Semantics for JWTs (`cnf`)
- [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037) (**OKP**) Ed25519 signatures and X25519 key agreement
- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) OAuth 2.0 Token Exchange (`act` and `may_act`)
- [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) JWT Best Current Practices
- [RFC 9278](https://datatracker.ietf.org/doc/html/rfc9278) JWK Thumbprint URI
- [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) (**DPoP**) OAuth 2.0 Demonstrating Proof of Possession

## History

[JOSE](https://datatracker.ietf.org/wg/jose/documents/) was developed by an IETF [working group](https://www.ietf.org/how/wgs/), 
 started in 2011. The group set out to develop a [JSON](https://datatracker.ietf.org/doc/html/rfc4627) syntax that could be 
used by applications to describe "secure data objects". It has become a well-known, standardized mechanism for integrity protection 
and encryption, as well as the format for keys and algorithm identifiers to support interoperability of security services for 
protocols that use JSON.
