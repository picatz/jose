# picatz/jose: reviewed (rung 1)

Recorded 2026-10-20 at commit `09b3aca`, Go 1.26.9 on linux/amd64.

This file is the evidence that the whole module, every package under `pkg/`,
meets the reviewed rung of the
[Keyblade stability ladder](https://github.com/picatz/go-keyblade/blob/main/docs/stability.md#gates).
That rung's gates are a second-reader review, a fuzz target for each parser, a
row in the threat model and a fresh-clone run by someone other than the
author. The module stays untagged; tags are the owner's call.

## Second-reader review

The reviewer was an AI second reader (Claude), working in a session separate
from the one that wrote the fixes. This is not an independent human audit or
an external audit. The full report is
[review-2026-10-20.md](review-2026-10-20.md).

- **What it read.** Every non-test source in jws, jwa, jwt and jwthttp, jwe,
  jwk with thumbprint and jwkhttp, dpop and dpophttp, jwtchain, ni, header,
  and the internal base64url and strictjson packages (about 9,500 lines). It
  read them against RFC 7515, 7516, 7517, 7518, 7519, 7638, 7797, 7800, 8037,
  8693, 8725, 9278, 9449 and 6920, wrote probe tests in a scratch copy, and
  fuzzed every target.
- **What it confirmed.** It found no way to:
  - forge a token;
  - get `alg: none` accepted;
  - use an HMAC secret as an RSA key or the other way round;
  - slip in an invalid-curve ECDH key;
  - make an attenuation chain broaden its parent;
  - follow `jku` or `x5u`.

  The report lists each of these checks with `file:line`, under "Verified
  correct".
- **Findings, all fixed on 2026-10-20:**
  - **Blocking, B1.** The JSON serializations put no cap on recipients or
    signatures, and each one costs a private-key or verify operation: 2,500
    recipients took 2.9 s of CPU. `ParseJSON` in jwe and jws now refuses more
    than 16 before any crypto (`f9dcb55`). Tests: `TestParseJSONRecipientLimit`,
    `TestParseJSONSignatureLimit`.
  - **Low, L1.** Base64url decoding skipped CR and LF, so one token had more
    than one spelling, which defeats caches keyed on the raw string. Fixed in
    `2f8e7b8`. Tests: `TestDecodeRejectsLineBreaks`, `TestParseRejectsLineBreaks`.
  - **Low, L2.** ES* signatures are malleable (s versus n-s), and a comment
    claimed otherwise. The docs now say to key replay and revocation caches on
    `jti` (`362fc43`). Test: `TestECDSAHighSVerifies` pins the behavior.
  - **Low, L3.** A jwtchain root whose `cnf` names no key thumbprint (empty,
    or mTLS-only) passed without `AllowBearer` and left `Grant.Holder` empty.
    It is now refused with `ErrBearer` (`472b98f`). Test:
    `TestRootWithoutHolderIsBearer`.
  - **Low, L4.** Anyone can fill `dpop.MemoryReplayCache` with self-signed
    proofs, and a full cache scanned the whole map on every check. It now
    refuses in constant time until its earliest expiry passes, still fails
    closed, and documents the fill attack (`a39e900`). Test:
    `TestMemoryReplayCacheEvictsOnlyExpired`.
  - **Low, L5 and R1.** One key with an unknown `kty`, or with an EC or OKP
    curve the module does not support, made a whole JWK Set unusable, against
    RFC 7517 §5. Such keys are now ignored (`ebcd0d6`, `f643b9f`). Tests:
    `TestSetValidateIgnoresUnknownKeyType`, `TestSetValidateIgnoresUnknownCurve`,
    `TestKeysFromSetIgnoresUnknownKeyType`, `TestKeysFromSetIgnoresUnknownCurve`.
  - **Nits fixed.** `jwt.Verifier` now wraps causes with `%w` and judges time
    claims only after the signature verifies (`2f227f9`). There is a
    truncated-tag test for every JWE `enc` (`b729fda`). Tests:
    `TestVerifierChecksSignatureBeforeTime`, `TestVerifierKeepsParseCause`,
    `TestWrongLengthTagFailsUniformly`.
- **Re-review.** The same reviewer re-read every fix and closed each finding.
  Its one new Low (R1, unsupported curves) was fixed in `f643b9f`.
- **Open findings.** None Blocking or Low. The remaining Nits stay open,
  each a documentation or ergonomics change, listed in the report:
  - `DecryptJSON` and `JSON.Verify` do not repeat the 16-entry cap for a value
    a caller builds by hand.
  - `jwt.Verifier` has no opt-in to require `cnf`.
  - `jwe.Parse` splits the string before counting its parts.
  - `enc` is allowed in an unprotected header.
  - `jwthttp` reads only the first Authorization header.
  - A `RootKey` chain root may have no `exp`.
  - A few non-verification errors have no sentinel.
  - `jwkhttp` accepts `localhost` by name.
  - `IsPrivate` knows only today's private member names.

## Fuzz targets

Every exported `Parse*`, `Decode*`, `Unmarshal*` and `Open*` function is
reached by a fuzz target, and so is every verifier and every HTTP header
reader. The targets added for this rung are in `70a536e`.

| Package | Parser or verifier | Target |
| --- | --- | --- |
| `jws` | `Parse` | `FuzzParse` |
| `jws` | `ParseJSON` | `FuzzParseJSON` |
| `jws` | `ParseDetached` | `FuzzParseDetached` |
| `jws` | `ParseCritical` | `FuzzParseCritical` |
| `jwt` | `Parse` | `FuzzParse` |
| `jwt` | `Verifier.Verify` | `FuzzVerify` |
| `jwt` | `Actors`, `AllowedActor`, `ConfirmedThumbprint` | `FuzzActors` |
| `jwt/jwthttp` | `BearerToken` | `FuzzBearerToken` |
| `jwe` | `Parse` | `FuzzParse` |
| `jwe` | `ParseJSON` | `FuzzParseJSON` |
| `jwe` | `Decrypter.Decrypt` | `FuzzDecrypt` |
| `jwk` | `ParseSet` | `FuzzParseSet` |
| `jwk` | `PublicKey` | `FuzzPublicKey` |
| `jwk/thumbprint` | `Generate`, `FromPublicKey` | `FuzzGenerate`, `FuzzFromPublicKey` |
| `jwtchain` | `Parse`, `Limits.Parse` | `FuzzParse` |
| `jwtchain` | `Policy.Verify` | `FuzzVerify` |
| `dpop` | `Verifier.Verify` | `FuzzVerify` |
| `dpop` | `TargetURI` | `FuzzTargetURI` |
| `dpop` | `BoundThumbprint` | `FuzzBoundThumbprint` |
| `dpop/dpophttp` | `AccessTokenFromRequest`, `FromRequest` | `FuzzAccessTokenFromRequest`, `FuzzFromRequest` |
| `header` | `ValidateCriticalHeaders` | `FuzzValidateCriticalHeaders` |
| `ni` | `Parse` | `FuzzParse` |

Each target is seeded with valid and malformed inputs and checks an invariant,
not only that nothing panics. For example, `jwt` `FuzzVerify` accepts a token
only if the test key signed exactly its header and payload. `jwtchain`
`FuzzVerify` accepts only a grant that is no broader than its root. All 24
targets ran for 10 s each in the fresh-clone run below, with no failure.

## Threat model

The module's row is under B3 in Keyblade's
[system threat model](https://github.com/picatz/go-keyblade/blob/main/docs/threat-model.md#b3-network-between-client-and-server):
token forgery, algorithm and key confusion, malleable encodings, and
verification-cost amplification.

## Fresh-clone run

- **Author:** the Keyblade "JOSE and DPoP" thread (Claude session 01UWbnnn6AFLNTpqCyppjazt)
- **Runner:** a fresh Claude session that did not write the code
- **Transcript:** [fresh-clone-2026-10-20.md](fresh-clone-2026-10-20.md)

The runner cloned `claude/jose-reviewed` at `f643b9f` and followed the README
quickstart literally, which printed `alice` as documented. It ran
`go mod verify`, `go vet`, `go test -race` and the examples, all of which
passed, and fuzzed all 24 targets. It also ran the tests under
`GODEBUG=fips140=only`. Its findings were fixed before this rung was recorded:

- **A typed nil key panicked.** In FIPS 140-only mode, RSA-1024 and X25519
  key generation fail, and `jwa.ForKey` panicked on the typed nil key left
  behind. Four tests also ignored the key-generation error. `ForKey` now
  refuses a typed nil RSA or ECDSA key, and the tests fail cleanly (`09b3aca`).
- **The README snippets showed no imports.** The README now shows the import
  paths and says that FIPS 140-only mode is not supported.

FIPS 140-only mode is not supported. Go refuses AES-GCM with a caller-chosen
IV in that mode, and JWE requires one, so GCM content encryption cannot work.
X25519 and RSA keys under 2048 bits are refused as well. The tests that use
them fail in that mode, which is expected and recorded in the transcript.

## Runs on 2026-10-20

| Command | Result |
| --- | --- |
| `go vet ./...` | clean |
| `go test -race -count=1 ./...` | ok, every package |
| `go test -run '^Example' ./...` | ok |
| `go mod verify` and `grep -c require go.mod` | verified, 0 requires (standard library only) |
| every `Fuzz` target alone, `-fuzztime=10s` | 24 targets, 166k to 904k execs each, no failure |
| `GODEBUG=fips140=only go test ./...` | fails as expected (not supported; see above). After `09b3aca` the only panic left is an `Example` that calls `panic(err)` by design |

Not yet: the next rung, conformance-tested, needs a `josetest` harness that
another implementation can run against official vectors. The jws and jwe
cookbook and RFC vectors already checked in are its start.
