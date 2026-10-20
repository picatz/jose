# Fresh-clone verification: github.com/picatz/jose

- Date: 2026-10-20
- Runner: fresh Claude session, not the author
- Commit: f643b9f7aa59fa7ccba2391fc916e147e555a86f (branch claude/jose-reviewed)
- Go: go1.26.9 linux/amd64 (GOOS=linux GOARCH=amd64)

## 1. Clone
```
$ git clone --branch claude/jose-reviewed https://github.com/picatz/jose.git
$ git rev-parse HEAD
f643b9f7aa59fa7ccba2391fc916e147e555a86f
```
## 2. Toolchain
```
$ export PATH=$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.linux-amd64/bin:$PATH
$ go version
go version go1.26.9 linux/amd64
```
## 3. README quickstart (a scratch module outside the clone, with a replace directive pointing at it)
README snippets have no imports/package line; I added imports from pkg/{header,jwa,jwt,jwk/jwkhttp}. Both snippets compiled.
```
$ go build ./... && go run .
alice
jwkhttp verifier (no Algorithms) err: jwt: verification keys unavailable: jwkhttp: fetching key set failed: Get "https://issuer.example/jwks": Forbidden
```
Quickstart 1 worked exactly as documented (prints alice). Snippet 2 compiles; fetch fails only because issuer.example is fake and the sandbox proxy returned 403 (expected). Snippet 2 omits `Algorithms`; I could not test whether that is accepted/defaulted because no key set was reachable.

## 4. Module checks (in clone)
```
$ go mod verify            -> all modules verified (rc=0)
$ go vet ./...             -> no output (rc=0)
$ go test -count=1 -race ./...   -> all 17 packages ok (examples/pprof: no test files)
$ go test -run '^Example' ./...  -> all ok
```
### GODEBUG=fips140=only go test -count=1 ./...  -> FAIL (rc=1)
Failing packages: pkg/dpop, pkg/jwa, pkg/jwe, pkg/jwk, pkg/jws, pkg/jwt, pkg/jwtchain. 14 distinct failing tests:
TestNewSignerRejectsUnusableKeys, TestForKey, TestDecrypterZeroValueAndDefaults, TestDecrypterCritical, TestDecryptMessage, TestCookbookJSONDecrypt, TestJSONMultipleRecipientsRoundTrip, TestJSONFlattenedAndDirect, TestCookbookKeys, TestPrivateKeyRoundTrips, TestPSSSaltLengthEqualsHash, TestSignRejectsWrongKeyType, TestConfirmationFor, TestReviewRegressions.
Representative messages:
```
jwa_test.go:103: crypto/rsa: use of keys smaller than 2048 bits is not allowed in FIPS 140-only mode
decrypter_test.go:57: crypto/cipher: use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode, use NewGCMWithRandomNonce
json_test.go:64: Decrypt: index -1, jwe: decryption failed   (A128KW/A128GCM, RSA-OAEP/A256GCM, ECDH-ES+A128KW, dir/A128GCM...)
--- FAIL: TestNewSignerRejectsUnusableKeys
panic: runtime error: invalid memory address or nil pointer dereference
  crypto/rsa.(*PrivateKey).Public rsa.go:123
  jwa.ForKey key.go:24 <- dpop.NewSigner signer.go:72 <- dpop_test.go:129
```
(4 panics total in the run: nil-pointer in rsa.Public via jwa.ForKey from a typed-nil/invalid RSA key after the 1024-bit GenerateKey fails in FIPS mode; the test ignores the GenerateKey error.)
Interpretation: mostly legitimate FIPS-only refusals (sub-2048-bit RSA test keys, AES-GCM with caller-supplied IV, which the JWE spec requires). The nil-pointer panic is a test-robustness issue (error ignored) but jwa.ForKey also does not guard a nil RSA key.

## 5. Fuzzing (24 targets, each alone, -fuzztime=10s); all passed, no failures, no testdata created (git status clean)
```
$ go test -run='^$' -fuzz='^NAME$' -fuzztime=10s ./PKG
```
| Package | Target | Final execs |
|---|---|---|
| pkg/ni | FuzzParse | 773,514 |
| pkg/jws | FuzzParse | 610,753 |
| pkg/jws | FuzzParseJSON | 624,254 |
| pkg/jws | FuzzParseDetached | 236,167 |
| pkg/jws | FuzzParseCritical | 266,050 |
| pkg/jwt/jwthttp | FuzzBearerToken | 538,043 |
| pkg/jwt | FuzzVerify | 176,718 |
| pkg/jwt | FuzzActors | 453,560 |
| pkg/jwt | FuzzParse | 230,724 |
| pkg/header | FuzzValidateCriticalHeaders | 903,863 |
| pkg/jwk/thumbprint | FuzzGenerate | 876,788 |
| pkg/jwk/thumbprint | FuzzFromPublicKey | 876,987 |
| pkg/jwk | FuzzPublicKey | 890,565 |
| pkg/jwk | FuzzParseSet | 166,577 |
| pkg/jwtchain | FuzzVerify | 420,363 |
| pkg/jwtchain | FuzzParse | 309,516 |
| pkg/jwe | FuzzParse | 648,408 |
| pkg/jwe | FuzzParseJSON | 191,632 |
| pkg/jwe | FuzzDecrypt | 218,489 |
| pkg/dpop | FuzzTargetURI | 472,060 |
| pkg/dpop | FuzzVerify | 289,716 |
| pkg/dpop | FuzzBoundThumbprint | 538,419 |
| pkg/dpop/dpophttp | FuzzAccessTokenFromRequest | 343,113 |
| pkg/dpop/dpophttp | FuzzFromRequest | 349,587 |

## 6. go.mod
```
module github.com/picatz/jose
go 1.24.4
```
`grep -c require go.mod` = 0: stdlib only.

## Findings
1. README snippets are fragments: no package/imports, and import paths (github.com/picatz/jose/pkg/jwt etc.) are not shown; a newcomer must guess them. Install says `go get github.com/picatz/jose@latest`, but the module root has no Go package (only pkg/...).
2. Quickstart 1 runs correctly as written.
3. Snippet 2 (jwkhttp) omits `Algorithms`; behaviour unverified here (network blocked).
4. GODEBUG=fips140=only: 14 tests fail across 7 packages. Mostly legitimate FIPS refusals (<2048-bit RSA, GCM arbitrary IV), but README/docs say nothing about FIPS mode, and AES-GCM JWE decrypt fails entirely in fips140=only (JWE inherently needs caller IVs).
5. FIPS run produces a nil-pointer panic: jwa.ForKey(nil *rsa.PrivateKey) -> rsa.Public; test ignores GenerateKey error. Possible hardening: nil-key guard in ForKey.
6. All fuzz targets (24) clean at 10s; go.mod has zero requires; clone remained unmodified.
