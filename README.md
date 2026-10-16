# JOSE [![Go Reference](https://pkg.go.dev/badge/github.com/picatz/jose.svg)](https://pkg.go.dev/github.com/picatz/jose) [![Go Report Card](https://goreportcard.com/badge/github.com/picatz/jose)](https://goreportcard.com/report/github.com/picatz/jose) [![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0) 

JavaScript Object Signing and Encryption ([JOSE](https://datatracker.ietf.org/wg/jose/documents/)) implemented in Go.

## Installation

```console
$ go get github.com/picatz/jose@latest
```

## Packages

| Package | What it does |
| --- | --- |
| [`jwt`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwt) | Create, parse and verify JSON Web Tokens, with algorithm allow-lists and claim checks |
| [`jws`](https://pkg.go.dev/github.com/picatz/jose/pkg/jws) | Sign and verify JWS with any `crypto.Signer`, compact or JSON (general and flattened), with detached and unencoded (RFC 7797) payloads |
| [`jwe`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwe) | Encrypt and decrypt compact and JSON (general/flattened, multi-recipient) JWE: ECDH-ES, RSA-OAEP, AES key wrap, `dir`; GCM and CBC-HS |
| [`jwk`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwk) | Parse and emit JWKs and JWK Sets strictly; [`thumbprint`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwk/thumbprint) computes RFC 7638 thumbprints |
| [`jwt/jwthttp`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwt/jwthttp) | Read and set bearer tokens in HTTP Authorization headers |
| [`jwk/jwkhttp`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwk/jwkhttp) | Fetch and cache a JWK Set from a URL you trust |
| [`dpop`](https://pkg.go.dev/github.com/picatz/jose/pkg/dpop) | Mint DPoP proofs and verify them, with replay, nonce and token binding checks |
| [`dpop/dpophttp`](https://pkg.go.dev/github.com/picatz/jose/pkg/dpop/dpophttp) | An `http.RoundTripper` that adds proofs and retries on `use_dpop_nonce` |
| [`jwtchain`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwtchain) | Attenuation chains: capability tokens any holder can narrow offline (fewer audiences and scopes, sooner expiry, caveats, a new holder key), linked by digest or embedded, verified back to the issuer, and re-issued with RFC 8693 `act` lineage |
| [`ni`](https://pkg.go.dev/github.com/picatz/jose/pkg/ni) | Named Information URIs (RFC 6920), digests that name content, such as one token referring to another |
| [`jwa`](https://pkg.go.dev/github.com/picatz/jose/pkg/jwa), [`header`](https://pkg.go.dev/github.com/picatz/jose/pkg/header) | Algorithm identifiers and header parameters |

None of the packages above import `net/http` except the `*http` helpers, so offline programs link no HTTP code.

## Example Usage

```go
// Create a public/private key pair (ECDSA)
private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
	panic(err)
}

// Create a JWT token, sign it with the private key.
token, err := jwt.New(
	header.Parameters{
		header.Type:      jwt.Type,
		header.Algorithm: jwa.ES256,
	},
	jwt.ClaimsSet{
		"sub":  "1234567890",
		"name": "John Doe",
	},
	private,
)
if err != nil {
	panic(err)
}

mux := http.NewServeMux()

mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	bearerToken, err := jwthttp.BearerToken(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err = jwt.ParseAndVerify(bearerToken, jwt.WithKey(&private.PublicKey))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	sub, err := token.Claims.Get(jwt.Subject)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if sub != "1234567890" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	name, err := token.Claims.Get("name")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Welcome back, %s!", name)))
})

fmt.Println("Listening on http://127.0.0.1:8080")

fmt.Printf("Try running: curl http://127.0.0.1:8080 -H 'Authorization: Bearer %s' -v\n", token)

err = http.ListenAndServe("127.0.0.1:8080", mux)
if err != nil {
	panic(err)
}
```

## RFCs

- [RFC7515](https://datatracker.ietf.org/doc/html/rfc7515) (**JWS**) JSON Web Signature
- [RFC7516](https://datatracker.ietf.org/doc/html/rfc7516) (**JWE**) JSON Web Encryption
- [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517) (**JWK**) JSON Web Key
- [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518) (**JWA**) JSON Web Algorithms
- [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) (**JWT**) JSON Web Token
- [RFC6920](https://datatracker.ietf.org/doc/html/rfc6920) Naming Things with Hashes (`ni` URIs)
- [RFC7638](https://datatracker.ietf.org/doc/html/rfc7638) JSON Web Key (JWK) Thumbprint
- [RFC7800](https://datatracker.ietf.org/doc/html/rfc7800) Proof-of-Possession Key Semantics for JWTs (`cnf`)
- [RFC8037](https://datatracker.ietf.org/doc/html/rfc8037) (**OKP**) Ed25519 signatures and X25519 key agreement
- [RFC8693](https://datatracker.ietf.org/doc/html/rfc8693) OAuth 2.0 Token Exchange (`act` and `may_act`)
- [RFC9278](https://datatracker.ietf.org/doc/html/rfc9278) JWK Thumbprint URI
- [RFC9449](https://datatracker.ietf.org/doc/html/rfc9449) (**DPoP**) OAuth 2.0 Demonstrating Proof of Possession

Asymmetric signing accepts any `crypto.Signer`, so keys held in hardware
(PIV, TPM, Secure Enclave) or a remote KMS sign the same way as in-memory
keys, and JWE decryption accepts `jwe.KeyAgreement` and `crypto.Decrypter`
for the same reason.

## History

[JOSE](https://datatracker.ietf.org/wg/jose/documents/) was developed by an IETF [working group](https://www.ietf.org/how/wgs/), 
 started in 2011. The group set out to develop a [JSON](https://datatracker.ietf.org/doc/html/rfc4627) syntax that could be 
used by applications to describe "secure data objects". It has become a well-known, standardized mechanism for integrity protection 
and encryption, as well as the format for keys and algorithm identifiers to support interoperability of security services for 
protocols that use JSON.
