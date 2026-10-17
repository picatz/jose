// Package josetest provides utilities for testing code that uses JOSE.
//
// It plays the role for this module that net/http/httptest plays for
// net/http: [Key] and [Secret] make fresh keys, [Token] mints a signed JWT, and
// [JWKS] starts a server that publishes a JWK Set, so a test can exercise a
// [jwt.Verifier] or a [jwkhttp.Keys] without fixtures checked into the
// repository.
//
// Every key is generated fresh, so tests never share key material and nothing
// here is deterministic. Keys are made for tests only: RSA keys are 2048 bits
// and are generated on each call, which is slow enough that a test should
// create one and reuse it.
//
// Functions take a [testing.TB] and fail the test on error, rather than
// returning one.
//
// [jwt.Verifier]: https://pkg.go.dev/github.com/picatz/jose/pkg/jwt#Verifier
// [jwkhttp.Keys]: https://pkg.go.dev/github.com/picatz/jose/pkg/jwk/jwkhttp#Keys
package josetest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
	"github.com/picatz/jose/pkg/jwt"
)

// Key returns a fresh private key suited to the signature algorithm alg: a
// 2048-bit RSA key for RS256, RS384, RS512, PS256, PS384 and PS512; the
// matching curve for ES256 (P-256), ES384 (P-384) and ES512 (P-521); and an
// Ed25519 key for EdDSA. The result is a *rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey, and its Public method gives the verification key.
//
// Key fails the test for a symmetric or unknown algorithm; use [Secret] for
// HMAC.
func Key(t testing.TB, alg jwa.Algorithm) crypto.Signer {
	t.Helper()

	var (
		key crypto.Signer
		err error
	)
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case jwa.ES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jwa.ES384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jwa.ES512:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case jwa.EdDSA:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("josetest.Key: no asymmetric signing key for %q", string(alg))
	}
	if err != nil {
		t.Fatalf("josetest.Key(%s): %v", alg, err)
	}
	return key
}

// Secret returns a fresh random secret suited to the symmetric algorithm alg:
// the hash size in bytes for HS256 (32), HS384 (48) and HS512 (64), which is
// the minimum RFC 7518 §3.2 allows, and the key size for A128KW (16), A192KW
// (24) and A256KW (32).
//
// Secret fails the test for any other algorithm.
func Secret(t testing.TB, alg jwa.Algorithm) []byte {
	t.Helper()

	var n int
	switch alg {
	case jwa.HS256, jwa.A256KW:
		n = 32
	case jwa.HS384:
		n = 48
	case jwa.HS512:
		n = 64
	case jwa.A128KW:
		n = 16
	case jwa.A192KW:
		n = 24
	default:
		t.Fatalf("josetest.Secret: no symmetric key for %q", string(alg))
	}
	secret := make([]byte, n)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("josetest.Secret(%s): %v", alg, err)
	}
	return secret
}

// Token returns a compact JWT carrying claims, signed with key. The algorithm
// is the conventional one for the key, as chosen by [jwa.ForKey] (RSA gets
// PS256), and the "typ" is "JWT". Token sets no claim of its own, so add "exp"
// and the rest yourself if the code under test requires them.
//
// Token fails the test if key cannot sign.
func Token(t testing.TB, key crypto.Signer, claims jwt.ClaimsSet) string {
	t.Helper()

	alg, err := jwa.ForKey(key)
	if err != nil {
		t.Fatalf("josetest.Token: %v", err)
	}
	token, err := jwt.New(header.Parameters{header.Type: jwt.Type, header.Algorithm: alg}, claims, key)
	if err != nil {
		t.Fatalf("josetest.Token: %v", err)
	}
	return token.String()
}

// JWKS starts a server that serves a JWK Set (RFC 7517 §5) holding the public
// part of each key, and closes it when the test and its subtests finish. Each
// key's "kid" is its RFC 7638 SHA-256 thumbprint, and its "use" is "sig". Keys
// may be public or private keys, or crypto.Signers; a private key is published
// as its public key only.
//
// The server speaks plain HTTP on a loopback address, which
// [jwkhttp.Keys] accepts as an exception to its https-only rule, so use
// the server's URL directly:
//
//	srv := josetest.JWKS(t, key.Public())
//	keys := &jwkhttp.Keys{URL: srv.URL}
//
// Use [httptest.Server.URL] for the address, and [KeyID] to learn a key's
// "kid".
//
// JWKS fails the test if a key cannot be represented as a JWK.
//
// [jwkhttp.Keys]: https://pkg.go.dev/github.com/picatz/jose/pkg/jwk/jwkhttp#Keys
func JWKS(t testing.TB, keys ...crypto.PublicKey) *httptest.Server {
	t.Helper()

	set := jwk.Set{Keys: make([]jwk.Key, 0, len(keys))}
	for _, key := range keys {
		value, err := jwk.PublicValue(key)
		if err != nil {
			t.Fatalf("josetest.JWKS: %v", err)
		}
		value[jwk.KeyID] = KeyID(t, key)
		value[jwk.PublicKeyUse] = "sig"
		set.Keys = append(set.Keys, value)
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("josetest.JWKS: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// KeyID returns the "kid" that [JWKS] gives key: its RFC 7638 SHA-256
// thumbprint. It fails the test if key cannot be represented as a JWK.
func KeyID(t testing.TB, key crypto.PublicKey) string {
	t.Helper()

	value, err := jwk.PublicValue(key)
	if err != nil {
		t.Fatalf("josetest.KeyID: %v", err)
	}
	kid, err := thumbprint.GenerateString(value, crypto.SHA256)
	if err != nil {
		t.Fatalf("josetest.KeyID: %v", err)
	}
	return kid
}
