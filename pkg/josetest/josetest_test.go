package josetest_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/josetest"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk/jwkhttp"
	"github.com/picatz/jose/pkg/jwt"
)

// fakeTB records Fatalf instead of ending the test, so the failure paths can
// be checked.
type fakeTB struct {
	testing.TB
	failed bool
}

func (f *fakeTB) Helper()               {}
func (f *fakeTB) Fatalf(string, ...any) { f.failed = true; panic(f) }
func (f *fakeTB) Cleanup(func())        {}

func fails(fn func(testing.TB)) (failed bool) {
	f := &fakeTB{}
	defer func() {
		if r := recover(); r != nil {
			failed = r == f
			if !failed {
				panic(r)
			}
		}
	}()
	fn(f)
	return false
}

func TestKeyMatchesAlgorithm(t *testing.T) {
	tests := []struct {
		alg  jwa.Algorithm
		bits int
	}{
		{jwa.RS256, 2048}, {jwa.RS384, 2048}, {jwa.RS512, 2048},
		{jwa.PS256, 2048}, {jwa.PS384, 2048}, {jwa.PS512, 2048},
		{jwa.ES256, 256}, {jwa.ES384, 384}, {jwa.ES512, 521},
		{jwa.EdDSA, 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			key := josetest.Key(t, tt.alg)
			switch k := key.(type) {
			case *rsa.PrivateKey:
				if k.N.BitLen() != tt.bits {
					t.Fatalf("RSA bits = %d, want %d", k.N.BitLen(), tt.bits)
				}
			case *ecdsa.PrivateKey:
				if k.Curve.Params().BitSize != tt.bits {
					t.Fatalf("curve bits = %d, want %d", k.Curve.Params().BitSize, tt.bits)
				}
			case ed25519.PrivateKey:
				if tt.alg != jwa.EdDSA {
					t.Fatalf("got Ed25519 for %s", tt.alg)
				}
			default:
				t.Fatalf("unexpected key type %T", key)
			}
		})
	}
}

func TestKeyIsFresh(t *testing.T) {
	a, b := josetest.Key(t, jwa.EdDSA), josetest.Key(t, jwa.EdDSA)
	if a.(ed25519.PrivateKey).Equal(b) {
		t.Fatal("two calls returned the same key")
	}
}

func TestKeyAndSecretFailOnWrongAlgorithm(t *testing.T) {
	for _, alg := range []jwa.Algorithm{jwa.HS256, jwa.None, "bogus", jwa.A128KW} {
		if !fails(func(tb testing.TB) { josetest.Key(tb, alg) }) {
			t.Errorf("Key(%q) did not fail", alg)
		}
	}
	for _, alg := range []jwa.Algorithm{jwa.ES256, jwa.RSAOAEP, "bogus"} {
		if !fails(func(tb testing.TB) { josetest.Secret(tb, alg) }) {
			t.Errorf("Secret(%q) did not fail", alg)
		}
	}
}

func TestSecretLength(t *testing.T) {
	want := map[jwa.Algorithm]int{
		jwa.HS256: 32, jwa.HS384: 48, jwa.HS512: 64,
		jwa.A128KW: 16, jwa.A192KW: 24, jwa.A256KW: 32,
	}
	for alg, n := range want {
		a, b := josetest.Secret(t, alg), josetest.Secret(t, alg)
		if len(a) != n {
			t.Errorf("Secret(%s) length = %d, want %d", alg, len(a), n)
		}
		if string(a) == string(b) {
			t.Errorf("Secret(%s) repeated", alg)
		}
	}
}

func TestTokenVerifiesForEveryAlgorithm(t *testing.T) {
	for _, alg := range []jwa.Algorithm{jwa.RS256, jwa.PS256, jwa.ES256, jwa.ES384, jwa.ES512, jwa.EdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			key := josetest.Key(t, alg)
			compact := josetest.Token(t, key, jwt.ClaimsSet{
				jwt.Issuer:         "https://issuer.example",
				jwt.Audience:       "api",
				jwt.ExpirationTime: time.Now().Add(time.Hour),
			})
			v := &jwt.Verifier{
				Keys:       jwt.Keys{{Public: key.Public()}},
				Algorithms: []jwa.Algorithm{alg, jwa.PS256},
				Issuer:     "https://issuer.example",
				Audience:   "api",
			}
			if _, err := v.Verify(context.Background(), compact); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestTokenFailsForUnsignableKey(t *testing.T) {
	if !fails(func(tb testing.TB) { josetest.Token(tb, nil, jwt.ClaimsSet{}) }) {
		t.Fatal("Token(nil key) did not fail")
	}
}

// TestJWKSEndToEnd serves a key set, fetches it with jwkhttp.Keys, and
// verifies a token against it.
func TestJWKSEndToEnd(t *testing.T) {
	ec := josetest.Key(t, jwa.ES256)
	ed := josetest.Key(t, jwa.EdDSA)
	other := josetest.Key(t, jwa.ES256)

	srv := josetest.JWKS(t, ec.Public(), ed.Public())
	v := &jwt.Verifier{
		Keys:       &jwkhttp.Keys{URL: srv.URL},
		Algorithms: []jwa.Algorithm{jwa.ES256, jwa.EdDSA},
		AnyIssuer:  true, AnyAudience: true, AllowNoExpiry: true,
	}
	ctx := context.Background()

	for _, key := range []crypto.Signer{ec, ed} {
		compact := josetest.Token(t, key, jwt.ClaimsSet{jwt.Subject: "alice"})
		if _, err := v.Verify(ctx, compact); err != nil {
			t.Fatalf("Verify(%T): %v", key, err)
		}
	}

	// A token from a key the server does not publish is refused.
	if _, err := v.Verify(ctx, josetest.Token(t, other, jwt.ClaimsSet{jwt.Subject: "mallory"})); err == nil {
		t.Fatal("token from an unpublished key verified")
	}
}

func TestJWKSKeyIDsAreThumbprints(t *testing.T) {
	key := josetest.Key(t, jwa.RS256)
	srv := josetest.JWKS(t, key) // a private key publishes only its public half
	set, err := jwkhttp.FetchSet(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := set.Get(josetest.KeyID(t, key.Public()))
	if !ok {
		t.Fatalf("no key with the thumbprint kid in %v", set.Keys)
	}
	if _, private := got["d"]; private {
		t.Fatal("private member published")
	}
}

func ExampleJWKS() {
	t := &testing.T{} // in a real test, use the *testing.T you are given

	key := josetest.Key(t, jwa.ES256)
	srv := josetest.JWKS(t, key.Public())
	defer srv.Close()

	verifier := &jwt.Verifier{
		Keys:     &jwkhttp.Keys{URL: srv.URL},
		Issuer:   "https://issuer.example",
		Audience: "https://api.example",
	}
	compact := josetest.Token(t, key, jwt.ClaimsSet{
		jwt.Issuer:         "https://issuer.example",
		jwt.Audience:       "https://api.example",
		jwt.Subject:        "alice",
		jwt.ExpirationTime: time.Now().Add(time.Hour),
	})

	token, err := verifier.Verify(context.Background(), compact)
	if err != nil {
		fmt.Println("refused:", err)
		return
	}
	fmt.Println(token.Claims[jwt.Subject])
	// Output: alice
}
