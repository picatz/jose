package jwt_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

type opaqueSigner struct{ signer crypto.Signer }

func (s opaqueSigner) Public() crypto.PublicKey { return s.signer.Public() }
func (s opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signer.Sign(r, digest, opts)
}

func TestNewWithSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewWithSigner(header.Parameters{header.Algorithm: jwa.ES256}, jwt.ClaimsSet{jwt.Subject: "device"}, opaqueSigner{key})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseAndVerify(token.String(), jwt.WithKey(&key.PublicKey), jwt.WithAllowedAlgorithms(jwa.ES256))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Claims[jwt.Subject] != "device" {
		t.Fatalf("sub = %v", parsed.Claims[jwt.Subject])
	}
	if _, err := jwt.NewWithSigner(header.Parameters{header.Algorithm: jwa.ES256}, jwt.ClaimsSet{jwt.Subject: "x"}, nil); err == nil {
		t.Fatal("accepted a nil signer")
	}
}

// Re-signing a parsed token must cover its current claims.
func TestResignParsedTokenCoversNewClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.New(header.Parameters{header.Algorithm: jwa.ES256}, jwt.ClaimsSet{jwt.Subject: "before"}, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.Parse(token.String())
	if err != nil {
		t.Fatal(err)
	}
	parsed.Claims[jwt.Subject] = "after"
	if _, err := parsed.Sign(key); err != nil {
		t.Fatal(err)
	}
	again, err := jwt.ParseAndVerify(parsed.String(), jwt.WithKey(&key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if again.Claims[jwt.Subject] != "after" {
		t.Fatalf("sub = %v, want after", again.Claims[jwt.Subject])
	}
}
