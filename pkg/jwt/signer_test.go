package jwt_test

import (
	"context"
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

func signerVerifier(key *ecdsa.PrivateKey) *jwt.Verifier {
	return &jwt.Verifier{
		Keys:          jwt.Keys{{Public: &key.PublicKey}},
		AnyIssuer:     true,
		AnyAudience:   true,
		AllowNoExpiry: true,
	}
}

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
	parsed, err := signerVerifier(key).Verify(context.Background(), token.String())
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
