package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/picatz/jose/pkg/dpop"
)

// A client mints a proof for a token request; the authorization server
// verifies it and binds the issued token to the proof key's thumbprint.
// The key can be any crypto.Signer, including one held in hardware.
func Example() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := dpop.NewSigner(key)
	if err != nil {
		panic(err)
	}
	proof, err := signer.Proof(http.MethodPost, "https://as.example.com/token", dpop.ProofOptions{})
	if err != nil {
		panic(err)
	}

	verifier := dpop.Verifier{Replay: dpop.NewMemoryReplayCache(10_000, nil)}
	verified, err := verifier.Verify(context.Background(), proof, dpop.Request{
		Method: http.MethodPost,
		URI:    "https://as.example.com/token",
	})
	if err != nil {
		panic(err)
	}

	// Put this in the access token's "cnf" claim: jwt.ConfirmationFor(key).
	fmt.Println(verified.Thumbprint == signer.Thumbprint())
	// Output: true
}
