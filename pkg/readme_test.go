package jose_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

// Example_quickstart is the quickstart in the README.
func Example_quickstart() {
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
	fmt.Println(verified.Claims[jwt.Subject])
	// Output: alice
}
