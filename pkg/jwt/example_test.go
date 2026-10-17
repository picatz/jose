package jwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

var now = time.Time{} // time.Now() would be used in reality

// https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1
var secretKeyBytes = []byte{
	3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
	143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
	46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
	98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
	208, 128, 163,
}

func ExampleNew_symmetric() {
	token, _ := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.HS256,
		},
		jwt.ClaimsSet{
			jwt.Subject:        "example",
			jwt.IssuedAt:       now,
			jwt.NotBefore:      now.Add(2 * time.Hour),
			jwt.ExpirationTime: now.Add(24 * time.Hour),
		},
		secretKeyBytes,
	)

	fmt.Println(token)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOi02MjEzNTUxMDQwMCwiaWF0IjotNjIxMzU1OTY4MDAsIm5iZiI6LTYyMTM1NTg5NjAwLCJzdWIiOiJleGFtcGxlIn0.9GTH7vLxrY4VmuMexoSBOPG5-Z1hoCpfOPcu5jWbo5I
}

func ExampleNew_asymmetric() {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	token, _ := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.RS256,
		},
		jwt.ClaimsSet{
			jwt.Subject:        "example",
			jwt.IssuedAt:       now,
			jwt.NotBefore:      now.Add(2 * time.Hour),
			jwt.ExpirationTime: now.Add(24 * time.Hour),
		},
		privateKey,
	)

	fmt.Println(token.Claims[jwt.Subject])
	// Output: example
}

// issued is the fixed clock the examples use.
var issued = time.Unix(1_700_000_000, 0)

func exampleKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
}

// Mint a token with New and verify it with a Verifier.
func Example() {
	key := exampleKey()

	token, err := jwt.New(
		header.Parameters{header.Algorithm: jwa.EdDSA, header.KeyID: "k1"},
		jwt.ClaimsSet{
			jwt.Issuer:         "https://issuer.example",
			jwt.Audience:       "https://api.example",
			jwt.Subject:        "alice",
			jwt.IssuedAt:       issued,
			jwt.ExpirationTime: issued.Add(time.Hour),
		},
		key,
	)
	if err != nil {
		panic(err)
	}

	verifier := &jwt.Verifier{
		Keys:     jwt.Keys{{ID: "k1", Public: key.Public()}},
		Issuer:   "https://issuer.example",
		Audience: "https://api.example",
		Now:      func() time.Time { return issued.Add(time.Minute) },
	}
	verified, err := verifier.Verify(context.Background(), token.String())
	if err != nil {
		panic(err)
	}

	fmt.Println(verified.Claims[jwt.Subject])

	// A token for another audience is refused.
	verifier.Audience = "https://other.example"
	_, err = verifier.Verify(context.Background(), token.String())
	fmt.Println(errors.Is(err, jwt.ErrClaims))
	// Output:
	// alice
	// true
}

// Parse decodes a token without verifying it, which is enough to read the
// "kid" that selects a key.
func ExampleParse() {
	token, _ := jwt.New(
		header.Parameters{header.Algorithm: jwa.EdDSA, header.KeyID: "k1"},
		jwt.ClaimsSet{jwt.Subject: "alice"},
		exampleKey(),
	)

	decoded, err := jwt.Parse(token.String())
	if err != nil {
		panic(err)
	}
	fmt.Println(decoded.Header[header.KeyID], decoded.Claims[jwt.Subject])
	// Output: k1 alice
}

// Record a delegation chain in the "act" claim, newest actor first.
func ExampleClaimsSet_SetActors() {
	claims := jwt.ClaimsSet{jwt.Subject: "alice"}

	err := claims.SetActors([]jwt.Party{
		{Subject: "agent-2"},
		{Subject: "agent-1"},
	})
	if err != nil {
		panic(err)
	}

	actors, _ := claims.Actors()
	for _, actor := range actors {
		fmt.Println(actor.Subject)
	}
	// Output:
	// agent-2
	// agent-1
}

// Bind a token to a holder's key with a "cnf" claim.
func ExampleConfirmationFor() {
	holder := exampleKey()

	claims := jwt.ClaimsSet{jwt.Subject: "alice"}
	claims[jwt.Confirmation], _ = jwt.ConfirmationFor(holder)

	jkt, ok := claims.ConfirmedThumbprint()
	fmt.Println(jkt, ok)
	// Output: 9ZP03Nu8GrXPAUkbKNxHOKBzxPX83SShgFkRNK-f2lw true
}

// Carry a token through a request context.
func ExampleNewContext() {

	ctx := jwt.NewContext(context.Background(), &jwt.Token{Claims: jwt.ClaimsSet{jwt.Subject: "alice"}})

	fmt.Println(jwt.FromContext(ctx).Claims[jwt.Subject])
	fmt.Println(jwt.FromContext(context.Background()) == nil)
	// Output:
	// alice
	// true
}
