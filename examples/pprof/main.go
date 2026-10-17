package main

import (
	"context"
	"os"
	"runtime/pprof"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

func main() {
	const (
		symmetricKeyID = "test"
		symmetricKey   = "example-hs256-secret-of-32-bytes"
	)

	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.HS256,
			header.KeyID:     symmetricKeyID,
		}, jwt.ClaimsSet{
			jwt.Issuer:         "https://issuer.example",
			jwt.Audience:       "https://api.example",
			jwt.ExpirationTime: time.Now().Add(time.Hour),
			jwt.Subject:        "1234567890",
			"name":             "John Doe",
		},
		symmetricKey,
	)
	if err != nil {
		panic(err)
	}

	f, err := os.Create("cpu.pprof")
	if err != nil {
		panic(err)
	}

	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	tokenString := token.String()

	verifier := &jwt.Verifier{
		Keys:       jwt.Keys{{ID: symmetricKeyID, Algorithm: jwa.HS256, Public: []byte(symmetricKey)}},
		Algorithms: []jwa.Algorithm{jwa.HS256},
		Issuer:     "https://issuer.example",
		Audience:   "https://api.example",
	}

	for range 500000 {
		// parse and verify the token
		_, err := verifier.Verify(context.Background(), tokenString)
		if err != nil {
			panic(err)
		}

		// check the claims
		if token.Claims == nil {
			panic("claims are nil")
		}
	}

	// View the profile with `go tool pprof` in a web browser:
	//
	// $ go tool pprof -http=:8080 cpu.pprof
}
