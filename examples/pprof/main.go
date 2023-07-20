package main

import (
	"os"
	"runtime/pprof"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwt"
)

func main() {
	const (
		symmetricKeyID = "test"
		symmetricKey   = "supersecret"
	)

	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.HS256,
		}, jwt.ClaimsSet{
			jwt.Subject:           "1234567890",
			jwk.KeyID:             symmetricKeyID,
			jwt.ClaimName("name"): "John Doe",
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

	for i := 0; i < 500000; i++ {
		// parse and verify the token
		_, err := jwt.ParseAndVerify(tokenString, jwt.WithIdentifiableKey(symmetricKeyID, symmetricKey))
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
