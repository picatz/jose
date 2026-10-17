package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/jwt/jwthttp"
)

func main() {
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
			jwt.Issuer:         "https://issuer.example",
			jwt.Audience:       "https://api.example",
			jwt.ExpirationTime: time.Now().Add(time.Hour),
			"sub":              "1234567890",
			"name":             "John Doe",
		},
		private,
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Starting Example Server\n")
	verifier := &jwt.Verifier{
		Keys:     jwt.Keys{{Public: &private.PublicKey}},
		Issuer:   "https://issuer.example",
		Audience: "https://api.example",
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		bearerToken, err := jwthttp.BearerToken(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		token, err = verifier.Verify(r.Context(), bearerToken)
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

	fmt.Printf("Listening on http://127.0.0.1:8080\n")

	// Print out the curl command to test the server
	fmt.Printf("\nTry running in another terminal:\ncurl http://127.0.0.1:8080 -H 'Authorization: Bearer %s' -v\n\n", token)

	panic(http.ListenAndServe("127.0.0.1:8080", mux))
}
