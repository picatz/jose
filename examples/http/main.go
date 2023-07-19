package main

import (
	"fmt"
	"net/http"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

func main() {
	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.HS256,
		}, jwt.ClaimsSet{
			"sub":  "1234567890",
			"name": "John Doe",
		},
		"supersecret",
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Use this token:", token)

	// Print out the curl command to test the server
	fmt.Printf("\ncurl http://127.0.0.1:8080 -H 'Authorization: Bearer %s' -v\n\n", token)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		bearerToken, err := jwt.FromHTTPAuthorizationHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		_, err = jwt.ParseAndVerify(bearerToken, jwt.WithKey("supersecret"))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	fmt.Println("Listening on http://127.0.0.1:8080")
	panic(http.ListenAndServe(":8080", mux))
}
