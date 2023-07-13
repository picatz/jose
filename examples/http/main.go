package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

func main() {
	token, err := jwt.New(
		header.Parameters{
			header.Type:      header.TypeJWT,
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

	fmt.Println(token)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		bearerToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		_, err := jwt.ParseAndVerify(bearerToken, jwt.SecretKey("supersecret"))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	fmt.Println("Listening on http://0.0.0.0:8080")
	panic(http.ListenAndServe(":8080", mux))
}
