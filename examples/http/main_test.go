package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

func Test_main(t *testing.T) {
	// Create a public/private key pair (ECDSA)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Create a JWT token, sign it with the private key.
	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.ES256,
		},
		jwt.ClaimsSet{
			"sub":  "1234567890",
			"name": "John Doe",
		},
		private,
	)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		bearerToken, err := jwt.FromHTTPAuthorizationHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		token, err = jwt.ParseAndVerify(bearerToken, jwt.WithKey(&private.PublicKey))
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

	rec := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token.String())

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, rec.Code)
	}
}
