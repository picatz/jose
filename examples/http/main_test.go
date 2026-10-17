package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/jwt/jwthttp"
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

		sub, ok := token.Claims[jwt.Subject]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if sub != "1234567890" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		name, ok := token.Claims["name"]
		if !ok {
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
