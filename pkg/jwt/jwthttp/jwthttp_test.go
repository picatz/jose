package jwthttp_test

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/josetest"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/jwt/jwthttp"
)

func TestBearerToken(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	jwthttp.SetBearerToken(r, "a.b.c")
	if got := r.Header.Get("Authorization"); got != "Bearer a.b.c" {
		t.Fatalf("Authorization = %q", got)
	}
	token, err := jwthttp.BearerToken(r)
	if err != nil || token != "a.b.c" {
		t.Fatalf("BearerToken() = %q, %v", token, err)
	}

	r.Header.Set("Authorization", "bearer x.y.z")
	if token, err := jwthttp.BearerToken(r); err != nil || token != "x.y.z" {
		t.Fatalf("BearerToken(lowercase scheme) = %q, %v", token, err)
	}

	for _, value := range []string{"", "Bearer", "Bearer ", "Basic dXNlcjpwYXNz", "Bearer a b", "Bearera.b.c"} {
		r.Header.Set("Authorization", value)
		if _, err := jwthttp.BearerToken(r); !errors.Is(err, jwthttp.ErrNoBearerToken) {
			t.Fatalf("BearerToken(%q) error = %v, want ErrNoBearerToken", value, err)
		}
	}
}

func TestSetBearerTokenFromToken(t *testing.T) {
	key := josetest.Key(t, jwa.EdDSA)
	token, err := jwt.New(header.Parameters{header.Algorithm: jwa.EdDSA, header.Type: jwt.Type}, jwt.ClaimsSet{jwt.Subject: "alice"}, key)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	jwthttp.SetBearerToken(r, token)
	got, err := jwthttp.BearerToken(r)
	if err != nil || got != token.String() {
		t.Fatalf("BearerToken() = %q, %v", got, err)
	}
}
