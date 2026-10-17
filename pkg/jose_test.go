package jose_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
)

func Example_verify() {
	verifier := &jwt.Verifier{
		Keys:          jwt.Keys{{Algorithm: jwa.HS256, Public: []byte("example-hs256-secret-of-32-bytes")}},
		Algorithms:    []jwa.Algorithm{jwa.HS256},
		AnyIssuer:     true,
		AnyAudience:   true,
		AllowNoExpiry: true,
	}

	token, err := verifier.Verify(context.Background(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.YKkW2pAxINn-dLNQKBShDBRn57Wzd3OxmGbxtZYTvEU")
	if err != nil {
		panic(fmt.Sprintf("failed to verify JWT: %v", err))
	}

	sub, err := token.Claims.Get(jwt.Subject)
	if err != nil {
		panic(fmt.Sprintf("failed to get JWT claim %q: %v", jwt.Subject, err))
	}

	fmt.Println(sub)
	// Output: 1234567890
}

func TestExampleJWTVerifyHS256(t *testing.T) {
	verifier := &jwt.Verifier{
		Keys:          jwt.Keys{{Algorithm: jwa.HS256, Public: []byte("example-hs256-secret-of-32-bytes")}},
		Algorithms:    []jwa.Algorithm{jwa.HS256},
		AnyIssuer:     true,
		AnyAudience:   true,
		AllowNoExpiry: true,
	}

	token, err := verifier.Verify(context.Background(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.YKkW2pAxINn-dLNQKBShDBRn57Wzd3OxmGbxtZYTvEU")
	if err != nil {
		t.Fatalf("verifier.Verify() error = %v", err)
	}
	if token == nil {
		t.Fatal("token = nil, want non-nil")
	}

	// RFC 7518 §3.2: an HS256 key shorter than 32 bytes is refused when
	// verifying, not only when signing.
	short := *verifier
	short.Keys = jwt.Keys{{Algorithm: jwa.HS256, Public: []byte("supersecret")}}
	if _, err := short.Verify(context.Background(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.UOXSwO9AAuqSpOCt-PDjMmek7SmKOR7v35rmMzeyYfM"); !errors.Is(err, jwt.ErrInvalidToken) {
		t.Fatalf("Verify() with short key error = %v, want %v", err, jwt.ErrInvalidToken)
	}

	alg, err := token.Header.Algorithm()
	if err != nil {
		t.Fatalf("token.Header.Algorithm() error = %v", err)
	}
	if alg != jwa.HS256 {
		t.Fatalf("alg = %v, want %v", alg, jwa.HS256)
	}

	typ, err := token.Header.Type()
	if err != nil {
		t.Fatalf("token.Header.Type() error = %v", err)
	}
	if typ != jwt.Type {
		t.Fatalf("typ = %v, want %v", typ, jwt.Type)
	}

	claimNames := token.Claims.Names()
	if !slices.Equal(claimNames, []jwt.ClaimName{"sub", "name", "iat"}) {
		t.Fatalf("claimNames = %v, want %v", claimNames, []jwt.ClaimName{"sub", "name", "iat"})
	}

	sub, err := token.Claims.Get(jwt.Subject)
	if err != nil {
		t.Fatalf("token.Claims.Get() error = %v", err)
	}
	if sub != "1234567890" {
		t.Fatalf("sub = %q, want %q", sub, "1234567890")
	}

	iat, err := token.Claims.Get(jwt.IssuedAt)
	if err != nil {
		t.Fatalf("token.Claims.Get() error = %v", err)
	}
	if iat != int64(1516239022) {
		t.Fatalf("iat = %v, want %v", iat, int64(1516239022))
	}

	name, err := token.Claims.Get("name")
	if err != nil {
		t.Fatalf("token.Claims.Get() error = %v", err)
	}
	if name != "picatz" {
		t.Fatalf("name = %q, want %q", name, "picatz")
	}
}

func TestExampleCreateJWTAndSignWithHS256(t *testing.T) {
	const secret = "supersecret-key-that-is-at-least-32-bytes-long-for-security"

	token, err := jwt.New(
		jws.Header{
			header.Algorithm: jwa.HS256,
		},
		jwt.ClaimsSet{
			jwt.Subject:  "1234567890",
			jwt.Issuer:   "test",
			jwt.IssuedAt: time.Now(),
		},
		secret,
	)
	if err != nil {
		t.Fatalf("jwt.New() error = %v", err)
	}
	if len(token.Signature) == 0 {
		t.Fatal("signature is empty")
	}

	verifier := &jwt.Verifier{
		Keys:          jwt.Keys{{Algorithm: jwa.HS256, Public: []byte(secret)}},
		Algorithms:    []jwa.Algorithm{jwa.HS256},
		Issuer:        "test",
		AnyAudience:   true,
		AllowNoExpiry: true,
	}
	if _, err := verifier.Verify(context.Background(), token.String()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}
