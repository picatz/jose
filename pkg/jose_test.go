package jose_test

import (
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

func ExampleParseString() {
	token, err := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.YKkW2pAxINn-dLNQKBShDBRn57Wzd3OxmGbxtZYTvEU")
	if err != nil {
		panic(fmt.Sprintf("failed to parse JWT string: %v", err))
	}

	err = token.Verify(jwt.WithAllowedAlgorithms(jwa.HS256), jwt.WithKey("example-hs256-secret-of-32-bytes"))
	if err != nil {
		panic(fmt.Sprintf("failed to verify JWT signature: %v", err))
	}

	sub, err := token.Claims.Get(jwt.Subject)
	if err != nil {
		panic(fmt.Sprintf("failed to get JWT claim %q: %v", jwt.Subject, err))
	}

	fmt.Println(sub)
	// Output: 1234567890
}

func TestExampleJWTParseStringAndVerifySignatureHS256(t *testing.T) {
	token, err := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.YKkW2pAxINn-dLNQKBShDBRn57Wzd3OxmGbxtZYTvEU")
	if err != nil {
		t.Fatalf("jwt.ParseString() error = %v", err)
	}
	if token == nil {
		t.Fatal("token = nil, want non-nil")
	}

	err = token.Verify(jwt.WithAllowedAlgorithms(jwa.HS256), jwt.WithKey("example-hs256-secret-of-32-bytes"))
	if err != nil {
		t.Fatalf("token.Verify() error = %v", err)
	}

	// RFC 7518 §3.2: an HS256 key shorter than 32 bytes is refused when
	// verifying, not only when signing.
	short, err := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.UOXSwO9AAuqSpOCt-PDjMmek7SmKOR7v35rmMzeyYfM")
	if err != nil {
		t.Fatalf("jwt.ParseString() error = %v", err)
	}
	if err := short.Verify(jwt.WithAllowedAlgorithms(jwa.HS256), jwt.WithKey("supersecret")); !errors.Is(err, jwt.ErrInvalidToken) {
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
	token := &jwt.Token{
		Header: jws.Header{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.HS256,
		},
		Claims: jwt.ClaimsSet{
			jwt.Subject:  "1234567890",
			jwt.Issuer:   "test",
			jwt.IssuedAt: time.Now(),
		},
	}

	signature, err := token.Sign("supersecret-key-that-is-at-least-32-bytes-long-for-security")
	if err != nil {
		t.Fatalf("token.Sign() error = %v", err)
	}
	if signature == nil {
		t.Fatal("signature = nil, want non-nil")
	}
	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Essentially same as:

	token, err = jwt.New(
		jws.Header{
			header.Algorithm: jwa.HS256,
		},
		jwt.ClaimsSet{
			jwt.Subject:  "1234567890",
			jwt.Issuer:   "test",
			jwt.IssuedAt: time.Now(),
		},
		"supersecret-key-that-is-at-least-32-bytes-long-for-security",
	)
	if err != nil {
		t.Fatalf("jwt.New() error = %v", err)
	}

	t.Logf("generated signed token: %v", token)
}
