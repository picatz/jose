package jwt_test

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

func TestNewDoesNotMutateInputs(t *testing.T) {
	params := header.Parameters{header.Algorithm: jwa.EdDSA}
	claims := jwt.ClaimsSet{jwt.Subject: "alice", jwt.ExpirationTime: issued}
	wantParams, wantClaims := maps.Clone(params), maps.Clone(claims)

	token, err := jwt.New(params, claims, exampleKey())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(params, wantParams) {
		t.Errorf("params mutated: %v", params)
	}
	if !reflect.DeepEqual(claims, wantClaims) {
		t.Errorf("claims mutated: %v", claims)
	}
	if token.Header[header.Type] != jwt.Type {
		t.Errorf("token typ = %v", token.Header[header.Type])
	}
	// Changing the caller's maps afterwards must not change the token.
	claims[jwt.Subject] = "mallory"
	params[header.KeyID] = "x"
	if token.Claims[jwt.Subject] != "alice" || token.Header.Has(header.KeyID) {
		t.Error("token aliases the caller's maps")
	}
}

func TestNewRefusals(t *testing.T) {
	claims := jwt.ClaimsSet{jwt.Subject: "alice"}
	if _, err := jwt.New(header.Parameters{header.Algorithm: jwa.None}, claims, []byte("k")); err == nil {
		t.Error("alg none minted")
	}
	if _, err := jwt.New(header.Parameters{header.Algorithm: jwa.EdDSA}, claims, nil); err == nil {
		t.Error("nil key accepted")
	}
}

func TestParseRefusesNonStringAlg(t *testing.T) {
	enc := func(s string) string { return base64url.Encode([]byte(s)) }
	for _, alg := range []string{`42`, `true`, `["EdDSA"]`, `null`, `{"a":1}`} {
		compact := enc(`{"alg":`+alg+`,"typ":"JWT"}`) + "." + enc(`{"sub":"a"}`) + ".c2ln"
		_, err := jwt.Parse(compact)
		if !errors.Is(err, jwt.ErrFormat) || !errors.Is(err, jwt.ErrInvalidToken) {
			t.Errorf("alg %s: err = %v, want ErrFormat", alg, err)
		}
	}
	for _, bad := range []string{"", "a.b", "!.!.!"} {
		if _, err := jwt.Parse(bad); !errors.Is(err, jwt.ErrFormat) {
			t.Errorf("Parse(%q) err = %v, want ErrFormat", bad, err)
		}
	}
}

func TestTokenStringUnusable(t *testing.T) {
	if got := (&jwt.Token{}).String(); got != "" {
		t.Errorf("zero Token String() = %q, want empty", got)
	}
	var nilToken *jwt.Token
	if got := nilToken.String(); got != "" {
		t.Errorf("nil Token String() = %q, want empty", got)
	}
	bad := &jwt.Token{Header: header.Parameters{"alg": make(chan int)}, Claims: jwt.ClaimsSet{"a": 1}}
	if got := bad.String(); got != "" {
		t.Errorf("unmarshalable Token String() = %q, want empty", got)
	}
}

func TestContext(t *testing.T) {
	if jwt.FromContext(context.Background()) != nil {
		t.Error("empty context has a token")
	}
	tok := &jwt.Token{}
	if jwt.FromContext(jwt.NewContext(context.Background(), tok)) != tok {
		t.Error("token not round-tripped")
	}
}

func TestConfirmedThumbprintNestedClaimsSet(t *testing.T) {
	cnf, err := jwt.ConfirmationFor(exampleKey())
	if err != nil {
		t.Fatal(err)
	}
	want := cnf["jkt"].(string)
	for name, v := range map[string]any{"map": cnf, "claimsset": jwt.ClaimsSet(cnf)} {
		got, ok := jwt.ClaimsSet{jwt.Confirmation: v}.ConfirmedThumbprint()
		if !ok || got != want {
			t.Errorf("%s: got %q, %v", name, got, ok)
		}
	}
}
