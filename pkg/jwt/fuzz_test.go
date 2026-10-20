package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
)

// FuzzVerify checks that Verifier.Verify never panics, that it refuses with
// an error wrapping jwt.ErrInvalidToken, and that it never accepts a token
// whose signing input the verifier's key did not sign: only the tokens
// minted below, and nothing derived from them, may verify.
func FuzzVerify(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	fx := &verifierFixture{key: key, verifier: &jwt.Verifier{
		Keys:     jwt.Keys{{ID: "k1", Public: key.Public()}},
		Types:    []string{"at+jwt"},
		Issuer:   "https://issuer.example",
		Audience: "https://api.example",
		Now:      func() time.Time { return verifierNow },
	}}
	mint := func(signer *ecdsa.PrivateKey, mutate func(h jws.Header, c map[string]any)) string {
		h := jws.Header{header.Algorithm: jwa.ES256, header.Type: "at+jwt", header.KeyID: "k1"}
		c := fx.claims()
		if mutate != nil {
			mutate(h, c)
		}
		return signCompact(f, h, c, signer)
	}

	// Every token the key signed. A fuzzed input may verify only if its
	// signing input (the first two segments) is one of these.
	signed := map[string]bool{}
	valid := mint(key, nil)
	for _, token := range []string{
		valid,
		mint(key, func(_ jws.Header, c map[string]any) { c["scope"] = "read" }),
		mint(key, func(h jws.Header, _ map[string]any) { delete(h, header.KeyID) }),
		mint(key, func(_ jws.Header, c map[string]any) { c["exp"] = verifierNow.Add(-time.Hour).Unix() }),
		mint(key, func(_ jws.Header, c map[string]any) { c["aud"] = "https://elsewhere.example" }),
	} {
		f.Add(token)
		signed[signingInput(token)] = true
	}

	parts := strings.Split(valid, ".")
	f.Add(parts[0] + "." + parts[1] + ".")
	f.Add(parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-2] + "AA")
	f.Add(parts[0] + "." + parts[1] + "." + parts[2] + ".")
	f.Add(parts[0] + "." + parts[1])
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0." + parts[1] + ".")
	f.Add(mint(other, nil))
	f.Add(mint(other, func(h jws.Header, _ map[string]any) { delete(h, header.KeyID) }))
	f.Add("")
	f.Add("..")
	f.Add("a.b.c")
	f.Add(strings.Repeat("A", 20<<10))

	f.Fuzz(func(t *testing.T, token string) {
		got, err := fx.verifier.Verify(context.Background(), token)
		if err != nil {
			if got != nil {
				t.Fatalf("Verify() returned a token with error %v", err)
			}
			if !errors.Is(err, jwt.ErrInvalidToken) {
				t.Fatalf("Verify() error = %v, want one wrapping ErrInvalidToken", err)
			}
			return
		}
		if got == nil {
			t.Fatal("Verify() = nil, nil")
		}
		if !signed[signingInput(token)] {
			t.Fatalf("Verify() accepted a token whose signing input the key never signed: %q", token)
		}
		if got.String() != token {
			t.Fatalf("String() = %q, want the verified token %q", got.String(), token)
		}
	})
}

// signingInput returns the "header.payload" a compact JWS signature covers,
// or the whole token when it has no signature segment.
func signingInput(token string) string {
	if i := strings.LastIndex(token, "."); i >= 0 {
		return token[:i]
	}
	return token
}

func signCompact(tb testing.TB, h jws.Header, claims map[string]any, key *ecdsa.PrivateKey) string {
	tb.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	s, err := jws.New(h, payload, key)
	if err != nil {
		tb.Fatal(err)
	}
	return s.String()
}

// FuzzActors checks that the "act", "may_act" and "cnf" claim readers never
// panic on arbitrary JSON claims, and that the delegation chain Actors
// reads survives SetActors and back unchanged.
func FuzzActors(f *testing.F) {
	for _, s := range []string{
		`{}`,
		`{"act":{"sub":"a"}}`,
		`{"act":{"sub":"a","iss":"i","client_id":"c","act":{"sub":"b","act":{"sub":"c"}}}}`,
		`{"act":{"sub":"a","exp":1}}`,
		`{"act":{"iss":"i"}}`,
		`{"act":"a"}`,
		`{"act":{"sub":""}}`,
		`{"may_act":{"sub":"a","iss":"i"}}`,
		`{"may_act":{"sub":"a","act":{"sub":"b"}}}`,
		`{"cnf":{"jkt":"abc"}}`,
		`{"cnf":{"jkt":"abc","x5t#S256":"def"}}`,
		`{"cnf":{"jkt":""}}`,
		`{"cnf":[]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var claims jwt.ClaimsSet
		if json.Unmarshal(data, &claims) != nil {
			return
		}
		_, _, _ = claims.AllowedActor()
		if jkt, ok := claims.ConfirmedThumbprint(); ok && jkt == "" {
			t.Fatal("ConfirmedThumbprint() = empty, true")
		}
		actors, err := claims.Actors()
		if err != nil {
			if !errors.Is(err, jwt.ErrActor) {
				t.Fatalf("Actors() error = %v, want ErrActor", err)
			}
			return
		}
		if len(actors) > jwt.MaxActors {
			t.Fatalf("Actors() returned %d, over MaxActors", len(actors))
		}
		for _, actor := range actors {
			if actor.Subject == "" {
				t.Fatal("Actors() returned a party without a subject")
			}
		}
		again := jwt.ClaimsSet{}
		if err := again.SetActors(actors); err != nil {
			t.Fatalf("SetActors(Actors()) error = %v", err)
		}
		back, err := again.Actors()
		if err != nil || !slices.EqualFunc(back, actors, jwt.Party.Is) {
			t.Fatalf("round trip = %+v, %v, want %+v", back, err, actors)
		}
	})
}
