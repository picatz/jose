package jwt_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/picatz/jose/pkg/jwt"
)

// The nested "act" example from RFC 8693 §4.1.
//
// https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
const rfc8693NestedActor = `{
  "aud":"https://service16.example.com",
  "iss":"https://issuer.example.com",
  "exp":1443904177,
  "nbf":1443904077,
  "sub":"user@example.com",
  "act":{
    "sub":"https://service16.example.com",
    "act":{
      "sub":"https://service77.example.com"
    }
  }
}`

func decodeClaims(t *testing.T, s string) jwt.ClaimsSet {
	t.Helper()
	var claims jwt.ClaimsSet
	if err := json.Unmarshal([]byte(s), &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestActorsRFC8693(t *testing.T) {
	claims := decodeClaims(t, rfc8693NestedActor)
	actors, err := claims.Actors()
	if err != nil {
		t.Fatal(err)
	}
	want := []jwt.Party{
		{Subject: "https://service16.example.com"},
		{Subject: "https://service77.example.com"},
	}
	if !reflect.DeepEqual(actors, want) {
		t.Fatalf("Actors() = %+v, want %+v", actors, want)
	}

	// Re-issuing for a new actor keeps the lineage behind it.
	next := jwt.ClaimsSet{jwt.Subject: "user@example.com"}
	newActor := jwt.Party{Subject: "agent-7", Issuer: "https://issuer.example.com", Claims: map[string]any{jwt.ClientID: "agents"}}
	if err := next.SetActors(append([]jwt.Party{newActor}, actors...)); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"act":{"act":{"act":{"sub":"https://service77.example.com"},"sub":"https://service16.example.com"},"client_id":"agents","iss":"https://issuer.example.com","sub":"agent-7"},"sub":"user@example.com"}`; got != want {
		t.Fatalf("SetActors() encoded\n%s\nwant\n%s", got, want)
	}
	again, err := decodeClaims(t, string(encoded)).Actors()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, append([]jwt.Party{newActor}, want...)) {
		t.Fatalf("round trip = %+v", again)
	}

	if err := next.SetActors(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := next[jwt.Actor]; ok {
		t.Fatal("SetActors(nil) kept the act claim")
	}
}

func TestActorsRefusals(t *testing.T) {
	for name, input := range map[string]string{
		"not an object":     `{"act":"svc"}`,
		"no subject":        `{"act":{"iss":"x"}}`,
		"empty subject":     `{"act":{"sub":""}}`,
		"numeric subject":   `{"act":{"sub":7}}`,
		"exp inside act":    `{"act":{"sub":"a","exp":1}}`,
		"aud inside act":    `{"act":{"sub":"a","act":{"sub":"b","aud":"x"}}}`,
		"nested not object": `{"act":{"sub":"a","act":[]}}`,
		"nested null":       `{"act":{"sub":"a","act":null}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeClaims(t, input).Actors(); !errors.Is(err, jwt.ErrActor) {
				t.Fatalf("Actors(%s) error = %v, want ErrActor", input, err)
			}
		})
	}

	t.Run("too deep", func(t *testing.T) {
		chain := make([]jwt.Party, jwt.MaxActors+1)
		for i := range chain {
			chain[i] = jwt.Party{Subject: "s"}
		}
		if err := (jwt.ClaimsSet{}).SetActors(chain); !errors.Is(err, jwt.ErrActor) {
			t.Fatalf("SetActors() error = %v, want ErrActor", err)
		}
		claims := jwt.ClaimsSet{}
		if err := claims.SetActors(chain[:jwt.MaxActors]); err != nil {
			t.Fatal(err)
		}
		inner := claims[jwt.Actor].(map[string]any)
		for range jwt.MaxActors {
			next := map[string]any{jwt.Subject: "s"}
			inner[jwt.Actor] = next
			inner = next
		}
		if _, err := claims.Actors(); !errors.Is(err, jwt.ErrActor) {
			t.Fatalf("Actors() error = %v, want ErrActor", err)
		}
	})

	t.Run("reserved names in Claims", func(t *testing.T) {
		for _, name := range []string{jwt.Subject, jwt.Issuer, jwt.Actor, jwt.ExpirationTime, jwt.NotBefore, jwt.Audience} {
			err := (jwt.ClaimsSet{}).SetActors([]jwt.Party{{Subject: "a", Claims: map[string]any{name: "x"}}})
			if !errors.Is(err, jwt.ErrActor) {
				t.Fatalf("SetActors() with %q in Claims error = %v, want ErrActor", name, err)
			}
		}
	})
}

// The "may_act" example from RFC 8693 §4.4.
//
// https://www.rfc-editor.org/rfc/rfc8693.html#section-4.4
func TestAllowedActor(t *testing.T) {
	claims := decodeClaims(t, `{
	  "aud":"https://as.example.com",
	  "iss":"https://original-issuer.example.net",
	  "exp":1499863217,
	  "nbf":1499859617,
	  "sub":"user@example.net",
	  "may_act":{
	    "sub":"admin@example.net"
	  }
	}`)
	party, ok, err := claims.AllowedActor()
	if err != nil || !ok {
		t.Fatalf("AllowedActor() = %v, %v", ok, err)
	}
	if !party.Is(jwt.Party{Subject: "admin@example.net"}) {
		t.Fatalf("AllowedActor() = %+v", party)
	}
	if party.Is(jwt.Party{Subject: "admin@example.net", Issuer: "https://other.example"}) {
		t.Fatal("Is() ignored the issuer")
	}

	if _, ok, err := (jwt.ClaimsSet{}).AllowedActor(); ok || err != nil {
		t.Fatalf("AllowedActor() without may_act = %v, %v", ok, err)
	}
	if _, _, err := decodeClaims(t, `{"may_act":{"sub":"a","act":{"sub":"b"}}}`).AllowedActor(); !errors.Is(err, jwt.ErrActor) {
		t.Fatalf("AllowedActor() with nested act error = %v, want ErrActor", err)
	}
}
