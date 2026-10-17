package jwtchain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/jwtchain"
)

func TestLimitsZeroIsDefault(t *testing.T) {
	f := newFixture(t)
	c := parse(t, f.root)
	for range jwtchain.DefaultMaxLinks {
		next, err := jwtchain.Derive(c, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: f.a.Public()}, jwtchain.WithClock(clock), jwtchain.WithLimits(jwtchain.Limits{}))
		if err != nil {
			t.Fatal(err)
		}
		c = next
	}
	if _, err := jwtchain.Derive(c, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)}, jwtchain.WithClock(clock)); err == nil {
		t.Fatal("Derive() exceeded the default link limit")
	}
	if _, err := (jwtchain.Limits{}).Inspect(c); err != nil {
		t.Fatalf("Limits{}.Inspect() = %v", err)
	}
}

func TestDeriveWithLimits(t *testing.T) {
	f := newFixture(t)
	limits := jwtchain.Limits{MaxLinks: 1}
	c, err := jwtchain.Derive(parse(t, f.root), f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: f.a.Public()},
		jwtchain.WithClock(clock), jwtchain.WithLimits(limits))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwtchain.Derive(c, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)},
		jwtchain.WithClock(clock), jwtchain.WithLimits(limits)); err == nil {
		t.Fatal("Derive() ignored MaxLinks")
	}
	if _, err := jwtchain.Derive(parse(t, f.root), f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)},
		jwtchain.WithClock(clock), jwtchain.WithLimits(jwtchain.Limits{MaxSize: 100})); err == nil {
		t.Fatal("Derive() ignored MaxSize")
	}
	// Algorithms the limits exclude are refused for the new link.
	if _, err := jwtchain.Derive(parse(t, f.root), f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)},
		jwtchain.WithClock(clock), jwtchain.WithLimits(jwtchain.Limits{Algorithms: []jwa.Algorithm{jwa.EdDSA}})); err == nil {
		t.Fatal("Derive() signed with an algorithm outside Limits.Algorithms")
	}
}

func TestLimitsInspectAndParse(t *testing.T) {
	f := newFixture(t)
	c, err := jwtchain.Derive(parse(t, f.root), f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: f.b.Public()}, jwtchain.WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Inspect(); err != nil {
		t.Fatal(err)
	}
	if _, err := (jwtchain.Limits{Algorithms: []jwa.Algorithm{jwa.EdDSA}}).Inspect(c); !errors.Is(err, jwtchain.ErrVerification) {
		t.Fatalf("Inspect() with ES256 excluded = %v, want ErrVerification", err)
	}
	if _, err := (jwtchain.Limits{MaxLinks: 1}).Inspect(c); err != nil {
		t.Fatal(err)
	}
	if _, err := (jwtchain.Limits{MaxSize: 10}).Inspect(c); !errors.Is(err, jwtchain.ErrFormat) {
		t.Fatalf("Inspect() over MaxSize = %v, want ErrFormat", err)
	}
	if _, err := (jwtchain.Limits{}).Inspect(nil); !errors.Is(err, jwtchain.ErrFormat) {
		t.Fatalf("Inspect(nil) = %v, want ErrFormat", err)
	}
	if _, err := (jwtchain.Limits{MaxLinks: 1}).Parse(c.String() + jwtchain.Separator + c.Leaf()); !errors.Is(err, jwtchain.ErrFormat) {
		t.Fatalf("Limits.Parse() over MaxLinks = %v", err)
	}
	if _, err := (jwtchain.Limits{MaxSize: 20}).Parse(strings.Repeat("A", 21)); !errors.Is(err, jwtchain.ErrFormat) {
		t.Fatalf("Limits.Parse() over MaxSize = %v", err)
	}
	if parsed, err := (jwtchain.Limits{MaxLinks: 1}).Parse(c.String()); err != nil || parsed.Links() != 1 {
		t.Fatalf("Limits.Parse() = %v, %v", parsed, err)
	}
}

// A root "cnf" that carries another confirmation method beside "jkt"
// binds no holder this package enforces, so nothing derives from it.
func TestRootConfirmationMustBeSingleMember(t *testing.T) {
	f := newFixture(t)
	cnf, _ := jwt.ConfirmationFor(f.a.Public())
	cnf["x5t#S256"] = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
	root := f.mintRoot(t, jwt.ClaimsSet{jwt.Subject: "alice", jwt.ExpirationTime: now.Add(time.Hour).Unix(), jwt.Confirmation: cnf})
	_, err := jwtchain.Derive(parse(t, root), f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)}, jwtchain.WithClock(clock))
	if err == nil {
		t.Fatal("Derive() from a root with a two-member cnf succeeded")
	}
}
