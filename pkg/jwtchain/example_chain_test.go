package jwtchain_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/jwtchain"
)

var exampleNow = time.Unix(1_800_000_000, 0).UTC()

// exampleKey returns a deterministic Ed25519 key for name, so outputs are
// stable. Never derive real keys from a name.
func exampleKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(name))
	return ed25519.NewKeyFromSeed(seed[:])
}

// exampleRoot mints an issuer-signed root bound to holder.
func exampleRoot(issuer, holder ed25519.PrivateKey) string {
	cnf, _ := jwt.ConfirmationFor(holder.Public())
	claims, _ := json.Marshal(jwt.ClaimsSet{
		jwt.Subject:        "alice",
		jwt.Audience:       "https://api.example",
		jwt.Scope:          "read write",
		jwt.ExpirationTime: exampleNow.Add(time.Hour).Unix(),
		jwt.Confirmation:   cnf,
	})
	root, _ := jws.New(jws.Header{header.Algorithm: jwa.EdDSA}, claims, issuer)
	return root.String()
}

// Derive narrows a chain offline, and a [jwtchain.Policy] verifies the
// result. A link that asks for more than its parent allows is refused.
func ExampleDerive() {
	issuer, agent, helper := exampleKey("issuer"), exampleKey("agent"), exampleKey("helper")
	root, _ := jwtchain.Parse(exampleRoot(issuer, agent))

	chain, err := jwtchain.Derive(root, agent, jwtchain.Restriction{
		Expiry: exampleNow.Add(5 * time.Minute),
		Scope:  []string{"read"},
		Holder: helper.Public(),
	}, jwtchain.WithClock(func() time.Time { return exampleNow }))
	if err != nil {
		panic(err)
	}

	policy := &jwtchain.Policy{
		Root:     jwtchain.RootKey(issuer.Public()),
		Audience: "https://api.example",
		Now:      func() time.Time { return exampleNow },
	}
	grant, err := policy.Verify(context.Background(), chain.String())
	fmt.Println(err, grant.Subject, grant.Scope, grant.Expiry.Sub(exampleNow))

	// Asking for a scope the parent never granted fails at Derive...
	_, err = jwtchain.Derive(root, agent, jwtchain.Restriction{
		Expiry: exampleNow.Add(time.Minute),
		Scope:  []string{"admin"},
	}, jwtchain.WithClock(func() time.Time { return exampleNow }))
	fmt.Println(errors.Is(err, jwtchain.ErrBroadens))
	// Output:
	// <nil> alice [read] 5m0s
	// true
}

// Embed puts the parent inside the new link, so the link alone is one
// ordinary JWS that carries its whole history.
func ExampleEmbed() {
	issuer, agent := exampleKey("issuer"), exampleKey("agent")
	root, _ := jwtchain.Parse(exampleRoot(issuer, agent))

	chain, err := jwtchain.Derive(root, agent, jwtchain.Restriction{
		Expiry: exampleNow.Add(time.Minute),
	}, jwtchain.WithClock(func() time.Time { return exampleNow }), jwtchain.Embed())
	if err != nil {
		panic(err)
	}
	token := chain.String()
	fmt.Println("segments:", len(strings.Split(token, ".")), "separators:", strings.Count(token, jwtchain.Separator))

	// The single token parses back into the root and its link.
	again, _ := jwtchain.Parse(token)
	fmt.Println("links:", again.Links(), "root recovered:", again.Root() == root.Root())
	// Output:
	// segments: 3 separators: 0
	// links: 1 root recovered: true
}

// Grant.Claims is how an issuer re-issues a verified chain as a fresh,
// short root: the narrowed claims, plus the lineage as an RFC 8693 "act"
// claim naming each key that held the chain.
func ExampleGrant_Claims() {
	issuer, agent, helper := exampleKey("issuer"), exampleKey("agent"), exampleKey("helper")
	root, _ := jwtchain.Parse(exampleRoot(issuer, agent))
	chain, _ := jwtchain.Derive(root, agent, jwtchain.Restriction{
		Expiry: exampleNow.Add(5 * time.Minute),
		Scope:  []string{"read"},
		Holder: helper.Public(),
	}, jwtchain.WithClock(func() time.Time { return exampleNow }))

	policy := &jwtchain.Policy{
		Root:     jwtchain.RootKey(issuer.Public()),
		Audience: "https://api.example",
		Now:      func() time.Time { return exampleNow },
	}
	grant, err := policy.VerifyChain(context.Background(), chain)
	if err != nil {
		panic(err)
	}
	claims, err := grant.Claims()
	if err != nil {
		panic(err)
	}
	actors, _ := claims.Actors()

	fmt.Println("sub:", claims[jwt.Subject])
	fmt.Println("scope:", claims[jwt.Scope])
	fmt.Println("exp:", claims[jwt.ExpirationTime])
	fmt.Println("actors:", len(actors), strings.HasPrefix(actors[0].Subject, "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"))
	fmt.Println("holder is newest actor:", actors[0].Subject == "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"+grant.Holder)
	// Output:
	// sub: alice
	// scope: read
	// exp: 1800000300
	// actors: 2 true
	// holder is newest actor: true
}

// A zero [jwtchain.Limits] applies the secure defaults; set fields to
// tighten them, and share one value between Derive and the Policy.
func ExampleLimits() {
	issuer, agent := exampleKey("issuer"), exampleKey("agent")
	root, _ := jwtchain.Parse(exampleRoot(issuer, agent))
	limits := jwtchain.Limits{MaxLinks: 1}
	opts := []jwtchain.DeriveOption{
		jwtchain.WithClock(func() time.Time { return exampleNow }),
		jwtchain.WithLimits(limits),
	}
	restriction := jwtchain.Restriction{Expiry: exampleNow.Add(time.Minute), Holder: agent.Public()}

	one, err := jwtchain.Derive(root, agent, restriction, opts...)
	fmt.Println(err)
	_, err = jwtchain.Derive(one, agent, restriction, opts...)
	fmt.Println(err)
	// Output:
	// <nil>
	// jwtchain: a chain may hold at most 1 links
}
