package jwtchain_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/jwtchain"
)

// An issuer grants an agent broad access; the agent hands a sub-agent a
// five-minute, read-only slice of it without asking the issuer, and the
// API checks the whole chain plus the sub-agent's DPoP proof.
func Example() {
	issuerPublic, issuer, _ := ed25519.GenerateKey(rand.Reader)
	agent, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subAgent, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// The issuer mints an ordinary JWT bound to the agent's key.
	cnf, _ := jwt.ConfirmationFor(agent.Public())
	claims, _ := json.Marshal(jwt.ClaimsSet{
		jwt.Issuer:         "https://issuer.example",
		jwt.Subject:        "alice",
		jwt.Audience:       "https://api.example",
		jwt.Scope:          "vault:read vault:write",
		jwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		jwt.Confirmation:   cnf,
	})
	root, _ := jws.New(jws.Header{header.Algorithm: jwa.EdDSA, header.Type: "at+jwt"}, claims, issuer)

	// The agent narrows it for the sub-agent, offline.
	parent, _ := jwtchain.Parse(root.String())
	chain, err := jwtchain.Derive(parent, agent, jwtchain.Restriction{
		Expiry:  time.Now().Add(5 * time.Minute),
		Scope:   []string{"vault:read"},
		Caveats: []string{"item:github-token"},
		Holder:  subAgent.Public(),
	})
	if err != nil {
		panic(err)
	}
	token := chain.String()

	// The sub-agent calls the API with the chain and a DPoP proof.
	proofs, _ := dpop.NewSigner(subAgent)
	proof, _ := proofs.Proof("GET", "https://api.example/items/github-token", dpop.ProofOptions{AccessToken: token})

	// The API verifies the root as it would any token from the issuer.
	policy := &jwtchain.Policy{
		Root: jwtchain.RootVerifier(&jwt.Verifier{
			Keys:     jwt.Keys{{Public: issuerPublic}},
			Types:    []string{"at+jwt"},
			Issuer:   "https://issuer.example",
			Audience: "https://api.example",
		}),
		Audience: "https://api.example",
		Caveat: func(_ context.Context, caveat string) error {
			if caveat != "item:github-token" {
				return fmt.Errorf("unknown caveat")
			}
			return nil
		},
	}
	verified, err := policy.Verify(context.Background(), token)
	if err != nil {
		panic(err)
	}
	_, err = new(dpop.Verifier).Verify(context.Background(), proof, dpop.Request{
		Method:      "GET",
		URI:         "https://api.example/items/github-token",
		AccessToken: token,
		Thumbprint:  verified.Holder,
	})
	fmt.Println("proof:", err == nil)
	fmt.Println("subject:", verified.Subject)
	fmt.Println("scope:", strings.Join(verified.Scope, " "))
	fmt.Println("can write:", verified.HasScope("vault:write"))
	fmt.Println("links:", chain.Links())
	// Output:
	// proof: true
	// subject: alice
	// scope: vault:read
	// can write: false
	// links: 1
}
