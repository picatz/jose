package jwtchain_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/jwtchain"
)

// FuzzVerify checks that Policy.Verify never panics and that a chain that
// verifies never broadens its root: the grant keeps the root's subject, its
// scopes and audiences are subsets of the root's, and it expires no later
// than the root does.
func FuzzVerify(f *testing.F) {
	fx := newFixture(f)
	rootScope := []string{"read", "write", "delete"}
	rootAudience := []string{"https://api.example", "https://admin.example"}
	rootExpiry := now.Add(time.Hour)

	root := parse(f, fx.root)
	one := derive(f, root, fx.a, jwtchain.Restriction{
		Expiry:   now.Add(30 * time.Minute),
		Audience: []string{"https://api.example"},
		Scope:    []string{"read", "write"},
		Holder:   fx.b.Public(),
	})
	two := derive(f, one, fx.b, jwtchain.Restriction{
		Expiry:  now.Add(5 * time.Minute),
		Scope:   []string{"read"},
		Caveats: []string{"path:/reports/*"},
		Holder:  fx.c.Public(),
	}, jwtchain.Embed())
	wide := derive(f, root, fx.a, jwtchain.Restriction{Expiry: rootExpiry, Holder: fx.b.Public()})

	f.Add(fx.root)
	f.Add(one.String())
	f.Add(two.String())
	f.Add(wide.String())
	f.Add(strings.Join(two.Tokens(), jwtchain.Separator))
	f.Add(strings.Join(one.Tokens(), jwtchain.Separator) + jwtchain.Separator + root.Tokens()[0])
	f.Add(one.Tokens()[0] + jwtchain.Separator + one.Tokens()[0])
	f.Add(one.String() + jwtchain.Separator)
	f.Add(jwtchain.Separator + one.String())
	f.Add(two.String()[:len(two.String())-3])
	f.Add("")
	f.Add(jwtchain.Separator)
	f.Add("a.b.c")

	policy := fx.policy()
	policy.Caveat = jwtchain.AcceptCaveats("path:/reports/*")
	f.Fuzz(func(t *testing.T, input string) {
		grant, err := policy.Verify(t.Context(), input)
		if err != nil {
			if grant != nil {
				t.Fatalf("Verify() returned a grant with error %v", err)
			}
			return
		}
		if grant == nil {
			t.Fatal("Verify() = nil, nil")
		}
		if grant.Subject != "alice" {
			t.Fatalf("Subject = %q, want the root's", grant.Subject)
		}
		if grant.Expiry.IsZero() || grant.Expiry.After(rootExpiry) {
			t.Fatalf("Expiry = %v, want it set and no later than the root's %v", grant.Expiry, rootExpiry)
		}
		if grant.Scope != nil {
			for _, scope := range grant.Scope {
				if !slices.Contains(rootScope, scope) {
					t.Fatalf("Scope = %q broadens the root's %q", grant.Scope, rootScope)
				}
			}
		} else {
			t.Fatal("Scope = nil although the root carries a scope")
		}
		if !slices.Contains(grant.Audience, "https://api.example") {
			t.Fatalf("Audience = %q does not name the policy's audience", grant.Audience)
		}
		for _, aud := range grant.Audience {
			if !slices.Contains(rootAudience, aud) {
				t.Fatalf("Audience = %q broadens the root's %q", grant.Audience, rootAudience)
			}
		}
		for _, caveat := range grant.Caveats {
			if caveat != "path:/reports/*" {
				t.Fatalf("Caveats = %q holds one the policy never accepted", grant.Caveats)
			}
		}
		if grant.Holder == "" {
			t.Fatal("Holder is empty although bearer chains are refused")
		}
	})
}
