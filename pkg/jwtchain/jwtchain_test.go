package jwtchain_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/jwtchain"
	"github.com/picatz/jose/pkg/ni"
)

var now = time.Unix(1_800_000_000, 0)

func clock() time.Time { return now }

func ed25519Key(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func p256Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// fixture is an issuer and three holders, A (bound by the root), B and C.
type fixture struct {
	issuer  ed25519.PrivateKey
	a, b, c crypto.Signer
	root    string
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{issuer: ed25519Key(t), a: p256Key(t), b: ed25519Key(t), c: p256Key(t)}
	cnf, err := jwtchain.Confirmation(f.a.Public())
	if err != nil {
		t.Fatal(err)
	}
	f.root = f.mintRoot(t, jwt.ClaimsSet{
		jwt.Issuer:         "https://issuer.example",
		jwt.Subject:        "alice",
		jwt.Audience:       []string{"https://api.example", "https://admin.example"},
		jwt.Scope:          "read write delete",
		jwt.ExpirationTime: now.Add(time.Hour).Unix(),
		jwt.Confirmation:   cnf,
	})
	return f
}

func (f *fixture) mintRoot(t testing.TB, claims jwt.ClaimsSet) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jws.New(jws.Header{header.Algorithm: jwa.EdDSA, header.Type: "at+jwt"}, payload, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	return signed.String()
}

func (f *fixture) policy() *jwtchain.Policy {
	return &jwtchain.Policy{
		Root:     jwtchain.RootKey(f.issuer.Public()),
		Audience: "https://api.example",
		Now:      clock,
	}
}

func parse(t testing.TB, s string) *jwtchain.Chain {
	t.Helper()
	c, err := jwtchain.Parse(s)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return c
}

func derive(t testing.TB, parent *jwtchain.Chain, key crypto.Signer, r jwtchain.Restriction, opts ...jwtchain.DeriveOption) *jwtchain.Chain {
	t.Helper()
	c, err := jwtchain.Derive(parent, key, r, append([]jwtchain.DeriveOption{jwtchain.WithClock(clock)}, opts...)...)
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}
	return c
}

func urn(t testing.TB, key crypto.Signer) string {
	t.Helper()
	s, err := thumbprint.URN(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRootAlone(t *testing.T) {
	f := newFixture(t)
	v, err := f.policy().Verify(f.root)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	jkt, _ := thumbprint.FromPublicKey(f.a.Public())
	if v.Subject != "alice" || v.Holder != jkt || len(v.Links) != 0 || !v.HasScope("delete") {
		t.Fatalf("Verify() = %+v", v)
	}
	if actors := v.Actors(); len(actors) != 0 {
		t.Fatalf("Actors() = %+v, want none", actors)
	}
}

func TestDeriveNarrowsAndVerifies(t *testing.T) {
	f := newFixture(t)
	one := derive(t, parse(t, f.root), f.a, jwtchain.Restriction{
		Expiry:   now.Add(30 * time.Minute),
		Audience: []string{"https://api.example"},
		Scope:    []string{"read", "write"},
		Holder:   f.b.Public(),
	})
	two := derive(t, one, f.b, jwtchain.Restriction{
		Expiry:  now.Add(5 * time.Minute),
		Scope:   []string{"read"},
		Caveats: []string{"path:/reports/*"},
		Holder:  f.c.Public(),
	})
	if got := strings.Count(two.String(), jwtchain.Separator); got != 2 {
		t.Fatalf("String() has %d separators, want 2", got)
	}

	policy := f.policy()
	policy.Caveat = jwtchain.AcceptCaveats("path:/reports/*")
	v, err := policy.Verify(two.String())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	jkt, _ := thumbprint.FromPublicKey(f.c.Public())
	switch {
	case v.Subject != "alice":
		t.Errorf("Subject = %q", v.Subject)
	case !slices.Equal(v.Audience, []string{"https://api.example"}):
		t.Errorf("Audience = %q", v.Audience)
	case !slices.Equal(v.Scope, []string{"read"}) || v.HasScope("write"):
		t.Errorf("Scope = %q", v.Scope)
	case !v.Expiry.Equal(now.Add(5 * time.Minute)):
		t.Errorf("Expiry = %v", v.Expiry)
	case !slices.Equal(v.Caveats, []string{"path:/reports/*"}):
		t.Errorf("Caveats = %q", v.Caveats)
	case v.Holder != jkt:
		t.Errorf("Holder = %q, want %q", v.Holder, jkt)
	case len(v.Links) != 2 || v.Root[jwt.Issuer] != "https://issuer.example":
		t.Errorf("Links = %d, Root = %v", len(v.Links), v.Root)
	}

	want := []jwt.Party{{Subject: urn(t, f.c)}, {Subject: urn(t, f.b)}, {Subject: urn(t, f.a)}}
	if got := v.Actors(); !slices.EqualFunc(got, want, jwt.Party.Is) {
		t.Fatalf("Actors() = %+v, want %+v", got, want)
	}

	// The narrowed audience is enforced: the admin service is in the root
	// but not in the chain.
	admin := f.policy()
	admin.Audience = "https://admin.example"
	admin.Caveat = policy.Caveat
	if _, err := admin.Verify(two.String()); !errors.Is(err, jwtchain.ErrVerification) {
		t.Fatalf("Verify() for a dropped audience error = %v", err)
	}
	// Caveats are never ignored.
	if _, err := f.policy().Verify(two.String()); !errors.Is(err, jwtchain.ErrCaveat) {
		t.Fatalf("Verify() without Caveat error = %v, want ErrCaveat", err)
	}
	policy.Caveat = jwtchain.AcceptCaveats("something else")
	if _, err := policy.Verify(two.String()); !errors.Is(err, jwtchain.ErrCaveat) {
		t.Fatalf("Verify() with another caveat error = %v, want ErrCaveat", err)
	}
}

func TestEmbed(t *testing.T) {
	f := newFixture(t)
	root := parse(t, f.root)
	one := derive(t, root, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: f.b.Public()}, jwtchain.Embed())
	two := derive(t, one, f.b, jwtchain.Restriction{Expiry: now.Add(time.Minute)}, jwtchain.Embed())

	// Every link embeds its parent, so the chain is one compact JWS.
	single := two.String()
	if strings.Contains(single, jwtchain.Separator) || strings.Count(single, ".") != 2 || single != two.Leaf() {
		t.Fatalf("String() = %q, want the leaf alone", single)
	}
	again := parse(t, single)
	if again.Links() != 2 || !slices.Equal(again.Tokens(), two.Tokens()) {
		t.Fatalf("Parse(embedded) tokens differ")
	}
	if _, err := f.policy().Verify(single); !errors.Is(err, jwtchain.ErrVerification) {
		t.Fatalf("Verify(bearer leaf) error = %v, want a refusal without AllowBearer", err)
	}
	bearer := f.policy()
	bearer.AllowBearer = true
	v, err := bearer.Verify(single)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if v.Holder != "" || v.Confirmation != nil || len(v.Actors()) != 2 {
		t.Fatalf("a bearer leaf: Holder = %q, Actors = %+v", v.Holder, v.Actors())
	}

	// A presenter may also send the embedded parents explicitly.
	if _, err := bearer.Verify(strings.Join(two.Tokens(), jwtchain.Separator)); err != nil {
		t.Fatalf("Verify(redundant bundle) error = %v", err)
	}

	// Mixed: the first link references the root, the second embeds the
	// first, so the root travels and the first link does not.
	ref := derive(t, root, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: f.b.Public()})
	mixed := derive(t, ref, f.b, jwtchain.Restriction{Expiry: now.Add(time.Minute)}, jwtchain.Embed())
	if want := f.root + jwtchain.Separator + mixed.Leaf(); mixed.String() != want {
		t.Fatalf("String() = %q, want root~leaf", mixed.String())
	}
	if _, err := bearer.Verify(mixed.String()); err != nil {
		t.Fatalf("Verify(mixed) error = %v", err)
	}
}

func TestDeriveRefusals(t *testing.T) {
	f := newFixture(t)
	root := parse(t, f.root)
	for name, tc := range map[string]struct {
		key crypto.Signer
		r   jwtchain.Restriction
	}{
		"wrong key":          {f.b, jwtchain.Restriction{Expiry: now.Add(time.Minute)}},
		"no expiry":          {f.a, jwtchain.Restriction{}},
		"expired":            {f.a, jwtchain.Restriction{Expiry: now.Add(-time.Second)}},
		"outlives parent":    {f.a, jwtchain.Restriction{Expiry: now.Add(2 * time.Hour)}},
		"new audience":       {f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Audience: []string{"https://evil.example"}}},
		"new scope":          {f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Scope: []string{"admin"}}},
		"empty scope":        {f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Scope: []string{}}},
		"bad scope token":    {f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Scope: []string{"read write"}}},
		"empty caveat":       {f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Caveats: []string{""}}},
		"nbf after expiry":   {f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), NotBefore: now.Add(time.Hour)}},
		"empty audience":     {f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Audience: []string{}}},
		"unusable holder":    {f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: "not a key"}},
		"symmetric override": {f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)}},
	} {
		t.Run(name, func(t *testing.T) {
			var opts []jwtchain.DeriveOption
			opts = append(opts, jwtchain.WithClock(clock))
			if name == "symmetric override" {
				opts = append(opts, jwtchain.WithAlgorithm(jwa.HS256))
			}
			_, err := jwtchain.Derive(root, tc.key, tc.r, opts...)
			if err == nil {
				t.Fatal("Derive() succeeded")
			}
			t.Log(err)
		})
	}

	t.Run("bearer leaf", func(t *testing.T) {
		leaf := derive(t, root, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)})
		if _, err := jwtchain.Derive(leaf, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)}, jwtchain.WithClock(clock)); err == nil {
			t.Fatal("Derive() extended a bearer leaf")
		}
	})

	t.Run("unbound root", func(t *testing.T) {
		unbound := parse(t, f.mintRoot(t, jwt.ClaimsSet{jwt.Subject: "alice", jwt.ExpirationTime: now.Add(time.Hour).Unix()}))
		if _, err := jwtchain.Derive(unbound, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)}, jwtchain.WithClock(clock)); err == nil {
			t.Fatal("Derive() extended a root with no cnf")
		}
	})

	t.Run("too many links", func(t *testing.T) {
		c := root
		for range jwtchain.DefaultMaxLinks {
			c = derive(t, c, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: f.a.Public()})
		}
		if _, err := jwtchain.Derive(c, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute)}, jwtchain.WithClock(clock)); err == nil {
			t.Fatal("Derive() exceeded DefaultMaxLinks")
		}
		if _, err := f.policy().Verify(c.String()); err != nil {
			t.Fatalf("Verify() of DefaultMaxLinks links error = %v", err)
		}
	})
}

// forge signs a link by hand, so tests can build links Derive refuses.
func forge(t testing.TB, parent string, key crypto.Signer, alg jwa.Algorithm, claims map[string]any, edit func(jws.Header)) string {
	t.Helper()
	publicJWK, err := jwk.PublicValue(key)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := ni.Sum(crypto.SHA256, []byte(parent))
	h := jws.Header{
		header.Algorithm:          alg,
		header.Type:               jwtchain.Type,
		header.JSONWebKey:         map[string]any(publicJWK),
		header.Critical:           []string{jwtchain.HeaderParentHash},
		jwtchain.HeaderParentHash: digest.String(),
	}
	if edit != nil {
		edit(h)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var signingKey any = key
	if alg == jwa.HS256 {
		signingKey = make([]byte, 32)
	}
	signed, err := jws.New(h, payload, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed.String()
}

func TestVerifyRefusals(t *testing.T) {
	f := newFixture(t)
	exp := now.Add(time.Minute).Unix()
	bJKT, _ := thumbprint.FromPublicKey(f.b.Public())
	good := func() map[string]any {
		return map[string]any{jwt.Issuer: urn(t, f.a), jwt.ExpirationTime: exp, jwt.Confirmation: map[string]any{"jkt": bJKT}}
	}
	with := func(name string, value any) map[string]any {
		claims := good()
		claims[name] = value
		return claims
	}
	without := func(name string) map[string]any {
		claims := good()
		delete(claims, name)
		return claims
	}
	link := func(claims map[string]any, edit func(jws.Header)) string {
		return f.root + jwtchain.Separator + forge(t, f.root, f.a, jwa.ES256, claims, edit)
	}

	// The forge itself makes a link that verifies.
	if _, err := f.policy().Verify(link(good(), nil)); err != nil {
		t.Fatalf("Verify(forged good link) error = %v", err)
	}

	for name, input := range map[string]string{
		"broader audience":   link(with(jwt.Audience, []string{"https://api.example", "https://evil.example"}), nil),
		"broader scope":      link(with(jwt.Scope, "read admin"), nil),
		"later expiry":       link(with(jwt.ExpirationTime, now.Add(2*time.Hour).Unix()), nil),
		"no expiry":          link(without(jwt.ExpirationTime), nil),
		"changes subject":    link(with(jwt.Subject, "mallory"), nil),
		"unknown claim":      link(with("role", "admin"), nil),
		"wrong issuer":       link(with(jwt.Issuer, "urn:ietf:params:oauth:jwk-thumbprint:sha-256:AAAA"), nil),
		"no issuer":          link(without(jwt.Issuer), nil),
		"cnf two members":    link(with(jwt.Confirmation, map[string]any{"jkt": strings.Repeat("A", 43), "x5t#S256": "x"}), nil),
		"cnf mTLS only":      link(with(jwt.Confirmation, map[string]any{"x5t#S256": "x"}), nil),
		"caveat string":      link(with(jwtchain.ClaimCaveats, "path:/"), nil),
		"scope double space": link(with(jwt.Scope, "read  write"), nil),
		"empty audience":     link(with(jwt.Audience, []string{}), nil),
		"numeric jti":        link(with(jwt.JWTID, 7), nil),
		"expired":            link(with(jwt.ExpirationTime, now.Add(-time.Hour).Unix()), nil),
		"not yet valid":      link(with(jwt.NotBefore, now.Add(10*time.Minute).Unix()), nil),
		"other typ":          link(good(), func(h jws.Header) { h[header.Type] = "JWT" }),
		"prh not critical":   link(good(), func(h jws.Header) { delete(h, header.Critical) }),
		"no jwk":             link(good(), func(h jws.Header) { delete(h, header.JSONWebKey) }),
		"wrong parent digest": link(good(), func(h jws.Header) {
			h[jwtchain.HeaderParentHash] = "ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk"
		}),
		"embeds a bundle": link(good(), func(h jws.Header) { h[jwtchain.HeaderParentToken] = f.root + jwtchain.Separator + f.root }),
		"symmetric link": link(good(), func(h jws.Header) {
			delete(h, header.JSONWebKey)
			h[header.JSONWebKey] = map[string]any{"kty": "oct", "k": strings.Repeat("A", 43)}
		}),
		"signed by another": f.root + jwtchain.Separator + forge(t, f.root, f.b, jwa.EdDSA, map[string]any{jwt.Issuer: urn(t, f.b), jwt.ExpirationTime: exp}, nil),
		"root missing":      forge(t, f.root, f.a, jwa.ES256, good(), nil),
		"extra token first": f.root + jwtchain.Separator + link(good(), nil),
		"swapped":           forge(t, f.root, f.a, jwa.ES256, good(), nil) + jwtchain.Separator + f.root,
		"link as root": forge(t, f.root, f.a, jwa.ES256, good(), func(h jws.Header) {
			delete(h, jwtchain.HeaderParentHash)
			h[header.Critical] = nil
			delete(h, header.Critical)
		}),
		"empty":         "",
		"empty element": f.root + jwtchain.Separator,
		"oversized":     strings.Repeat("A", jwtchain.DefaultMaxSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.policy().Verify(input)
			if err == nil {
				t.Fatal("Verify() succeeded")
			}
			t.Log(err)
		})
	}

	t.Run("HS256 link", func(t *testing.T) {
		input := link(good(), nil)
		forged := f.root + jwtchain.Separator + forge(t, f.root, f.a, jwa.HS256, good(), nil)
		if _, err := f.policy().Verify(forged); err == nil {
			t.Fatal("Verify() accepted an HS256 link")
		}
		policy := f.policy()
		policy.Algorithms = []jwa.Algorithm{jwa.EdDSA}
		if _, err := policy.Verify(input); err == nil {
			t.Fatal("Verify() accepted an algorithm outside Policy.Algorithms")
		}
	})

	t.Run("tampered root", func(t *testing.T) {
		other := newFixture(t)
		input := link(good(), nil)
		// The same link presented under another valid root does not match
		// its digest.
		swapped := other.root + input[len(f.root):]
		if _, err := f.policy().Verify(swapped); err == nil {
			t.Fatal("Verify() accepted a link under another root")
		}
		policy := f.policy()
		policy.Root = jwtchain.RootKey(other.issuer.Public())
		if _, err := policy.Verify(input); !errors.Is(err, jwtchain.ErrVerification) {
			t.Fatalf("Verify() with the wrong issuer key error = %v", err)
		}
	})

	t.Run("policy configuration", func(t *testing.T) {
		if _, err := (&jwtchain.Policy{Audience: "x"}).Verify(f.root); err == nil {
			t.Fatal("Verify() without Root succeeded")
		}
		if _, err := (&jwtchain.Policy{Root: jwtchain.RootKey(f.issuer.Public())}).Verify(f.root); err == nil {
			t.Fatal("Verify() without Audience succeeded")
		}
		anyAudience := &jwtchain.Policy{Root: jwtchain.RootKey(f.issuer.Public()), AnyAudience: true, Now: clock}
		if _, err := anyAudience.Verify(f.root); err != nil {
			t.Fatalf("Verify() with AnyAudience error = %v", err)
		}
	})

	t.Run("max links", func(t *testing.T) {
		c := parse(t, f.root)
		for range 3 {
			c = derive(t, c, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: f.a.Public()})
		}
		policy := f.policy()
		policy.MaxLinks = 2
		if _, err := policy.Verify(c.String()); !errors.Is(err, jwtchain.ErrFormat) {
			t.Fatalf("Verify() over MaxLinks error = %v, want ErrFormat", err)
		}
		if _, err := policy.VerifyChain(c); !errors.Is(err, jwtchain.ErrFormat) {
			t.Fatalf("VerifyChain() over MaxLinks error = %v, want ErrFormat", err)
		}
	})
}

func TestRootKey(t *testing.T) {
	f := newFixture(t)
	if _, err := jwtchain.RootKey(f.issuer.Public(), jwa.ES256)(f.root); err == nil {
		t.Fatal("RootKey accepted an algorithm it was not given")
	}
	unsecured := "eyJhbGciOiJub25lIn0." + strings.Split(f.root, ".")[1] + "."
	if _, err := jwtchain.RootKey(f.issuer.Public(), jwa.None)(unsecured); err == nil {
		t.Fatal("RootKey accepted an unsecured root")
	}

	// HMAC roots work when the algorithm is named.
	secret := make([]byte, 32)
	signed, err := jws.New(jws.Header{header.Algorithm: jwa.HS256}, []byte(`{"aud":"https://api.example"}`), secret)
	if err != nil {
		t.Fatal(err)
	}
	policy := &jwtchain.Policy{Root: jwtchain.RootKey(secret, jwa.HS256), Audience: "https://api.example", AllowBearer: true, Now: clock}
	if _, err := policy.Verify(signed.String()); err != nil {
		t.Fatalf("Verify(HS256 root) error = %v", err)
	}
}

// A root verified by package jwt composes with a chain.
func TestRootFromPackageJWT(t *testing.T) {
	f := newFixture(t)
	c := derive(t, parse(t, f.root), f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Scope: []string{"read"}, Holder: f.b.Public()})
	policy := f.policy()
	policy.Root = func(root string) (jwt.ClaimsSet, error) {
		token, err := jwt.ParseAndVerify(root,
			jwt.WithKey(f.issuer.Public().(ed25519.PublicKey)),
			jwt.WithAllowedAlgorithms(jwa.EdDSA),
			jwt.WithAllowedIssuers("https://issuer.example"),
			jwt.WithAllowedAudiences("https://api.example"),
			jwt.WithClock(clock),
		)
		if err != nil {
			return nil, err
		}
		return token.Claims, nil
	}
	v, err := policy.Verify(c.String())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !slices.Equal(v.Scope, []string{"read"}) || !v.Expiry.Equal(now.Add(time.Minute)) {
		t.Fatalf("Verify() = %+v", v)
	}
}

func TestRootScopeRules(t *testing.T) {
	f := newFixture(t)
	cnf, _ := jwtchain.Confirmation(f.a.Public())
	noScope := parse(t, f.mintRoot(t, jwt.ClaimsSet{
		jwt.Audience:       "https://api.example",
		jwt.ExpirationTime: now.Add(time.Hour).Unix(),
		jwt.Confirmation:   cnf,
	}))
	if _, err := jwtchain.Derive(noScope, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Scope: []string{"read"}}, jwtchain.WithClock(clock)); !errors.Is(err, jwtchain.ErrBroadens) {
		t.Fatalf("Derive() adding scope to a scopeless root error = %v, want ErrBroadens", err)
	}
	c := derive(t, noScope, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: f.b.Public()})
	v, err := f.policy().Verify(c.String())
	if err != nil {
		t.Fatal(err)
	}
	if v.Scope != nil {
		t.Fatalf("Scope = %q, want nil", v.Scope)
	}

	// A root without "aud" lets the first link choose one.
	noAudience := parse(t, f.mintRoot(t, jwt.ClaimsSet{jwt.ExpirationTime: now.Add(time.Hour).Unix(), jwt.Confirmation: cnf}))
	if _, err := f.policy().Verify(noAudience.String()); err == nil {
		t.Fatal("Verify() accepted a chain that names no audience")
	}
	narrowed := derive(t, noAudience, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Audience: []string{"https://api.example"}, Holder: f.b.Public()})
	if _, err := f.policy().Verify(narrowed.String()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestRootCaveatsAndJWKConfirmation(t *testing.T) {
	f := newFixture(t)
	value, _ := jwk.PublicValue(f.a)
	root := parse(t, f.mintRoot(t, jwt.ClaimsSet{
		jwt.Audience:          "https://api.example",
		jwt.ExpirationTime:    now.Add(time.Hour).Unix(),
		jwt.Confirmation:      map[string]any{"jwk": map[string]any(value)},
		jwtchain.ClaimCaveats: []string{"tenant:acme"},
	}))
	c := derive(t, root, f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Caveats: []string{"read-only"}, Holder: f.b.Public()})
	policy := f.policy()
	policy.Caveat = jwtchain.AcceptCaveats("tenant:acme", "read-only")
	v, err := policy.Verify(c.String())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !slices.Equal(v.Caveats, []string{"tenant:acme", "read-only"}) {
		t.Fatalf("Caveats = %q", v.Caveats)
	}
}

func TestReissueWithLineage(t *testing.T) {
	f := newFixture(t)
	c := derive(t, parse(t, f.root), f.a, jwtchain.Restriction{
		Expiry: now.Add(10 * time.Minute),
		Scope:  []string{"read"},
		Holder: f.b.Public(),
	})
	v, err := f.policy().Verify(c.String())
	if err != nil {
		t.Fatal(err)
	}

	// The issuer collapses the chain into a fresh root for the holder.
	claims := jwt.ClaimsSet{
		jwt.Issuer:         "https://issuer.example",
		jwt.Subject:        v.Subject,
		jwt.Audience:       v.Audience,
		jwt.Scope:          strings.Join(v.Scope, " "),
		jwt.ExpirationTime: v.Expiry.Unix(),
		jwt.Confirmation:   v.Confirmation,
	}
	if err := claims.SetActors(v.Actors()); err != nil {
		t.Fatal(err)
	}
	reissued := f.mintRoot(t, claims)
	again, err := f.policy().Verify(reissued)
	if err != nil {
		t.Fatalf("Verify(reissued) error = %v", err)
	}
	if again.Holder != v.Holder || !slices.Equal(again.Scope, []string{"read"}) {
		t.Fatalf("reissued = %+v", again)
	}
	actors, err := again.Root.Actors()
	if err != nil {
		t.Fatal(err)
	}
	if want := []jwt.Party{{Subject: urn(t, f.b)}, {Subject: urn(t, f.a)}}; !slices.EqualFunc(actors, want, jwt.Party.Is) {
		t.Fatalf("Actors() = %+v, want %+v", actors, want)
	}

	// The re-issued root carries its lineage into the next chain.
	next := derive(t, parse(t, reissued), f.b, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: f.c.Public()})
	nv, err := f.policy().Verify(next.String())
	if err != nil {
		t.Fatal(err)
	}
	want := []jwt.Party{{Subject: urn(t, f.c)}, {Subject: urn(t, f.b)}, {Subject: urn(t, f.b)}, {Subject: urn(t, f.a)}}
	if got := nv.Actors(); !slices.EqualFunc(got, want, jwt.Party.Is) {
		t.Fatalf("Actors() = %+v, want %+v", got, want)
	}
}

func FuzzParse(f *testing.F) {
	fx := newFixture(f)
	root := parse(f, fx.root)
	one := derive(f, root, fx.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Holder: fx.b.Public()})
	two := derive(f, one, fx.b, jwtchain.Restriction{Expiry: now.Add(time.Minute)}, jwtchain.Embed())
	f.Add(fx.root)
	f.Add(one.String())
	f.Add(two.String())
	f.Add(strings.Join(two.Tokens(), jwtchain.Separator))
	f.Fuzz(func(t *testing.T, input string) {
		c, err := jwtchain.Parse(input)
		if err != nil {
			return
		}
		again, err := jwtchain.Parse(c.String())
		if err != nil {
			t.Fatalf("Parse(String()) error = %v", err)
		}
		if !slices.Equal(again.Tokens(), c.Tokens()) {
			t.Fatal("String() lost tokens")
		}
		_, _ = fx.policy().VerifyChain(c)
	})
}

func TestInspect(t *testing.T) {
	f := newFixture(t)
	c := derive(t, parse(t, f.root), f.a, jwtchain.Restriction{Expiry: now.Add(time.Minute), Scope: []string{"read"}, Holder: f.b.Public()})
	grant, err := c.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	jkt, _ := thumbprint.FromPublicKey(f.b.Public())
	if grant.Subject != "alice" || !slices.Equal(grant.Scope, []string{"read"}) || grant.Holder != jkt || !grant.Expiry.Equal(now.Add(time.Minute)) {
		t.Fatalf("Inspect() = %+v", grant)
	}

	// Inspect still checks links: one signed by the wrong key fails.
	forged := parse(t, f.root+jwtchain.Separator+forge(t, f.root, f.b, jwa.EdDSA, map[string]any{jwt.Issuer: urn(t, f.b), jwt.ExpirationTime: now.Add(time.Minute).Unix()}, nil))
	if _, err := forged.Inspect(); !errors.Is(err, jwtchain.ErrVerification) {
		t.Fatalf("Inspect(forged) error = %v", err)
	}
}
