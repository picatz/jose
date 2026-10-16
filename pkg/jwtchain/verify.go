package jwtchain

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
)

// DefaultLeeway is the clock skew a zero [Policy] tolerates.
const DefaultLeeway = 30 * time.Second

// Policy verifies chains. Root is required, and so is Audience unless
// AnyAudience is set; every other field has a safe default.
type Policy struct {
	// Root verifies the root token and returns its claims. Verify it the
	// way the application verifies any token from this issuer, including
	// "iss" and "typ" checks: the chain is only as trustworthy as its
	// root. [RootKey] covers a single issuer key. Root need not check
	// "exp", "nbf" or "aud"; the Policy checks them for the whole chain.
	Root func(root string) (jwt.ClaimsSet, error)

	// Audience is this verifier's identifier. The chain verifies only if
	// what it allows, after every link has narrowed it, still names
	// Audience.
	Audience string
	// AnyAudience skips the audience check. Use it only where every
	// audience is acceptable, since a link that narrows the audience to
	// someone else would otherwise pass here too.
	AnyAudience bool

	// AllowBearer accepts a chain whose last token has no "cnf": one that
	// anyone holding it can use. By default such chains are refused, so a
	// verifier that checks proof of possession against [Grant.Holder]
	// is never handed an empty thumbprint.
	AllowBearer bool

	// Caveat decides whether a caveat holds for this request; it returns
	// nil to accept it. Every caveat in the chain must be accepted. A nil
	// Caveat accepts none, so a chain with caveats fails, as caveats must
	// never be ignored. [AcceptCaveats] accepts a fixed set.
	Caveat func(caveat string) error

	// Algorithms lists the link signature algorithms accepted; nil means
	// [DefaultAlgorithms]. Symmetric algorithms and "none" are always
	// refused for links. The root's algorithm is Root's concern.
	Algorithms []jwa.Algorithm

	// MaxLinks and MaxSize bound the chain; zero means [DefaultMaxLinks]
	// and [DefaultMaxSize].
	MaxLinks int
	MaxSize  int

	// Leeway is the clock skew tolerated for "exp" and "nbf"; zero means
	// [DefaultLeeway].
	Leeway time.Duration
	// Now is the clock; nil means [time.Now].
	Now func() time.Time
}

// Grant is what a chain allows once every link has narrowed it. A
// [Policy] returns one only for a chain that verifies; [Chain.Inspect]
// returns one without verifying the root.
type Grant struct {
	// Chain is the chain the grant comes from.
	Chain *Chain
	// Root holds the claims Root returned for the root token.
	Root jwt.ClaimsSet
	// Links holds each link's claims, root-most first.
	Links []jwt.ClaimsSet

	// Subject is the root's "sub"; links cannot change it.
	Subject string
	// Audience lists who may accept the chain. It is empty only when the
	// root names no audience and no link narrowed it.
	Audience []string
	// Scope lists the scopes the chain grants. It is nil when the root
	// carries no "scope" claim, and empty when links narrowed it to none.
	Scope []string
	// NotBefore and Expiry bound when the chain is valid. Either is zero
	// when nothing in the chain sets it.
	NotBefore time.Time
	Expiry    time.Time
	// Caveats lists every caveat in the chain, root first. Each one was
	// accepted by [Policy.Caveat].
	Caveats []string

	// Holder is the base64url SHA-256 JWK Thumbprint of the key that must
	// present this chain, from the last token's "cnf". It is empty for a
	// bearer chain, or when the root binds its holder in a way other than
	// "jkt" or "jwk" (such as an mTLS certificate): check Confirmation.
	// To require proof of possession with DPoP, pass Holder as
	// dpop.Request.Thumbprint.
	Holder string
	// Confirmation is the last token's "cnf" claim as given, or nil.
	Confirmation map[string]any

	signers    []string
	rootActors []jwt.Party
}

// HasScope reports whether the chain grants scope.
func (g *Grant) HasScope(scope string) bool {
	return slices.Contains(g.Scope, scope)
}

// Actors returns the chain's lineage as RFC 8693 actors, the current one
// first: the holder of the last link, then each key that signed a link,
// newest first, then any actors the root itself records. Each key is named
// by its thumbprint URI (RFC 9278). A root alone has only the root's
// actors.
//
// An issuer that re-issues a verified chain as a fresh token keeps the
// lineage with [jwt.ClaimsSet.SetActors]:
//
//	err := claims.SetActors(grant.Actors())
//
// https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
func (g *Grant) Actors() []jwt.Party {
	var actors []jwt.Party
	if len(g.signers) > 0 && g.Holder != "" {
		actors = append(actors, jwt.Party{Subject: thumbprintURN(g.Holder)})
	}
	for _, signer := range slices.Backward(g.signers) {
		actors = append(actors, jwt.Party{Subject: signer})
	}
	return append(actors, g.rootActors...)
}

// Verify parses input and verifies it with [Policy.VerifyChain].
func (p *Policy) Verify(input string) (*Grant, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	chain, err := parse(input, orDefault(p.MaxLinks, DefaultMaxLinks), orDefault(p.MaxSize, DefaultMaxSize))
	if err != nil {
		return nil, err
	}
	return p.VerifyChain(chain)
}

// VerifyChain verifies a parsed chain: the root with [Policy.Root], then
// each link's signature against its parent's holder key and its claims
// against what its parent allows, then the audience, the validity window
// and every caveat.
func (p *Policy) VerifyChain(c *Chain) (*Grant, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	if c == nil || len(c.tokens) == 0 {
		return nil, fmt.Errorf("%w: empty chain", ErrFormat)
	}
	if c.Links() > orDefault(p.MaxLinks, DefaultMaxLinks) {
		return nil, fmt.Errorf("%w: more than %d links", ErrFormat, orDefault(p.MaxLinks, DefaultMaxLinks))
	}
	root, err := p.Root(c.Root())
	if err != nil {
		return nil, fmt.Errorf("%w: root: %w", ErrVerification, err)
	}
	if root == nil {
		return nil, fmt.Errorf("%w: root: Root returned no claims", ErrVerification)
	}
	s, err := rootState(root)
	if err != nil {
		return nil, err
	}
	algorithms := p.Algorithms
	if algorithms == nil {
		algorithms = DefaultAlgorithms
	}
	for _, link := range c.tokens[1:] {
		if err := s.apply(link, algorithms); err != nil {
			return nil, err
		}
	}

	if !p.AnyAudience && !slices.Contains(s.audience, p.Audience) {
		return nil, fmt.Errorf("%w: not meant for audience %q", ErrVerification, p.Audience)
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	leeway := p.Leeway
	if leeway == 0 {
		leeway = DefaultLeeway
	}
	current := now()
	if !s.notBefore.IsZero() && current.Add(leeway).Before(s.notBefore) {
		return nil, fmt.Errorf("%w: not valid until %s", ErrVerification, s.notBefore.UTC().Format(time.RFC3339))
	}
	if !s.expiry.IsZero() && !current.Add(-leeway).Before(s.expiry) {
		return nil, fmt.Errorf("%w: expired at %s", ErrVerification, s.expiry.UTC().Format(time.RFC3339))
	}
	if s.confirmation == nil && !p.AllowBearer {
		return nil, fmt.Errorf("%w: its last token binds no holder (\"cnf\"), and AllowBearer is not set", ErrVerification)
	}
	for _, caveat := range s.caveats {
		if p.Caveat == nil {
			return nil, fmt.Errorf("%w: %q (no Caveat function is set)", ErrCaveat, caveat)
		}
		if err := p.Caveat(caveat); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrCaveat, caveat, err)
		}
	}
	return s.grant(c, root), nil
}

func (p *Policy) check() error {
	switch {
	case p.Root == nil:
		return errors.New("jwtchain: Policy.Root is required")
	case p.Audience == "" && !p.AnyAudience:
		return errors.New("jwtchain: Policy.Audience is required unless AnyAudience is set")
	}
	return nil
}

func orDefault(n, fallback int) int {
	if n <= 0 {
		return fallback
	}
	return n
}

// RootKey returns a [Policy.Root] function that accepts a root signed by
// key with one of algorithms; with none given, it accepts only the
// algorithm [jwa.ForKey] picks for key. For an HMAC key, name the
// algorithm. The root must not be a link and must not be unsecured.
//
// RootKey checks only the signature. Wrap it when the root's issuer, type
// or other claims also need checking.
func RootKey(key any, algorithms ...jwa.Algorithm) func(root string) (jwt.ClaimsSet, error) {
	allowed := slices.Clone(algorithms)
	if len(allowed) == 0 {
		if alg, err := jwa.ForKey(key); err == nil {
			allowed = []jwa.Algorithm{alg}
		}
	}
	return func(root string) (jwt.ClaimsSet, error) {
		signature, err := jws.Parse(root)
		if err != nil {
			return nil, err
		}
		alg, err := signature.Header.Algorithm()
		if err != nil || alg == jwa.None || !slices.Contains(allowed, alg) {
			return nil, fmt.Errorf("algorithm %q is not accepted", alg)
		}
		if typ, _ := signature.Header[header.Type].(string); strings.EqualFold(typ, Type) {
			return nil, fmt.Errorf("a link cannot be a root")
		}
		if err := signature.Verify(key); err != nil {
			return nil, err
		}
		return decodeClaims(signature.Payload)
	}
}

// AcceptCaveats returns a [Policy.Caveat] function that accepts exactly
// the given caveats and no others.
func AcceptCaveats(caveats ...string) func(caveat string) error {
	accepted := slices.Clone(caveats)
	return func(caveat string) error {
		if !slices.Contains(accepted, caveat) {
			return errors.New("not accepted")
		}
		return nil
	}
}
