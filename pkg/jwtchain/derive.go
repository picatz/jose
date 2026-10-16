package jwtchain

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/ni"
)

// Restriction is what a new link narrows its parent to. Zero fields
// inherit what the parent allows, except Expiry, which every link sets.
type Restriction struct {
	// Expiry is when the link stops being valid. It is required and may
	// not be later than the parent's expiry. Keep it short.
	Expiry time.Time
	// NotBefore, when set, is when the link starts being valid.
	NotBefore time.Time
	// Audience, when set, must be a subset of the audiences the parent
	// allows.
	Audience []string
	// Scope, when set, must be a subset of the scopes the parent grants.
	Scope []string
	// Caveats are added to every caveat already in the chain. A verifier
	// must accept each of them; see [Policy.Caveat].
	Caveats []string
	// Holder is the public key (or a private key or [crypto.Signer], whose
	// public half is used) of the next holder, who can present the chain
	// with proof of possession and derive from it in turn. Nil makes a
	// bearer leaf that nobody can derive from and anyone holding can use.
	Holder any
	// ID is the link's "jti"; empty means a random 128-bit value.
	ID string
}

// DeriveOption configures [Derive].
type DeriveOption func(*deriveConfig) error

type deriveConfig struct {
	embed bool
	alg   jwa.Algorithm
	now   func() time.Time
}

// Embed carries the parent inside the new link's "prt" header, so the link
// alone is one compact JWS that holds its history. Use it when the chain
// must travel where only a single JWT fits, such as an Authorization
// header. Each embedding grows the token by about a third.
func Embed() DeriveOption {
	return func(c *deriveConfig) error {
		c.embed = true
		return nil
	}
}

// WithAlgorithm sets the link's signature algorithm instead of the one
// [jwa.ForKey] picks. It must be an asymmetric algorithm that fits the key.
func WithAlgorithm(alg jwa.Algorithm) DeriveOption {
	return func(c *deriveConfig) error {
		if !jwa.IsAsymmetricSignature(alg) {
			return fmt.Errorf("jwtchain: %q is not an asymmetric signature algorithm", alg)
		}
		c.alg = alg
		return nil
	}
}

// WithClock sets the clock used for "iat" and to refuse an Expiry in the
// past; the default is [time.Now].
func WithClock(now func() time.Time) DeriveOption {
	return func(c *deriveConfig) error {
		if now == nil {
			return errors.New("jwtchain: nil clock")
		}
		c.now = now
		return nil
	}
}

// Derive returns parent extended by one link that key signs. key must be
// the parent's holder key: the one its last token's "cnf" names. Hardware
// keys work like any other [crypto.Signer].
//
// Derive checks the new link with the same rules a [Policy] applies, so it
// refuses to mint a link that broadens its parent. It cannot check the
// root's signature, which needs the issuer's key; a holder learns that the
// root is genuine the same way a verifier does.
func Derive(parent *Chain, key crypto.Signer, r Restriction, opts ...DeriveOption) (*Chain, error) {
	if parent == nil || len(parent.tokens) == 0 {
		return nil, errors.New("jwtchain: no parent chain")
	}
	if key == nil {
		return nil, errors.New("jwtchain: nil key")
	}
	config := deriveConfig{now: time.Now}
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return nil, err
		}
	}
	if parent.Links() >= DefaultMaxLinks {
		return nil, fmt.Errorf("jwtchain: a chain may hold at most %d links", DefaultMaxLinks)
	}

	// Replay the parent to learn what it allows and who holds it.
	s, err := rootState(parent.tokens[0].claims)
	if err != nil {
		return nil, err
	}
	for _, link := range parent.tokens[1:] {
		if err := s.apply(link, DefaultAlgorithms); err != nil {
			return nil, err
		}
	}
	if s.holder == "" {
		return nil, errors.New("jwtchain: the parent binds no holder key, so nothing can be derived from it")
	}
	signer, err := thumbprint.FromPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("jwtchain: key: %w", err)
	}
	if signer != s.holder {
		return nil, errors.New("jwtchain: key is not the parent's holder key")
	}

	now := config.now()
	if r.Expiry.IsZero() {
		return nil, errors.New("jwtchain: Restriction.Expiry is required")
	}
	if !r.Expiry.After(now) {
		return nil, errors.New("jwtchain: Restriction.Expiry is not in the future")
	}
	if !r.NotBefore.IsZero() && !r.NotBefore.Before(r.Expiry) {
		return nil, errors.New("jwtchain: Restriction.NotBefore is not before Expiry")
	}

	claims := jwt.ClaimsSet{
		jwt.Issuer:         thumbprint.URNPrefix + signer,
		jwt.ExpirationTime: r.Expiry.Unix(),
		jwt.IssuedAt:       now.Unix(),
	}
	if r.ID == "" {
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return nil, fmt.Errorf("jwtchain: jti: %w", err)
		}
		r.ID, _ = base64.Encode(id)
	}
	claims[jwt.JWTID] = r.ID
	if !r.NotBefore.IsZero() {
		claims[jwt.NotBefore] = r.NotBefore.Unix()
	}
	if r.Audience != nil {
		if len(r.Audience) == 0 || slices.Contains(r.Audience, "") {
			return nil, errors.New("jwtchain: Restriction.Audience must hold non-empty strings")
		}
		claims[jwt.Audience] = slices.Clone(r.Audience)
	}
	if r.Scope != nil {
		for _, token := range r.Scope {
			if err := checkScopeToken(token); err != nil {
				return nil, fmt.Errorf("jwtchain: Restriction.Scope: %w", err)
			}
		}
		if len(r.Scope) == 0 {
			return nil, errors.New("jwtchain: Restriction.Scope must not be empty; leave it nil to inherit")
		}
		claims[jwt.Scope] = strings.Join(r.Scope, " ")
	}
	if r.Caveats != nil {
		if len(r.Caveats) == 0 || slices.Contains(r.Caveats, "") {
			return nil, errors.New("jwtchain: Restriction.Caveats must hold non-empty strings")
		}
		claims[ClaimCaveats] = slices.Clone(r.Caveats)
	}
	if r.Holder != nil {
		confirmation, err := Confirmation(r.Holder)
		if err != nil {
			return nil, fmt.Errorf("jwtchain: Restriction.Holder: %w", err)
		}
		claims[jwt.Confirmation] = confirmation
	}

	alg := config.alg
	if alg == "" {
		if alg, err = jwa.ForKey(key); err != nil {
			return nil, fmt.Errorf("jwtchain: %w", err)
		}
	}
	publicJWK, err := jwk.PublicValue(key)
	if err != nil {
		return nil, fmt.Errorf("jwtchain: %w", err)
	}
	parentToken := parent.Leaf()
	digest, err := ni.Sum(crypto.SHA256, []byte(parentToken))
	if err != nil {
		return nil, fmt.Errorf("jwtchain: %w", err)
	}
	h := jws.Header{
		header.Algorithm:  alg,
		header.Type:       Type,
		header.JSONWebKey: map[string]any(publicJWK),
		header.Critical:   []string{HeaderParentHash},
		HeaderParentHash:  digest.String(),
	}
	if config.embed {
		h[HeaderParentToken] = parentToken
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("jwtchain: claims: %w", err)
	}
	signed, err := jws.New(h, payload, key)
	if err != nil {
		return nil, fmt.Errorf("jwtchain: sign: %w", err)
	}

	// Parse the link back and hold it to the verifier's rules, so Derive
	// never returns a link a Policy would refuse.
	link, err := parseToken(signed.String())
	if err != nil {
		return nil, err
	}
	if err := s.apply(link, DefaultAlgorithms); err != nil {
		return nil, err
	}
	chain := &Chain{tokens: append(slices.Clone(parent.tokens), link)}
	if len(chain.String()) > DefaultMaxSize {
		return nil, fmt.Errorf("jwtchain: the chain would exceed %d bytes", DefaultMaxSize)
	}
	return chain, nil
}

// Confirmation returns the "cnf" claim that makes holder the holder of a
// root: an issuer sets it so that holder can present the token with proof
// of possession and derive links from it.
//
//	claims[jwt.Confirmation], err = jwtchain.Confirmation(holderKey)
//
// https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1
func Confirmation(holder any) (map[string]any, error) {
	if _, err := jwa.ForKey(holder); err != nil {
		return nil, fmt.Errorf("jwtchain: holder must be a signing key, so it can prove possession: %w", err)
	}
	jkt, err := thumbprint.FromPublicKey(holder)
	if err != nil {
		return nil, fmt.Errorf("jwtchain: holder: %w", err)
	}
	return map[string]any{"jkt": jkt}, nil
}

func thumbprintURN(jkt string) string { return thumbprint.URNPrefix + jkt }
