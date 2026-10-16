package jwtchain

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
	"github.com/picatz/jose/pkg/jwt"
)

// DefaultAlgorithms are the link signature algorithms a zero [Policy]
// accepts: every asymmetric JWS algorithm this module implements. Links
// are never signed with "none" or a symmetric algorithm, because a link
// must be checkable by anyone who holds its parent.
var DefaultAlgorithms = []jwa.Algorithm{
	jwa.ES256, jwa.ES384, jwa.ES512,
	jwa.EdDSA,
	jwa.PS256, jwa.PS384, jwa.PS512,
	jwa.RS256, jwa.RS384, jwa.RS512,
}

// linkClaims are the only claims a link may carry.
var linkClaims = []string{
	jwt.Issuer, jwt.ExpirationTime, jwt.IssuedAt, jwt.JWTID,
	jwt.Audience, jwt.NotBefore, jwt.Scope, ClaimCaveats, jwt.Confirmation,
}

// state is what a chain allows after its root and some of its links.
type state struct {
	subject      string
	audience     []string
	hasAudience  bool
	scope        []string
	hasScope     bool
	notBefore    time.Time
	expiry       time.Time
	caveats      []string
	holder       string         // JWK Thumbprint of the current holder, if any
	confirmation map[string]any // the current "cnf", as given
	signers      []string       // thumbprint URIs of link signers, root-most first
	rootActors   []jwt.Party
}

// rootState reads what a root token allows. Roots come from issuers, so
// "scope" is split leniently and "cnf" may bind a key some other way, in
// which case the root has no holder a link can be checked against.
func rootState(claims jwt.ClaimsSet) (*state, error) {
	s := &state{}
	var err error
	if v, ok := claims[jwt.Subject]; ok {
		if s.subject, ok = v.(string); !ok {
			return nil, rootErr("%q must be a string", jwt.Subject)
		}
	}
	if v, ok := claims[jwt.Audience]; ok {
		if s.audience, err = stringOrList(v); err != nil {
			return nil, rootErr("%q: %v", jwt.Audience, err)
		}
		s.hasAudience = true
	}
	if v, ok := claims[jwt.Scope]; ok {
		text, ok := v.(string)
		if !ok {
			return nil, rootErr("%q must be a string", jwt.Scope)
		}
		s.scope, s.hasScope = strings.Fields(text), true
	}
	if v, ok := claims[jwt.ExpirationTime]; ok {
		if s.expiry, err = numericDate(v, false); err != nil {
			return nil, rootErr("%q: %v", jwt.ExpirationTime, err)
		}
	}
	if v, ok := claims[jwt.NotBefore]; ok {
		if s.notBefore, err = numericDate(v, true); err != nil {
			return nil, rootErr("%q: %v", jwt.NotBefore, err)
		}
	}
	if v, ok := claims[ClaimCaveats]; ok {
		if s.caveats, err = caveatList(v); err != nil {
			return nil, rootErr("%q: %v", ClaimCaveats, err)
		}
	}
	if v, ok := claims[jwt.Confirmation]; ok {
		cnf, ok := v.(map[string]any)
		if !ok {
			return nil, rootErr("%q must be a JSON object", jwt.Confirmation)
		}
		s.confirmation = cnf
		_, hasJKT := cnf["jkt"]
		_, hasJWK := cnf["jwk"]
		if hasJKT || hasJWK {
			if s.holder, err = holderOf(cnf); err != nil {
				return nil, rootErr("%q: %v", jwt.Confirmation, err)
			}
		}
	}
	if s.rootActors, err = claims.Actors(); err != nil {
		return nil, rootErr("%v", err)
	}
	return s, nil
}

func rootErr(format string, args ...any) error {
	return fmt.Errorf("%w: root: %s", ErrVerification, fmt.Sprintf(format, args...))
}

func linkErr(format string, args ...any) error {
	return fmt.Errorf("%w: link: %s", ErrVerification, fmt.Sprintf(format, args...))
}

func broadens(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBroadens, fmt.Sprintf(format, args...))
}

// apply checks one link against what its parent allows and, when it
// passes, narrows s to what the link allows. It does not check time.
func (s *state) apply(t *token, algorithms []jwa.Algorithm) error {
	h := t.signature.Header
	alg, err := h.Algorithm()
	if err != nil || !jwa.IsAsymmetricSignature(alg) || !slices.Contains(algorithms, alg) {
		return linkErr("algorithm %q is not accepted", alg)
	}
	if s.holder == "" {
		return linkErr("its parent binds no holder key, so nothing can be derived from it")
	}
	rawKey, ok := h[header.JSONWebKey].(map[string]any)
	if !ok {
		return linkErr("missing %q header", header.JSONWebKey)
	}
	if jwk.IsPrivate(jwk.Value(rawKey)) {
		return linkErr("%q header holds private key material", header.JSONWebKey)
	}
	key, err := jwk.PublicKey(jwk.Value(rawKey))
	if err != nil {
		return linkErr("%q header: %v", header.JSONWebKey, err)
	}
	signer, err := thumbprint.FromPublicKey(key)
	if err != nil {
		return linkErr("%q header: %v", header.JSONWebKey, err)
	}
	if signer != s.holder {
		return linkErr("not signed by its parent's holder key")
	}
	if err := t.signature.Verify(key); err != nil {
		return linkErr("signature: %v", err)
	}

	claims := t.claims
	for name := range claims {
		if !slices.Contains(linkClaims, name) {
			return linkErr("claim %q is not allowed in a link", name)
		}
	}
	if iss, _ := claims[jwt.Issuer].(string); iss != thumbprint.URNPrefix+signer {
		return linkErr("%q must be the signer's thumbprint URI", jwt.Issuer)
	}
	if v, ok := claims[jwt.IssuedAt]; ok {
		if _, err := numericDate(v, false); err != nil {
			return linkErr("%q: %v", jwt.IssuedAt, err)
		}
	}
	if v, ok := claims[jwt.JWTID]; ok {
		if _, ok := v.(string); !ok {
			return linkErr("%q must be a string", jwt.JWTID)
		}
	}

	v, ok := claims[jwt.ExpirationTime]
	if !ok {
		return linkErr("missing %q", jwt.ExpirationTime)
	}
	expiry, err := numericDate(v, false)
	if err != nil {
		return linkErr("%q: %v", jwt.ExpirationTime, err)
	}
	if !s.expiry.IsZero() && expiry.After(s.expiry) {
		return broadens("it expires after its parent")
	}
	var notBefore time.Time
	if v, ok := claims[jwt.NotBefore]; ok {
		if notBefore, err = numericDate(v, true); err != nil {
			return linkErr("%q: %v", jwt.NotBefore, err)
		}
	}

	var audience []string
	_, hasAudience := claims[jwt.Audience]
	if hasAudience {
		if audience, err = stringOrList(claims[jwt.Audience]); err != nil {
			return linkErr("%q: %v", jwt.Audience, err)
		}
		if len(audience) == 0 {
			return linkErr("%q must not be empty", jwt.Audience)
		}
		if s.hasAudience {
			for _, a := range audience {
				if !slices.Contains(s.audience, a) {
					return broadens("audience %q is not allowed by its parent", a)
				}
			}
		}
	}

	var scope []string
	_, hasScope := claims[jwt.Scope]
	if hasScope {
		text, ok := claims[jwt.Scope].(string)
		if !ok {
			return linkErr("%q must be a string", jwt.Scope)
		}
		if scope, err = scopeTokens(text); err != nil {
			return linkErr("%q: %v", jwt.Scope, err)
		}
		if !s.hasScope {
			return broadens("its parent grants no scope to narrow")
		}
		for _, name := range scope {
			if !slices.Contains(s.scope, name) {
				return broadens("scope %q is not allowed by its parent", name)
			}
		}
	}

	var caveats []string
	if v, ok := claims[ClaimCaveats]; ok {
		if caveats, err = caveatList(v); err != nil {
			return linkErr("%q: %v", ClaimCaveats, err)
		}
	}

	var holder string
	var confirmation map[string]any
	if v, ok := claims[jwt.Confirmation]; ok {
		if confirmation, ok = v.(map[string]any); !ok || len(confirmation) != 1 {
			return linkErr("%q must hold exactly one of \"jkt\" or \"jwk\"", jwt.Confirmation)
		}
		if holder, err = holderOf(confirmation); err != nil {
			return linkErr("%q: %v", jwt.Confirmation, err)
		}
	}

	// Every check passed: narrow.
	s.expiry = expiry
	if notBefore.After(s.notBefore) {
		s.notBefore = notBefore
	}
	if hasAudience {
		s.audience, s.hasAudience = audience, true
	}
	if hasScope {
		s.scope = scope
	}
	s.caveats = append(s.caveats, caveats...)
	s.holder, s.confirmation = holder, confirmation
	s.signers = append(s.signers, thumbprint.URNPrefix+signer)
	return nil
}

// holderOf returns the JWK Thumbprint a "cnf" object binds: its "jkt", or
// the thumbprint of its "jwk". An object with neither, or both, binds no
// key this package can check.
//
// https://www.rfc-editor.org/rfc/rfc7800.html#section-3.2
// https://www.rfc-editor.org/rfc/rfc9449.html#section-6.1
func holderOf(cnf map[string]any) (string, error) {
	jkt, hasJKT := cnf["jkt"]
	value, hasJWK := cnf["jwk"]
	switch {
	case hasJKT && hasJWK:
		return "", fmt.Errorf("holds both \"jkt\" and \"jwk\"")
	case hasJKT:
		s, ok := jkt.(string)
		if !ok {
			return "", fmt.Errorf("\"jkt\" must be a string")
		}
		if raw, err := base64.Decode(s); err != nil || len(raw) != 32 {
			return "", fmt.Errorf("\"jkt\" must be a base64url SHA-256 thumbprint")
		}
		return s, nil
	case hasJWK:
		object, ok := value.(map[string]any)
		if !ok || jwk.IsPrivate(jwk.Value(object)) {
			return "", fmt.Errorf("\"jwk\" must be a public JWK")
		}
		key, err := jwk.PublicKey(jwk.Value(object))
		if err != nil {
			return "", fmt.Errorf("\"jwk\": %v", err)
		}
		return thumbprint.FromPublicKey(key)
	}
	return "", fmt.Errorf("binds no \"jkt\" or \"jwk\"")
}

// stringOrList reads a claim that is a string or an array of strings, as
// "aud" is (RFC 7519 §4.1.3).
func stringOrList(v any) ([]string, error) {
	switch v := v.(type) {
	case string:
		return []string{v}, nil
	case []string:
		return slices.Clone(v), nil
	case []any:
		list := make([]string, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("must hold only strings")
			}
			list[i] = s
		}
		return list, nil
	}
	return nil, fmt.Errorf("must be a string or an array of strings")
}

// caveatList reads "cav": a non-empty array of non-empty strings.
func caveatList(v any) ([]string, error) {
	if _, ok := v.(string); ok {
		return nil, fmt.Errorf("must be an array of strings")
	}
	list, err := stringOrList(v)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 || slices.Contains(list, "") {
		return nil, fmt.Errorf("must hold non-empty strings")
	}
	return list, nil
}

// scopeTokens splits a link's "scope" strictly: single spaces between
// non-empty tokens of the characters RFC 6749 §3.3 allows.
func scopeTokens(text string) ([]string, error) {
	tokens := strings.Split(text, " ")
	for _, token := range tokens {
		if err := checkScopeToken(token); err != nil {
			return nil, err
		}
	}
	return tokens, nil
}

// checkScopeToken reports whether token is a valid scope-token:
// 1*( %x21 / %x23-5B / %x5D-7E ).
//
// https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
func checkScopeToken(token string) error {
	if token == "" {
		return fmt.Errorf("empty scope token")
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return fmt.Errorf("scope token %q has a character RFC 6749 does not allow", token)
		}
	}
	return nil
}

// numericDate reads a NumericDate (RFC 7519 §2). Fractions round down, or
// up when roundUp is set, so that rounding never widens a time window.
func numericDate(v any, roundUp bool) (time.Time, error) {
	var seconds float64
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return time.Time{}, fmt.Errorf("not a number")
		}
		seconds = f
	case float64:
		seconds = n
	case int64:
		seconds = float64(n)
	case int:
		seconds = float64(n)
	default:
		return time.Time{}, fmt.Errorf("not a number")
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > 253402300799 {
		return time.Time{}, fmt.Errorf("out of range")
	}
	if roundUp {
		seconds = math.Ceil(seconds)
	}
	return time.Unix(int64(seconds), 0), nil
}

// verified copies s into the exported result.
func (s *state) verified(c *Chain, root jwt.ClaimsSet) *Verified {
	v := &Verified{
		Chain:        c,
		Root:         root,
		Subject:      s.subject,
		Audience:     slices.Clone(s.audience),
		NotBefore:    s.notBefore,
		Expiry:       s.expiry,
		Caveats:      slices.Clone(s.caveats),
		Holder:       s.holder,
		Confirmation: maps.Clone(s.confirmation),
		signers:      slices.Clone(s.signers),
		rootActors:   s.rootActors,
	}
	if s.hasScope {
		v.Scope = slices.Clone(s.scope)
		if v.Scope == nil {
			v.Scope = []string{}
		}
	}
	for _, t := range c.tokens[1:] {
		v.Links = append(v.Links, maps.Clone(t.claims))
	}
	return v
}
