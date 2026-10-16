package jwtchain

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/picatz/jose/internal/strictjson"
	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/ni"
)

// Names this package defines.
const (
	// Type is the "typ" header of every link.
	Type = "chain+jwt"
	// HeaderParentHash ("prh") is the link header holding the ni URI of its
	// parent token. It is always listed in "crit".
	HeaderParentHash = "prh"
	// HeaderParentToken ("prt") is the link header that embeds the parent
	// token itself; see [Embed].
	HeaderParentToken = "prt"
	// ClaimCaveats ("cav") lists caveats: conditions, as strings, that a
	// verifier must accept for the chain to verify. See [Policy.Caveat].
	ClaimCaveats = "cav"
	// Separator joins the tokens of a chain, root first.
	Separator = "~"
)

// Limits a [Policy] and [Parse] apply unless told otherwise.
const (
	DefaultMaxLinks = 8
	DefaultMaxSize  = 64 << 10
)

var (
	// ErrFormat means the input is not a well-formed chain.
	ErrFormat = errors.New("jwtchain: malformed chain")
	// ErrVerification means a chain is well formed but does not verify.
	ErrVerification = errors.New("jwtchain: chain does not verify")
	// ErrBroadens means a link claims more than its parent allows. It also
	// matches [ErrVerification].
	ErrBroadens = fmt.Errorf("%w: a link broadens its parent", ErrVerification)
	// ErrCaveat means the verifier did not accept a caveat. It also matches
	// [ErrVerification].
	ErrCaveat = fmt.Errorf("%w: caveat not satisfied", ErrVerification)
	// ErrBearer means the chain binds no holder and [Policy.AllowBearer] is
	// not set. It also matches [ErrVerification].
	ErrBearer = fmt.Errorf("%w: bearer chain", ErrVerification)
)

// Chain is a parsed chain: a root token and the links derived from it, in
// order. Parsing checks structure and digests only; use a [Policy] to
// verify signatures, narrowing and time.
type Chain struct {
	tokens []*token // root first
}

// token is one compact JWS in a chain.
type token struct {
	raw       string
	signature *jws.Signature
	claims    jwt.ClaimsSet
	parent    *ni.URI // nil for the root
	embeds    bool    // carries its parent in "prt"
}

// Parse parses a chain in any of its forms: a bare root, tokens joined by
// [Separator], a link that embeds its ancestors, or a mix. It applies
// [DefaultMaxLinks] and [DefaultMaxSize].
func Parse(input string) (*Chain, error) {
	return parse(input, DefaultMaxLinks, DefaultMaxSize)
}

func parse(input string, maxLinks, maxSize int) (*Chain, error) {
	if len(input) == 0 || len(input) > maxSize {
		return nil, fmt.Errorf("%w: must be between 1 and %d bytes", ErrFormat, maxSize)
	}
	pending := strings.Split(input, Separator)
	if len(pending) > maxLinks+1 {
		return nil, fmt.Errorf("%w: more than %d links", ErrFormat, maxLinks)
	}
	current := pending[len(pending)-1]
	pending = pending[:len(pending)-1]

	// Walk from the leaf toward the root, taking each parent from the
	// link's own "prt" or else from the token before it.
	var reversed []*token
	for {
		if len(reversed) > maxLinks {
			return nil, fmt.Errorf("%w: more than %d links", ErrFormat, maxLinks)
		}
		t, err := parseToken(current)
		if err != nil {
			return nil, err
		}
		reversed = append(reversed, t)
		if t.parent == nil {
			break
		}
		var parent string
		switch {
		case t.embeds:
			parent = t.signature.Header[HeaderParentToken].(string)
			// A presenter may send an embedded parent again; it must be
			// the same token.
			if n := len(pending); n > 0 && pending[n-1] == parent {
				pending = pending[:n-1]
			}
		case len(pending) == 0:
			return nil, fmt.Errorf("%w: a link's parent is missing", ErrFormat)
		default:
			parent, pending = pending[len(pending)-1], pending[:len(pending)-1]
		}
		if !t.parent.Matches([]byte(parent)) {
			return nil, fmt.Errorf("%w: a link does not match its parent's digest", ErrFormat)
		}
		current = parent
	}
	if len(pending) > 0 {
		return nil, fmt.Errorf("%w: tokens precede the root", ErrFormat)
	}
	slices.Reverse(reversed)
	return &Chain{tokens: reversed}, nil
}

func parseToken(raw string) (*token, error) {
	if !canonical(raw) {
		return nil, fmt.Errorf("%w: a token is not in canonical unpadded base64url", ErrFormat)
	}
	signature, err := jws.ParseCritical(raw, HeaderParentHash)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	claims, err := decodeClaims(signature.Payload)
	if err != nil {
		return nil, err
	}
	t := &token{raw: raw, signature: signature, claims: claims}
	h := signature.Header
	typ, _ := h[header.Type].(string)
	value, isLink := h[HeaderParentHash]
	if !isLink {
		if h.Has(HeaderParentToken) || strings.EqualFold(typ, Type) {
			return nil, fmt.Errorf("%w: a %q token without %q", ErrFormat, Type, HeaderParentHash)
		}
		return t, nil
	}
	if !strings.EqualFold(typ, Type) {
		return nil, fmt.Errorf("%w: a link's %q must be %q", ErrFormat, header.Type, Type)
	}
	if !listsCritical(h, HeaderParentHash) {
		return nil, fmt.Errorf("%w: %q must be listed in %q", ErrFormat, HeaderParentHash, header.Critical)
	}
	uri, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("%w: %q must be a string", ErrFormat, HeaderParentHash)
	}
	parent, err := ni.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrFormat, HeaderParentHash, err)
	}
	if !slices.Contains([]crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}, parent.Hash) {
		return nil, fmt.Errorf("%w: %q must use sha-256, sha-384 or sha-512", ErrFormat, HeaderParentHash)
	}
	t.parent = &parent
	if embedded, ok := h[HeaderParentToken]; ok {
		if s, ok := embedded.(string); !ok || s == "" || strings.Contains(s, Separator) {
			return nil, fmt.Errorf("%w: %q must be one compact token", ErrFormat, HeaderParentToken)
		}
		t.embeds = true
	}
	return t, nil
}

// canonical reports whether every segment of a compact JWS is unpadded
// base64url that re-encodes to itself, so a token has one spelling. (An
// ECDSA signature still has two valid values; name tokens by "jti", not
// by their bytes.)
func canonical(raw string) bool {
	for _, segment := range strings.Split(raw, ".") {
		if segment == "" {
			continue
		}
		decoded, err := base64.Decode(segment)
		if err != nil {
			return false
		}
		if again, err := base64.Encode(decoded); err != nil || again != segment {
			return false
		}
	}
	return true
}

func listsCritical(h header.Parameters, name string) bool {
	crit, _ := h[header.Critical].([]any)
	return slices.Contains(crit, any(name))
}

// decodeClaims decodes a JWT claims set, refusing invalid UTF-8, duplicate
// names and trailing data, and keeping numbers as [json.Number].
func decodeClaims(payload []byte) (jwt.ClaimsSet, error) {
	if !utf8.Valid(payload) {
		return nil, fmt.Errorf("%w: claims are not valid UTF-8", ErrFormat)
	}
	if err := strictjson.CheckDuplicates(payload); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrFormat, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims jwt.ClaimsSet
	if err := decoder.Decode(&claims); err != nil || claims == nil {
		return nil, fmt.Errorf("%w: claims are not a JSON object", ErrFormat)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: trailing data after claims", ErrFormat)
	}
	return claims, nil
}

// String returns the chain in its shortest self-contained form: the tokens
// joined by [Separator], leaving out any parent its child embeds. A chain
// whose every link embeds its parent is a single token.
func (c *Chain) String() string {
	var parts []string
	for i, t := range c.tokens {
		if i+1 < len(c.tokens) && c.tokens[i+1].embeds {
			continue
		}
		parts = append(parts, t.raw)
	}
	return strings.Join(parts, Separator)
}

// Tokens returns every token in the chain, root first, each in its
// compact serialization.
func (c *Chain) Tokens() []string {
	tokens := make([]string, len(c.tokens))
	for i, t := range c.tokens {
		tokens[i] = t.raw
	}
	return tokens
}

// Root returns the root token.
func (c *Chain) Root() string { return c.tokens[0].raw }

// Leaf returns the last token. It is self-contained only when it embeds
// its ancestors; otherwise present [Chain.String].
func (c *Chain) Leaf() string { return c.tokens[len(c.tokens)-1].raw }

// Links returns how many links follow the root.
func (c *Chain) Links() int { return len(c.tokens) - 1 }

// Inspect reports what the chain would grant, checking each link's
// signature and narrowing against its parent but not the root, whose
// signature needs the issuer's key, nor time, audience or caveats. Use it
// to show or plan a chain, such as before [Derive]; never to authorize.
// Authorize with [Policy.Verify].
func (c *Chain) Inspect() (*Grant, error) {
	root := c.tokens[0].claims
	s, err := rootState(root)
	if err != nil {
		return nil, err
	}
	for _, link := range c.tokens[1:] {
		if err := s.apply(link, DefaultAlgorithms); err != nil {
			return nil, err
		}
	}
	return s.grant(c, root), nil
}
