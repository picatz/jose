package dpop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/picatz/jose/internal/strictjson"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
)

// Defaults for [Verifier].
const (
	DefaultMaxAge  = 5 * time.Minute
	DefaultLeeway  = 30 * time.Second
	DefaultMaxSize = 8 << 10
)

// DefaultAlgorithms are the algorithms a zero [Verifier] accepts: every
// asymmetric JWS algorithm this module implements. RFC 9449 §4.3 forbids
// "none" and symmetric algorithms, which are never accepted.
var DefaultAlgorithms = []jwa.Algorithm{
	jwa.ES256, jwa.ES384, jwa.ES512,
	jwa.EdDSA,
	jwa.PS256, jwa.PS384, jwa.PS512,
	jwa.RS256, jwa.RS384, jwa.RS512,
}

// ReplayCache records proof identifiers so each is accepted once.
//
// https://www.rfc-editor.org/rfc/rfc9449.html#section-11.1
type ReplayCache interface {
	// Seen records jti until expires and reports whether it was already
	// recorded. It must be atomic: of two concurrent calls with the same
	// jti, exactly one returns false.
	Seen(ctx context.Context, jti string, expires time.Time) (bool, error)
}

// Verifier checks DPoP proofs. The zero value is ready to use with the
// defaults described on each field; it does not detect replays until
// Replay is set.
type Verifier struct {
	// Algorithms lists the accepted JWS algorithms; nil means
	// [DefaultAlgorithms]. Symmetric algorithms and "none" are always
	// rejected.
	Algorithms []jwa.Algorithm

	// MaxAge is how far in the past "iat" may be; zero means
	// [DefaultMaxAge].
	MaxAge time.Duration

	// Leeway is how far in the future "iat" may be, to absorb clock skew;
	// zero means [DefaultLeeway].
	Leeway time.Duration

	// MaxSize bounds the proof length in bytes; zero means
	// [DefaultMaxSize].
	MaxSize int

	// Now returns the current time; nil means [time.Now].
	Now func() time.Time

	// Replay, when set, rejects a "jti" seen within MaxAge + Leeway.
	// Without it, a captured proof can be replayed until it ages out.
	Replay ReplayCache

	// CheckNonce, when set and [Request.Nonce] is empty, validates the
	// proof's "nonce" (which may be empty). Return an error wrapping
	// [ErrUseNonce] to ask the client to retry with a fresh nonce. Use it
	// for servers that accept several recent nonces.
	CheckNonce func(ctx context.Context, nonce string) error
}

// Request describes the HTTP request a proof arrived with.
type Request struct {
	// Method is the HTTP method, such as "POST".
	Method string
	// URI is the request's target URI as the server sees it, including
	// scheme and host. Its query and fragment are ignored.
	URI string
	// AccessToken, when set, requires a matching "ath" claim. Set it to the
	// DPoP-bound access token from the Authorization header.
	AccessToken string
	// Thumbprint, when set, requires the proof key to have this JWK
	// Thumbprint: the "jkt" the access token or authorization code is
	// bound to. Without it, the proof shows possession of some key, not of
	// the bound one.
	Thumbprint string
	// Nonce, when set, requires exactly this "nonce" claim.
	Nonce string
}

// Proof is a verified DPoP proof.
type Proof struct {
	// Algorithm is the JWS algorithm the proof was signed with.
	Algorithm jwa.Algorithm
	// PublicKey is the proof key from the "jwk" header.
	PublicKey crypto.PublicKey
	// JWK is the public JWK from the "jwk" header.
	JWK jwk.Value
	// Thumbprint is the proof key's base64url SHA-256 JWK Thumbprint.
	Thumbprint string

	JTI             string
	Method          string
	URI             string
	IssuedAt        time.Time
	AccessTokenHash string
	Nonce           string

	// Header and Claims hold every member, including extensions.
	Header header.Parameters
	Claims map[string]any
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidProof, fmt.Sprintf(format, args...))
}

// Verify checks proof against req and returns the verified proof. It
// performs every check in RFC 9449 §4.3:
//
//  1. a single, well-formed JWT within MaxSize;
//  2. "typ" is "dpop+jwt", "alg" is an accepted asymmetric algorithm and
//     "jwk" is a public key with no private members;
//  3. the signature verifies with that key;
//  4. "jti", "htm", "htu" and "iat" are present; "htm" equals req.Method;
//     "htu" equals req.URI after [TargetURI] normalization;
//  5. "iat" is within MaxAge in the past and Leeway in the future;
//  6. "nonce" matches req.Nonce or passes CheckNonce;
//  7. "ath" matches req.AccessToken, and the key matches req.Thumbprint;
//  8. "jti" has not been seen before, when Replay is set.
//
// Failures wrap [ErrInvalidProof]; a missing or stale nonce wraps
// [ErrUseNonce], a replay wraps [ErrReplay] and a key mismatch wraps
// [ErrBinding]. The replay check runs last, so a proof that fails any other
// check does not consume its jti.
//
// https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3
func (v *Verifier) Verify(ctx context.Context, proof string, req Request) (*Proof, error) {
	maxSize := v.MaxSize
	if maxSize == 0 {
		maxSize = DefaultMaxSize
	}
	if len(proof) == 0 || len(proof) > maxSize {
		return nil, invalidf("proof must be between 1 and %d bytes", maxSize)
	}

	signed, err := jws.Parse(proof)
	if err != nil {
		return nil, invalidf("not a well-formed JWS: %v", err)
	}
	typ, err := header.Get[string](signed.Header, header.Type)
	if err != nil || !strings.EqualFold(typ, Type) {
		return nil, invalidf("%q must be %q", header.Type, Type)
	}
	alg, err := signed.Header.Algorithm()
	if err != nil {
		return nil, invalidf("missing %q", header.Algorithm)
	}
	allowed := v.Algorithms
	if allowed == nil {
		allowed = DefaultAlgorithms
	}
	if !jwa.IsAsymmetricSignature(alg) || !slices.Contains(allowed, alg) {
		return nil, invalidf("algorithm %q is not accepted", alg)
	}
	rawJWK, ok := signed.Header[header.JSONWebKey].(map[string]any)
	if !ok {
		return nil, invalidf("missing or invalid %q header", header.JSONWebKey)
	}
	value := jwk.Value(rawJWK)
	if jwk.IsPrivate(value) {
		return nil, invalidf("%q header contains private key material", header.JSONWebKey)
	}
	publicKey, err := jwk.PublicKey(value)
	if err != nil {
		return nil, invalidf("%q header: %v", header.JSONWebKey, err)
	}
	if err := signed.Verify(publicKey); err != nil {
		return nil, invalidf("signature: %v", err)
	}

	claims, err := decodeClaims(signed.Payload)
	if err != nil {
		return nil, err
	}
	p := &Proof{
		Algorithm: alg,
		PublicKey: publicKey,
		JWK:       value,
		Header:    signed.Header,
		Claims:    claims,
	}
	if p.JTI, err = stringClaim(claims, jwt.JWTID, true); err != nil {
		return nil, err
	}
	if p.Method, err = stringClaim(claims, ClaimHTTPMethod, true); err != nil {
		return nil, err
	}
	if p.URI, err = stringClaim(claims, ClaimHTTPURI, true); err != nil {
		return nil, err
	}
	if p.AccessTokenHash, err = stringClaim(claims, ClaimAccessTokenHash, false); err != nil {
		return nil, err
	}
	if p.Nonce, err = stringClaim(claims, ClaimNonce, false); err != nil {
		return nil, err
	}
	iat, ok := claims[jwt.IssuedAt].(json.Number)
	if !ok {
		return nil, invalidf("missing or non-numeric %q", jwt.IssuedAt)
	}
	seconds, err := iat.Float64()
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > 253402300799 {
		return nil, invalidf("invalid %q", jwt.IssuedAt)
	}
	p.IssuedAt = time.Unix(int64(seconds), 0)

	if p.Method != req.Method {
		return nil, invalidf("%q is %q, want %q", ClaimHTTPMethod, p.Method, req.Method)
	}
	want, err := TargetURI(req.URI)
	if err != nil {
		return nil, fmt.Errorf("dpop: request URI: %w", err)
	}
	got, err := TargetURI(p.URI)
	if err != nil || got != want {
		return nil, invalidf("%q does not match the request URI", ClaimHTTPURI)
	}

	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	maxAge, leeway := v.MaxAge, v.Leeway
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	if leeway == 0 {
		leeway = DefaultLeeway
	}
	current := now()
	if p.IssuedAt.Before(current.Add(-maxAge)) {
		return nil, invalidf("issued %s ago, beyond the %s limit", current.Sub(p.IssuedAt).Truncate(time.Second), maxAge)
	}
	if p.IssuedAt.After(current.Add(leeway)) {
		return nil, invalidf("issued in the future")
	}

	switch {
	case req.Nonce != "":
		if subtle.ConstantTimeCompare([]byte(p.Nonce), []byte(req.Nonce)) != 1 {
			return nil, ErrUseNonce
		}
	case v.CheckNonce != nil:
		if err := v.CheckNonce(ctx, p.Nonce); err != nil {
			return nil, err
		}
	}

	if req.AccessToken != "" {
		if p.AccessTokenHash == "" {
			return nil, invalidf("missing %q for the presented access token", ClaimAccessTokenHash)
		}
		if subtle.ConstantTimeCompare([]byte(p.AccessTokenHash), []byte(AccessTokenHash(req.AccessToken))) != 1 {
			return nil, invalidf("%q does not match the access token", ClaimAccessTokenHash)
		}
	}

	// Canonicalize before hashing so the thumbprint does not depend on how
	// the client spelled its JWK.
	if p.Thumbprint, err = thumbprint.FromPublicKey(publicKey); err != nil {
		return nil, invalidf("thumbprint: %v", err)
	}
	if req.Thumbprint != "" && subtle.ConstantTimeCompare([]byte(p.Thumbprint), []byte(req.Thumbprint)) != 1 {
		return nil, ErrBinding
	}

	if v.Replay != nil {
		seen, err := v.Replay.Seen(ctx, p.JTI, p.IssuedAt.Add(maxAge+leeway))
		if err != nil {
			return nil, fmt.Errorf("dpop: replay cache: %w", err)
		}
		if seen {
			return nil, ErrReplay
		}
	}
	return p, nil
}

func decodeClaims(payload []byte) (map[string]any, error) {
	if !utf8.Valid(payload) {
		return nil, invalidf("claims are not valid UTF-8")
	}
	if err := strictjson.CheckDuplicates(payload); err != nil {
		return nil, invalidf("claims: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims map[string]any
	if err := decoder.Decode(&claims); err != nil || claims == nil {
		return nil, invalidf("claims are not a JSON object")
	}
	if decoder.More() {
		return nil, invalidf("trailing data after claims")
	}
	return claims, nil
}

func stringClaim(claims map[string]any, name string, required bool) (string, error) {
	raw, ok := claims[name]
	if !ok {
		if required {
			return "", invalidf("missing %q", name)
		}
		return "", nil
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", invalidf("%q must be a non-empty string", name)
	}
	return s, nil
}
