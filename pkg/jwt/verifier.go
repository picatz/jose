package jwt

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/internal/strictjson"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jws"
)

// Defaults a zero [Verifier] uses.
const (
	// DefaultMaxSize bounds a token's length in bytes.
	DefaultMaxSize = 16 << 10
	// DefaultLeeway is the clock skew tolerated for "exp", "nbf" and "iat".
	DefaultLeeway = 30 * time.Second
	// MaxCandidateKeys bounds the signature checks spent on one token, so
	// a key source that returns many keys cannot be used to make a
	// verifier do unbounded work.
	MaxCandidateKeys = 8
)

// DefaultAlgorithms are the algorithms a zero [Verifier] accepts: every
// asymmetric JWS algorithm this module implements. HMAC algorithms must be
// listed in [Verifier.Algorithms] explicitly, and "none" is never accepted.
var DefaultAlgorithms = []jwa.Algorithm{
	jwa.ES256, jwa.ES384, jwa.ES512,
	jwa.EdDSA,
	jwa.PS256, jwa.PS384, jwa.PS512,
	jwa.RS256, jwa.RS384, jwa.RS512,
}

// Errors returned by [Verifier.Verify]. Each refusal also wraps
// [ErrInvalidToken], so callers that only need to know a token was refused
// can test for that; [ErrKeysUnavailable] does not, since it is not a
// refusal.
var (
	// ErrFormat reports a token that is not a well-formed compact JWS JWT,
	// or whose type, algorithm or headers are not accepted.
	ErrFormat = errors.New("jwt: malformed token")
	// ErrSignature reports a token that no candidate key verifies.
	ErrSignature = errors.New("jwt: signature verification failed")
	// ErrKeysUnavailable reports that the key source failed. It says
	// nothing about the token and does not wrap [ErrInvalidToken], so a
	// server can answer it with a retryable error instead of a 401.
	ErrKeysUnavailable = errors.New("jwt: verification keys unavailable")
	// ErrExpired reports a token past its "exp".
	ErrExpired = errors.New("jwt: token expired")
	// ErrNotYetValid reports a token before its "nbf", or issued in the
	// future.
	ErrNotYetValid = errors.New("jwt: token not yet valid")
	// ErrClaims reports a registered claim that is missing, malformed, or
	// names another issuer or audience.
	ErrClaims = errors.New("jwt: claims not accepted")
)

// Key is a candidate verification key.
type Key struct {
	// ID is the key's "kid". When both the key and the token name one,
	// they must match.
	ID string
	// Algorithm, when set, is the only algorithm this key verifies.
	Algorithm jwa.Algorithm
	// Public is the verification key: a *ecdsa.PublicKey,
	// ed25519.PublicKey or *rsa.PublicKey, or a []byte HMAC secret.
	Public any
}

// KeySource supplies the candidate keys for a token. kid is the token's
// "kid" header, or empty when it has none. A source may return keys that
// do not match; the [Verifier] filters them.
//
// kid comes from the token, so it is attacker-controlled until the
// signature verifies: never use it unescaped in a path, query or URL.
//
// A source that fetches keys over the network belongs to the caller: this
// package never fetches keys, and never follows "jku" or "x5u".
type KeySource interface {
	Keys(ctx context.Context, kid string) ([]Key, error)
}

// Keys is a fixed [KeySource].
type Keys []Key

// Keys returns the keys whose ID matches kid, or every key when kid is
// empty. A key without an ID matches any kid.
func (k Keys) Keys(_ context.Context, kid string) ([]Key, error) {
	var out []Key
	for _, key := range k {
		if kid == "" || key.ID == "" || key.ID == kid {
			out = append(out, key)
		}
	}
	return out, nil
}

// KeysFromSet returns the signature verification keys in set: those whose
// "use" is "sig" or absent and whose "key_ops", if present, include
// "verify". Each key's "kid" and "alg" carry over. A set that holds a
// private or symmetric key is refused, since a published set never should.
//
// https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2
func KeysFromSet(set *jwk.Set) (Keys, error) {
	if set == nil {
		return nil, errors.New("jwt: nil key set")
	}
	var out Keys
	for i, v := range set.Keys {
		if jwk.IsPrivate(v) || v[jwk.KeyType] == "oct" {
			return nil, fmt.Errorf("jwt: key set entry %d is a private or symmetric key", i)
		}
		if use, ok := v[jwk.PublicKeyUse]; ok && use != "sig" {
			continue
		}
		if ops, ok := v[jwk.KeyOperations]; ok {
			list, _ := ops.([]any)
			if !slices.Contains(list, any("verify")) {
				continue
			}
		}
		public, err := jwk.PublicKey(v)
		if err != nil {
			return nil, fmt.Errorf("jwt: key set entry %d: %w", i, err)
		}
		kid, _ := v[jwk.KeyID].(string)
		alg, _ := v[jwk.Algorithm].(string)
		out = append(out, Key{ID: kid, Algorithm: jwa.Algorithm(alg), Public: public})
	}
	return out, nil
}

// Verifier checks JWTs: their JOSE layer (size, encoding, type,
// algorithm, critical headers and signature) and their registered claims
// ("iss", "aud", "exp", "nbf", "iat"). Keys is required, and so are
// Issuer and Audience unless AnyIssuer and AnyAudience are set; every
// other field has a safe default. A Verifier is safe for concurrent use
// once configured.
//
// It follows the JWT Best Current Practices: algorithms come from an
// allowlist and never from the token alone, "typ" is checked (explicit
// typing), and the issuer and audience are always checked unless the
// caller opts out by name.
//
// https://www.rfc-editor.org/rfc/rfc8725.html#section-3
type Verifier struct {
	// Keys supplies the verification keys. Use [Keys] for fixed keys and
	// [KeysFromSet] for a JWK Set.
	Keys KeySource

	// Algorithms lists the accepted "alg" values; nil means
	// [DefaultAlgorithms]. "none" is never accepted.
	Algorithms []jwa.Algorithm

	// Types lists the accepted "typ" header values, such as "at+jwt"
	// (RFC 9068) or "JWT". They compare without regard to case and with
	// an optional "application/" prefix. The empty string accepts a token
	// with no "typ". Nil means "JWT" or no "typ"; set it to the type your
	// tokens carry, so a token minted for another purpose is refused.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9
	Types []string

	// Issuer is the required "iss". AnyIssuer skips the check.
	Issuer    string
	AnyIssuer bool

	// Audience is this verifier's identifier; the token's "aud" must name
	// it. AnyAudience skips the check.
	//
	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	Audience    string
	AnyAudience bool

	// AllowNoExpiry accepts a token without "exp". By default one is
	// required, because a token that never expires cannot be contained
	// once it leaks.
	AllowNoExpiry bool

	// Critical lists the "crit" header parameters the caller understands
	// and checks itself. A token whose "crit" names anything else is
	// refused (RFC 7515 §4.1.11).
	Critical []string

	// Leeway is the clock skew tolerated for "exp", "nbf" and "iat"; zero
	// means [DefaultLeeway]. For effectively none, use [time.Nanosecond].
	Leeway time.Duration
	// MaxSize bounds the token length in bytes; zero means
	// [DefaultMaxSize].
	MaxSize int
	// Now is the clock; nil means [time.Now].
	Now func() time.Time
}

// Verify checks token and returns it decoded. A refused token gives an
// error wrapping [ErrInvalidToken] and one of [ErrFormat], [ErrSignature],
// [ErrExpired], [ErrNotYetValid] or [ErrClaims]; a failed key source gives
// [ErrKeysUnavailable].
//
// The returned token's "exp", "nbf" and "iat" are int64 seconds, an "aud"
// array is a []string, and other numbers are float64, as [Parse] gives
// them.
func (v *Verifier) Verify(ctx context.Context, token string) (*Token, error) {
	if err := v.check(); err != nil {
		return nil, err
	}
	if len(token) > cmp.Or(v.MaxSize, DefaultMaxSize) {
		return nil, refuse(ErrFormat, "token exceeds %d bytes", cmp.Or(v.MaxSize, DefaultMaxSize))
	}
	if strings.Count(token, ".") != 2 || !canonical(token) {
		return nil, refuse(ErrFormat, "not a compact JWS in canonical base64url")
	}
	signature, err := jws.ParseCritical(token, v.Critical...)
	if err != nil {
		return nil, refuse(ErrFormat, "%v", err)
	}
	// A JWT payload is always base64url-encoded (RFC 7519 §7.2), so "b64"
	// is refused here although the JWS layer understands it, and so is
	// any "crit" entry the caller did not list.
	if _, ok := signature.Header["b64"]; ok && !slices.Contains(v.Critical, "b64") {
		return nil, refuse(ErrFormat, "the b64 header parameter is not allowed in a JWT")
	}
	if names, ok := signature.Header[header.Critical].([]any); ok {
		for _, name := range names {
			if s, _ := name.(string); !slices.Contains(v.Critical, s) {
				return nil, refuse(ErrFormat, "critical header %q is not understood", s)
			}
		}
	}
	alg, err := signature.Header.Algorithm()
	if err != nil || alg == jwa.None || !slices.Contains(v.algorithms(), alg) {
		return nil, refuse(ErrFormat, "algorithm %q is not accepted", alg)
	}
	typ, present := signature.Header[header.Type]
	typeName, _ := typ.(string)
	if present && typeName == "" {
		return nil, refuse(ErrFormat, "typ is not a non-empty string")
	}
	if !typeAccepted(typeName, v.types()) {
		return nil, refuse(ErrFormat, "token type %q is not accepted", typeName)
	}
	var kid string
	if value, ok := signature.Header[header.KeyID]; ok {
		if kid, ok = value.(string); !ok || kid == "" {
			return nil, refuse(ErrFormat, "kid is not a non-empty string")
		}
	}

	// Decode and bound the claims before spending any signature checks.
	claims, err := decodeVerifiedClaims(signature.Payload)
	if err != nil {
		return nil, err
	}
	if err := v.checkTimes(claims, true); err != nil {
		return nil, err
	}

	keys, err := v.Keys.Keys(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
	}
	verified, tried := false, 0
	for _, key := range keys {
		if key.Public == nil || key.Algorithm != "" && key.Algorithm != alg || kid != "" && key.ID != "" && key.ID != kid {
			continue
		}
		if tried++; tried > MaxCandidateKeys {
			break
		}
		if signature.Verify(key.Public) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, ErrSignature)
	}

	if err := v.checkClaims(claims); err != nil {
		return nil, err
	}
	// Check the clock again: the key source may have taken a while.
	if err := v.checkTimes(claims, false); err != nil {
		return nil, err
	}
	result := &Token{Header: signature.Header, Claims: tokenClaims(claims), Signature: signature.Signature, raw: token}
	return result, nil
}

func (v *Verifier) check() error {
	switch {
	case v == nil:
		return errors.New("jwt: nil Verifier")
	case v.Keys == nil:
		return errors.New("jwt: Verifier.Keys is required")
	case v.Issuer == "" && !v.AnyIssuer:
		return errors.New("jwt: Verifier.Issuer is required unless AnyIssuer is set")
	case v.Audience == "" && !v.AnyAudience:
		return errors.New("jwt: Verifier.Audience is required unless AnyAudience is set")
	}
	return nil
}

func (v *Verifier) algorithms() []jwa.Algorithm {
	if v.Algorithms == nil {
		return DefaultAlgorithms
	}
	return v.Algorithms
}

func (v *Verifier) types() []string {
	if v.Types == nil {
		return []string{"", string(Type)}
	}
	return v.Types
}

func (v *Verifier) now() time.Time {
	if v.Now == nil {
		return time.Now()
	}
	return v.Now()
}

// checkTimes checks "exp", "nbf" and "iat". When early is set it runs
// before the signature check, so it reports only what is cheap and
// certain; the full check repeats after.
func (v *Verifier) checkTimes(claims map[string]any, early bool) error {
	now, leeway := v.now(), cmp.Or(v.Leeway, DefaultLeeway)
	expiry, hasExpiry, err := dateClaim(claims, ExpirationTime)
	if err != nil {
		return err
	}
	if !hasExpiry && !v.AllowNoExpiry {
		return refuse(ErrClaims, "missing %q claim", ExpirationTime)
	}
	if hasExpiry && !now.Before(expiry.Add(leeway)) {
		return fmt.Errorf("%w: %w: expired at %s", ErrInvalidToken, ErrExpired, expiry.UTC().Format(time.RFC3339))
	}
	if early {
		return nil
	}
	if notBefore, ok, err := dateClaim(claims, NotBefore); err != nil {
		return err
	} else if ok && now.Add(leeway).Before(notBefore) {
		return fmt.Errorf("%w: %w: valid from %s", ErrInvalidToken, ErrNotYetValid, notBefore.UTC().Format(time.RFC3339))
	}
	if issuedAt, ok, err := dateClaim(claims, IssuedAt); err != nil {
		return err
	} else if ok && now.Add(leeway).Before(issuedAt) {
		return fmt.Errorf("%w: %w: issued in the future at %s", ErrInvalidToken, ErrNotYetValid, issuedAt.UTC().Format(time.RFC3339))
	}
	return nil
}

func (v *Verifier) checkClaims(claims map[string]any) error {
	if issuer, ok := claims[Issuer]; ok {
		if _, ok := issuer.(string); !ok {
			return refuse(ErrClaims, "%q claim is not a string", Issuer)
		}
	}
	if !v.AnyIssuer {
		if issuer, _ := claims[Issuer].(string); issuer != v.Issuer {
			return refuse(ErrClaims, "%q claim does not name the expected issuer", Issuer)
		}
	}
	audiences, err := audienceClaim(claims)
	if err != nil {
		return err
	}
	if !v.AnyAudience && !slices.Contains(audiences, v.Audience) {
		return refuse(ErrClaims, "%q claim does not name this audience", Audience)
	}
	if subject, ok := claims[Subject]; ok {
		if _, ok := subject.(string); !ok {
			return refuse(ErrClaims, "%q claim is not a string", Subject)
		}
	}
	return nil
}

func refuse(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrInvalidToken, kind, fmt.Sprintf(format, args...))
}

// decodeVerifiedClaims decodes a JWT claims set strictly: valid UTF-8, a
// JSON object, no duplicate names (RFC 7519 §4), no trailing data.
func decodeVerifiedClaims(payload []byte) (map[string]any, error) {
	if !utf8.Valid(payload) {
		return nil, refuse(ErrFormat, "claims are not valid UTF-8")
	}
	if err := strictjson.CheckDuplicates(payload); err != nil {
		return nil, refuse(ErrFormat, "claims: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims map[string]any
	if err := decoder.Decode(&claims); err != nil || claims == nil {
		return nil, refuse(ErrFormat, "claims are not a JSON object")
	}
	if decoder.More() {
		return nil, refuse(ErrFormat, "trailing data after claims")
	}
	return claims, nil
}

// dateClaim returns a NumericDate claim (RFC 7519 §2), refusing values
// that are not finite, non-negative numbers before year 10000.
func dateClaim(claims map[string]any, name string) (time.Time, bool, error) {
	value, ok := claims[name]
	if !ok {
		return time.Time{}, false, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return time.Time{}, false, refuse(ErrClaims, "%q claim is not a number", name)
	}
	seconds, err := number.Float64()
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > 253402300799 {
		return time.Time{}, false, refuse(ErrClaims, "%q claim is out of range", name)
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*1e9)), true, nil
}

// audienceClaim returns "aud" as a list (RFC 7519 §4.1.3).
func audienceClaim(claims map[string]any) ([]string, error) {
	switch aud := claims[Audience].(type) {
	case nil:
		if _, present := claims[Audience]; present {
			return nil, refuse(ErrClaims, "%q claim is null", Audience)
		}
		return nil, nil
	case string:
		return []string{aud}, nil
	case []any:
		list := make([]string, 0, len(aud))
		for _, item := range aud {
			s, ok := item.(string)
			if !ok {
				return nil, refuse(ErrClaims, "%q claim holds a non-string", Audience)
			}
			list = append(list, s)
		}
		return list, nil
	default:
		return nil, refuse(ErrClaims, "%q claim is neither a string nor an array", Audience)
	}
}

// tokenClaims converts strictly decoded claims to the shape [Parse]
// gives: NumericDate claims as int64 seconds, an "aud" array as []string,
// and other numbers as float64. It runs only on verified claims, whose
// dates and audience have been checked.
func tokenClaims(claims map[string]any) ClaimsSet {
	var convert func(any) any
	convert = func(value any) any {
		switch v := value.(type) {
		case json.Number:
			f, _ := v.Float64()
			return f
		case map[string]any:
			for name, item := range v {
				v[name] = convert(item)
			}
		case []any:
			for i, item := range v {
				v[i] = convert(item)
			}
		}
		return value
	}
	out := make(ClaimsSet, len(claims))
	for name, value := range claims {
		out[name] = convert(value)
	}
	if list, ok := out[Audience].([]any); ok {
		audiences := make([]string, 0, len(list))
		for _, item := range list {
			s, _ := item.(string)
			audiences = append(audiences, s)
		}
		out[Audience] = audiences
	}
	for _, name := range []string{ExpirationTime, NotBefore, IssuedAt} {
		if f, ok := out[name].(float64); ok {
			out[name] = int64(f)
		}
	}
	return out
}

func typeAccepted(typ string, accepted []string) bool {
	normalize := func(s string) string {
		s = strings.ToLower(s)
		return strings.TrimPrefix(s, "application/")
	}
	for _, a := range accepted {
		if normalize(a) == normalize(typ) {
			return true
		}
	}
	return false
}

// canonical reports whether every segment of token is canonical unpadded
// base64url (RFC 7515 §2), so one signed token has exactly one string form
// and caches keyed by the raw token cannot be bypassed.
func canonical(token string) bool {
	for segment := range strings.SplitSeq(token, ".") {
		if segment == "" {
			return false
		}
		decoded, err := base64url.Decode(segment)
		if err != nil {
			return false
		}
		if base64url.Encode(decoded) != segment {
			return false
		}
	}
	return true
}
