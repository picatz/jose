package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/internal/strictjson"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
)

// ErrInvalidToken reports a token that cannot be decoded, or that a
// [Verifier] refuses; the Verifier's more specific errors wrap it.
var ErrInvalidToken = errors.New("jwt: invalid token")

// Type "JWT" is the media type used by JSON Web Token (JWT).
//
// # Example
//
//	header := header.Parameters{
//		header.Type:      jwt.Type,
//		header.Algorithm: jwa.HS256,
//	}
//
// https://www.rfc-editor.org/rfc/rfc7515.html#section-3.3
const Type = "JWT"

// Token is a decoded JSON Web Token, a string representing a
// set of claims as a JSON object that is encoded in a JWS or
// JWE, enabling the claims to be digitally signed or MACed
// and/or encrypted.
//
// At this time, only JWS JWTs are supported. In other words,
// these tokens are only signed, not encrypted.
//
// JWTs contain three parts, separated by dots (".") which are:
//
//  1. Header
//  2. Claims (Payload)
//  3. Signature
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-1
type Token struct {
	// Header is the set of parameters that are used to describe
	// the cryptographic operations applied to the JWT claims set.
	Header header.Parameters

	// Claims is the set of claims that are asserted by the JWT.
	//
	// This is sometimes referred to as the "payload".
	Claims ClaimsSet

	// Signature is the cryptographic signature or MAC value
	// that is used to validate the JWT.
	Signature []byte

	// raw is the (original) string representation of the JWT.
	raw string
}

// New signs claims under params with key and returns the token.
//
// params must name the signing algorithm; New adds "typ": "JWT" when it is
// absent and refuses any other "typ". It refuses alg "none": an unsecured JWT
// (RFC 7519 §6) is never minted. claims must not be empty. Registered claims
// are checked for their RFC 7519 §4.1 types: "exp", "nbf" and "iat" are
// int64 or time.Time (stored as Unix seconds), "iss" and "sub" and "jti" are
// strings (or [fmt.Stringer]s), and "aud" is a string or []string. An empty
// "iss" is refused.
//
// key is whatever [jws.New] accepts: a []byte or string secret for HS*, an
// *rsa.PrivateKey, *ecdsa.PrivateKey or ed25519.PrivateKey, or any
// [crypto.Signer], such as a hardware-backed or KMS key. The "alg" header must
// suit the key; [jwa.ForKey] picks the conventional algorithm for a key.
//
// New does not modify params or claims: the token holds copies. The copies
// are shallow, so nested maps and slices are shared with the caller; the
// signed serialization ([Token.String]) does not change if they are.
func New(params header.Parameters, claims ClaimsSet, key any) (*Token, error) {
	// Given params set cannot be empty.
	if len(params) == 0 {
		return nil, fmt.Errorf("jwt: cannot create token with empty header parameters")
	}
	if key == nil {
		return nil, fmt.Errorf("jwt: cannot create token with a nil key")
	}

	// An unsecured JWT (RFC 7519 §6) is never minted: anyone could forge one.
	if alg, _ := params.Algorithm(); alg == jwa.None {
		return nil, fmt.Errorf("jwt: cannot create an unsecured token with alg %q", jwa.None)
	}

	// Given claims set cannot be empty.
	if len(claims) == 0 {
		return nil, fmt.Errorf("jwt: cannot create token with empty claims set")
	}

	params = maps.Clone(params)
	claims = maps.Clone(claims)

	// Verify or otherwise handle registered claim types nicely.
	for name, value := range claims {
		switch name {
		case ExpirationTime, NotBefore, IssuedAt:
			switch v := value.(type) {
			case int64:
			case time.Time:
				claims[name] = v.Unix()
			default:
				return nil, fmt.Errorf("jwt: cannot use type %T with %q claim", v, name)
			}
		case Issuer, Subject, ID:
			switch v := value.(type) {
			case string:
				if name == Issuer && v == "" {
					return nil, fmt.Errorf("jwt: issuer claim cannot be empty string")
				}
			case fmt.Stringer:
				s := v.String()
				if name == Issuer && s == "" {
					return nil, fmt.Errorf("jwt: issuer claim cannot be empty string")
				}
				claims[name] = s
			default:
				return nil, fmt.Errorf("jwt: cannot use type %T with %q claim", v, name)
			}
		case Audience:
			switch v := value.(type) {
			case string:
				// Empty-audience checking is left to the verifier.
			case fmt.Stringer:
				claims[name] = v.String()
			case []string:
				for i, aud := range v {
					if aud == "" {
						return nil, fmt.Errorf("jwt: audience claim array element %d cannot be empty string", i)
					}
				}
			default:
				return nil, fmt.Errorf("jwt: cannot use type %T with %q claim", v, name)
			}
		}
	}

	// Ensure the "typ" header parameter is "JWT".
	if !params.Has(header.Type) {
		params[header.Type] = Type
	} else if existing, err := params.Get(header.Type); err == nil && existing != Type {
		return nil, fmt.Errorf("jwt: header type %v is not supported", existing)
	}

	token := &Token{Header: params, Claims: claims}
	if err := token.sign(key); err != nil {
		return nil, fmt.Errorf("jwt: failed to sign token: %w", err)
	}
	return token, nil
}

const dot = "."

// computeString computes the string representation of the token,
// which is used for signing and verifying the token.
func (t *Token) computeString() (string, error) {
	b := strings.Builder{}

	// Marshal header directly to avoid newlines (consistent with signingInput)
	headerBytes, err := json.Marshal(t.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	header := base64url.Encode(headerBytes)
	b.WriteString(header)
	b.WriteString(dot)

	// Marshal claims directly to avoid newlines (consistent with signingInput)
	claimsBytes, err := json.Marshal(t.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	claims := base64url.Encode(claimsBytes)
	b.WriteString(claims)

	b.WriteString(dot)
	b.WriteString(base64url.Encode(t.Signature))

	return b.String(), nil
}

// String returns the compact serialization of the token:
// base64url(header).base64url(claims).base64url(signature).
//
// It is the serialization computed when the token was signed by [New] or
// decoded by [Parse] or a [Verifier]; later changes to Header, Claims or
// Signature are not reflected. A token that was never signed or decoded,
// such as the zero Token or one built by hand, returns "".
func (t *Token) String() string {
	if t == nil {
		return ""
	}
	return t.raw
}

// Parse decodes a compact JWT without verifying it.
//
// # Warning
//
// Parse checks the token's structure only: it verifies neither the signature
// nor any claim, so nothing in the returned token is trustworthy, and it
// accepts alg "none". Use a [Verifier] to verify a token. Errors wrap
// [ErrInvalidToken] and [ErrFormat].
func Parse(token string) (*Token, error) {
	return parseString(token)
}

// sign signs the token's current Header and Claims with key through the
// shared JWS implementation, and caches the compact serialization.
func (t *Token) sign(key any) error {
	typ, err := t.Header.Type()
	if err != nil {
		return fmt.Errorf("invalid JWT header type: %w", err)
	}
	if typ != Type {
		return fmt.Errorf("invalid JWT header type: %q", typ)
	}
	claimsBytes, err := json.Marshal(t.Claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}
	signed := &jws.Signature{Header: jws.Header(t.Header), Payload: claimsBytes}
	sig, err := signed.Sign(key)
	if err != nil {
		return err
	}
	t.Signature = sig
	t.raw, err = t.computeString()
	if err != nil {
		return fmt.Errorf("failed to compute token string: %w", err)
	}
	return nil
}

// parseString decodes a JWT string without verifying it.
func parseString(input string) (*Token, error) {
	// First, we split our input into three parts, separated by dots.
	// This also validates the JWT structure per RFC 7519 Section 7.2
	parts, err := splitToken(input)
	if err != nil {
		return nil, err
	}

	// Next, we decode the header base64 content.
	b, err := base64url.Decode(parts[0])
	if err != nil {
		return nil, malformed("failed to decode JOSE header base64: %w", err)
	}

	// RFC 7519 Section 7.2 Step 4: Verify UTF-8 encoded completely valid JSON
	if len(b) == 0 {
		return nil, malformed("failed to decode JOSE header JSON: header cannot be empty")
	}
	if !utf8.Valid(b) {
		return nil, malformed("header is not valid UTF-8")
	}

	// Decode the header JSON, refusing duplicate names (RFC 7515 §4).
	if err := strictjson.CheckDuplicates(b); err != nil {
		return nil, malformed("failed to decode JOSE header JSON: %w", err)
	}
	h := header.Parameters{}
	err = json.Unmarshal(b, &h)
	if err != nil {
		return nil, malformed("failed to decode JOSE header JSON: %w", err)
	}

	// "alg" must be a JSON string; it is never coerced.
	if v, ok := h[header.Algorithm]; ok {
		alg, isString := v.(string)
		if !isString {
			return nil, malformed("%q header is %T, not a string", header.Algorithm, v)
		}
		h[header.Algorithm] = jwa.Algorithm(alg)
	}

	// Next, we decode the claims base64 content.
	b, err = base64url.Decode(parts[1])
	if err != nil {
		return nil, malformed("failed to decode claims base64: %w", err)
	}

	// RFC 7519 Section 7.2 Step 10: Verify UTF-8 encoded completely valid JSON
	if len(b) == 0 {
		return nil, malformed("failed to decode claims JSON: claims cannot be empty")
	}

	// RFC 7519 Section 7.2 Step 10: Verify UTF-8 encoded completely valid JSON
	if !utf8.Valid(b) {
		return nil, malformed("claims are not valid UTF-8")
	}

	// Decode the claims JSON, refusing duplicate names (RFC 7519 §4).
	if err := strictjson.CheckDuplicates(b); err != nil {
		return nil, malformed("failed to decode claims JSON: %w", err)
	}
	claims := ClaimsSet{}
	err = json.Unmarshal(b, &claims)
	if err != nil {
		return nil, malformed("failed to decode claims JSON: %w", err)
	}

	// Ensure we're using the correct types for registered claims per RFC 7519.
	// Handle potential precision loss and edge cases in numeric conversions.
	{
		// Process IssuedAt claim
		if issuedAt, ok := claims[IssuedAt]; ok {
			switch v := issuedAt.(type) {
			case int64: // Already correct type
			case float64: // Common from JSON unmarshaling
				// Check for potential precision loss or invalid values
				if v != v { // NaN check
					return nil, malformed("invalid NaN value for %q claim", IssuedAt)
				}
				if v < 0 || v > 253402300799 { // Unix timestamp bounds (year 9999)
					return nil, malformed("invalid timestamp value %v for %q claim", v, IssuedAt)
				}
				claims[IssuedAt] = int64(v)
			case int: // Handle int type
				claims[IssuedAt] = int64(v)
			default:
				return nil, malformed("invalid type %T used for %q", v, IssuedAt)
			}
		}

		// Process ExpirationTime claim
		if expirationTime, ok := claims[ExpirationTime]; ok {
			switch v := expirationTime.(type) {
			case int64: // Already correct type
			case float64: // Common from JSON unmarshaling
				if v != v { // NaN check
					return nil, malformed("invalid NaN value for %q claim", ExpirationTime)
				}
				if v < 0 || v > 253402300799 { // Unix timestamp bounds
					return nil, malformed("invalid timestamp value %v for %q claim", v, ExpirationTime)
				}
				claims[ExpirationTime] = int64(v)
			case int: // Handle int type
				claims[ExpirationTime] = int64(v)
			default:
				return nil, malformed("invalid type %T used for %q", v, ExpirationTime)
			}
		}

		// Process NotBefore claim
		if notBefore, ok := claims[NotBefore]; ok {
			switch v := notBefore.(type) {
			case int64: // Already correct type
			case float64: // Common from JSON unmarshaling
				if v != v { // NaN check
					return nil, malformed("invalid NaN value for %q claim", NotBefore)
				}
				if v < 0 || v > 253402300799 { // Unix timestamp bounds
					return nil, malformed("invalid timestamp value %v for %q claim", v, NotBefore)
				}
				claims[NotBefore] = int64(v)
			case int: // Handle int type
				claims[NotBefore] = int64(v)
			default:
				return nil, malformed("invalid type %T used for %q", v, NotBefore)
			}
		}

		// Process string claims (iss, sub, jti) for proper validation
		for _, claimName := range []string{Issuer, Subject, ID} {
			if claimValue, ok := claims[claimName]; ok {
				switch v := claimValue.(type) {
				case string:
					// Only validate issuer cannot be empty (critical for security)
					if claimName == Issuer && v == "" {
						return nil, malformed("issuer claim cannot be empty string")
					}
				default:
					return nil, malformed("invalid type %T used for %q claim", v, claimName)
				}
			}
		}

		// Process Audience claim which can be string or array of strings
		if audience, ok := claims[Audience]; ok {
			switch v := audience.(type) {
			case string:
				// Allow empty strings in parsing, validate during verification if needed
			case []interface{}:
				// Convert []interface{} to []string if all elements are strings
				stringArray := make([]string, len(v))
				for i, elem := range v {
					if str, ok := elem.(string); ok {
						stringArray[i] = str
					} else {
						return nil, malformed("invalid audience element type %T at index %d", elem, i)
					}
				}
				claims[Audience] = stringArray
			case []string:
				// Accept existing string array as-is
			default:
				return nil, malformed("invalid type %T used for %q claim", v, Audience)
			}
		}
	}

	// Lastly, we decode the signature base64 content.
	// For "none" algorithm, the signature part may be empty
	var sigBytes []byte
	if parts[2] != "" {
		sigBytes, err = base64url.Decode(parts[2])
		if err != nil {
			return nil, malformed("failed to decode signature base64: %w", err)
		}
	} else {
		// Empty signature is allowed for "none" algorithm
		sigBytes = []byte{}
	}

	// Create a new token object, with the header and raw input string.
	//
	// We've deferred allocating this object until now, because we
	// didn't want to allocate it if we were going to return an error.
	token := &Token{
		Header:    h,
		Claims:    claims,
		Signature: sigBytes,
		raw:       input,
	}

	return token, nil
}

// splitToken splits a JWT into its three parts, returning an error if the
// token is not in the correct format. This implements the parsing step
// from RFC 7519 Section 7.2 with combined structure validation.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-7.2
func splitToken(token string) ([3]string, error) {
	// RFC 7519 Section 7.2: Validate JWT structure first
	if len(token) == 0 {
		return [3]string{}, malformed("token is empty")
	}

	// Count dots using strings.Count to ensure exactly 2 dots
	dotCount := strings.Count(token, ".")
	if dotCount != 2 {
		return [3]string{}, malformed("expected 2 dots, got %d", dotCount)
	}

	parts := strings.SplitN(token, dot, 3)
	if len(parts) != 3 {
		return [3]string{}, malformed("incorrect number of JWT parts")
	}

	return [3]string{parts[0], parts[1], parts[2]}, nil
}

type contextKey struct{}

// NewContext returns a copy of ctx that carries token.
func NewContext(ctx context.Context, token *Token) context.Context {
	return context.WithValue(ctx, contextKey{}, token)
}

// FromContext returns the Token in ctx, or nil if there is none.
func FromContext(ctx context.Context) *Token {
	token, _ := ctx.Value(contextKey{}).(*Token)
	return token
}

// malformed reports a token that is not a well-formed JWT.
func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %w: "+format, append([]any{ErrInvalidToken, ErrFormat}, args...)...)
}
