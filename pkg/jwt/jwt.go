package jwt

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
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
const Type string = "JWT"

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

// New can be used to create a signed Token object. If this fails for any
// reason, an error is returned with a nil token.
//
// Using this function does not require the given header parameters define
// the "typ" (header.Type), which is always set to "JWT" ([Type]), but
// callers can include it if they like.
//
// The claims set must not be empty, or will return an error.
//
// The given key can be a symmetric or asymmetric (private) key. The type for this
// argument depends on the algorithm "alg" defined in the header.
//
// Example algorithm(s) to Supported Key Type(s):
//   - HS256, HS384, HS512: []byte or string
//   - RS256, RS384, RS512: *rsa.PrivateKey
//   - PS256, PS384, PS512: *rsa.PrivateKey
//   - ES256, ES384, ES512: *ecdsa.PrivateKey
//   - EdDSA: ed25519.PrivateKey
func New[T jwa.SigningKey](params header.Parameters, claims ClaimsSet, key T) (*Token, error) {
	return newToken(params, claims, key)
}

// NewWithSigner is like [New], but signs with a [crypto.Signer], such as a
// hardware-backed PIV, TPM or Secure Enclave key, or a remote KMS key.
//
// The "alg" header parameter must match the signer's public key: ES256,
// ES384 or ES512 for P-256, P-384 or P-521; RS* or PS* for RSA keys of at
// least 2048 bits; EdDSA for Ed25519. [jwa.ForKey] picks the conventional
// algorithm for a public key.
func NewWithSigner(params header.Parameters, claims ClaimsSet, signer crypto.Signer) (*Token, error) {
	if signer == nil {
		return nil, fmt.Errorf("cannot create token with a nil signer")
	}
	return newToken(params, claims, signer)
}

func newToken(params header.Parameters, claims ClaimsSet, key any) (*Token, error) {
	// Given params set cannot be empty.
	if len(params) == 0 {
		return nil, fmt.Errorf("cannot create token with empty header parameters")
	}

	// An unsecured JWT (RFC 7519 §6) is never minted: anyone could forge one.
	if alg, _ := params.Algorithm(); alg == jwa.None {
		return nil, fmt.Errorf("cannot create an unsecured token with alg %q", jwa.None)
	}

	// Given claims set cannot be empty.
	if len(claims) == 0 {
		return nil, fmt.Errorf("cannot create token with empty claims set")
	}

	// Verify or otherwise handle registered claim types nicely.
	for name, value := range claims {
		switch name {
		case ExpirationTime, NotBefore, IssuedAt:
			switch v := value.(type) {
			// good
			case int64:
			// ok
			case time.Time:
				claims[name] = v.Unix()
			// bad
			default:
				return nil, fmt.Errorf("cannot use type %T with %q claim", v, name)
			}
		case Issuer, Subject, JWTID:
			switch v := value.(type) {
			// good
			case string:
				// Only validate issuer claim cannot be empty (iss is critical for security)
				if name == Issuer && v == "" {
					return nil, fmt.Errorf("issuer claim cannot be empty string")
				}
			// ok
			case fmt.Stringer:
				strValue := v.String()
				if name == Issuer && strValue == "" {
					return nil, fmt.Errorf("issuer claim cannot be empty string")
				}
				claims[name] = strValue
			// bad
			default:
				return nil, fmt.Errorf("cannot use type %T with %q claim", v, name)
			}
		case Audience:
			switch v := value.(type) {
			// good
			case string:
				// Only validate non-empty if audience validation will be performed
				// (let runtime validation handle empty audience checking)
			// ok
			case fmt.Stringer:
				claims[name] = v.String()
			// meh, but ok - validate each element
			case []string:
				// Basic validation for arrays
				for i, aud := range v {
					if aud == "" {
						return nil, fmt.Errorf("audience claim array element %d cannot be empty string", i)
					}
				}
			// bad
			default:
				return nil, fmt.Errorf("cannot use type %T with %q claim", v, name)
			}
		}
	}

	// Ensure the "typ" header parameter is set to "JWT", as it is required.
	if !params.Has(header.Type) {
		params[header.Type] = Type
	} else {
		if existingType, err := params.Get(header.Type); err == nil && existingType != Type {
			return nil, fmt.Errorf("header type %q is not supported", existingType)
		}
	}

	// Create a token, in preparation to sign it.
	token := &Token{
		Header: params,
		Claims: claims,
	}

	// Sign it.
	err := token.sign(key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
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

	if len(t.Signature) != 0 {
		b.WriteString(dot)
		signature := base64url.Encode(t.Signature)
		b.WriteString(signature)
	}

	if len(t.raw) == 0 {
		t.raw = b.String()
	}

	return b.String(), nil
}

// String returns the string representation of the token, which is
// the raw JWT string of three base64url encoded parts, separated
// by a period.
func (t *Token) String() string {
	// Return the raw string if it is set.
	if len(t.raw) > 0 {
		return t.raw
	}

	// If there raw string is not set, compute it.
	s, err := t.computeString()
	if err != nil {
		return fmt.Sprintf("<invalid-token %q>", err)
	}

	return s
}

// Parseable is a type that can be parsed into a JWT,
// either a string or byte slice.
type Parseable interface {
	~string | ~[]byte
}

// Parse decodes a given JWT, and returns a Token or an error
// if the JWT fails to parse.
//
// # Warning
//
// Parse decodes without verifying: it checks neither the signature nor
// any claim, so nothing in the returned token is trustworthy. Use a
// [Verifier] to verify a token.
func Parse[T Parseable](input T) (*Token, error) {
	return parseString(string(input))
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
	t.raw = ""
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
		return nil, fmt.Errorf("failed to split token: %w", err)
	}

	// Next, we decode the header base64 content.
	b, err := base64url.Decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JOSE header base64: %w", err)
	}

	// RFC 7519 Section 7.2 Step 4: Verify UTF-8 encoded completely valid JSON
	if len(b) == 0 {
		return nil, fmt.Errorf("failed to decode JOSE header JSON: header cannot be empty")
	}
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("header is not valid UTF-8")
	}

	// Decode the header JSON, refusing duplicate names (RFC 7515 §4).
	if err := strictjson.CheckDuplicates(b); err != nil {
		return nil, fmt.Errorf("failed to decode JOSE header JSON: %w", err)
	}
	h := header.Parameters{}
	err = json.Unmarshal(b, &h)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JOSE header JSON: %w", err)
	}

	// Ensure we're using JWA types instead of raw string values.
	if h.Has(header.Algorithm) {
		if algValue, err := h.Get(header.Algorithm); err == nil {
			h[header.Algorithm] = jwa.Algorithm(fmt.Sprintf("%v", algValue))
		}
	}

	// Next, we decode the claims base64 content.
	b, err = base64url.Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims base64: %w", err)
	}

	// RFC 7519 Section 7.2 Step 10: Verify UTF-8 encoded completely valid JSON
	if len(b) == 0 {
		return nil, fmt.Errorf("failed to decode claims JSON: claims cannot be empty")
	}

	// RFC 7519 Section 7.2 Step 10: Verify UTF-8 encoded completely valid JSON
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("claims are not valid UTF-8")
	}

	// Decode the claims JSON, refusing duplicate names (RFC 7519 §4).
	if err := strictjson.CheckDuplicates(b); err != nil {
		return nil, fmt.Errorf("failed to decode claims JSON: %w", err)
	}
	claims := ClaimsSet{}
	err = json.Unmarshal(b, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims JSON: %w", err)
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
					return nil, fmt.Errorf("invalid NaN value for %q claim", IssuedAt)
				}
				if v < 0 || v > 253402300799 { // Unix timestamp bounds (year 9999)
					return nil, fmt.Errorf("invalid timestamp value %v for %q claim", v, IssuedAt)
				}
				claims[IssuedAt] = int64(v)
			case int: // Handle int type
				claims[IssuedAt] = int64(v)
			default:
				return nil, fmt.Errorf("invalid type %T used for %q", v, IssuedAt)
			}
		}

		// Process ExpirationTime claim
		if expirationTime, ok := claims[ExpirationTime]; ok {
			switch v := expirationTime.(type) {
			case int64: // Already correct type
			case float64: // Common from JSON unmarshaling
				if v != v { // NaN check
					return nil, fmt.Errorf("invalid NaN value for %q claim", ExpirationTime)
				}
				if v < 0 || v > 253402300799 { // Unix timestamp bounds
					return nil, fmt.Errorf("invalid timestamp value %v for %q claim", v, ExpirationTime)
				}
				claims[ExpirationTime] = int64(v)
			case int: // Handle int type
				claims[ExpirationTime] = int64(v)
			default:
				return nil, fmt.Errorf("invalid type %T used for %q", v, ExpirationTime)
			}
		}

		// Process NotBefore claim
		if notBefore, ok := claims[NotBefore]; ok {
			switch v := notBefore.(type) {
			case int64: // Already correct type
			case float64: // Common from JSON unmarshaling
				if v != v { // NaN check
					return nil, fmt.Errorf("invalid NaN value for %q claim", NotBefore)
				}
				if v < 0 || v > 253402300799 { // Unix timestamp bounds
					return nil, fmt.Errorf("invalid timestamp value %v for %q claim", v, NotBefore)
				}
				claims[NotBefore] = int64(v)
			case int: // Handle int type
				claims[NotBefore] = int64(v)
			default:
				return nil, fmt.Errorf("invalid type %T used for %q", v, NotBefore)
			}
		}

		// Process string claims (iss, sub, jti) for proper validation
		for _, claimName := range []ClaimName{Issuer, Subject, JWTID} {
			if claimValue, ok := claims[claimName]; ok {
				switch v := claimValue.(type) {
				case string:
					// Only validate issuer cannot be empty (critical for security)
					if claimName == Issuer && v == "" {
						return nil, fmt.Errorf("issuer claim cannot be empty string")
					}
				default:
					return nil, fmt.Errorf("invalid type %T used for %q claim", v, claimName)
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
						return nil, fmt.Errorf("invalid audience element type %T at index %d", elem, i)
					}
				}
				claims[Audience] = stringArray
			case []string:
				// Accept existing string array as-is
			default:
				return nil, fmt.Errorf("invalid type %T used for %q claim", v, Audience)
			}
		}
	}

	// Lastly, we decode the signature base64 content.
	// For "none" algorithm, the signature part may be empty
	var sigBytes []byte
	if parts[2] != "" {
		sigBytes, err = base64url.Decode(parts[2])
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature base64: %w", err)
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
		return [3]string{}, fmt.Errorf("%w: token is empty", ErrInvalidToken)
	}

	// Count dots using strings.Count to ensure exactly 2 dots
	dotCount := strings.Count(token, ".")
	if dotCount != 2 {
		return [3]string{}, fmt.Errorf("%w: expected 2 dots, got %d", ErrInvalidToken, dotCount)
	}

	parts := strings.SplitN(token, dot, 3)
	if len(parts) != 3 {
		return [3]string{}, fmt.Errorf("%w: incorrect number of JWT parts", ErrInvalidToken)
	}

	return [3]string{parts[0], parts[1], parts[2]}, nil
}

// contextKey is a type used to store values in a context object.
//
// We use this type to avoid collisions with other packages that
// may also use context values in the same context.
type contextKey string

const (
	// ContextKey is the key used to store the JWT in the context.
	ContextKey contextKey = "jwt"
)

// FromContext extracts a JWT from the given context. If the JWT is not
// in the context, then nil is returned.
func FromContext(ctx context.Context) *Token {
	token, ok := ctx.Value(ContextKey).(*Token)
	if !ok {
		return nil
	}
	return token
}

// WithContext sets the JWT in the given context.
func WithContext(ctx context.Context, token *Token) context.Context {
	return context.WithValue(ctx, ContextKey, token)
}
