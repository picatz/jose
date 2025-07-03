package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
)

var (
	ErrInvalidToken = fmt.Errorf("jwt: invalid token")
)

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
const Type header.ParameterName = "JWT"

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
// the "typ" (header.Type), which is always set to "JWT" (header.TypeJWT), but
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
	// Given params set cannot be empty.
	if len(params) == 0 {
		return nil, fmt.Errorf("cannot create token with empty header parameters")
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
	_, err := token.Sign(key)
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

	header, err := base64.Encode(headerBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}
	b.WriteString(header)
	b.WriteString(dot)

	// Marshal claims directly to avoid newlines (consistent with signingInput)
	claimsBytes, err := json.Marshal(t.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	claims, err := base64.Encode(claimsBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encode claims: %w", err)
	}
	b.WriteString(claims)

	if len(t.Signature) != 0 {
		b.WriteString(dot)
		signature, err := base64.Encode(t.Signature)
		if err != nil {
			return "", fmt.Errorf("failed to encode signature: %w", err)
		}
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

// Parse parses a given JWT, and returns a Token or an error
// if the JWT fails to parse.
//
// # Warning
//
// This is a low-level function that does not verify the
// signature of the token. Use [ParseAndVerify] to parse
// and verify the signature of a token in one step.
// Otherwise, use Parse to parse a token, and then
// use the VerifySignature method to verify the signature.
func Parse[T Parseable](input T) (*Token, error) {
	return ParseString(string(input))
}

// ParseAndVerify parses a given JWT, and verifies the signature
// using the given verification configuration options.
func ParseAndVerify[T Parseable](input T, veryifyOptions ...VerifyOption) (*Token, error) {
	token, err := Parse(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	err = token.Verify(veryifyOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT signature: %w", err)
	}

	return token, nil
}

// ParseString parses a given JWT string, and returns a Token
// or an error if the JWT fails to parse.
//
// # Warning
//
// This is a low-level function that does not verify the
// signature of the token. Use ParseAndVerify to parse
// and verify the signature of a token in one step.
// Otherwise, use Parse to parse a token, and then
// use the VerifySignature method to verify the signature.
func ParseString(input string) (*Token, error) {
	// First, we split our input into three parts, separated by dots.
	// This also validates the JWT structure per RFC 7519 Section 7.2
	parts, err := splitToken(input)
	if err != nil {
		return nil, fmt.Errorf("failed to split token: %w", err)
	}

	// Next, we decode the header base64 content.
	b, err := base64.Decode(parts[0])
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

	// Decode the header JSON.
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
	b, err = base64.Decode(parts[1])
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

	// Decode the claims JSON.
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
		sigBytes, err = base64.Decode(parts[2])
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

// Issuers is a set of issuers.
type Issuers = []string

// VerifyConfig is a configuration type for verifying JWTs.
type VerifyConfig struct {
	// InsecureAllowNone allows the "none" algorithm to be used, which
	// is considered insecure, dangerous, and disabled by default. It must be
	// set in addition to being enabled in the allowed algorithms.
	InsecureAllowNone bool

	// AllowedAlgorithms is a set of allowed algorithms for the JWT.
	//
	// If not set, then jwt.DefaultAllowedAlgorithms will be used.
	AllowedAlgorithms []jwa.Algorithm

	// AllowedIssuers is a set of allowed issuers for the JWT.
	//
	// If not set, then any issuers are allowed.
	AllowedIssuers []string

	// AllowedAudiences is a set of allowed audiences for the JWT.
	//
	// If not set, then any audiences are allowed.
	AllowedAudiences []string

	// AllowedKeys is a set of allowed keys for the JWT keyed by
	// the corresponding "kid" header parameter.
	//
	// If not set, then verification will fail if the algorithm
	// is not "none".
	AllowedKeys map[string]any

	// Clock is a function that returns the current time.
	//
	// This is used to verify the "exp", "nbf", and "iat" claims.
	//
	// If not set, then time.Now will be used.
	Clock func() time.Time

	// ClockSkewTolerance is the maximum amount of clock skew to allow
	// when validating time-based claims (exp, nbf, iat).
	//
	// If not set, defaults to 0 (no tolerance).
	ClockSkewTolerance time.Duration

	// SupportedCriticalHeaders is a set of critical header parameter names
	// that this application understands and can process. Per RFC 7515 section 4.1.11,
	// if a JWT contains a "crit" header with extension parameters not in this set,
	// the JWT will be rejected.
	//
	// If not set, then no critical headers are supported (recommended default).
	SupportedCriticalHeaders []string
}

// VerifyOption is a functional option type used to configure
// the verification requirements for JWTs.
type VerifyOption func(*VerifyConfig) error

// WithAllowInsecureNoneAlgorithm allows the "none" algorithm to be used.
// Users must explicitly enable this option, as it is
// considered insecure, dangerous, and disabled by default.
//
// # WARNING
//
// This is not recommended, and should only be used
// for testing purposes.
func WithAllowInsecureNoneAlgorithm(value bool) VerifyOption {
	return func(vc *VerifyConfig) error {
		vc.InsecureAllowNone = value
		return nil
	}
}

// WithAllowedIssuers sets the allowed issuers for the JWT.
func WithAllowedIssuers(issuers ...string) VerifyOption {
	return func(vc *VerifyConfig) error {
		vc.AllowedIssuers = issuers
		return nil
	}
}

// WithAllowedAudiences sets the allowed audiences for the JWT.
func WithAllowedAudiences(audiences ...string) VerifyOption {
	return func(vc *VerifyConfig) error {
		vc.AllowedAudiences = audiences
		return nil
	}
}

// WithAllowedAlgorithms sets the allowed algorithms for the JWT.
func WithAllowedAlgorithms(algs ...jwa.Algorithm) VerifyOption {
	return func(vc *VerifyConfig) error {
		vc.AllowedAlgorithms = algs
		return nil
	}
}

// WithKey appends a key to the set of allowed keys for the JWT using a
// randomly generated key ID.
//
// This is the preferred way to add a key to the set of allowed keys,
// because it will ensure that the given key is of the correct type
// at compile time.
func WithKey[T jwa.VerifyKey](key T) VerifyOption {
	return func(vc *VerifyConfig) error {
		if vc.AllowedKeys == nil {
			vc.AllowedKeys = make(map[string]any)
		}

		// generate a random key ID
		kid := make([]byte, 16)
		_, err := rand.Read(kid)
		if err != nil {
			return fmt.Errorf("failed to generate random key ID: %w", err)
		}

		// convert to hex string
		kidStr := fmt.Sprintf("%x", kid)

		// add key to set of allowed keys
		vc.AllowedKeys[kidStr] = key

		return nil
	}
}

// WithIdentifiableKey adds a key by ID to the set of allowed keys for the JWT.
//
// This is the preferred way to add a key to the set of allowed keys,
// because it will ensure that the given key is of the correct type
// at compile time.
func WithIdentifiableKey[T jwa.VerifyKey](kid string, key T) VerifyOption {
	return func(vc *VerifyConfig) error {
		if vc.AllowedKeys == nil {
			vc.AllowedKeys = make(map[string]any)
		}
		vc.AllowedKeys[kid] = key
		return nil
	}
}

// WithClock sets the clock function for verifying the JWT.
func WithClock(clock Clock) VerifyOption {
	return func(vc *VerifyConfig) error {
		vc.Clock = clock
		return nil
	}
}

// WithDefaultClock sets the clock function for verifying the JWT
// to time.Now.
func WithDefaultClock() VerifyOption {
	return func(vc *VerifyConfig) error {
		vc.Clock = time.Now
		return nil
	}
}

// WithClockSkewTolerance sets the clock skew tolerance for time-based claims.
// This allows for small differences in system clocks between the issuer and verifier.
func WithClockSkewTolerance(tolerance time.Duration) VerifyOption {
	return func(vc *VerifyConfig) error {
		vc.ClockSkewTolerance = tolerance
		return nil
	}
}

// WithSupportedCriticalHeaders sets the supported critical header parameter names
// for JWT verification. Per RFC 7515 section 4.1.11, if a JWT contains a "crit"
// header with extension parameters not in this list, verification will fail.
func WithSupportedCriticalHeaders(headers ...string) VerifyOption {
	return func(config *VerifyConfig) error {
		config.SupportedCriticalHeaders = headers
		return nil
	}
}

// Clock is type used to represent a function that returns the current time.
type Clock func() time.Time

// Expired returns true if the token is expired, false otherwise.
// If an error occurs while checking expiration, it is returned.
//
// Only use the boolean value if error is nil.
func (t *Token) Expired(clock Clock) (bool, error) {
	expValue, ok := t.Claims[ExpirationTime]
	if !ok {
		return false, nil
	}
	expInt, ok := expValue.(int64)
	if !ok {
		return false, fmt.Errorf("invalid value %q for %q", expValue, ExpirationTime)
	}
	exp := time.Unix(expInt, 0)

	return exp.Before(clock()), nil
}

// Expires returns true if the token has an expiration time claim,
// false otherwise. If an error occurs while checking expiration,
// it is returned.
//
// Only use the boolean value if error is nil.
func (t *Token) Expires() (bool, error) {
	expValue, ok := t.Claims[ExpirationTime]
	if !ok {
		return false, nil
	}
	_, ok = expValue.(int64)
	if !ok {
		return false, fmt.Errorf("invalid value %q of type %[1]T for %q", expValue, ExpirationTime)
	}
	return true, nil
}

// algorithm to corresponding hash function
var algHash = map[jwa.Algorithm]crypto.Hash{
	jwa.HS256: crypto.SHA256,
	jwa.HS384: crypto.SHA384,
	jwa.HS512: crypto.SHA512,
	jwa.RS256: crypto.SHA256,
	jwa.RS384: crypto.SHA384,
	jwa.RS512: crypto.SHA512,
	jwa.ES256: crypto.SHA256,
	jwa.ES384: crypto.SHA384,
	jwa.ES512: crypto.SHA512,
	jwa.PS256: crypto.SHA256,
	jwa.PS384: crypto.SHA384,
	jwa.PS512: crypto.SHA512,
	jwa.EdDSA: crypto.Hash(0), // no hashing option for EdDSA, Ed25519 enforced ( SHA512 only ).
}

// VerifySignature verifies the signature of the token using the
// given verification configuration options.
//
// # Warning
//
// This only verifies the signature, and does not verify any
// other claims, such as expiration time, issuer, audience, etc.
func (t *Token) VerifySignature(allowedAlgs []jwa.Algorithm, allowedKeys map[string]any) error {
	alg, err := t.Header.Algorithm()
	if err != nil {
		return fmt.Errorf("%w: failed to get algorithm from header: %w", ErrInvalidToken, err)
	}

	// RFC 7518 Section 3.1 - Validate algorithm against known secure algorithms
	// Prevent algorithm confusion attacks by strictly validating algorithm values
	if err := jwa.ValidateAlgorithm(alg, allowedAlgs); err != nil {
		return fmt.Errorf("%w: failed to validate algorithm: %w", ErrInvalidToken, err)
	}

	// Special handling for "none" algorithm per RFC 7518 Section 3.1
	// Note: Additional check for InsecureAllowNone is done in the Verify method
	if alg == jwa.None {
		// For "none" algorithm, signature must be empty
		if len(t.Signature) != 0 {
			return fmt.Errorf("%w: signature must be empty when algorithm is %q", ErrInvalidToken, alg)
		}
		return nil
	}

	// Require a key (symmetric or asymmetric) for all algorithms except "none".
	if len(allowedKeys) == 0 {
		return fmt.Errorf("%w: no key provided to verify signature using algorithm %q", ErrInvalidToken, alg)
	}

	// There might be a key identifier we want to use.
	var keyID string
	if t.Header.Has(header.KeyID) {
		keyID, err = header.Get[string](t.Header, header.KeyID)
		if err != nil {
			return fmt.Errorf("%w: failed to get key ID %q: %w", ErrInvalidToken, header.KeyID, err)
		}
	}

	// Verify the signature based on the algorithm.
	switch alg {
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return t.verifyHMACSignatureWithKeys(algHash[alg], keyID, allowedKeys)
	case jwa.RS256, jwa.RS384, jwa.RS512:
		return t.verifyRSASignatureWithKeys(algHash[alg], keyID, allowedKeys)
	case jwa.PS256, jwa.PS384, jwa.PS512:
		return t.verifyRSAPSSSignatureWithKeys(algHash[alg], keyID, allowedKeys)
	case jwa.ES256, jwa.ES384, jwa.ES512:
		return t.verifyECDSASignatureWithKeys(algHash[alg], keyID, allowedKeys)
	case jwa.EdDSA:
		return t.verifyEdDSASignatureWithKeys(keyID, allowedKeys)
	default:
		return fmt.Errorf("algorithm %q not implemented or allowed", alg)
	}
}

// HMACSignature returns the HMAC signature of the token using the
// given hash and key.
func (t *Token) HMACSignature(hash crypto.Hash, key any) ([]byte, error) {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return nil, fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual signing operation with advanced validation
	return jwsToken.SignHMAC(hash, key, signingInput)
}

// VerifyHMACSignature verifies the HMAC signature of the token using the
// given hash and key.
func (t *Token) VerifyHMACSignature(hash crypto.Hash, key any) error {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual verification operation (without key size validation for compatibility)
	return jwsToken.VerifyHMACForLegacy(hash, key, signingInput)
}

// VerifyRSASignature verifies the RSA signature of the token using the
// given hash and public key.
func (t *Token) VerifyRSASignature(hash crypto.Hash, publicKey *rsa.PublicKey) error {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual verification operation with advanced validation
	return jwsToken.VerifyRSA(hash, publicKey, signingInput)
}

// RSASignature returns the RSA signature of the token using the
// given hash and private key.
func (t *Token) RSASignature(hash crypto.Hash, privateKey *rsa.PrivateKey) ([]byte, error) {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return nil, fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual signing operation with advanced validation
	return jwsToken.SignRSA(hash, privateKey, signingInput)
}

// RSAPSSSignature returns the RSA-PSS signature of the token using the given hash
// and private key.
//
// This is similar to RSASignature, but uses the RSA-PSS algorithm, which
// is probabilistic, and therefore, the signature will be different each time.
func (t *Token) RSAPSSSignature(hash crypto.Hash, privateKey *rsa.PrivateKey) ([]byte, error) {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return nil, fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual signing operation with advanced validation
	return jwsToken.SignRSAPSS(hash, privateKey, signingInput)
}

// VerifyRSAPSSSignature verifies the RSA-PSS signature of the token using the
// given hash and public key.
//
// This is similar to VerifyRSASignature, but uses the RSA-PSS algorithm, which
// is probabilistic, and therefore, the signature will be different each time.
func (t *Token) VerifyRSAPSSSignature(hash crypto.Hash, publicKey *rsa.PublicKey) error {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual verification operation with advanced validation
	return jwsToken.VerifyRSAPSS(hash, publicKey, signingInput)
}

// VerifyECDSASignature verifies the ECDSA signature of the token using the
// given hash and public key.
func (t *Token) VerifyECDSASignature(hash crypto.Hash, publicKey *ecdsa.PublicKey) error {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual verification operation with advanced validation
	return jwsToken.VerifyECDSA(hash, publicKey, signingInput)
}

// ECDSASignature returns the ECDSA signature of the token using the
// given hash and private key.
func (t *Token) ECDSASignature(hash crypto.Hash, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return nil, fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual signing operation with advanced validation
	return jwsToken.SignECDSA(hash, privateKey, signingInput)
}

// VerifyEdDSASignature verifies the EdDSA signature of the token using the
// given public key.
func (t *Token) VerifyEdDSASignature(publicKey ed25519.PublicKey) error {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual verification operation with advanced validation
	return jwsToken.VerifyEdDSA(publicKey, signingInput)
}

// EdDSASignature returns the EdDSA signature of the token using the
// given private key.
func (t *Token) EdDSASignature(privateKey ed25519.PrivateKey) ([]byte, error) {
	// Create a JWS signature instance for cryptographic operations
	jwsToken, err := t.asJWS()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWS instance: %w", err)
	}

	// Get the signing input
	signingInput, err := t.signingInput()
	if err != nil {
		return nil, fmt.Errorf("failed to create signing input: %w", err)
	}

	// Use JWS for the actual signing operation with advanced validation
	return jwsToken.SignEdDSA(privateKey, signingInput)
}

// Sign returns the signature of the token using the given options.
func (t *Token) Sign(key any) ([]byte, error) {
	typ, err := t.Header.Type()
	if err != nil {
		return nil, fmt.Errorf("invalid JWT header type: %w", err)
	}

	if typ != Type {
		return nil, fmt.Errorf("invalid JWT header type: %q", typ)
	}

	alg, err := t.Header.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("missing JWT header algorithm: %w", err)
	}

	switch alg {
	case jwa.HS256:
		sig, err := t.HMACSignature(crypto.SHA256, key)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.HS384:
		sig, err := t.HMACSignature(crypto.SHA384, key)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.HS512:
		sig, err := t.HMACSignature(crypto.SHA512, key)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.ES256:
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for ECDSA SHA256", key)
		}
		sig, err := t.ECDSASignature(crypto.SHA256, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.ES384:
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for ECDSA SHA384", key)
		}
		sig, err := t.ECDSASignature(crypto.SHA384, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.ES512:
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for ECDSA SHA512", key)
		}
		sig, err := t.ECDSASignature(crypto.SHA512, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.PS256:
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for RSA SHA256", key)
		}
		sig, err := t.RSAPSSSignature(crypto.SHA256, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.PS384:
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for RSA SHA384", key)
		}
		sig, err := t.RSAPSSSignature(crypto.SHA384, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.PS512:
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for RSA SHA512", key)
		}
		sig, err := t.RSAPSSSignature(crypto.SHA512, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.RS256:
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for RSA SHA256", key)
		}
		sig, err := t.RSASignature(crypto.SHA256, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.RS384:
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for RSA SHA384", key)
		}
		sig, err := t.RSASignature(crypto.SHA384, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.RS512:
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for RSA SHA512", key)
		}
		sig, err := t.RSASignature(crypto.SHA512, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.EdDSA:
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for EdDSA", key)
		}
		sig, err := t.EdDSASignature(privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.None:
		// no signature
	default:
		return nil, fmt.Errorf("algorithm %q not implemented", alg)
	}

	t.raw, err = t.computeString()
	if err != nil {
		return nil, fmt.Errorf("failed to compute token string: %w", err)
	}

	return t.Signature, nil
}

var defaultAllowedAlgorithms = []jwa.Algorithm{
	jwa.RS256, jwa.RS384, jwa.RS512,
	jwa.PS256, jwa.PS384, jwa.PS512,
	jwa.ES256, jwa.ES384, jwa.ES512,
	jwa.EdDSA,
	// These are allowed by default, but should be used with caution.
	// They are not recommended for production use, as they are
	// considered insecure and can lead to vulnerabilities in many cases.
	jwa.HS256, jwa.HS384, jwa.HS512,
}

// DefaultAllowedAlgorithms returns the default set of allowed algorithms
// for verifying JWTs. This set is used by the Verify method if no
// other algorithms are specified. It includes the most common
// algorithms used in JWTs, such as RS256, PS256, ES256, and
// EdDSA, as well as HMAC algorithms (HS256, HS384, HS512).
//
// # Warning
//
// This set of algorithms are generally considered secure, but the HMAC algorithms
// (HS256, HS384, HS512) should be used with caution, as they require a shared secret
// between the issuer and the verifier, which can lead to vulnerabilities
// if not managed properly. It is recommended to use asymmetric algorithms
// (RS256, PS256, ES256, EdDSA) for production use, as they provide better security
// by using public/private key pairs.
func DefaultAllowedAlgorithms() []jwa.Algorithm {
	return defaultAllowedAlgorithms
}

// Verify is used to verify a signed Token object with the given config options.
// If this fails for any reason, an error is returned.
func (t *Token) Verify(opts ...VerifyOption) error {
	// Set default config values that can be overridden by options.
	config := &VerifyConfig{
		InsecureAllowNone: false,
		AllowedAlgorithms: []jwa.Algorithm{
			jwa.RS256, jwa.RS384, jwa.RS512,
			jwa.PS256, jwa.PS384, jwa.PS512,
			jwa.ES256, jwa.ES384, jwa.ES512,
			jwa.HS256, jwa.HS384, jwa.HS512,
			jwa.EdDSA,
		},
		Clock: time.Now,
	}

	// Apply options.
	for _, opt := range opts {
		err := opt(config)
		if err != nil {
			return fmt.Errorf("verify option error: %w", err)
		}
	}

	// Handle "none" algorithm security: remove it from allowed algorithms
	// if InsecureAllowNone is false, regardless of whether it was in the list
	if !config.InsecureAllowNone {
		var filteredAlgs []jwa.Algorithm
		for _, alg := range config.AllowedAlgorithms {
			if alg != jwa.None {
				filteredAlgs = append(filteredAlgs, alg)
			}
		}
		config.AllowedAlgorithms = filteredAlgs
	}

	// Verify the signature of the token, which may be "none" if the
	// explicitly allowed "none" algorithm is set in the config.
	err := t.VerifySignature(config.AllowedAlgorithms, config.AllowedKeys)
	if err != nil {
		return fmt.Errorf("%w: failed to verify token signature: %v", ErrInvalidToken, err)
	}

	// Validate critical headers per RFC 7515 section 4.1.11
	err = t.Header.ValidateCriticalHeaders(config.SupportedCriticalHeaders)
	if err != nil {
		return fmt.Errorf("%w: failed to validate critical headers: %v", ErrInvalidToken, err)
	}

	// If the allowed issuers is empty, then any issuer is allowed.
	//
	// Otherwise, the issuer must be in the allowed issuers map.
	if config.AllowedIssuers != nil {
		issuer, ok := t.Claims[Issuer]
		if !ok {
			return fmt.Errorf("%w: missing %q claim in token", ErrInvalidToken, Issuer)
		}
		issuerStr, ok := issuer.(string)
		if !ok {
			return fmt.Errorf("%w: invalid %q claim type %T in token", ErrInvalidToken, Issuer, issuer)
		}
		if !slices.Contains(config.AllowedIssuers, issuerStr) {
			return fmt.Errorf("%w: requested issuer %q is not allowed", ErrInvalidToken, issuerStr)
		}
	}

	// If the allowed audiences is empty, then any audience is allowed.
	//
	// Otherwise, the audience must be in the allowed audiences map.
	if config.AllowedAudiences != nil {
		// Check if the Audience claim exists in the token
		aud, ok := t.Claims[Audience]
		if !ok {
			return fmt.Errorf("missing %q claim in token", Audience)
		}
		switch aud := aud.(type) {
		case string:
			// If the audience is a string, then we need to check if the audience
			// is in the allowed audiences.
			if !slices.Contains(config.AllowedAudiences, aud) {
				return fmt.Errorf("requested audience %q is not allowed", aud)
			}
		case []string:
			// If the audience is a slice, then we need to check if any of the
			// audiences are in the allowed audiences.
			//
			// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
			found := false
			for _, audience := range aud {
				if slices.Contains(config.AllowedAudiences, audience) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("none of the requested audiences %q are allowed", aud)
			}
		case []interface{}:
			// Handle JSON unmarshaling case where array might be []interface{}
			found := false
			for _, aud := range aud {
				if audStr, ok := aud.(string); ok {
					if slices.Contains(config.AllowedAudiences, audStr) {
						found = true
						break
					}
				} else {
					return fmt.Errorf("invalid audience element type %T in token claims", aud)
				}
			}
			if !found {
				return fmt.Errorf("none of the requested audiences are allowed")
			}
		default:
			return fmt.Errorf("invalid audience type %T in token claims", t.Claims[Audience])
		}
	}

	// Verify expiration time (exp) claim per RFC 7519 Section 4.1.4
	expired, err := t.Expired(config.Clock)
	if err != nil {
		return fmt.Errorf("failed to validate token expiration: %w", err)
	}

	if expired {
		// Apply clock skew tolerance for expiration if configured
		if config.ClockSkewTolerance > 0 {
			if expValue, ok := t.Claims[ExpirationTime]; ok {
				if expInt, ok := expValue.(int64); ok {
					exp := time.Unix(expInt, 0)
					// Token is only truly expired if current time exceeds exp + tolerance
					if config.Clock().After(exp.Add(config.ClockSkewTolerance)) {
						return fmt.Errorf("token is expired (exp: %v, now: %v, tolerance: %v)",
							exp.UTC(), config.Clock().UTC(), config.ClockSkewTolerance)
					}
					// Token is within tolerance, continue verification
				} else {
					return fmt.Errorf("token is expired")
				}
			} else {
				return fmt.Errorf("token is expired")
			}
		} else {
			return fmt.Errorf("token is expired")
		}
	}

	// Verify not before (nbf) claim per RFC 7519 Section 4.1.5
	if notBeforeValue, ok := t.Claims[NotBefore]; ok {
		if notBeforeInt, ok := notBeforeValue.(int64); ok {
			notBefore := time.Unix(notBeforeInt, 0)
			// Apply clock skew tolerance for "not before" - subtract tolerance from nbf
			adjustedNotBefore := notBefore
			if config.ClockSkewTolerance > 0 {
				adjustedNotBefore = notBefore.Add(-config.ClockSkewTolerance)
			}
			if config.Clock().Before(adjustedNotBefore) {
				return fmt.Errorf("token is unable to be used before %v", notBefore)
			}
		} else {
			return fmt.Errorf("token contains invalid %q value %v", NotBefore, notBeforeValue)
		}
	}

	// Verify issued at (iat) claim per RFC 7519 Section 4.1.6
	// Only validate if iat is not excessively in the future to prevent obvious forgeries
	if issuedAtValue, ok := t.Claims[IssuedAt]; ok {
		if issuedAtInt, ok := issuedAtValue.(int64); ok {
			issuedAt := time.Unix(issuedAtInt, 0)
			now := config.Clock()

			// Check if iat is too far in the future (with tolerance)
			// Only flag tokens that are clearly forged (more than 1 hour in future)
			futureThreshold := now.Add(time.Hour)
			if config.ClockSkewTolerance > time.Hour {
				futureThreshold = now.Add(config.ClockSkewTolerance)
			}
			if issuedAt.After(futureThreshold) {
				return fmt.Errorf("token issued at time %v is too far in the future (now: %v)",
					issuedAt.UTC(), now.UTC())
			}
		} else {
			return fmt.Errorf("token contains invalid %q value %v", IssuedAt, issuedAtValue)
		}
	}

	return nil
}

// asJWS creates a JWS Signature instance from this JWT Token for cryptographic operations.
// This allows JWT to leverage the advanced signing and verification logic without
// duplicating the logic for the Token type.
func (t *Token) asJWS() (*jws.Signature, error) {
	claimsBytes, err := json.Marshal(t.Claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	return &jws.Signature{
		Header:    jws.Header(t.Header),
		Payload:   claimsBytes,
		Signature: t.Signature,
	}, nil
}

// signingInput returns the JWT signing input compatible with JWS.
func (t *Token) signingInput() (string, error) {
	// If we have the original raw token, use its parts for exact reproduction
	if t.raw != "" {
		parts := strings.Split(t.raw, dot)
		if len(parts) >= 2 {
			return strings.Join(parts[0:2], dot), nil
		}
	}

	// Fallback: Marshal header and claims directly to avoid newlines
	headerBytes, err := json.Marshal(t.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	headerStr, err := base64.Encode(headerBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}

	claimsBytes, err := json.Marshal(t.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	claimsStr, err := base64.Encode(claimsBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encode claims: %w", err)
	}

	return headerStr + dot + claimsStr, nil
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

// FromHTTPAuthorizationHeader extracts a JWT string from the Authorization header of an HTTP request.
// If the Authorization header is not set, then an error is returned.
//
// # Warning
//
// This value needs to be parsed and verified before it can be used safely.
func FromHTTPAuthorizationHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid authorization header format")
	}

	if strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

// HTTPHeaderValue is a type that can be used as a value when setting
// an HTTP request header.
type HTTPHeaderValue interface {
	string | *Token
}

// SetHTTPAuthorizationHeader sets the Authorization header of an HTTP request
// to the given JWT. The JWT is prefixed with "Bearer ", as required by the
// HTTP Authorization header specification.
//
// https://tools.ietf.org/html/rfc6750#section-2.1
func SetHTTPAuthorizationHeader[T HTTPHeaderValue](r *http.Request, jwt T) {
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))
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

// verifyHMACSignatureWithKeys verifies HMAC signature using the provided keys.
// This method prevents timing attacks by testing all keys when no specific keyID is provided.
func (t *Token) verifyHMACSignatureWithKeys(hash crypto.Hash, keyID string, allowedKeys map[string]any) error {
	if keyID != "" {
		if key, ok := allowedKeys[keyID]; ok {
			return t.VerifyHMACSignature(hash, key)
		}
		return fmt.Errorf("failed to verify HMAC signature using key %q", keyID)
	}

	// When no specific key ID, try all keys but don't leak timing information
	var lastErr error
	validKeyFound := false
	keyCount := 0

	for _, key := range allowedKeys {
		// Count all keys that could potentially be HMAC keys
		switch key.(type) {
		case []byte, string:
			keyCount++
		default:
			continue // Skip non-HMAC compatible keys
		}

		err := t.VerifyHMACSignature(hash, key)
		if err == nil {
			validKeyFound = true
			// Continue testing all keys to prevent timing attacks
		} else {
			lastErr = err
		}
	}

	if validKeyFound {
		return nil
	}

	if keyCount == 0 {
		return fmt.Errorf("failed to verify HMAC signature using any of the allowed keys")
	}

	if lastErr != nil {
		return fmt.Errorf("failed to verify HMAC signature using any of the allowed keys: %w", lastErr)
	}
	return fmt.Errorf("failed to verify HMAC signature using any of the allowed keys")
}

// verifyRSASignatureWithKeys verifies RSA signature using the provided keys.
func (t *Token) verifyRSASignatureWithKeys(hash crypto.Hash, keyID string, allowedKeys map[string]any) error {
	if keyID != "" {
		if key, ok := allowedKeys[keyID]; ok {
			publicKey, ok := key.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("failed to verify RSA signature: public key type %T is invalid", key)
			}
			return t.VerifyRSASignature(hash, publicKey)
		}
		return fmt.Errorf("failed to verify RSA signature using key %q", keyID)
	}

	// When verifying with multiple keys, we need to handle key validation errors specially
	var keyValidationErrors []error
	keyCount := 0

	for _, key := range allowedKeys {
		publicKey, ok := key.(*rsa.PublicKey)
		if !ok {
			continue // Skip non-RSA keys
		}
		keyCount++

		err := t.VerifyRSASignature(hash, publicKey)
		if err == nil {
			return nil
		}

		// If it's a key validation error, collect it separately
		if strings.Contains(err.Error(), "RSA key validation failed") {
			keyValidationErrors = append(keyValidationErrors, err)
		}
	}

	// If we only had one RSA key and it failed key validation, return that specific error
	if keyCount == 1 && len(keyValidationErrors) == 1 {
		return keyValidationErrors[0]
	}

	// If all keys failed validation, return the first validation error
	if len(keyValidationErrors) == keyCount && len(keyValidationErrors) > 0 {
		return keyValidationErrors[0]
	}

	if keyCount == 0 {
		return fmt.Errorf("failed to verify RSA signature using any of the allowed keys")
	}

	return fmt.Errorf("failed to verify RSA signature using any of the allowed keys")
}

// verifyRSAPSSSignatureWithKeys verifies RSA-PSS signature using the provided keys.
func (t *Token) verifyRSAPSSSignatureWithKeys(hash crypto.Hash, keyID string, allowedKeys map[string]any) error {
	if keyID != "" {
		if key, ok := allowedKeys[keyID]; ok {
			publicKey, ok := key.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("failed to verify RSA-PSS signature: public key type %T is invalid", key)
			}
			return t.VerifyRSAPSSSignature(hash, publicKey)
		}
		return fmt.Errorf("failed to verify RSA-PSS signature using key %q", keyID)
	}

	// When verifying with multiple keys, we need to handle key validation errors specially
	var keyValidationErrors []error
	keyCount := 0

	for _, key := range allowedKeys {
		publicKey, ok := key.(*rsa.PublicKey)
		if !ok {
			continue // Skip non-RSA keys
		}
		keyCount++

		err := t.VerifyRSAPSSSignature(hash, publicKey)
		if err == nil {
			return nil
		}

		// If it's a key validation error, collect it separately
		if strings.Contains(err.Error(), "RSA key validation failed") {
			keyValidationErrors = append(keyValidationErrors, err)
		}
	}

	// If we only had one RSA key and it failed key validation, return that specific error
	if keyCount == 1 && len(keyValidationErrors) == 1 {
		return keyValidationErrors[0]
	}

	// If all keys failed validation, return the first validation error
	if len(keyValidationErrors) == keyCount && len(keyValidationErrors) > 0 {
		return keyValidationErrors[0]
	}

	if keyCount == 0 {
		return fmt.Errorf("failed to verify RSA-PSS signature using any of the allowed keys")
	}

	return fmt.Errorf("failed to verify RSA-PSS signature using any of the allowed keys")
}

// verifyECDSASignatureWithKeys verifies ECDSA signature using the provided keys.
// This method ensures consistent timing behavior to prevent information leakage.
func (t *Token) verifyECDSASignatureWithKeys(hash crypto.Hash, keyID string, allowedKeys map[string]any) error {
	if keyID != "" {
		if key, ok := allowedKeys[keyID]; ok {
			publicKey, ok := key.(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("failed to verify ECDSA signature: public key type %T is invalid", key)
			}
			return t.VerifyECDSASignature(hash, publicKey)
		}
		return fmt.Errorf("failed to verify ECDSA signature using key %q", keyID)
	}

	// When no specific key ID, try all keys with consistent timing
	var lastErr error
	validKeyFound := false
	keyCount := 0

	for _, key := range allowedKeys {
		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			continue // Skip non-ECDSA keys
		}
		keyCount++

		err := t.VerifyECDSASignature(hash, publicKey)
		if err == nil {
			validKeyFound = true
			// Continue testing all keys to prevent timing attacks
		} else {
			lastErr = err
		}
	}

	if validKeyFound {
		return nil
	}

	if keyCount == 0 {
		return fmt.Errorf("failed to verify ECDSA signature using any of the allowed keys")
	}

	if lastErr != nil {
		return fmt.Errorf("failed to verify ECDSA signature using any of the allowed keys: %w", lastErr)
	}
	return fmt.Errorf("failed to verify ECDSA signature using any of the allowed keys")
}

// verifyEdDSASignatureWithKeys verifies EdDSA signature using the provided keys.
// This method ensures consistent timing behavior to prevent information leakage.
func (t *Token) verifyEdDSASignatureWithKeys(keyID string, allowedKeys map[string]any) error {
	if keyID != "" {
		if key, ok := allowedKeys[keyID]; ok {
			publicKey, ok := key.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("failed to verify EdDSA signature: public key type %T is invalid", key)
			}
			return t.VerifyEdDSASignature(publicKey)
		}
		return fmt.Errorf("failed to verify EdDSA signature using key %q", keyID)
	}

	// When no specific key ID, try all keys with consistent timing
	var lastErr error
	validKeyFound := false
	keyCount := 0

	for _, key := range allowedKeys {
		publicKey, ok := key.(ed25519.PublicKey)
		if !ok {
			continue // Skip non-EdDSA keys
		}
		keyCount++

		err := t.VerifyEdDSASignature(publicKey)
		if err == nil {
			validKeyFound = true
			// Continue testing all keys to prevent timing attacks
		} else {
			lastErr = err
		}
	}

	if validKeyFound {
		return nil
	}

	if keyCount == 0 {
		return fmt.Errorf("failed to verify EdDSA signature using any of the allowed keys")
	}

	if lastErr != nil {
		return fmt.Errorf("failed to verify EdDSA signature using any of the allowed keys: %w", lastErr)
	}
	return fmt.Errorf("failed to verify EdDSA signature using any of the allowed keys")
}
