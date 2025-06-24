package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
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
func New[T SigningKey](params header.Parameters, claims ClaimsSet, key T) (*Token, error) {
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
		case Issuer, Subject:
			switch v := value.(type) {
			// good
			case string:
			// ok
			case fmt.Stringer:
				claims[name] = v.String()
			// bad
			default:
				return nil, fmt.Errorf("cannot use type %T with %q claim", v, name)
			}
		case Audience:
			switch v := value.(type) {
			// good
			case string:
			// ok
			case fmt.Stringer:
				claims[name] = v.String()
			// meh, but ok
			case []string:
			// bad
			default:
				return nil, fmt.Errorf("cannot use type %T with %q claim", v, name)
			}
		}
	}

	// Ensure the "typ" header parameter is set to "JWT", as it is required.
	if _, ok := params[header.Type]; !ok {
		params[header.Type] = Type
	} else if params[header.Type] != Type {
		return nil, fmt.Errorf("header type %q is not supported", params[header.Type])
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

	header, err := t.Header.Base64URLString()
	if err != nil {
		return "", fmt.Errorf("failed to compute header base64 string: %w", err)
	}
	b.WriteString(header)
	b.WriteString(dot)

	claims, err := t.Claims.Base64URLString()
	if err != nil {
		return "", fmt.Errorf("failed to compute claims base64 string: %w", err)
	}
	b.WriteString(claims)

	if len(t.Signature) != 0 {
		b.WriteString(dot)
		b.WriteString(base64.Encode(t.Signature))
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

// PrivateKey is a type that can be used to sign a JWT,
// such as a *rsa.PrivateKey or *ecdsa.PrivateKey.
//
// This may be a shared secret key, such as a []byte or string, but
// this is not recommended.
type PrivateKey interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey | []byte | string
}

// PublicKey is a type that can be used to verify a JWT using
// an asymmetric algorithm, such as *rsa.PublicKey or *ecdsa.PublicKey.
type PublicKey interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

// SymmetricKey is a type that can be used to sign or verify a JWT using
// a symmetric algorithm, such as HMAC.
type SymmetricKey interface {
	[]byte | string
}

// VerifyKey is a type that can be used to verify a JWT using
// either a symmetric or asymmetric algorithm.
type VerifyKey interface {
	PublicKey | SymmetricKey
}

// SigningKey is a type that can be used to sign a JWT using
// either a symmetric or asymmetric algorithm.
type SigningKey interface {
	PrivateKey | SymmetricKey
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
	// RFC 7519 Section 7.2: Validate JWT structure first
	if err := validateJWTStructure(input); err != nil {
		return nil, err
	}

	// First, we split our input into three parts, separated by dots.
	parts, err := splitToken(input)
	if err != nil {
		return nil, fmt.Errorf("failed to split token: %w", err)
	}

	// Validate base64url format for each part (RFC compliance)
	if err := validateBase64URLString(parts[0]); err != nil {
		return nil, fmt.Errorf("failed to decode JOSE header base64: %w", err)
	}
	if err := validateBase64URLString(parts[1]); err != nil {
		return nil, fmt.Errorf("failed to decode claims base64: %w", err)
	}
	if err := validateBase64URLString(parts[2]); err != nil {
		return nil, fmt.Errorf("failed to decode signature base64: %w", err)
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

	// Decode the header JSON.
	h := jws.Header{}
	err = json.Unmarshal(b, &h)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JOSE header JSON: %w", err)
	}

	// Ensure we're using JWA types instead of raw string values.
	if _, ok := h[header.Algorithm]; ok {
		h[header.Algorithm] = jwa.Algorithm(fmt.Sprintf("%v", h[header.Algorithm]))
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

	// Decode the claims JSON.
	claims := ClaimsSet{}
	err = json.Unmarshal(b, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims JSON: %w", err)
	}

	// Ensure we're using the correct types for registered claims.
	{
		if issuedAt, ok := claims[IssuedAt]; ok {
			switch v := issuedAt.(type) {
			case int64: // good
			case float64: // ok
				claims[IssuedAt] = int64(v)
			default: // bad
				return nil, fmt.Errorf("invalid type %T used for %q", v, IssuedAt)
			}
		}

		if expirationTime, ok := claims[ExpirationTime]; ok {
			switch v := expirationTime.(type) {
			case int64: // good
			case float64: // ok
				claims[ExpirationTime] = int64(v)
			default: // bad
				return nil, fmt.Errorf("invalid type %T used for %q", v, ExpirationTime)
			}
		}

		if notBefore, ok := claims[NotBefore]; ok {
			switch v := notBefore.(type) {
			case int64: // good
			case float64: // ok
				claims[NotBefore] = int64(v)
			default: // bad
				return nil, fmt.Errorf("invalid type %T used for %q", v, NotBefore)
			}
		}
	}

	// Lastly, we decode the signature base64 content.
	b, err = base64.Decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature base64: %w", err)
	}

	// Create a new token object, with the header and raw input string.
	//
	// We've deferred allocating this object until now, because we
	// didn't want to allocate it if we were going to return an error.
	token := &Token{
		Header:    h,
		Claims:    claims,
		Signature: b,
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
// because it will ensure that the givne key is of the correct type
// at compile time.
func WithKey[T VerifyKey](key T) VerifyOption {
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
// because it will ensure that the givne key is of the correct type
// at compile time.
func WithIdentifiableKey[T VerifyKey](kid string, key T) VerifyOption {
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
		return false, fmt.Errorf("invalid value %q for %q", expValue, ExpirationTime)
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
		return fmt.Errorf("failed to verify alg: %w", err)
	}

	if !slices.Contains(allowedAlgs, alg) {
		return fmt.Errorf("requested algorithm %q is not allowed", alg)
	}

	// Special handling for "none" algorithm - require explicit allowance
	if alg == jwa.None {
		if !slices.Contains(allowedAlgs, jwa.None) {
			return fmt.Errorf("algorithm %q is not allowed", alg)
		}
		// For "none" algorithm, signature must be empty
		if len(t.Signature) != 0 {
			return fmt.Errorf("signature must be empty for algorithm %q", alg)
		}
		return nil
	}

	// Require a key (symmetric or asymmetric) for all algorithms except "none".
	if len(allowedKeys) == 0 {
		return fmt.Errorf("no key provided to verify signature using algorithm %q", alg)
	}

	// There might be a key identifier we want to use.
	var keyID string
	if t.Header.Has(header.KeyID) {
		kid, err := t.Header.Get(header.KeyID)
		if err != nil {
			return fmt.Errorf("failed to get key ID: %w", err)
		}
		keyID = fmt.Sprintf("%v", kid)
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
	var secretKey []byte

	// If the key is a string, convert it to a byte slice.
	switch keyTyped := key.(type) {
	case []byte:
		secretKey = keyTyped
	case string:
		secretKey = []byte(keyTyped)
	default:
		return nil, fmt.Errorf("secret key is %T, not a byte slice or string", key)
	}

	// Ensure the secret key is not empty.
	if len(secretKey) == 0 {
		return nil, fmt.Errorf("no secret key provided, cannot complete operation")
	}

	// Validate minimum key length for security
	minKeyLength := hash.Size()
	if len(secretKey) < minKeyLength {
		return nil, fmt.Errorf("HMAC key must be at least %d bytes for %s algorithm, got %d bytes", minKeyLength, hash.String(), len(secretKey))
	}

	// Ensure the hash is available.
	if !hash.Available() {
		return nil, fmt.Errorf("requested hash is not available")
	}

	var data string

	if parts := strings.Split(t.raw, dot); len(parts) >= 2 {
		data = strings.Join(parts[0:2], dot)
	} else {
		str, err := t.Header.Base64URLString()
		if err != nil {
			return nil, fmt.Errorf("failed to generate JOSE header base64 string: %w", err)
		}
		data = str

		claims, err := t.Claims.Base64URLString()
		if err != nil {
			return nil, fmt.Errorf("failed to generate claims base64 string: %w", err)
		}
		data += (dot + claims)
	}

	h := hmac.New(hash.New, secretKey)

	b := []byte(data)
	h.Write(b)

	sig := h.Sum(nil)
	return sig, nil
}

// hmacSignatureForVerification returns the HMAC signature without key size validation
// This is used for verifying existing tokens that may have been created with weaker keys
func (t *Token) hmacSignatureForVerification(hash crypto.Hash, key any) ([]byte, error) {
	var secretKey []byte

	// If the key is a string, convert it to a byte slice.
	switch keyTyped := key.(type) {
	case []byte:
		secretKey = keyTyped
	case string:
		secretKey = []byte(keyTyped)
	default:
		return nil, fmt.Errorf("secret key is %T, not a byte slice or string", key)
	}

	// Ensure the secret key is not empty.
	if len(secretKey) == 0 {
		return nil, fmt.Errorf("no secret key provided, cannot complete operation")
	}

	// Note: Skip key size validation for verification to maintain compatibility with legacy tokens

	// Ensure the hash is available.
	if !hash.Available() {
		return nil, fmt.Errorf("requested hash is not available")
	}

	var data string

	if parts := strings.Split(t.raw, dot); len(parts) >= 2 {
		data = strings.Join(parts[0:2], dot)
	} else {
		str, err := t.Header.Base64URLString()
		if err != nil {
			return nil, fmt.Errorf("failed to generate header string: %w", err)
		}

		str2, err := t.Claims.Base64URLString()
		if err != nil {
			return nil, fmt.Errorf("failed to generate claims string: %w", err)
		}

		data = str + dot + str2
	}

	mac := hmac.New(hash.New, secretKey)
	mac.Write([]byte(data))

	sig := mac.Sum(nil)

	return sig, nil
}

// VerifyHMACSignature verifies the HMAC signature of the token using the
// given hash and key.
func (t *Token) VerifyHMACSignature(hash crypto.Hash, key any) error {
	// Use the verification-specific method that doesn't validate key size
	sig, err := t.hmacSignatureForVerification(hash, key)
	if err != nil {
		return fmt.Errorf("failed to generate HMAC signature: %w", err)
	}

	// Compare the signature to the token's signature.
	if !hmac.Equal(t.Signature, sig) {
		return fmt.Errorf("invalid HMAC signature")
	}

	return nil
}

// validateRSAKeySize validates that the RSA key meets the minimum size requirement per RFC 7518.
// RSA keys must be at least 2048 bits (256 bytes) for RSA-based JWT algorithms.
func validateRSAKeySize(key any) error {
	const minKeySize = 2048                // bits
	const minKeySizeBytes = minKeySize / 8 // 256 bytes

	var keySize int
	switch rsaKey := key.(type) {
	case *rsa.PublicKey:
		keySize = rsaKey.Size()
	case *rsa.PrivateKey:
		keySize = rsaKey.Size()
	default:
		return fmt.Errorf("invalid RSA key type: %T", key)
	}

	if keySize < minKeySizeBytes {
		return fmt.Errorf("RSA key size %d bytes (%d bits) is below minimum required %d bytes (%d bits) per RFC 7518",
			keySize, keySize*8, minKeySizeBytes, minKeySize)
	}

	return nil
}

// VerifyRSASignature verifies the RSA signature of the token using the
// given hash and public key.
func (t *Token) VerifyRSASignature(hash crypto.Hash, publicKey *rsa.PublicKey) error {
	if !hash.Available() {
		return fmt.Errorf("requested hash is not available")
	}

	if publicKey == nil {
		return fmt.Errorf("no RSA public key")
	}

	// Validate RSA key size per RFC 7518
	if err := validateRSAKeySize(publicKey); err != nil {
		return fmt.Errorf("RSA key validation failed: %w", err)
	}

	parts, err := splitToken(t.raw)
	if err != nil {
		return fmt.Errorf("failed to split token: %w", err)
	}

	data := strings.Join(parts[0:2], dot)

	h := hash.New()
	h.Write([]byte(data))

	err = rsa.VerifyPKCS1v15(publicKey, hash, h.Sum(nil), t.Signature)
	if err != nil {
		return fmt.Errorf("failed to verify RSA signature: %w", err)
	}

	return nil
}

// RSASignature returns the RSA signature of the token using the
// given hash and private key.
func (t *Token) RSASignature(hash crypto.Hash, privateKey *rsa.PrivateKey) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("requested hash is not available")
	}

	if privateKey == nil {
		return nil, fmt.Errorf("no RSA private key")
	}

	// Validate RSA key size per RFC 7518
	if err := validateRSAKeySize(privateKey); err != nil {
		return nil, fmt.Errorf("RSA key validation failed: %w", err)
	}

	if len(t.raw) == 0 {
		t.raw = t.String()
	}

	parts := strings.Split(t.raw, dot)
	if len(parts) < 2 {
		return nil, fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	data := strings.Join(parts[0:2], dot)

	h := hash.New()
	h.Write([]byte(data))

	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, h.Sum(nil))
}

// RSAPSSSignature returns the RSA-PSS signature of the token using the given hash
// and private key.
//
// This is similar to RSASignature, but uses the RSA-PSS algorithm, which
// is probabilistic, and therefore, the signature will be different each time.
func (t *Token) RSAPSSSignature(hash crypto.Hash, privateKey *rsa.PrivateKey) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("requested hash is not available")
	}

	if privateKey == nil {
		return nil, fmt.Errorf("no RSA private key")
	}

	// Validate RSA key size per RFC 7518
	if err := validateRSAKeySize(privateKey); err != nil {
		return nil, fmt.Errorf("RSA key validation failed: %w", err)
	}

	if len(t.raw) == 0 {
		t.raw = t.String()
	}

	parts := strings.Split(t.raw, dot)
	if len(parts) < 2 {
		return nil, fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	data := strings.Join(parts[0:2], dot)
	h := hash.New()
	h.Write([]byte(data))

	return rsa.SignPSS(rand.Reader, privateKey, hash, h.Sum(nil), nil)
}

// VerifyRSAPSSSignature verifies the RSA-PSS signature of the token using the
// given hash and public key.
//
// This is similar to VerifyRSASignature, but uses the RSA-PSS algorithm, which
// is probabilistic, and therefore, the signature will be different each time.
func (t *Token) VerifyRSAPSSSignature(hash crypto.Hash, publicKey *rsa.PublicKey) error {
	if !hash.Available() {
		return fmt.Errorf("requested hash is not available")
	}

	if publicKey == nil {
		return fmt.Errorf("no RSA public key")
	}

	// Validate RSA key size per RFC 7518
	if err := validateRSAKeySize(publicKey); err != nil {
		return fmt.Errorf("RSA key validation failed: %w", err)
	}

	parts, err := splitToken(t.raw)
	if err != nil {
		return fmt.Errorf("failed to split token: %w", err)
	}

	data := strings.Join(parts[0:2], dot)
	h := hash.New()
	h.Write([]byte(data))

	return rsa.VerifyPSS(publicKey, hash, h.Sum(nil), t.Signature, nil)
}

// VerifyECDSASignature verifies the ECDSA signature of the token using the
// given hash and public key.
func (t *Token) VerifyECDSASignature(hash crypto.Hash, publicKey *ecdsa.PublicKey) error {
	if !hash.Available() {
		return fmt.Errorf("requested hash is not available")
	}

	if publicKey == nil {
		return fmt.Errorf("no ECDSA public key")
	}

	parts, err := splitToken(t.raw)
	if err != nil {
		return fmt.Errorf("failed to split token: %w", err)
	}

	sig := t.Signature

	data := strings.Join(parts[0:2], dot)

	var keySize int

	switch hash {
	case crypto.SHA256:
		keySize = 32
	case crypto.SHA512:
		keySize = 66
	default:
		return fmt.Errorf("invalid hash: %T", hash)
	}

	h := hash.New()
	h.Write([]byte(data))

	if len(sig) != 2*keySize {
		return fmt.Errorf("invalid signature length for key size")
	}

	r := big.NewInt(0).SetBytes(sig[:keySize])
	s := big.NewInt(0).SetBytes(sig[keySize:])

	verified := ecdsa.Verify(publicKey, h.Sum(nil), r, s)
	if !verified {
		return fmt.Errorf("failed to validate ECDSA signature")
	}

	return nil
}

// ECDSASignature returns the ECDSA signature of the token using the
// given hash and private key.
func (t *Token) ECDSASignature(hash crypto.Hash, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("requested hash %T is not available", hash)
	}

	if privateKey == nil {
		return nil, fmt.Errorf("no ECDSA private key")
	}

	if len(t.raw) == 0 {
		t.raw = t.String()
	}

	parts := strings.Split(t.raw, dot)
	if len(parts) < 2 {
		return nil, fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	data := strings.Join(parts[0:2], dot)

	h := hash.New()
	h.Write([]byte(data))

	var curveBits int

	switch hash {
	case crypto.SHA256:
		curveBits = 256
	case crypto.SHA384:
		curveBits = 384
	case crypto.SHA512:
		curveBits = 512
	default:
		return nil, fmt.Errorf("invalid hash %T requested", hash)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ECDSA private key: %w", err)
	}

	keyCurveBits := privateKey.Curve.Params().BitSize

	if keyCurveBits != curveBits {
		return nil, fmt.Errorf("invalid ECDSA key, curve bits does not match requested hash")
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return out, nil
}

// VerifyEdDSASignature verifies the EdDSA signature of the token using the
// given public key.
func (t *Token) VerifyEdDSASignature(publicKey ed25519.PublicKey) error {
	if len(publicKey) == 0 {
		return fmt.Errorf("no EdDSA public key")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid private EdDSA public key size")
	}

	parts, err := splitToken(t.raw)
	if err != nil {
		return fmt.Errorf("failed to split token: %w", err)
	}

	sig := t.Signature

	data := strings.Join(parts[0:2], dot)

	verified := ed25519.Verify(publicKey, []byte(data), sig)
	if !verified {
		return fmt.Errorf("failed to validate ECDSA signature")
	}

	return nil
}

// EdDSASignature returns the EdDSA signature of the token using the
// given private key.
func (t *Token) EdDSASignature(privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("no EdDSA private key")
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private EdDSA private key size")
	}

	if len(t.raw) == 0 {
		t.raw = t.String()
	}

	parts := strings.Split(t.raw, dot)
	if len(parts) < 2 {
		return nil, fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	data := strings.Join(parts[0:2], dot)

	return ed25519.Sign(privateKey, []byte(data)), nil
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

	// Verify the signature of the token, which may be "none" if the
	// explictly allowed "none" algorithm is set in the config.
	err := t.VerifySignature(config.AllowedAlgorithms, config.AllowedKeys)
	if err != nil {
		return fmt.Errorf("failed to validate token signature: %w", err)
	}

	// Validate critical headers per RFC 7515 section 4.1.11
	err = t.validateCriticalHeaders(config.SupportedCriticalHeaders)
	if err != nil {
		return fmt.Errorf("failed to validate critical headers: %w", err)
	}

	// If the allowed issuers is empty, then any issuer is allowed.
	//
	// Otherwise, the issuer must be in the allowed issuers map.
	if config.AllowedIssuers != nil {
		issuer := fmt.Sprintf("%s", t.Claims[Issuer])

		if !slices.Contains(config.AllowedIssuers, issuer) {
			return fmt.Errorf("requested issuer %q is not allowed", issuer)
		}
	}

	// If the allowed audiences is empty, then any audience is allowed.
	//
	// Otherwise, the audience must be in the allowed audiences map.
	if config.AllowedAudiences != nil {
		switch aud := t.Claims[Audience].(type) {
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
		default:
			return fmt.Errorf("invalid audience type %T in token claims", t.Claims[Audience])
		}
	}

	expired, err := t.Expired(config.Clock)
	if err != nil {
		return fmt.Errorf("failed to validate token expiration: %w", err)
	}

	if expired {
		// Apply clock skew tolerance for expiration
		if config.ClockSkewTolerance > 0 {
			if expValue, ok := t.Claims[ExpirationTime]; ok {
				if expInt, ok := expValue.(int64); ok {
					exp := time.Unix(expInt, 0)
					if config.Clock().After(exp.Add(config.ClockSkewTolerance)) {
						return fmt.Errorf("token is expired")
					}
				}
			} else {
				return fmt.Errorf("token is expired")
			}
		} else {
			return fmt.Errorf("token is expired")
		}
	}

	if notBeforeValue, ok := t.Claims[NotBefore]; ok {
		if notBeforeInt, ok := notBeforeValue.(int64); ok {
			notBefore := time.Unix(notBeforeInt, 0)
			// Apply clock skew tolerance for "not before"
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

	return nil
}

// splitToken splits a JWT into its three parts, returning an error if the
// token is not in the correct format.
func splitToken(token string) ([3]string, error) {
	var parts [3]string
	var i, j int
	for k := 0; k < 2; k++ {
		j = strings.IndexByte(token[i:], '.') + i
		if j < i {
			return [3]string{}, fmt.Errorf("jwt: incorrect number of JWT parts")
		}
		parts[k] = token[i:j]
		i = j + 1
	}
	parts[2] = token[i:]
	return parts, nil
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

// validateJWTStructure performs RFC 7519 compliant validation of JWT structure
// before attempting to parse individual components.
func validateJWTStructure(input string) error {
	// Additional basic structural validation
	if len(input) == 0 {
		return fmt.Errorf("jwt: incorrect number of JWT parts")
	}

	return nil
}

// validateBase64URLString checks if a string contains only valid base64url characters
// according to RFC 4648 Section 5, which is referenced by JWT specifications.
func validateBase64URLString(s string) error {
	// Base64url alphabet: A-Z, a-z, 0-9, -, _
	// Padding with '=' is allowed but not required in base64url
	for _, char := range s {
		if !((char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '=') {
			return fmt.Errorf("jwt: invalid base64url character: %c", char)
		}
	}
	return nil
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

	for _, key := range allowedKeys {
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

	return fmt.Errorf("failed to verify RSA-PSS signature using any of the allowed keys")
}

// verifyECDSASignatureWithKeys verifies ECDSA signature using the provided keys.
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

	for _, key := range allowedKeys {
		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			continue // Skip non-ECDSA keys
		}
		err := t.VerifyECDSASignature(hash, publicKey)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("failed to verify ECDSA signature using any of the allowed keys")
}

// verifyEdDSASignatureWithKeys verifies EdDSA signature using the provided keys.
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

	for _, key := range allowedKeys {
		publicKey, ok := key.(ed25519.PublicKey)
		if !ok {
			continue // Skip non-EdDSA keys
		}
		err := t.VerifyEdDSASignature(publicKey)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("failed to verify EdDSA signature using any of the allowed keys")
}

// validateCriticalHeaders validates critical headers per RFC 7515 section 4.1.11.
// If a "crit" header is present, it must contain only extension header parameter names
// that this application understands and can process.
func (t *Token) validateCriticalHeaders(supportedCriticalHeaders []string) error {
	// Check if the token has a "crit" (critical) header parameter
	critValue, err := t.Header.Get(header.Critical)
	if err != nil {
		// If there's no "crit" header, validation passes
		return nil
	}

	// The "crit" header must be an array of strings
	critArray, ok := critValue.([]any)
	if !ok {
		return fmt.Errorf("critical header parameter \"crit\" must be an array")
	}

	// RFC 7515 section 4.1.11: The "crit" header parameter MUST NOT be empty
	if len(critArray) == 0 {
		return fmt.Errorf("critical header parameter \"crit\" must not be empty")
	}

	// Convert to string slice and validate each critical header
	critHeaders := make([]string, len(critArray))
	for i, v := range critArray {
		critHeader, ok := v.(string)
		if !ok {
			return fmt.Errorf("critical header parameter names must be strings")
		}
		critHeaders[i] = critHeader
	}

	// RFC 7515 section 4.1.11: The "crit" header parameter MUST NOT include
	// any header parameter names that are defined by RFC 7515
	standardHeaders := []string{
		header.Algorithm,
		header.JWKSetURL,
		header.JSONWebKey,
		header.KeyID,
		header.X509URL,
		header.X509CertificateChain,
		header.X509CertificateSHA1Thumbprint,
		header.X509CertificateSHA256Thumbprint,
		header.Type,
		header.ContentType,
		header.Critical,
	}
	for _, critHeader := range critHeaders {
		if slices.Contains(standardHeaders, critHeader) {
			return fmt.Errorf("critical header parameter %q is a standard header and cannot be marked as critical", critHeader)
		}
	}

	// Now validate each critical header parameter
	for _, critHeader := range critHeaders {
		// RFC 7515 section 4.1.11: Critical header parameter names MUST be understood
		if !slices.Contains(supportedCriticalHeaders, critHeader) {
			return fmt.Errorf("unsupported critical header parameter: %q", critHeader)
		}

		// Verify that the critical header parameter is actually present in the header
		if !t.Header.Has(critHeader) {
			return fmt.Errorf("critical header parameter %q is missing from header", critHeader)
		}
	}

	return nil
}
