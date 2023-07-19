package jwt

import (
	"bytes"
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
	"strings"
	"time"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"golang.org/x/exp/slices"
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
const Type header.ParamaterName = "JWT"

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

	// Raw is the (original) string representation of the JWT.
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
// Algorithm(s) to Supported Key Type(s):
//   - HS256, HS384, HS512: []byte or string
//   - RS256: *rsa.PrivateKey
//   - ES256: *ecdsa.PrivateKey
func New(params header.Parameters, claims ClaimsSet, key any) (*Token, error) {
	// Given params set cannot be empty.
	if len(params) == 0 {
		return nil, fmt.Errorf("cannot create token with empty header parameters")
	}

	// Given claims set cannot be emtpy.
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
				return nil, fmt.Errorf("cannot use %T with %q", v, ExpirationTime)
			}
		case Issuer, Subject, Audience:
			switch v := value.(type) {
			// good
			case string:
			// ok
			case fmt.Stringer:
				claims[name] = v.String()
			// bad
			default:
				return nil, fmt.Errorf("cannot use %T with %q", v, ExpirationTime)
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

// computeString computes the string representation of the token,
// which is used for signing and verifying the token.
func (t *Token) computeString() string {
	buff := bytes.NewBuffer(nil)

	header, err := t.Header.Base64URLString()
	if err != nil {
		buff.Write([]byte(fmt.Sprintf("<invalid-header %#+v>.", header)))
	} else {
		buff.Write([]byte(header + "."))
	}

	if len(t.Claims) > 0 {
		buff.WriteString(t.Claims.String())
	}

	if len(t.Signature) != 0 {
		buff.Write([]byte("."))
		buff.WriteString(base64.Encode(t.Signature))
	}

	if len(t.raw) == 0 {
		t.raw = buff.String()
	}

	return buff.String()
}

// String returns the string representation of the token, which is
// the raw JWT string of three base64url encoded parts, separated
// by a period.
func (t *Token) String() string {
	// Return the raw string if it is set.
	if len(t.raw) != 0 {
		return t.raw
	}

	// If there raw string is not set, compute it.
	return t.computeString()
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
// signature of the token. Use ParseAndVerify to parse
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
	token := &Token{}

	token.raw = input

	fields := strings.Split(input, ".")

	if len(fields) != 3 {
		return nil, fmt.Errorf("invalid number of fields in JWT: %d", len(fields))
	}

	b, err := base64.Decode(fields[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JOSE header base64: %w", err)
	}
	h := jws.Header{}
	err = json.NewDecoder(bytes.NewReader(b)).Decode(&h)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JOSE header JSON: %w", err)
	}
	token.Header = h

	// ensure using JWA types instead of raw string
	if _, ok := token.Header[header.Algorithm]; ok {
		token.Header[header.Algorithm] = jwa.Algorithm(fmt.Sprintf("%v", token.Header[header.Algorithm]))
	}

	b, err = base64.Decode(fields[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims base64: %w", err)
	}
	claims := ClaimsSet{}
	err = json.NewDecoder(bytes.NewReader(b)).Decode(&claims)
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims JSON: %w", err)
	}
	token.Claims = claims

	for claimName, claimValue := range token.Claims {
		// parsing JSON values into an interface can be tricky
		switch claimName {
		case IssuedAt, ExpirationTime, NotBefore:
			switch v := claimValue.(type) {
			case int64: // good
			case float64: // ok
				token.Claims[claimName] = int64(v)
			default: // bad
				return nil, fmt.Errorf("invalid type %T used for %q", v, claimName)
			}
		}
	}

	b, err = base64.Decode(fields[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature base64: %w", err)
	}
	token.Signature = b

	return token, nil
}

// Set is a set of comparable values for JWT operations.
type Set[T comparable] map[T]struct{}

// NewSet creates a new set of strings.
func NewSet(strings ...string) Set[string] {
	m := make(Set[string])
	for _, s := range strings {
		m[s] = struct{}{}
	}
	return m
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

	// AllowedKeys is a set of allowed keys for the JWT.
	//
	// If not set, then verification will fail if the algorithm
	// is not "none".
	AllowedKeys []any

	// Clock is a function that returns the current time.
	//
	// This is used to verify the "exp", "nbf", and "iat" claims.
	//
	// If not set, then time.Now will be used.
	Clock func() time.Time

	// TODO(kent): add more verify options
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

// WithKey appends a key to the set of allowed keys for the JWT.
//
// This is the preferred way to add a key to the set of allowed keys,
// because it will ensure that the givne key is of the correct type
// at compile time.
func WithKey[T VerifyKey](key T) VerifyOption {
	return func(vc *VerifyConfig) error {
		vc.AllowedKeys = append(vc.AllowedKeys, key)
		return nil
	}
}

// WithKeys sets the allowed keys for the JWT.
func WithKeys(values ...any) VerifyOption {
	return func(vc *VerifyConfig) error {
		vc.AllowedKeys = values
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
	jwa.EdDSA: crypto.Hash(0), // no hashing for EdDSA
}

// VerifySignature verifies the signature of the token using the
// given verification configuration options.
//
// # Warning
//
// This only verifies the signature, and does not verify any
// other claims, such as expiration time, issuer, audience, etc.
func (t *Token) VerifySignature(allowedAlgs []string, allowedKeys ...any) error {
	alg, err := t.Header.Algorithm()
	if err != nil {
		return fmt.Errorf("failed to verify alg: %w", err)
	}

	if !slices.Contains(allowedAlgs, alg) {
		return fmt.Errorf("requested algorithm %q is not allowed", alg)
	}

	// Require a key (symmetric or asymmetric) for all algorithms except "none".
	if len(allowedKeys) == 0 && !slices.Contains(allowedAlgs, jwa.None) {
		return fmt.Errorf("no key provided to verify signature using algorithm %q", alg)
	}

	// Verify the signature based on the algorithm.
	switch alg {
	case jwa.HS256, jwa.HS384, jwa.HS512:
		for _, key := range allowedKeys {
			err := t.VerifyHMACSignature(algHash[alg], key)
			if err == nil {
				return nil
			}
		}
		return fmt.Errorf("failed to verify HMAC signature using any of the allowed keys")
	case jwa.RS256, jwa.RS384, jwa.RS512:
		for _, key := range allowedKeys {
			publicKey, ok := key.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("failed to verify RSA signature: public key type %T is invalid", key)
			}
			err := t.VerifyRSASignature(algHash[alg], publicKey)
			if err == nil {
				return nil
			}
		}
		return fmt.Errorf("failed to verify RSA signature using any of the allowed keys")
	case jwa.ES256, jwa.ES384, jwa.ES512:
		for _, key := range allowedKeys {
			publicKey, ok := key.(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("failed to verify ECDSA signature: public key type %T is invalid", key)
			}
			err := t.VerifyECDSASignature(algHash[alg], publicKey)
			if err == nil {
				return nil
			}
		}
		return fmt.Errorf("failed to verify ECDSA signature using any of the allowed keys")
	case jwa.EdDSA:
		for _, key := range allowedKeys {
			publicKey, ok := key.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("failed to verify EdDSA signature: public key type %T is invalid", key)
			}
			err := t.VerifyEdDSASignature(publicKey)
			if err == nil {
				return nil
			}
		}
		return fmt.Errorf("failed to verify EdDSA signature using any of the allowed keys")
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

	// Ensure the hash is available.
	if !hash.Available() {
		return nil, fmt.Errorf("requested hash is not available")
	}

	var data string

	if parts := strings.Split(t.raw, "."); len(parts) >= 2 {
		data = strings.Join(parts[0:2], ".")
	} else {
		if len(t.Header) > 0 {
			str, err := t.Header.Base64URLString()
			if err != nil {
				return nil, fmt.Errorf("failed to generate JOSE header base64 string: %w", err)
			}
			data = str
		}
		if len(t.Claims) > 0 {
			data += ("." + t.Claims.String())
		}
	}

	h := hmac.New(hash.New, secretKey)

	b := []byte(data)
	h.Write(b)

	sig := h.Sum(nil)
	return sig, nil
}

// VerifyHMACSignature verifies the HMAC signature of the token using the
// given hash and key.
func (t *Token) VerifyHMACSignature(hash crypto.Hash, key any) error {
	// Compute the HMAC signature.
	sig, err := t.HMACSignature(hash, key)
	if err != nil {
		return fmt.Errorf("failed to generate HMAC signature: %w", err)
	}

	// Compare the signature to the token's signature.
	if !hmac.Equal(t.Signature, []byte(sig)) {
		return fmt.Errorf("invalid HMAC signature")
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

	parts, err := splitToken(t.raw)
	if err != nil {
		return fmt.Errorf("failed to split token: %w", err)
	}

	data := strings.Join(parts[0:2], ".")

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

	if len(t.raw) == 0 {
		t.raw = t.String()
	}

	parts := strings.Split(t.raw, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	data := strings.Join(parts[0:2], ".")

	h := hash.New()
	h.Write([]byte(data))

	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, h.Sum(nil))
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

	data := strings.Join(parts[0:2], ".")

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

	parts := strings.Split(t.raw, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	data := strings.Join(parts[0:2], ".")

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

	data := strings.Join(parts[0:2], ".")

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

	parts := strings.Split(t.raw, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	data := strings.Join(parts[0:2], ".")

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

	t.raw = t.computeString()

	return t.Signature, nil
}

var defaultAllowedAlogrithms = []jwa.Algorithm{
	jwa.RS256, jwa.RS384, jwa.RS512,
	jwa.ES256, jwa.ES384, jwa.ES512,
	jwa.HS256, jwa.HS384, jwa.HS512,
	jwa.PS256, jwa.PS384, jwa.PS512,
	jwa.EdDSA,
}

func DefaultAllowedAlogrithms() []jwa.Algorithm {
	return defaultAllowedAlogrithms
}

// Verify is used to verify a signed Token object with the given config options.
// If this fails for any reason, an error is returned.
func (t *Token) Verify(opts ...VerifyOption) error {
	// Set default config values that can be overridden by options.
	config := &VerifyConfig{
		InsecureAllowNone: false,
		AllowedAlgorithms: []jwa.Algorithm{
			jwa.RS256, jwa.RS384, jwa.RS512,
			jwa.ES256, jwa.ES384, jwa.ES512,
			jwa.HS256, jwa.HS384, jwa.HS512,
			jwa.PS256, jwa.PS384, jwa.PS512,
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
	err := t.VerifySignature(config.AllowedAlgorithms, config.AllowedKeys...)
	if err != nil {
		return fmt.Errorf("failed to validate token signature: %w", err)
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
		audience := fmt.Sprintf("%s", t.Claims[Audience])

		if !slices.Contains(config.AllowedAudiences, audience) {
			return fmt.Errorf("requested audience %q is not allowed", audience)
		}
	}

	expired, err := t.Expired(time.Now)
	if err != nil {
		return fmt.Errorf("failed to validate token expiration: %w", err)
	}

	if expired {
		return fmt.Errorf("token is expired")
	}

	if notBeforeValue, ok := t.Claims[NotBefore]; ok {
		if notBeforeInt, ok := notBeforeValue.(int64); ok {
			notBefore := time.Unix(notBeforeInt, 0)
			if time.Now().Before(notBefore) {
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
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return [3]string{}, fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
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
	string | Token
}

// SetHTTPAuthorizationHeader sets the Authorization header of an HTTP request
// to the given JWT. The JWT is prefixed with "Bearer ", as required by the
// HTTP Authorization header specification.
//
// https://tools.ietf.org/html/rfc6750#section-2.1
func SetHTTPAuthorizationHeader[T HTTPHeaderValue](r *http.Request, jwt T) {
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))
}
