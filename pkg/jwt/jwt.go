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
	"strings"
	"time"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
)

// HeaderType "JWT" is used as the "typ" for all JSON Web Tokens.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
const HeaderType header.ParamaterName = "JWT"

// Token is a decoded JSON Web Token, a string representing a
// set of claims as a JSON object that is encoded in a JWS or
// JWE, enabling the claims to be digitally signed or MACed
// and/or encrypted.
//
// At this time, only JWS JWTs are supported. In other words,
// these tokens are only signed, not encrypted.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-1
type Token struct {
	Header    header.Parameters
	Claims    ClaimsSet
	Signature []byte
	raw       string
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
//  - HS256, HS384, HS512: []byte or string
//  - RS256: *rsa.PrivateKey
//  - ES256: *ecdsa.PrivateKey
func New(params header.Parameters, claims ClaimsSet, key interface{}) (*Token, error) {
	// Given params set cannot be empty.
	if len(params) == 0 {
		return nil, ErrNoJWTHeaderParametersSet
	}

	// Given claims set cannot be emtpy.
	if len(claims) == 0 {
		return nil, ErrNoClaimSet
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
				return nil, NewInvalidTypeError(fmt.Errorf("cannot use %T with %q", v, ExpirationTime))
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
				return nil, NewInvalidTypeError(fmt.Errorf("cannot use %T with %q", v, ExpirationTime))
			}
		}
	}

	// Header type parameter "typ" is always "JWT".
	params[header.Type] = header.TypeJWT

	// Create a token, in preparation to sign it.
	token := &Token{
		Header: params,
		Claims: claims,
	}

	// Sign it.
	_, err := token.Sign(SecretKey(key))
	if err != nil {
		return nil, NewSigningError(err)
	}

	return token, nil
}

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

	if t.raw == "" {
		t.raw = buff.String()
	}

	return buff.String()
}

func (t *Token) String() string {
	if t.raw != "" {
		return t.raw
	}

	return t.computeString()
}

// ParseString parses an input JWT string, and returns a Token
// or an error if the JWT fails to parse.
func ParseString(input string) (*Token, error) {
	fields := strings.Split(input, ".")

	token := &Token{}

	token.raw = input

	if len(fields) >= 1 {
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
	}

	if len(fields) >= 2 {
		b, err := base64.Decode(fields[1])
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
	}

	if len(fields) == 3 {
		b, err := base64.Decode(fields[2])
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature base64: %w", err)
		}
		token.Signature = b
	}

	return token, nil
}

type Issuers = map[string]struct{}

type Config struct {
	AllowNone         bool
	AllowedAlgorithms jwa.AllowedAlgorithms
	AllowedIssuers    Issuers
	SecretKey         interface{}
	PublicKey         interface{}

	// TODO(kent): add more verify options for other algorithms
}

type ConfigOption = func(*Config) error

func AllowNoneAlgorithm(value bool) ConfigOption {
	return func(vc *Config) error {
		vc.AllowNone = value
		return nil
	}
}

func AllowedIssuers(issuers ...string) ConfigOption {
	return func(vc *Config) error {
		if vc.AllowedIssuers == nil {
			vc.AllowedIssuers = Issuers{}
		}
		for _, issuer := range issuers {
			vc.AllowedIssuers[issuer] = struct{}{}
		}
		return nil
	}
}

func AllowedAlgorithms(algs ...jwa.Algorithm) ConfigOption {
	return func(vc *Config) error {
		vc.AllowedAlgorithms = jwa.NewAllowedAlgorithms(algs...)
		return nil
	}
}

func SecretKey(value interface{}) ConfigOption {
	return func(vc *Config) error {
		vc.SecretKey = value
		return nil
	}
}

func PublicKey(pubKey interface{}) ConfigOption {
	return func(vc *Config) error {
		vc.PublicKey = pubKey
		return nil
	}
}

func RSAPublicKey(pubKey *rsa.PublicKey) ConfigOption {
	return func(vc *Config) error {
		vc.PublicKey = pubKey
		return nil
	}
}

func ECDSAPublicKey(pubKey *ecdsa.PublicKey) ConfigOption {
	return func(vc *Config) error {
		vc.PublicKey = pubKey
		return nil
	}
}

func EdDSAPublicKey(pubKey ed25519.PublicKey) ConfigOption {
	return func(vc *Config) error {
		vc.PublicKey = pubKey
		return nil
	}
}

func PrivateKey(privKey interface{}) ConfigOption {
	return func(vc *Config) error {
		vc.SecretKey = privKey
		return nil
	}
}

func RSAPrivateKey(privKey *rsa.PrivateKey) ConfigOption {
	return func(vc *Config) error {
		vc.SecretKey = privKey
		return nil
	}
}

func ECDSAPrivateKey(privKey *ecdsa.PrivateKey) ConfigOption {
	return func(vc *Config) error {
		vc.SecretKey = privKey
		return nil
	}
}

func EdDSAPrivateKey(privKey ed25519.PrivateKey) ConfigOption {
	return func(vc *Config) error {
		vc.SecretKey = privKey
		return nil
	}
}

func (t *Token) Expired() (bool, error) {
	expValue, ok := t.Claims[ExpirationTime]
	if !ok {
		return false, nil
	}
	expInt, ok := expValue.(int64)
	if !ok {
		return false, fmt.Errorf("invalid value %q for %q", expValue, ExpirationTime)
	}
	exp := time.Unix(expInt, 0)

	return exp.Before(time.Now()), nil
}

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

func (t *Token) VerifySignature(veryifyOptions ...ConfigOption) error {
	config := &Config{
		AllowNone:         false,
		AllowedAlgorithms: jwa.DefaultAllowedAlgorithms(),
	}

	for _, opt := range veryifyOptions {
		err := opt(config)
		if err != nil {
			return fmt.Errorf("verify signature option error: %w", err)
		}
	}

	if len(config.AllowedIssuers) > 0 {
		issuer := fmt.Sprintf("%v", t.Claims[Issuer])

		if _, ok := config.AllowedIssuers[issuer]; !ok {
			return fmt.Errorf("requested issuer %q is not allowed", issuer)
		}
	}

	alg, err := t.Header.Algorithm()
	if err != nil {
		return fmt.Errorf("failed to verify alg: %w", err)
	}

	if len(config.AllowedAlgorithms) > 0 {
		if _, ok := config.AllowedAlgorithms[alg]; !ok {
			return fmt.Errorf("requested algorithm %q is not allowed", alg)
		}
	}

	if alg == jwa.None && !config.AllowNone {
		return fmt.Errorf("requested dangerous algorithm %q is not allowed", alg)
	}

	switch alg {
	case jwa.HS256:
		return t.VerifyHMACSignature(crypto.SHA256, config.SecretKey)
	case jwa.HS384:
		return t.VerifyHMACSignature(crypto.SHA384, config.SecretKey)
	case jwa.HS512:
		return t.VerifyHMACSignature(crypto.SHA256, config.SecretKey)
	case jwa.RS256:
		publicKey, ok := config.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to verify RSA signature: public key option %T is invalid", config.PublicKey)
		}
		return t.VerifyRSASignature(crypto.SHA256, publicKey)
	case jwa.RS384:
		publicKey, ok := config.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to verify RSA signature: public key option %T is invalid", config.PublicKey)
		}
		return t.VerifyRSASignature(crypto.SHA384, publicKey)
	case jwa.RS512:
		publicKey, ok := config.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to verify RSA signature: public key option %T is invalid", config.PublicKey)
		}
		return t.VerifyRSASignature(crypto.SHA512, publicKey)
	case jwa.ES256:
		publicKey, ok := config.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to verify ECDSA signature: public key option %T is invalid", config.PublicKey)
		}
		return t.VerifyECDSASignature(crypto.SHA256, publicKey)
	case jwa.ES384:
		publicKey, ok := config.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to verify ECDSA signature: public key option %T is invalid", config.PublicKey)
		}
		return t.VerifyECDSASignature(crypto.SHA384, publicKey)
	case jwa.ES512:
		publicKey, ok := config.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to verify ECDSA signature: public key option %T is invalid", config.PublicKey)
		}
		return t.VerifyECDSASignature(crypto.SHA512, publicKey)
	case jwa.EdDSA:
		publicKey, ok := config.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("failed to verify EdDSA signature: public key option %T is invalid", config.PublicKey)
		}
		return t.VerifyEdDSASignature(publicKey)
	default:
		return fmt.Errorf("%q algorithm not implemented", alg)
	}
}

func (t *Token) HMACSignature(hash crypto.Hash, key interface{}) ([]byte, error) {
	var secretKey []byte

	switch keyTyped := key.(type) {
	case []byte:
		secretKey = keyTyped
	case string:
		secretKey = []byte(keyTyped)
	default:
		return nil, fmt.Errorf("secret key is %T, not a byte slice or string", key)
	}

	if len(secretKey) == 0 {
		return nil, fmt.Errorf("no secret key provided, cannot complete operation")
	}

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

func (t *Token) VerifyHMACSignature(hash crypto.Hash, key interface{}) error {
	var secretKey []byte

	switch keyTyped := key.(type) {
	case []byte:
		secretKey = keyTyped
	case string:
		secretKey = []byte(keyTyped)
	default:
		return fmt.Errorf("secret key is %T, not a byte slice or string", key)
	}

	sig, err := t.HMACSignature(hash, secretKey)
	if err != nil {
		return fmt.Errorf("failed to generate HMAC signature: %w", err)
	}

	if !hmac.Equal(t.Signature, []byte(sig)) {
		return fmt.Errorf("invalid HMAC signature")
	}

	return nil
}

func (t *Token) VerifyRSASignature(hash crypto.Hash, publicKey *rsa.PublicKey) error {
	if !hash.Available() {
		return fmt.Errorf("requested hash is not available")
	}

	if publicKey == nil {
		return fmt.Errorf("no RSA public key")
	}

	parts := strings.Split(t.raw, ".")
	if len(parts) < 3 {
		return fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	data := strings.Join(parts[0:2], ".")

	h := hash.New()
	h.Write([]byte(data))

	err := rsa.VerifyPKCS1v15(publicKey, hash, h.Sum(nil), t.Signature)
	if err != nil {
		return fmt.Errorf("failed to verify RSA signature: %w", err)
	}

	return nil
}

func (t *Token) RSASignature(hash crypto.Hash, privateKey *rsa.PrivateKey) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("requested hash is not available")
	}

	if privateKey == nil {
		return nil, fmt.Errorf("no RSA private key")
	}

	if t.raw == "" {
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

func (t *Token) VerifyECDSASignature(hash crypto.Hash, publicKey *ecdsa.PublicKey) error {
	if !hash.Available() {
		return fmt.Errorf("requested hash is not available")
	}

	if publicKey == nil {
		return fmt.Errorf("no ECDSA public key")
	}

	parts := strings.Split(t.raw, ".")
	if len(parts) < 3 {
		return fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
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

func (t *Token) ECDSASignature(hash crypto.Hash, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("requested hash %T is not available", hash)
	}

	if privateKey == nil {
		return nil, fmt.Errorf("no ECDSA private key")
	}

	if t.raw == "" {
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

func (t *Token) VerifyEdDSASignature(publicKey ed25519.PublicKey) error {
	if publicKey == nil || len(publicKey) == 0 {
		return fmt.Errorf("no EdDSA public key")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid private EdDSA public key size")
	}

	parts := strings.Split(t.raw, ".")
	if len(parts) < 3 {
		return fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	sig := t.Signature

	data := strings.Join(parts[0:2], ".")

	verified := ed25519.Verify(publicKey, []byte(data), sig)
	if !verified {
		return fmt.Errorf("failed to validate ECDSA signature")
	}

	return nil
}

func (t *Token) EdDSASignature(privateKey ed25519.PrivateKey) ([]byte, error) {
	if privateKey == nil || len(privateKey) == 0 {
		return nil, fmt.Errorf("no EdDSA private key")
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private EdDSA private key size")
	}

	if t.raw == "" {
		t.raw = t.String()
	}

	parts := strings.Split(t.raw, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("incorrect number of JWT parts: %d", len(parts))
	}

	data := strings.Join(parts[0:2], ".")

	return ed25519.Sign(privateKey, []byte(data)), nil
}

func (t *Token) Sign(options ...ConfigOption) ([]byte, error) {
	config := &Config{}

	for _, opt := range options {
		err := opt(config)
		if err != nil {
			return nil, fmt.Errorf("sign config option error: %w", err)
		}
	}

	if len(config.AllowedIssuers) > 0 {
		issuer := fmt.Sprintf("%v", t.Claims[Issuer])

		if _, ok := config.AllowedIssuers[issuer]; !ok {
			return nil, fmt.Errorf("requested issuer %q is not allowed", issuer)
		}

	}

	alg, err := t.Header.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("failed to verify alg: %w", err)
	}

	if len(config.AllowedAlgorithms) > 0 {
		if _, ok := config.AllowedAlgorithms[alg]; !ok {
			return nil, fmt.Errorf("requested algorithm %q is not allowed", alg)
		}
	}

	if alg == jwa.None && !config.AllowNone {
		return nil, fmt.Errorf("requested dangerous algorithm %q is not allowed", alg)
	}

	typ, err := t.Header.Type()
	if err != nil {
		return nil, fmt.Errorf("invalid JWT header type: %w", err)
	}

	switch typ {
	case header.TypeJWT:
	default:
		return nil, fmt.Errorf("type %q not implemented", typ)
	}

	switch alg {
	case jwa.HS256:
		sig, err := t.HMACSignature(crypto.SHA256, config.SecretKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.HS384:
		sig, err := t.HMACSignature(crypto.SHA384, config.SecretKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.HS512:
		sig, err := t.HMACSignature(crypto.SHA512, config.SecretKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.ES256:
		privateKey, ok := config.SecretKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for ECDSA SHA256", config.SecretKey)
		}
		sig, err := t.ECDSASignature(crypto.SHA256, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	case jwa.RS256:
		privateKey, ok := config.SecretKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secret key type %T for RSA SHA256", config.SecretKey)
		}
		sig, err := t.RSASignature(crypto.SHA256, privateKey)
		if err != nil {
			return nil, err
		}
		t.Signature = sig
	default:
		return nil, fmt.Errorf("algorithm %q not implemented", alg)
	}

	t.raw = t.computeString()

	return t.Signature, nil
}

// Verify is used to verify a signed Token object with the given config options.
// If this fails for any reason, an error is returned.
func (t *Token) Verify(opts ...ConfigOption) error {
	err := t.VerifySignature(opts...)
	if err != nil {
		return fmt.Errorf("failed to validate token signature: %w", err)
	}

	expired, err := t.Expired()
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
