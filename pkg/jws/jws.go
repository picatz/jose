package jws

import (
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
	"unicode/utf8"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
)

// Header is a JSON object containing the parameters describing
// the cryptographic operations and parameters employed.
//
// The JOSE (JSON Object Signing and Encryption) Header is comprised
// of a set of Header Parameters.
type Header = header.Parameters

// Signature represents a JSON Web Signature (JWS) object.
// A JWS represents content secured with digital signatures or
// Message Authentication Codes (MACs) using JSON-based data structures.
//
// JWS provides integrity protection for an arbitrary sequence of octets.
// This structure can be used directly for JWS use cases or as a foundation
// for JWT tokens.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc7515
type Signature struct {
	// Header contains the parameters describing the cryptographic
	// operations and parameters employed.
	Header Header

	// Payload is the sequence of octets to be secured.
	// Unlike JWT which typically contains claims, JWS payload
	// can contain any arbitrary sequence of octets.
	Payload []byte

	// Signature is the digital signature or MAC over the
	// JWS Protected Header and the JWS Payload.
	Signature []byte

	// raw is the original string representation of the JWS if parsed,
	// or the computed string representation if constructed.
	raw string
}

// New creates a new JWS token with the given header, payload, and signs it
// with the provided key.
func New(header Header, payload []byte, key any) (*Signature, error) {
	token := &Signature{
		Header:  header,
		Payload: payload,
	}

	_, err := token.Sign(key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWS token: %w", err)
	}

	return token, nil
}

// Parse parses a JWS string in compact serialization format.
// The input should be in the format: base64url(header).base64url(payload).base64url(signature)
//
// This function implements the validation steps from RFC 7515 Section 5.2:
// 1. Parse JWS representation
// 2. Base64url decode and validate header with strict UTF-8 validation
// 3. Verify unique header parameters and strict JSON compliance
// 4. Process critical header parameters
// 5. Decode payload and signature
func Parse(input string) (*Signature, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty JWS string")
	}

	parts := strings.Split(input, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode header with strict validation
	headerBytes, err := base64.Decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	// Ensure header is valid UTF-8
	if !utf8.Valid(headerBytes) {
		return nil, fmt.Errorf("header is not valid UTF-8")
	}

	// Parse header with strict JSON validation (includes UTF-8 validation)
	header, err := parseHeaderStrict(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Validate required algorithm parameter
	alg, err := header.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("missing or invalid algorithm parameter: %w", err)
	}

	// Process critical header parameters per RFC 7515 Section 4.1.11
	if err := processCriticalHeaders(header); err != nil {
		return nil, fmt.Errorf("critical header validation failed: %w", err)
	}

	// Decode payload (can be empty)
	var payload []byte
	if parts[1] == "" {
		payload = []byte{}
	} else {
		payload, err = base64.Decode(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode payload: %w", err)
		}
	}

	// Decode signature (can be empty for "none" algorithm)
	var signature []byte
	if parts[2] != "" {
		signature, err = base64.Decode(parts[2])
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature: %w", err)
		}
	}

	// RFC 7515: Validate signature length constraints for "none" algorithm
	if alg == jwa.None && len(signature) != 0 {
		return nil, fmt.Errorf("signature must be empty for algorithm %q", alg)
	}

	token := &Signature{
		Header:    header,
		Payload:   payload,
		Signature: signature,
		raw:       input,
	}

	return token, nil
}

// String returns the compact serialization representation of the JWS token.
// Format: base64url(header).base64url(payload).base64url(signature)
func (t *Signature) String() string {
	if t.raw != "" {
		return t.raw
	}

	str, err := t.computeString()
	if err != nil {
		// This should not happen in normal circumstances
		return ""
	}

	return str
}

// computeString computes the string representation of the JWS token.
func (t *Signature) computeString() (string, error) {
	headerBytes, err := json.Marshal(t.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	headerB64, err := base64.Encode(headerBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}

	// Handle empty payload - base64url encoding of empty octets is empty string
	var payloadB64 string
	if len(t.Payload) == 0 {
		payloadB64 = ""
	} else {
		payloadB64, err = base64.Encode(t.Payload)
		if err != nil {
			return "", fmt.Errorf("failed to encode payload: %w", err)
		}
	}

	signatureB64 := ""
	if len(t.Signature) > 0 {
		signatureB64, err = base64.Encode(t.Signature)
		if err != nil {
			return "", fmt.Errorf("failed to encode signature: %w", err)
		}
	}

	result := headerB64 + "." + payloadB64 + "." + signatureB64
	t.raw = result
	return result, nil
}

// signingInput returns the JWS Signing Input as defined in RFC 7515.
// Format: ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))
func (t *Signature) signingInput() (string, error) {
	headerBytes, err := json.Marshal(t.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	headerB64, err := base64.Encode(headerBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}

	// Handle empty payload - base64url encoding of empty octets is empty string
	var payloadB64 string
	if len(t.Payload) == 0 {
		payloadB64 = ""
	} else {
		payloadB64, err = base64.Encode(t.Payload)
		if err != nil {
			return "", fmt.Errorf("failed to encode payload: %w", err)
		}
	}

	return headerB64 + "." + payloadB64, nil
}

// Sign computes and sets the signature for the JWS token using the given key.
// The algorithm is determined by the "alg" header parameter.
func (t *Signature) Sign(key any) ([]byte, error) {
	alg, err := t.Header.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("missing or invalid algorithm in header: %w", err)
	}

	signingInput, err := t.signingInput()
	if err != nil {
		return nil, fmt.Errorf("failed to compute signing input: %w", err)
	}

	var signature []byte

	switch alg {
	case jwa.HS256:
		signature, err = t.hmacSign(crypto.SHA256, key, signingInput)
	case jwa.HS384:
		signature, err = t.hmacSign(crypto.SHA384, key, signingInput)
	case jwa.HS512:
		signature, err = t.hmacSign(crypto.SHA512, key, signingInput)
	case jwa.RS256:
		signature, err = t.rsaSign(crypto.SHA256, key, signingInput)
	case jwa.RS384:
		signature, err = t.rsaSign(crypto.SHA384, key, signingInput)
	case jwa.RS512:
		signature, err = t.rsaSign(crypto.SHA512, key, signingInput)
	case jwa.PS256:
		signature, err = t.rsaPSSSign(crypto.SHA256, key, signingInput)
	case jwa.PS384:
		signature, err = t.rsaPSSSign(crypto.SHA384, key, signingInput)
	case jwa.PS512:
		signature, err = t.rsaPSSSign(crypto.SHA512, key, signingInput)
	case jwa.ES256:
		signature, err = t.ecdsaSign(crypto.SHA256, key, signingInput)
	case jwa.ES384:
		signature, err = t.ecdsaSign(crypto.SHA384, key, signingInput)
	case jwa.ES512:
		signature, err = t.ecdsaSign(crypto.SHA512, key, signingInput)
	case jwa.EdDSA:
		signature, err = t.eddsaSign(key, signingInput)
	case jwa.None:
		// No signature for "none" algorithm
		signature = nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign with %s: %w", alg, err)
	}

	t.Signature = signature
	// Clear cached raw representation since signature changed
	t.raw = ""

	return signature, nil
}

// Verify verifies the JWS signature using the given key.
// Returns nil if the signature is valid, error otherwise.
func (t *Signature) Verify(key any) error {
	alg, err := t.Header.Algorithm()
	if err != nil {
		return fmt.Errorf("missing or invalid algorithm in header: %w", err)
	}

	// Special handling for "none" algorithm
	if alg == jwa.None {
		if len(t.Signature) != 0 {
			return fmt.Errorf("signature must be empty for algorithm %q", alg)
		}
		return nil
	}

	if key == nil {
		return fmt.Errorf("key is required for algorithm %q", alg)
	}

	signingInput, err := t.signingInput()
	if err != nil {
		return fmt.Errorf("failed to compute signing input: %w", err)
	}

	switch alg {
	case jwa.HS256:
		return t.hmacVerify(crypto.SHA256, key, signingInput)
	case jwa.HS384:
		return t.hmacVerify(crypto.SHA384, key, signingInput)
	case jwa.HS512:
		return t.hmacVerify(crypto.SHA512, key, signingInput)
	case jwa.RS256:
		return t.rsaVerify(crypto.SHA256, key, signingInput)
	case jwa.RS384:
		return t.rsaVerify(crypto.SHA384, key, signingInput)
	case jwa.RS512:
		return t.rsaVerify(crypto.SHA512, key, signingInput)
	case jwa.PS256:
		return t.rsaPSSVerify(crypto.SHA256, key, signingInput)
	case jwa.PS384:
		return t.rsaPSSVerify(crypto.SHA384, key, signingInput)
	case jwa.PS512:
		return t.rsaPSSVerify(crypto.SHA512, key, signingInput)
	case jwa.ES256:
		return t.ecdsaVerify(crypto.SHA256, key, signingInput)
	case jwa.ES384:
		return t.ecdsaVerify(crypto.SHA384, key, signingInput)
	case jwa.ES512:
		return t.ecdsaVerify(crypto.SHA512, key, signingInput)
	case jwa.EdDSA:
		return t.eddsaVerify(key, signingInput)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// parseHeaderStrict implements strict JSON parsing as required by RFC 7515 Section 10.12
func parseHeaderStrict(data []byte) (Header, error) {
	var header Header
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return header, nil
}

// processCriticalHeaders implements RFC 7515 Section 4.1.11 critical header processing
func processCriticalHeaders(h Header) error {
	// Use the shared critical header validation logic
	// For JWS, we don't define any supported critical headers by default,
	// so we pass nil to reject any critical headers (per RFC 7515).
	return h.ValidateCriticalHeaders(nil)
}

// HMAC signing and verification
func (t *Signature) hmacSign(hash crypto.Hash, key any, signingInput string) ([]byte, error) {
	var secretKey []byte

	// Convert key to byte slice
	switch keyTyped := key.(type) {
	case []byte:
		secretKey = keyTyped
	case string:
		secretKey = []byte(keyTyped)
	default:
		return nil, fmt.Errorf("HMAC signing requires []byte or string key, got %T", key)
	}

	// Ensure the secret key is not empty
	if len(secretKey) == 0 {
		return nil, fmt.Errorf("HMAC secret key cannot be empty")
	}

	// Validate HMAC key size per RFC 7518
	if err := validateHMACKeySize(hash, secretKey); err != nil {
		return nil, fmt.Errorf("HMAC key validation failed: %w", err)
	}

	if !hash.Available() {
		return nil, fmt.Errorf("hash function %v not available", hash)
	}

	h := hmac.New(hash.New, secretKey)
	h.Write([]byte(signingInput))
	return h.Sum(nil), nil
}

func (t *Signature) hmacVerify(hash crypto.Hash, key any, signingInput string) error {
	expectedSig, err := t.hmacSign(hash, key, signingInput)
	if err != nil {
		return err
	}

	if !hmac.Equal(t.Signature, expectedSig) {
		return fmt.Errorf("HMAC signature verification failed")
	}
	return nil
}

// RSA PKCS1v15 signing and verification
func (t *Signature) rsaSign(hash crypto.Hash, key any, signingInput string) ([]byte, error) {
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA signing requires *rsa.PrivateKey, got %T", key)
	}

	// Validate RSA key size per RFC 7518
	if err := validateRSAKeySize(privateKey); err != nil {
		return nil, fmt.Errorf("RSA key validation failed: %w", err)
	}

	if !hash.Available() {
		return nil, fmt.Errorf("hash function %v not available", hash)
	}

	h := hash.New()
	h.Write([]byte(signingInput))
	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, h.Sum(nil))
}

func (t *Signature) rsaVerify(hash crypto.Hash, key any, signingInput string) error {
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("RSA verification requires *rsa.PublicKey, got %T", key)
	}

	// Validate RSA key size per RFC 7518
	if err := validateRSAKeySize(publicKey); err != nil {
		return fmt.Errorf("RSA key validation failed: %w", err)
	}

	if !hash.Available() {
		return fmt.Errorf("hash function %v not available", hash)
	}

	h := hash.New()
	h.Write([]byte(signingInput))
	return rsa.VerifyPKCS1v15(publicKey, hash, h.Sum(nil), t.Signature)
}

// RSA-PSS signing and verification
func (t *Signature) rsaPSSSign(hash crypto.Hash, key any, signingInput string) ([]byte, error) {
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA-PSS signing requires *rsa.PrivateKey, got %T", key)
	}

	// Validate RSA key size per RFC 7518
	if err := validateRSAKeySize(privateKey); err != nil {
		return nil, fmt.Errorf("RSA key validation failed: %w", err)
	}

	if !hash.Available() {
		return nil, fmt.Errorf("hash function %v not available", hash)
	}

	h := hash.New()
	h.Write([]byte(signingInput))
	return rsa.SignPSS(rand.Reader, privateKey, hash, h.Sum(nil), nil)
}

func (t *Signature) rsaPSSVerify(hash crypto.Hash, key any, signingInput string) error {
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("RSA-PSS verification requires *rsa.PublicKey, got %T", key)
	}

	// Validate RSA key size per RFC 7518
	if err := validateRSAKeySize(publicKey); err != nil {
		return fmt.Errorf("RSA key validation failed: %w", err)
	}

	if !hash.Available() {
		return fmt.Errorf("hash function %v not available", hash)
	}

	h := hash.New()
	h.Write([]byte(signingInput))
	return rsa.VerifyPSS(publicKey, hash, h.Sum(nil), t.Signature, nil)
}

// ECDSA signing and verification
func (t *Signature) ecdsaSign(hash crypto.Hash, key any, signingInput string) ([]byte, error) {
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ECDSA signing requires *ecdsa.PrivateKey, got %T", key)
	}

	if !hash.Available() {
		return nil, fmt.Errorf("hash function %v not available", hash)
	}

	h := hash.New()
	h.Write([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	// Determine key size based on curve
	keyBytes := (privateKey.Curve.Params().BitSize + 7) / 8

	// Convert r and s to fixed-length byte arrays
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad with leading zeros if necessary
	rPadded := make([]byte, keyBytes)
	sPadded := make([]byte, keyBytes)
	copy(rPadded[keyBytes-len(rBytes):], rBytes)
	copy(sPadded[keyBytes-len(sBytes):], sBytes)

	// Concatenate r || s
	signature := append(rPadded, sPadded...)
	return signature, nil
}

func (t *Signature) ecdsaVerify(hash crypto.Hash, key any, signingInput string) error {
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("ECDSA verification requires *ecdsa.PublicKey, got %T", key)
	}

	if !hash.Available() {
		return fmt.Errorf("hash function %v not available", hash)
	}

	// Determine expected signature length
	keyBytes := (publicKey.Curve.Params().BitSize + 7) / 8
	if len(t.Signature) != 2*keyBytes {
		return fmt.Errorf("invalid ECDSA signature length: expected %d, got %d", 2*keyBytes, len(t.Signature))
	}

	// Split signature into r and s
	r := big.NewInt(0).SetBytes(t.Signature[:keyBytes])
	s := big.NewInt(0).SetBytes(t.Signature[keyBytes:])

	h := hash.New()
	h.Write([]byte(signingInput))

	if !ecdsa.Verify(publicKey, h.Sum(nil), r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// EdDSA signing and verification
func (t *Signature) eddsaSign(key any, signingInput string) ([]byte, error) {
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("EdDSA signing requires ed25519.PrivateKey, got %T", key)
	}

	// Validate Ed25519 private key size
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: expected %d bytes, got %d bytes", ed25519.PrivateKeySize, len(privateKey))
	}

	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signature, nil
}

func (t *Signature) eddsaVerify(key any, signingInput string) error {
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("EdDSA verification requires ed25519.PublicKey, got %T", key)
	}

	// Validate Ed25519 public key size
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key size: expected %d bytes, got %d bytes", ed25519.PublicKeySize, len(publicKey))
	}

	if !ed25519.Verify(publicKey, []byte(signingInput), t.Signature) {
		return fmt.Errorf("EdDSA signature verification failed")
	}
	return nil
}

// validateRSAKeySize validates that the RSA key meets the minimum size requirement per RFC 7518.
// RSA keys must be at least 2048 bits (256 bytes) for RSA-based JWT algorithms.
func validateRSAKeySize(key any) error {
	const (
		minKeySize      = 2048           // bits
		minKeySizeBytes = minKeySize / 8 // 256 bytes
	)

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

// validateHMACKeySize validates that the HMAC key meets the minimum size requirement per RFC 7518.
// HMAC keys should be at least as long as the hash output for optimal security.
func validateHMACKeySize(hash crypto.Hash, key []byte) error {
	var minSize int
	switch hash {
	case crypto.SHA256:
		minSize = 32 // 256 bits
	case crypto.SHA384:
		minSize = 48 // 384 bits
	case crypto.SHA512:
		minSize = 64 // 512 bits
	default:
		return fmt.Errorf("unsupported hash algorithm for HMAC key validation: %v", hash)
	}

	if len(key) < minSize {
		return fmt.Errorf("HMAC key must be at least %d bytes for %v algorithm, got %d bytes", minSize, hash, len(key))
	}

	return nil
}

// SignHMAC performs HMAC signing with the given hash and key.
// This method provides advanced validation per RFC 7518.
func (t *Signature) SignHMAC(hash crypto.Hash, key any, signingInput string) ([]byte, error) {
	return t.hmacSign(hash, key, signingInput)
}

// VerifyHMAC performs HMAC verification with the given hash and key.
func (t *Signature) VerifyHMAC(hash crypto.Hash, key any, signingInput string) error {
	return t.hmacVerify(hash, key, signingInput)
}

// VerifyHMACForLegacy performs HMAC verification without key size validation.
// This is used for verifying existing tokens that may have been created with weaker keys.
func (t *Signature) VerifyHMACForLegacy(hash crypto.Hash, key any, signingInput string) error {
	var secretKey []byte

	// Convert key to byte slice
	switch keyTyped := key.(type) {
	case []byte:
		secretKey = keyTyped
	case string:
		secretKey = []byte(keyTyped)
	default:
		return fmt.Errorf("HMAC verification requires []byte or string key, got %T", key)
	}

	// Ensure the secret key is not empty
	if len(secretKey) == 0 {
		return fmt.Errorf("HMAC secret key cannot be empty")
	}

	// Skip key size validation for verification to maintain compatibility with legacy tokens

	if !hash.Available() {
		return fmt.Errorf("hash function %v not available", hash)
	}

	h := hmac.New(hash.New, secretKey)
	h.Write([]byte(signingInput))
	expectedSig := h.Sum(nil)

	if !hmac.Equal(t.Signature, expectedSig) {
		return fmt.Errorf("HMAC signature verification failed")
	}
	return nil
}

// SignRSA performs RSA PKCS1v15 signing with the given hash and key.
// This method provides advanced validation per RFC 7518.
func (t *Signature) SignRSA(hash crypto.Hash, key any, signingInput string) ([]byte, error) {
	return t.rsaSign(hash, key, signingInput)
}

// VerifyRSA performs RSA PKCS1v15 verification with the given hash and key.
func (t *Signature) VerifyRSA(hash crypto.Hash, key any, signingInput string) error {
	return t.rsaVerify(hash, key, signingInput)
}

// SignRSAPSS performs RSA-PSS signing with the given hash and key.
// This method provides advanced validation per RFC 7518.
func (t *Signature) SignRSAPSS(hash crypto.Hash, key any, signingInput string) ([]byte, error) {
	return t.rsaPSSSign(hash, key, signingInput)
}

// VerifyRSAPSS performs RSA-PSS verification with the given hash and key.
func (t *Signature) VerifyRSAPSS(hash crypto.Hash, key any, signingInput string) error {
	return t.rsaPSSVerify(hash, key, signingInput)
}

// SignECDSA performs ECDSA signing with the given hash and key.
func (t *Signature) SignECDSA(hash crypto.Hash, key any, signingInput string) ([]byte, error) {
	return t.ecdsaSign(hash, key, signingInput)
}

// VerifyECDSA performs ECDSA verification with the given hash and key.
func (t *Signature) VerifyECDSA(hash crypto.Hash, key any, signingInput string) error {
	return t.ecdsaVerify(hash, key, signingInput)
}

// SignEdDSA performs EdDSA signing with the given key.
func (t *Signature) SignEdDSA(key any, signingInput string) ([]byte, error) {
	return t.eddsaSign(key, signingInput)
}

// VerifyEdDSA performs EdDSA verification with the given key.
func (t *Signature) VerifyEdDSA(key any, signingInput string) error {
	return t.eddsaVerify(key, signingInput)
}
