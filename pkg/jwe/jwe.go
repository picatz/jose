// Package jwe implements JSON Web Encryption (JWE) compact serialization as
// defined in RFC 7516, with the key management and content encryption
// algorithms of RFC 7518 and the X25519 key agreement of RFC 8037.
//
// # Algorithms
//
// Key management ("alg"):
//
//   - "dir": a shared key used directly as the content key (RFC 7518 §4.5)
//   - "A128KW", "A192KW", "A256KW": AES Key Wrap under a shared key (§4.4)
//   - "ECDH-ES" and "ECDH-ES+A128KW/A192KW/A256KW": ephemeral-static ECDH on
//     P-256, P-384, P-521 or X25519 with the Concat KDF (§4.6, RFC 8037 §3.2)
//   - "RSA-OAEP", "RSA-OAEP-256": RSAES-OAEP with keys of at least 2048 bits
//     (§4.3)
//
// Content encryption ("enc"): "A128GCM", "A192GCM", "A256GCM" (§5.3) and
// "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" (§5.2).
//
// RSA1_5, PBES2 and compression ("zip") are deliberately not implemented:
// RSA1_5 invites padding-oracle attacks (RFC 8725 §3.2), and compressing
// before encryption can leak plaintext (RFC 8725 §3.6). Objects that use
// them are rejected.
//
// # Keys
//
// Encryption takes the recipient's public key (*[ecdh.PublicKey],
// *[ecdsa.PublicKey] or *[rsa.PublicKey]) or a shared []byte key. Decryption
// takes a [KeyAgreement] for ECDH-ES (which *[ecdh.PrivateKey] implements,
// and hardware keys can implement without exporting the scalar), an
// *[ecdsa.PrivateKey], a [crypto.Decrypter] with an RSA public key, or the
// shared []byte key.
//
// # Trust
//
// A successful decryption proves the content was encrypted to the
// recipient's key and not modified. It does not identify the sender:
// anyone holding the recipient's public key can produce a valid JWE. Sign
// first (a nested JWT, RFC 7519 §11.2) when the sender matters.
package jwe

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
)

// Registered header parameter names used in JWE.
//
// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1
const (
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1
	Algorithm header.ParameterName = "alg"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
	EncryptionAlgorithm header.ParameterName = "enc"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3
	CompressionAlgorithm header.ParameterName = "zip"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.4
	JWKSetURL header.ParameterName = "jku"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.5
	JSONWebKey header.ParameterName = "jwk"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6
	KeyID header.ParameterName = "kid"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.7
	X509URL header.ParameterName = "x5u"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.8
	X509CertificateChain header.ParameterName = "x5c"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.9
	X509CertificateSHA1Thumbprint header.ParameterName = "x5t"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.10
	X509CertificateSHA256Thumbprint header.ParameterName = "x5t#S256"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.11
	Type header.ParameterName = "typ"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.12
	ContentType header.ParameterName = "cty"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.13
	Critical header.ParameterName = "crit"

	// EphemeralPublicKey ("epk") carries the sender's ephemeral ECDH key.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1
	EphemeralPublicKey header.ParameterName = "epk"
	// AgreementPartyUInfo ("apu") and AgreementPartyVInfo ("apv") are
	// base64url-encoded Concat KDF inputs.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.2
	AgreementPartyUInfo header.ParameterName = "apu"
	AgreementPartyVInfo header.ParameterName = "apv"
)

var (
	// ErrUnsupported reports an algorithm, header or key type this package
	// does not implement.
	ErrUnsupported = errors.New("jwe: unsupported")

	// ErrMalformed reports a JWE that does not follow RFC 7516.
	ErrMalformed = errors.New("jwe: malformed")

	// ErrNotAllowed reports an algorithm the caller did not allow.
	ErrNotAllowed = errors.New("jwe: algorithm not allowed")

	// ErrDecryption reports that the content could not be decrypted with the
	// given key. It deliberately does not say which step failed.
	ErrDecryption = errDecryption
)

// KeyAgreement is the recipient half of ECDH-ES. *[ecdh.PrivateKey]
// implements it; a hardware or remote key can implement it to decrypt
// without exporting its private scalar.
type KeyAgreement interface {
	// PublicKey returns the recipient's public key, which fixes the curve.
	PublicKey() *ecdh.PublicKey
	// ECDH returns the shared secret with remote, which is on the same
	// curve as PublicKey.
	ECDH(remote *ecdh.PublicKey) ([]byte, error)
}

// Message is a parsed compact JWE. Parsing does not decrypt or
// authenticate anything; every field is untrusted until [Message.Decrypt]
// succeeds.
//
// https://www.rfc-editor.org/rfc/rfc7516.html#section-3.1
type Message struct {
	// Header is the decoded JWE Protected Header.
	Header header.Parameters
	// EncryptedKey is empty for "dir" and "ECDH-ES".
	EncryptedKey []byte
	IV           []byte
	Ciphertext   []byte
	Tag          []byte

	// protected is the received base64url header, the AAD for decryption.
	protected string
}

// Algorithm returns the "alg" header parameter.
func (m *Message) Algorithm() (jwa.Algorithm, error) {
	return header.Get[string](m.Header, Algorithm)
}

// Encryption returns the "enc" header parameter.
func (m *Message) Encryption() (jwa.ContentEncryption, error) {
	return header.Get[string](m.Header, EncryptionAlgorithm)
}

func decodeSegment(s, name string, required bool) ([]byte, error) {
	if s == "" {
		if required {
			return nil, fmt.Errorf("%w: empty %s", ErrMalformed, name)
		}
		return nil, nil
	}
	b, err := base64.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, name, err)
	}
	return b, nil
}

func encodeSegment(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s, _ := base64.Encode(b)
	return s
}

// Parse decodes a compact JWE without decrypting it.
//
// https://www.rfc-editor.org/rfc/rfc7516.html#section-5.2 (steps 1-3)
func Parse(compact string) (*Message, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("%w: compact JWE has %d parts, want 5", ErrMalformed, len(parts))
	}
	protected, err := decodeSegment(parts[0], "protected header", true)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(protected) {
		return nil, fmt.Errorf("%w: protected header is not UTF-8", ErrMalformed)
	}
	var h header.Parameters
	if err := json.Unmarshal(protected, &h); err != nil || h == nil {
		return nil, fmt.Errorf("%w: protected header is not a JSON object", ErrMalformed)
	}
	m := &Message{Header: h, protected: parts[0]}
	if m.EncryptedKey, err = decodeSegment(parts[1], "encrypted key", false); err != nil {
		return nil, err
	}
	if m.IV, err = decodeSegment(parts[2], "initialization vector", true); err != nil {
		return nil, err
	}
	if m.Ciphertext, err = decodeSegment(parts[3], "ciphertext", false); err != nil {
		return nil, err
	}
	if m.Tag, err = decodeSegment(parts[4], "authentication tag", true); err != nil {
		return nil, err
	}
	if _, err := m.Algorithm(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, err := m.Encryption(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return m, nil
}

// DecryptOptions restricts what [Message.Decrypt] accepts. The zero value
// allows every algorithm this package implements and no critical
// extensions.
type DecryptOptions struct {
	// Algorithms lists the allowed "alg" values; nil allows all.
	Algorithms []jwa.Algorithm
	// Encryptions lists the allowed "enc" values; nil allows all.
	Encryptions []jwa.ContentEncryption
	// SupportedCriticalHeaders lists the "crit" extensions the caller
	// understands and processes itself.
	SupportedCriticalHeaders []string
}

// Decrypt parses and decrypts a compact JWE. It is shorthand for [Parse]
// followed by [Message.Decrypt].
func Decrypt(compact string, key any, opts DecryptOptions) ([]byte, *Message, error) {
	m, err := Parse(compact)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := m.Decrypt(key, opts)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, m, nil
}

// Decrypt authenticates and decrypts the message with key and returns the
// plaintext. See the package documentation for the key types each
// algorithm takes. Every authentication or key failure returns
// [ErrDecryption]; unsupported or disallowed algorithms return
// [ErrUnsupported] or [ErrNotAllowed].
//
// https://www.rfc-editor.org/rfc/rfc7516.html#section-5.2
func (m *Message) Decrypt(key any, opts DecryptOptions) ([]byte, error) {
	alg, err := m.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	enc, err := m.Encryption()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if opts.Algorithms != nil && !slices.Contains(opts.Algorithms, alg) {
		return nil, fmt.Errorf("%w: %q", ErrNotAllowed, alg)
	}
	if opts.Encryptions != nil && !slices.Contains(opts.Encryptions, enc) {
		return nil, fmt.Errorf("%w: %q", ErrNotAllowed, enc)
	}
	// RFC 7516 §4.1.3: an unsupported "zip" must cause rejection.
	if m.Header.Has(CompressionAlgorithm) {
		return nil, fmt.Errorf("%w: compression (%q)", ErrUnsupported, CompressionAlgorithm)
	}
	if err := m.Header.ValidateCriticalHeaders(opts.SupportedCriticalHeaders); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	content, err := contentCipherFor(enc)
	if err != nil {
		return nil, err
	}
	cek, err := m.contentKey(alg, enc, content.keySize, key)
	if err != nil {
		return nil, err
	}
	return content.open(cek, m.IV, m.Ciphertext, m.Tag, []byte(m.protected))
}

// contentKey recovers the content encryption key.
func (m *Message) contentKey(alg jwa.Algorithm, enc jwa.ContentEncryption, size int, key any) ([]byte, error) {
	switch alg {
	case jwa.Direct:
		shared, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: %q needs a []byte key, got %T", ErrUnsupported, alg, key)
		}
		if len(m.EncryptedKey) != 0 {
			return nil, fmt.Errorf("%w: %q must have an empty encrypted key", ErrMalformed, alg)
		}
		if len(shared) != size {
			return nil, errDecryption
		}
		return shared, nil
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		kek, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: %q needs a []byte key, got %T", ErrUnsupported, alg, key)
		}
		if len(kek) != keyWrapSize(alg) {
			return nil, errDecryption
		}
		return unwrapContentKey(kek, m.EncryptedKey, size)
	case jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW:
		recipient, err := keyAgreement(key)
		if err != nil {
			return nil, err
		}
		z, apu, apv, err := m.agree(recipient)
		if err != nil {
			return nil, err
		}
		if alg == jwa.ECDHES {
			if len(m.EncryptedKey) != 0 {
				return nil, fmt.Errorf("%w: %q must have an empty encrypted key", ErrMalformed, alg)
			}
			return concatKDF(z, enc, apu, apv, size), nil
		}
		kek := concatKDF(z, alg, apu, apv, keyWrapSize(alg))
		return unwrapContentKey(kek, m.EncryptedKey, size)
	case jwa.RSAOAEP, jwa.RSAOAEP256:
		decrypter, ok := key.(crypto.Decrypter)
		if !ok {
			return nil, fmt.Errorf("%w: %q needs a crypto.Decrypter, got %T", ErrUnsupported, alg, key)
		}
		if _, ok := decrypter.Public().(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("%w: %q needs an RSA key", ErrUnsupported, alg)
		}
		cek, err := decrypter.Decrypt(rand.Reader, m.EncryptedKey, &rsa.OAEPOptions{Hash: oaepHash(alg)})
		if err != nil || len(cek) != size {
			// RFC 7516 §11.5: continue with a random key so a bad key and a
			// bad tag fail the same way.
			return randomBytes(size)
		}
		return cek, nil
	default:
		return nil, fmt.Errorf("%w: key management algorithm %q", ErrUnsupported, alg)
	}
}

func unwrapContentKey(kek, wrapped []byte, size int) ([]byte, error) {
	cek, err := unwrapKey(kek, wrapped)
	if err != nil || len(cek) != size {
		return nil, errDecryption
	}
	return cek, nil
}

// agree performs the recipient side of ECDH-ES with the "epk" header.
func (m *Message) agree(recipient KeyAgreement) (z, apu, apv []byte, err error) {
	raw, ok := m.Header[EphemeralPublicKey].(map[string]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%w: missing or invalid %q", ErrMalformed, EphemeralPublicKey)
	}
	epk := jwk.Value(raw)
	if jwk.IsPrivate(epk) {
		return nil, nil, nil, fmt.Errorf("%w: %q contains private key material", ErrMalformed, EphemeralPublicKey)
	}
	public, err := jwk.PublicKey(epk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %q: %v", ErrMalformed, EphemeralPublicKey, err)
	}
	remote, err := toECDHPublic(public)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %q: %v", ErrMalformed, EphemeralPublicKey, err)
	}
	if remote.Curve() != recipient.PublicKey().Curve() {
		return nil, nil, nil, errDecryption
	}
	z, err = recipient.ECDH(remote)
	if err != nil {
		return nil, nil, nil, errDecryption
	}
	if apu, err = partyInfo(m.Header, AgreementPartyUInfo); err != nil {
		return nil, nil, nil, err
	}
	if apv, err = partyInfo(m.Header, AgreementPartyVInfo); err != nil {
		return nil, nil, nil, err
	}
	return z, apu, apv, nil
}

func partyInfo(h header.Parameters, name string) ([]byte, error) {
	raw, ok := h[name]
	if !ok {
		return nil, nil
	}
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a string", ErrMalformed, name)
	}
	return decodeSegment(s, name, false)
}

func keyAgreement(key any) (KeyAgreement, error) {
	switch key := key.(type) {
	case KeyAgreement:
		return key, nil
	case *ecdsa.PrivateKey:
		private, err := key.ECDH()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
		}
		return private, nil
	default:
		return nil, fmt.Errorf("%w: ECDH-ES needs a jwe.KeyAgreement or *ecdsa.PrivateKey, got %T", ErrUnsupported, key)
	}
}

func toECDHPublic(key any) (*ecdh.PublicKey, error) {
	switch key := key.(type) {
	case *ecdh.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		return key.ECDH()
	case KeyAgreement:
		return key.PublicKey(), nil
	default:
		return nil, fmt.Errorf("%w: ECDH-ES needs an *ecdh.PublicKey or *ecdsa.PublicKey, got %T", ErrUnsupported, key)
	}
}

func keyWrapSize(alg jwa.Algorithm) int {
	switch alg {
	case jwa.A128KW, jwa.ECDHESA128KW:
		return 16
	case jwa.A192KW, jwa.ECDHESA192KW:
		return 24
	case jwa.A256KW, jwa.ECDHESA256KW:
		return 32
	}
	return 0
}

func oaepHash(alg jwa.Algorithm) crypto.Hash {
	if alg == jwa.RSAOAEP256 {
		return crypto.SHA256
	}
	return crypto.SHA1
}

func newOAEPHash(alg jwa.Algorithm) hash.Hash {
	if alg == jwa.RSAOAEP256 {
		return sha256.New()
	}
	return sha1.New()
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Encrypt encrypts plaintext to key and returns the compact JWE.
//
// h must contain "alg" and "enc"; any other members, such as "kid", "typ"
// or "cty", are copied into the protected header, and "apu"/"apv" feed the
// ECDH-ES key derivation. Encrypt sets "epk" itself and rejects "zip". h is
// not modified. See the package documentation for the key types each
// algorithm takes.
//
// https://www.rfc-editor.org/rfc/rfc7516.html#section-5.1
func Encrypt(h header.Parameters, plaintext []byte, key any) (string, error) {
	protectedHeader := make(header.Parameters, len(h)+1)
	for name, value := range h {
		protectedHeader[name] = value
	}
	alg, err := header.Get[string](protectedHeader, Algorithm)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	enc, err := header.Get[string](protectedHeader, EncryptionAlgorithm)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if protectedHeader.Has(CompressionAlgorithm) {
		return "", fmt.Errorf("%w: compression (%q)", ErrUnsupported, CompressionAlgorithm)
	}
	if protectedHeader.Has(EphemeralPublicKey) {
		return "", fmt.Errorf("%w: %q is generated by Encrypt", ErrMalformed, EphemeralPublicKey)
	}
	content, err := contentCipherFor(enc)
	if err != nil {
		return "", err
	}

	var cek, encryptedKey []byte
	switch alg {
	case jwa.Direct:
		shared, ok := key.([]byte)
		if !ok {
			return "", fmt.Errorf("%w: %q needs a []byte key, got %T", ErrUnsupported, alg, key)
		}
		if len(shared) != content.keySize {
			return "", fmt.Errorf("jwe: %q with %q needs a %d-byte key, got %d", alg, enc, content.keySize, len(shared))
		}
		cek = shared
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		kek, ok := key.([]byte)
		if !ok {
			return "", fmt.Errorf("%w: %q needs a []byte key, got %T", ErrUnsupported, alg, key)
		}
		if len(kek) != keyWrapSize(alg) {
			return "", fmt.Errorf("jwe: %q needs a %d-byte key, got %d", alg, keyWrapSize(alg), len(kek))
		}
		if cek, err = randomBytes(content.keySize); err != nil {
			return "", err
		}
		if encryptedKey, err = wrapKey(kek, cek); err != nil {
			return "", err
		}
	case jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW:
		recipient, err := toECDHPublic(key)
		if err != nil {
			return "", err
		}
		ephemeral, err := recipient.Curve().GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		z, err := ephemeral.ECDH(recipient)
		if err != nil {
			return "", fmt.Errorf("jwe: ECDH: %w", err)
		}
		epk, err := jwk.PublicValue(ephemeral.PublicKey())
		if err != nil {
			return "", err
		}
		protectedHeader[EphemeralPublicKey] = epk
		apu, err := partyInfo(protectedHeader, AgreementPartyUInfo)
		if err != nil {
			return "", err
		}
		apv, err := partyInfo(protectedHeader, AgreementPartyVInfo)
		if err != nil {
			return "", err
		}
		if alg == jwa.ECDHES {
			cek = concatKDF(z, enc, apu, apv, content.keySize)
			break
		}
		kek := concatKDF(z, alg, apu, apv, keyWrapSize(alg))
		if cek, err = randomBytes(content.keySize); err != nil {
			return "", err
		}
		if encryptedKey, err = wrapKey(kek, cek); err != nil {
			return "", err
		}
	case jwa.RSAOAEP, jwa.RSAOAEP256:
		public, ok := key.(*rsa.PublicKey)
		if !ok {
			return "", fmt.Errorf("%w: %q needs an *rsa.PublicKey, got %T", ErrUnsupported, alg, key)
		}
		if public.Size() < 256 {
			return "", fmt.Errorf("jwe: %q needs an RSA key of at least 2048 bits", alg)
		}
		if cek, err = randomBytes(content.keySize); err != nil {
			return "", err
		}
		if encryptedKey, err = rsa.EncryptOAEP(newOAEPHash(alg), rand.Reader, public, cek, nil); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("%w: key management algorithm %q", ErrUnsupported, alg)
	}

	headerJSON, err := json.Marshal(protectedHeader)
	if err != nil {
		return "", fmt.Errorf("jwe: encode header: %w", err)
	}
	protected := encodeSegment(headerJSON)
	iv, err := randomBytes(content.ivSize)
	if err != nil {
		return "", err
	}
	ciphertext, tag, err := content.seal(cek, iv, plaintext, []byte(protected))
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		protected,
		encodeSegment(encryptedKey),
		encodeSegment(iv),
		encodeSegment(ciphertext),
		encodeSegment(tag),
	}, "."), nil
}
