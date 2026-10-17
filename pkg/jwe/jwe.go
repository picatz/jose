// Package jwe implements JSON Web Encryption (JWE) as defined in RFC 7516,
// in the compact serialization and the JSON Serialization (general and
// flattened, with multiple recipients: see [ParseJSON], [EncryptJSON] and
// [Decrypter.DecryptJSON]), with the key management and content encryption
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
// RSA1_5 invites padding-oracle attacks (RFC 8725 §3.2), PBES2 turns a
// guessable password into a key, and compressing before encryption can leak
// plaintext (RFC 8725 §3.6). The AES GCM key wrapping algorithms "A128GCMKW",
// "A192GCMKW" and "A256GCMKW" (RFC 7518 §4.7, optional to implement) are not
// implemented either. Objects that use any of them are rejected with
// [ErrUnsupported].
//
// # Decrypting
//
// A [Decrypter] bundles the recipient's key with the policy (allowed
// algorithms and understood "crit" extensions) for [Decrypter.Decrypt]
// (compact) and [Decrypter.DecryptJSON] (JSON Serialization). Every
// decryption failure after the structure is accepted returns the same
// [ErrDecryption], so the error is no oracle for the key or the content.
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
// first when the sender matters.
//
// Nested JWTs (a JWE whose "cty" is "JWT" and whose plaintext is a signed
// JWT, RFC 7519 §5.2) are out of scope: this package returns the plaintext
// and leaves any further parsing, such as passing it to a jwt.Verifier, to
// the caller.
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

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
)

// JWE-specific header parameter names. The registered names shared with
// JWS ("alg", "enc", "kid", "zip", "crit" and so on) are in package header.
const (
	// EphemeralPublicKey ("epk") carries the sender's ephemeral ECDH key.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1
	EphemeralPublicKey string = "epk"
	// AgreementPartyUInfo ("apu") and AgreementPartyVInfo ("apv") are
	// base64url-encoded Concat KDF inputs.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.2
	AgreementPartyUInfo string = "apu"
	AgreementPartyVInfo string = "apv"
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
// authenticate anything; every field is untrusted until
// [Decrypter.DecryptMessage] succeeds. Changing Header after [Parse] does
// not change what is authenticated: decryption uses the received protected
// header bytes, not the modified map.
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
	return m.Header.Algorithm()
}

// Encryption returns the "enc" header parameter.
func (m *Message) Encryption() (jwa.ContentEncryption, error) {
	return m.Header.EncryptionAlgorithm()
}

func decodeSegment(s, name string, required bool) ([]byte, error) {
	if s == "" {
		if required {
			return nil, fmt.Errorf("%w: empty %s", ErrMalformed, name)
		}
		return nil, nil
	}
	b, err := base64url.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, name, err)
	}
	return b, nil
}

func encodeSegment(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := base64url.Encode(b)
	return s
}

// Parse decodes a compact JWE without decrypting it. Like [ParseJSON], it
// refuses a protected header with duplicate member names and any segment
// that is not canonical unpadded base64url.
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
	h, err := parseProtectedHeader(protected)
	if err != nil {
		return nil, err
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

// Decrypter holds the key and the policy for decrypting JWEs, in the way
// [jwt.Verifier] holds a verification key and policy. The zero value has no
// key and decrypts nothing.
//
// A symmetric Key (a []byte) needs an explicit Algorithms list: with nil
// Algorithms, decryption is refused with [ErrNotAllowed]. This mirrors
// [jwt.Verifier] and keeps one key from serving both "dir" and A*KW.
//
// Algorithms and Encryptions are allowlists. A nil list allows the default
// set: every key management algorithm and every content encryption
// algorithm listed in the package documentation, so RSA1_5, PBES2, A*GCMKW
// and compression stay refused as [ErrUnsupported]. An empty, non-nil list
// allows nothing. Naming the algorithms a key is meant for is still the
// better practice: a message cannot then choose the algorithm.
//
// A Decrypter is safe for concurrent use as long as its fields are not
// modified.
//
// [jwt.Verifier]: https://pkg.go.dev/github.com/picatz/jose/pkg/jwt#Verifier
type Decrypter struct {
	// Key is the recipient's private or shared key. See the package
	// documentation for the key types each algorithm takes.
	Key any

	// Algorithms lists the allowed "alg" values; nil allows every
	// implemented one, except that a []byte Key requires an explicit list.
	Algorithms []jwa.Algorithm

	// Encryptions lists the allowed "enc" values; nil allows every
	// implemented one.
	Encryptions []jwa.ContentEncryption

	// Critical lists the "crit" extensions the caller understands and
	// processes itself. Any other "crit" extension is refused.
	Critical []string
}

// requireAlgorithms refuses a symmetric key without an explicit allowlist.
func (d Decrypter) requireAlgorithms() error {
	if _, ok := d.Key.([]byte); ok && d.Algorithms == nil {
		return fmt.Errorf("%w: a []byte key needs an explicit Algorithms list", ErrNotAllowed)
	}
	return nil
}

func (d Decrypter) allowsAlgorithm(alg jwa.Algorithm) bool {
	// With nil Algorithms, an algorithm this package does not implement
	// is refused later as ErrUnsupported.
	return d.Algorithms == nil || slices.Contains(d.Algorithms, alg)
}

func (d Decrypter) allowsEncryption(enc jwa.ContentEncryption) bool {
	return d.Encryptions == nil || slices.Contains(d.Encryptions, enc)
}

// Decrypt parses and decrypts a compact JWE: [Parse] followed by
// [Decrypter.DecryptMessage]. The returned Message is non-nil only on
// success.
func (d Decrypter) Decrypt(compact string) ([]byte, *Message, error) {
	m, err := Parse(compact)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := d.DecryptMessage(m)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, m, nil
}

// DecryptMessage authenticates and decrypts a parsed compact JWE with d.Key
// and returns the plaintext. Use it after [Parse] when the header (for
// example "kid") picks the Decrypter. Every authentication or key failure
// returns [ErrDecryption]; unsupported or disallowed algorithms return
// [ErrUnsupported] or [ErrNotAllowed].
//
// https://www.rfc-editor.org/rfc/rfc7516.html#section-5.2
func (d Decrypter) DecryptMessage(m *Message) ([]byte, error) {
	alg, err := m.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	enc, err := m.Encryption()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := d.requireAlgorithms(); err != nil {
		return nil, err
	}
	if !d.allowsAlgorithm(alg) {
		return nil, fmt.Errorf("%w: %q", ErrNotAllowed, alg)
	}
	if !d.allowsEncryption(enc) {
		return nil, fmt.Errorf("%w: %q", ErrNotAllowed, enc)
	}
	// RFC 7516 §4.1.3: an unsupported "zip" must cause rejection.
	if m.Header.Has(header.Zip) {
		return nil, fmt.Errorf("%w: compression (%q)", ErrUnsupported, header.Zip)
	}
	if err := m.Header.ValidateCriticalHeaders(d.Critical); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	content, err := contentCipherFor(enc)
	if err != nil {
		return nil, err
	}
	cek, err := m.contentKey(alg, enc, content.keySize, d.Key)
	if err != nil {
		return nil, err
	}
	return content.open(cek, m.IV, m.Ciphertext, m.Tag, []byte(m.protected))
}

// contentKey recovers the content encryption key.
func (m *Message) contentKey(alg jwa.Algorithm, enc jwa.ContentEncryption, size int, key any) ([]byte, error) {
	return recoverContentKey(alg, enc, size, key, m.Header, m.EncryptedKey)
}

// recoverContentKey recovers the content encryption key for one recipient
// from its JOSE Header h and encrypted key. It is shared by the compact and
// JSON serializations.
func recoverContentKey(alg jwa.Algorithm, enc jwa.ContentEncryption, size int, key any, h header.Parameters, encryptedKey []byte) ([]byte, error) {
	switch alg {
	case jwa.Direct:
		shared, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: %q needs a []byte key, got %T", ErrUnsupported, alg, key)
		}
		if len(encryptedKey) != 0 {
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
		return unwrapContentKey(kek, encryptedKey, size)
	case jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW:
		recipient, err := keyAgreement(key)
		if err != nil {
			return nil, err
		}
		z, apu, apv, err := agree(h, recipient)
		if err != nil {
			return nil, err
		}
		if alg == jwa.ECDHES {
			if len(encryptedKey) != 0 {
				return nil, fmt.Errorf("%w: %q must have an empty encrypted key", ErrMalformed, alg)
			}
			return concatKDF(z, string(enc), apu, apv, size), nil
		}
		kek := concatKDF(z, string(alg), apu, apv, keyWrapSize(alg))
		return unwrapContentKey(kek, encryptedKey, size)
	case jwa.RSAOAEP, jwa.RSAOAEP256:
		decrypter, ok := key.(crypto.Decrypter)
		if !ok {
			return nil, fmt.Errorf("%w: %q needs a crypto.Decrypter, got %T", ErrUnsupported, alg, key)
		}
		if _, ok := decrypter.Public().(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("%w: %q needs an RSA key", ErrUnsupported, alg)
		}
		cek, err := decrypter.Decrypt(rand.Reader, encryptedKey, &rsa.OAEPOptions{Hash: oaepHash(alg)})
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
func agree(h header.Parameters, recipient KeyAgreement) (z, apu, apv []byte, err error) {
	raw, ok := h[EphemeralPublicKey].(map[string]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%w: missing or invalid %q", ErrMalformed, EphemeralPublicKey)
	}
	epk := jwk.Key(raw)
	if jwk.IsPrivate(epk) {
		return nil, nil, nil, fmt.Errorf("%w: %q contains private key material", ErrMalformed, EphemeralPublicKey)
	}
	// jwk.PublicKey accepts more key types than ECDH-ES; narrow the type
	// before it parses attacker-controlled members.
	if kty, _ := raw["kty"].(string); kty != "EC" && kty != "OKP" {
		return nil, nil, nil, fmt.Errorf("%w: %q must be an EC or OKP key", ErrMalformed, EphemeralPublicKey)
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
	if apu, err = partyInfo(h, AgreementPartyUInfo); err != nil {
		return nil, nil, nil, err
	}
	if apv, err = partyInfo(h, AgreementPartyVInfo); err != nil {
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
	alg, err := protectedHeader.Algorithm()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	enc, err := protectedHeader.EncryptionAlgorithm()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if protectedHeader.Has(header.Zip) {
		return "", fmt.Errorf("%w: compression (%q)", ErrUnsupported, header.Zip)
	}
	if protectedHeader.Has(EphemeralPublicKey) {
		return "", fmt.Errorf("%w: %q is generated by Encrypt", ErrMalformed, EphemeralPublicKey)
	}
	content, err := contentCipherFor(enc)
	if err != nil {
		return "", err
	}

	cek, encryptedKey, epk, err := manageKey(alg, enc, key, protectedHeader, content, nil)
	if err != nil {
		return "", err
	}
	if epk != nil {
		protectedHeader[EphemeralPublicKey] = epk
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

// manageKey performs the sender side of key management for one recipient.
// h is the recipient's combined JOSE Header, which supplies "apu" and
// "apv". For "dir" and "ECDH-ES" the returned content key is the shared or
// derived one and cek is ignored; for the wrapping algorithms cek is wrapped,
// or generated when nil. A non-nil epk must be added to the header.
func manageKey(alg jwa.Algorithm, enc jwa.ContentEncryption, key any, h header.Parameters, content contentCipher, cek []byte) (contentKey, encryptedKey []byte, epk map[string]any, err error) {
	newCEK := func() error {
		if cek != nil {
			return nil
		}
		cek, err = randomBytes(content.keySize)
		return err
	}
	switch alg {
	case jwa.Direct:
		shared, ok := key.([]byte)
		if !ok {
			return nil, nil, nil, fmt.Errorf("%w: %q needs a []byte key, got %T", ErrUnsupported, alg, key)
		}
		if len(shared) != content.keySize {
			return nil, nil, nil, fmt.Errorf("jwe: %q with %q needs a %d-byte key, got %d", alg, enc, content.keySize, len(shared))
		}
		return shared, nil, nil, nil
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		kek, ok := key.([]byte)
		if !ok {
			return nil, nil, nil, fmt.Errorf("%w: %q needs a []byte key, got %T", ErrUnsupported, alg, key)
		}
		if len(kek) != keyWrapSize(alg) {
			return nil, nil, nil, fmt.Errorf("jwe: %q needs a %d-byte key, got %d", alg, keyWrapSize(alg), len(kek))
		}
		if err := newCEK(); err != nil {
			return nil, nil, nil, err
		}
		if encryptedKey, err = wrapKey(kek, cek); err != nil {
			return nil, nil, nil, err
		}
		return cek, encryptedKey, nil, nil
	case jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW:
		recipient, err := toECDHPublic(key)
		if err != nil {
			return nil, nil, nil, err
		}
		ephemeral, err := recipient.Curve().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		z, err := ephemeral.ECDH(recipient)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("jwe: ECDH: %w", err)
		}
		if epk, err = jwk.PublicValue(ephemeral.PublicKey()); err != nil {
			return nil, nil, nil, err
		}
		apu, err := partyInfo(h, AgreementPartyUInfo)
		if err != nil {
			return nil, nil, nil, err
		}
		apv, err := partyInfo(h, AgreementPartyVInfo)
		if err != nil {
			return nil, nil, nil, err
		}
		if alg == jwa.ECDHES {
			return concatKDF(z, string(enc), apu, apv, content.keySize), nil, epk, nil
		}
		kek := concatKDF(z, string(alg), apu, apv, keyWrapSize(alg))
		if err := newCEK(); err != nil {
			return nil, nil, nil, err
		}
		if encryptedKey, err = wrapKey(kek, cek); err != nil {
			return nil, nil, nil, err
		}
		return cek, encryptedKey, epk, nil
	case jwa.RSAOAEP, jwa.RSAOAEP256:
		public, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, nil, nil, fmt.Errorf("%w: %q needs an *rsa.PublicKey, got %T", ErrUnsupported, alg, key)
		}
		if public.Size() < 256 {
			return nil, nil, nil, fmt.Errorf("jwe: %q needs an RSA key of at least 2048 bits", alg)
		}
		if err := newCEK(); err != nil {
			return nil, nil, nil, err
		}
		if encryptedKey, err = rsa.EncryptOAEP(newOAEPHash(alg), rand.Reader, public, cek, nil); err != nil {
			return nil, nil, nil, err
		}
		return cek, encryptedKey, nil, nil
	default:
		return nil, nil, nil, fmt.Errorf("%w: key management algorithm %q", ErrUnsupported, alg)
	}
}
