package jwe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/internal/strictjson"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
)

// JSON is a JWE in the JSON Serialization: one encrypted payload that one
// or more recipients can each decrypt with their own key. The content is
// encrypted once under a single content encryption key (CEK), which is
// then wrapped separately for every recipient, so recipients may use
// different key management algorithms (for example "A128KW" for one and
// "ECDH-ES+A128KW" for another).
//
// The general syntax lists recipients under "recipients"; the flattened
// syntax inlines the only recipient. [ParseJSON] reads both, and
// [JSON.General] and [JSON.Flattened] write them.
//
// Parsing does not decrypt or authenticate anything; every field is
// untrusted until [JSON.Decrypt] succeeds. In particular, Unprotected and
// the per-recipient headers are not integrity protected.
//
// https://www.rfc-editor.org/rfc/rfc7516#section-7.2
type JSON struct {
	// Protected holds the integrity-protected header parameters shared by
	// all recipients. The content authentication tag covers them.
	Protected header.Parameters

	// Unprotected holds shared header parameters that are not integrity
	// protected. Treat them as hints.
	Unprotected header.Parameters

	// Recipients are the per-recipient key management data, in order.
	Recipients []Recipient

	// IV is the initialization vector for content encryption.
	IV []byte
	// Ciphertext is the encrypted content.
	Ciphertext []byte
	// Tag is the authentication tag.
	Tag []byte
	// AAD is the optional additional authenticated data, which can only be
	// carried in the JSON Serialization.
	AAD []byte

	// The base64url encodings as received, so authentication covers the
	// exact bytes another implementation produced, not a re-serialization.
	protected string
	aad       string
	hasAAD    bool
}

// Recipient is one recipient of a [JSON] JWE.
//
// https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
type Recipient struct {
	// Header holds this recipient's per-recipient unprotected header
	// parameters, such as "alg", "kid" or the ECDH-ES "epk". They are not
	// integrity protected.
	Header header.Parameters

	// EncryptedKey is the CEK encrypted for this recipient; it is empty for
	// "dir" and "ECDH-ES".
	EncryptedKey []byte
}

// RecipientKey describes one recipient for [EncryptJSON].
type RecipientKey struct {
	// Header holds the per-recipient unprotected header parameters. It must
	// carry "alg" unless the shared headers do. "apu" and "apv" for ECDH-ES
	// may be set here; "epk" is generated.
	Header header.Parameters

	// Key is the recipient's key, as for [Encrypt]: a public key or a
	// shared []byte key.
	Key any
}

// Header returns the JOSE Header of recipient i: the union of the protected,
// shared unprotected and per-recipient parameters, which RFC 7516 §7.2.1
// requires to be disjoint. It returns nil when i is out of range.
func (j *JSON) Header(i int) header.Parameters {
	if i < 0 || i >= len(j.Recipients) {
		return nil
	}
	return joseHeader(j.Protected, j.Unprotected, j.Recipients[i].Header)
}

func joseHeader(parts ...header.Parameters) header.Parameters {
	union := make(header.Parameters)
	for _, part := range parts {
		maps.Copy(union, part)
	}
	return union
}

// jsonWire is the JSON Serialization in either syntax.
type jsonWire struct {
	Protected    *string         `json:"protected,omitempty"`
	Unprotected  map[string]any  `json:"unprotected,omitempty"`
	Header       map[string]any  `json:"header,omitempty"`
	EncryptedKey *string         `json:"encrypted_key,omitempty"`
	Recipients   []jsonWireRecip `json:"recipients,omitempty"`
	AAD          *string         `json:"aad,omitempty"`
	IV           *string         `json:"iv"`
	Ciphertext   *string         `json:"ciphertext"`
	Tag          *string         `json:"tag"`
}

type jsonWireRecip struct {
	Header       map[string]any `json:"header,omitempty"`
	EncryptedKey *string        `json:"encrypted_key,omitempty"`
}

// ParseJSON parses a JWE in the general or flattened JSON Serialization.
// It checks the structure, not the cryptography: call [JSON.Decrypt].
//
// It enforces RFC 7516 §7.2.1: duplicate member names are refused at every
// level, the protected, shared unprotected and per-recipient header names
// must be disjoint, every recipient needs "alg" and "enc" in its combined
// header, and "enc" must be shared by all recipients, so it may only appear
// in the protected or shared unprotected header. "crit" is only accepted in
// the protected header (§4.1.13), "zip" is refused as in the compact
// serialization, and "dir" and "ECDH-ES" are refused for more than one
// recipient because they fix the CEK. Unknown top-level members are
// ignored.
func ParseJSON(data []byte) (*JSON, error) {
	// encoding/json would replace invalid UTF-8 in an unprotected header
	// with U+FFFD, exposing values that differ from the wire.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: JSON serialization is not UTF-8", ErrMalformed)
	}
	if err := strictjson.CheckDuplicates(data); err != nil {
		return nil, fmt.Errorf("%w: JSON serialization: %v", ErrMalformed, err)
	}
	var wire jsonWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&wire); err != nil {
		return nil, fmt.Errorf("%w: JSON serialization: %v", ErrMalformed, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: trailing data after JSON serialization", ErrMalformed)
	}

	recipients := wire.Recipients
	flattened := wire.Header != nil || wire.EncryptedKey != nil
	switch {
	case flattened && recipients != nil:
		return nil, fmt.Errorf("%w: JSON serialization mixes general and flattened syntax", ErrMalformed)
	case recipients != nil && len(recipients) == 0:
		return nil, fmt.Errorf("%w: JSON serialization has no recipients", ErrMalformed)
	case recipients == nil:
		recipients = []jsonWireRecip{{Header: wire.Header, EncryptedKey: wire.EncryptedKey}}
	}

	j := &JSON{}
	var err error
	if wire.Protected != nil {
		protectedJSON, err := decodeJSONSegment(*wire.Protected, "protected header")
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(protectedJSON) {
			return nil, fmt.Errorf("%w: protected header is not UTF-8", ErrMalformed)
		}
		if j.Protected, err = parseProtectedHeader(protectedJSON); err != nil {
			return nil, err
		}
		j.protected = *wire.Protected
	}
	if wire.Unprotected != nil {
		j.Unprotected = header.Parameters(wire.Unprotected)
	}
	if wire.AAD != nil {
		if j.AAD, err = decodeJSONSegment(*wire.AAD, "aad"); err != nil {
			return nil, err
		}
		j.aad, j.hasAAD = *wire.AAD, true
	}
	if wire.IV == nil || wire.Ciphertext == nil || wire.Tag == nil {
		return nil, fmt.Errorf("%w: JSON serialization needs iv, ciphertext and tag", ErrMalformed)
	}
	if j.IV, err = decodeJSONSegment(*wire.IV, "initialization vector"); err != nil {
		return nil, err
	}
	if len(j.IV) == 0 {
		return nil, fmt.Errorf("%w: empty initialization vector", ErrMalformed)
	}
	if j.Ciphertext, err = decodeJSONSegment(*wire.Ciphertext, "ciphertext"); err != nil {
		return nil, err
	}
	if j.Tag, err = decodeJSONSegment(*wire.Tag, "authentication tag"); err != nil {
		return nil, err
	}
	if len(j.Tag) == 0 {
		return nil, fmt.Errorf("%w: empty authentication tag", ErrMalformed)
	}

	for i, entry := range recipients {
		r := Recipient{Header: header.Parameters(entry.Header)}
		if entry.EncryptedKey != nil {
			if r.EncryptedKey, err = decodeJSONSegment(*entry.EncryptedKey, "encrypted key"); err != nil {
				return nil, fmt.Errorf("recipient %d: %w", i, err)
			}
		}
		j.Recipients = append(j.Recipients, r)
	}
	if err := j.check(); err != nil {
		return nil, err
	}
	return j, nil
}

// check applies the structural rules common to parsing and encrypting.
func (j *JSON) check() error {
	if len(j.Recipients) == 0 {
		return fmt.Errorf("%w: no recipients", ErrMalformed)
	}
	if j.Unprotected.Has(Critical) {
		return fmt.Errorf(`%w: "crit" must be integrity protected`, ErrMalformed)
	}
	if j.Protected.Has(EncryptionAlgorithm) == j.Unprotected.Has(EncryptionAlgorithm) {
		return fmt.Errorf(`%w: "enc" must be in exactly one of the protected and shared unprotected headers`, ErrMalformed)
	}
	for name := range j.Unprotected {
		if j.Protected.Has(name) {
			return fmt.Errorf("%w: header parameter %q is both protected and unprotected", ErrMalformed, name)
		}
	}
	for i, r := range j.Recipients {
		for name := range r.Header {
			if j.Protected.Has(name) || j.Unprotected.Has(name) {
				return fmt.Errorf("%w: recipient %d: header parameter %q is not disjoint from the shared headers", ErrMalformed, i, name)
			}
		}
		combined := j.Header(i)
		switch {
		case r.Header.Has(Critical):
			return fmt.Errorf(`%w: recipient %d: "crit" must be integrity protected`, ErrMalformed, i)
		case r.Header.Has(EncryptionAlgorithm):
			return fmt.Errorf(`%w: recipient %d: "enc" must be shared by all recipients`, ErrMalformed, i)
		case combined.Has(CompressionAlgorithm):
			return fmt.Errorf("%w: compression (%q)", ErrUnsupported, CompressionAlgorithm)
		}
		alg, err := combined.Algorithm()
		if err != nil {
			return fmt.Errorf("%w: recipient %d: %v", ErrMalformed, i, err)
		}
		if _, err := combined.EncryptionAlgorithm(); err != nil {
			return fmt.Errorf("%w: recipient %d: %v", ErrMalformed, i, err)
		}
		if len(j.Recipients) > 1 && (alg == jwa.Direct || alg == jwa.ECDHES) {
			return fmt.Errorf("%w: %q fixes the content key and allows a single recipient", ErrMalformed, alg)
		}
	}
	return nil
}

// decodeJSONSegment decodes strict, unpadded base64url; empty is allowed.
func decodeJSONSegment(segment, what string) ([]byte, error) {
	if segment == "" {
		return []byte{}, nil
	}
	if strings.ContainsAny(segment, "=+/") {
		return nil, fmt.Errorf("%w: %s is not unpadded base64url", ErrMalformed, what)
	}
	decoded, err := base64url.Decode(segment)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, what, err)
	}
	return decoded, nil
}

func parseProtectedHeader(data []byte) (header.Parameters, error) {
	if err := strictjson.CheckDuplicates(data); err != nil {
		return nil, fmt.Errorf("%w: protected header: %v", ErrMalformed, err)
	}
	var h header.Parameters
	if err := json.Unmarshal(data, &h); err != nil || h == nil {
		return nil, fmt.Errorf("%w: protected header is not a JSON object", ErrMalformed)
	}
	return h, nil
}

// supportedKeyManagement reports whether alg is a key management
// algorithm this package implements.
func supportedKeyManagement(alg jwa.Algorithm) bool {
	switch alg {
	case jwa.Direct, jwa.A128KW, jwa.A192KW, jwa.A256KW,
		jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW,
		jwa.RSAOAEP, jwa.RSAOAEP256:
		return true
	}
	return false
}

// Decrypt tries the recipients in order with key and returns the plaintext
// and the index of the recipient that decrypted. A single key is tried
// against every recipient, so a JWE addressed to several recipients
// decrypts for each of them with their own key.
//
// Recipients whose "alg" is not in opts.Algorithms or is not implemented
// (RSA1_5, PBES2) are skipped; if none remain, Decrypt returns
// [ErrNotAllowed] or [ErrUnsupported]. A disallowed or unsupported "enc",
// "zip", and a "crit" extension not in opts.SupportedCriticalHeaders are
// refused for the whole message. Every other failure, including a key of
// the wrong type, a wrong key, and any modification of the protected
// header, AAD, IV, ciphertext, tag or encrypted key, returns the same
// [ErrDecryption], so the error does not reveal which step failed.
//
// The additional authenticated data is the protected header as received,
// followed by "." and the AAD when present (RFC 7516 §5.1 step 14), so
// re-serializing never changes what is authenticated.
//
// https://www.rfc-editor.org/rfc/rfc7516#section-5.2
func (j *JSON) Decrypt(key any, opts DecryptOptions) (plaintext []byte, recipient int, err error) {
	if key == nil {
		return nil, -1, fmt.Errorf("%w: Decrypt needs a key", ErrUnsupported)
	}
	if err := j.check(); err != nil {
		return nil, -1, err
	}
	enc, err := joseHeader(j.Protected, j.Unprotected).EncryptionAlgorithm()
	if err != nil {
		return nil, -1, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if opts.Encryptions != nil && !slices.Contains(opts.Encryptions, enc) {
		return nil, -1, fmt.Errorf("%w: %q", ErrNotAllowed, enc)
	}
	content, err := contentCipherFor(enc)
	if err != nil {
		return nil, -1, err
	}
	if err := j.Protected.ValidateCriticalHeaders(opts.SupportedCriticalHeaders); err != nil {
		return nil, -1, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	aad := []byte(j.authenticatedData())

	var notAllowed, unsupported int
	for i, r := range j.Recipients {
		h := j.Header(i)
		alg, _ := h.Algorithm()
		switch {
		case opts.Algorithms != nil && !slices.Contains(opts.Algorithms, alg):
			notAllowed++
			continue
		case !supportedKeyManagement(alg):
			unsupported++
			continue
		}
		cek, err := recoverContentKey(alg, enc, content.keySize, key, h, r.EncryptedKey)
		if err != nil {
			continue
		}
		plaintext, err := content.open(cek, j.IV, j.Ciphertext, j.Tag, aad)
		if err != nil {
			continue
		}
		return plaintext, i, nil
	}
	switch {
	case unsupported > 0 && notAllowed+unsupported == len(j.Recipients):
		return nil, -1, fmt.Errorf("%w: no recipient uses a key management algorithm this package implements", ErrUnsupported)
	case notAllowed+unsupported == len(j.Recipients):
		return nil, -1, fmt.Errorf("%w: no recipient uses an allowed algorithm", ErrNotAllowed)
	}
	return nil, -1, errDecryption
}

// authenticatedData returns the content encryption AAD: the encoded
// protected header and, when present, "." and the encoded AAD.
func (j *JSON) authenticatedData() string {
	protected := j.encodedProtected()
	if aad, ok := j.encodedAAD(); ok {
		return protected + "." + aad
	}
	return protected
}

// encodedProtected returns the protected header's encoding as received (or
// as encrypted) while Protected still holds what it says, else a fresh
// encoding of Protected.
//
// An explicitly empty protected header ("e30", "{}") is kept: it is part of
// the authenticated data, so it cannot be treated as absent.
func (j *JSON) encodedProtected() string {
	if j.protected != "" {
		if decoded, err := base64url.Decode(j.protected); err == nil {
			if parsed, err := parseProtectedHeader(decoded); err == nil &&
				(len(parsed) == 0 && len(j.Protected) == 0 || reflect.DeepEqual(parsed, j.Protected)) {
				return j.protected
			}
		}
	}
	if len(j.Protected) == 0 {
		return ""
	}
	protectedJSON, err := json.Marshal(j.Protected)
	if err != nil {
		return ""
	}
	return encodeSegment(protectedJSON)
}

func (j *JSON) encodedAAD() (string, bool) {
	if j.hasAAD {
		if decoded, err := decodeJSONSegment(j.aad, "aad"); err == nil && bytes.Equal(decoded, j.AAD) {
			return j.aad, true
		}
	}
	if len(j.AAD) > 0 {
		return encodeSegment(j.AAD), true
	}
	return "", false
}

// EncryptJSON encrypts plaintext once and wraps the content key for every
// recipient, returning the JWE in JSON Serialization form.
//
// protected must carry "enc" or unprotected must (not both); the combined
// header of each recipient (protected, unprotected and RecipientKey.Header)
// must carry "alg" and have disjoint names. Put every parameter a recipient
// relies on in protected, since only it is integrity protected. aad is
// optional additional authenticated data that is authenticated but not
// encrypted. "dir" and "ECDH-ES" fix the content key and so are accepted
// only with a single recipient. Each ECDH-ES recipient gets its own
// ephemeral key, returned in that recipient's Header as "epk". The inputs
// are not modified. See the package documentation for the key types each
// algorithm takes.
//
// https://www.rfc-editor.org/rfc/rfc7516#section-5.1
func EncryptJSON(protected, unprotected header.Parameters, plaintext, aad []byte, recipients ...RecipientKey) (*JSON, error) {
	if len(recipients) == 0 {
		return nil, errors.New("jwe: EncryptJSON needs at least one recipient")
	}
	j := &JSON{
		Protected:   maps.Clone(protected),
		Unprotected: maps.Clone(unprotected),
		AAD:         slices.Clone(aad),
	}
	for _, r := range recipients {
		j.Recipients = append(j.Recipients, Recipient{Header: maps.Clone(r.Header)})
	}
	if err := j.check(); err != nil {
		return nil, err
	}
	for i := range j.Recipients {
		if j.Header(i).Has(EphemeralPublicKey) {
			return nil, fmt.Errorf("%w: recipient %d: %q is generated by EncryptJSON", ErrMalformed, i, EphemeralPublicKey)
		}
	}
	enc, _ := joseHeader(j.Protected, j.Unprotected).EncryptionAlgorithm()
	content, err := contentCipherFor(enc)
	if err != nil {
		return nil, err
	}

	cek, err := randomBytes(content.keySize)
	if err != nil {
		return nil, err
	}
	for i, r := range recipients {
		h := j.Header(i)
		alg, _ := h.Algorithm()
		contentKey, encryptedKey, epk, err := manageKey(alg, enc, r.Key, h, content, cek)
		if err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		cek = contentKey // only differs for the single "dir" or "ECDH-ES" recipient
		j.Recipients[i].EncryptedKey = encryptedKey
		if epk != nil {
			if j.Recipients[i].Header == nil {
				j.Recipients[i].Header = make(header.Parameters)
			}
			j.Recipients[i].Header[EphemeralPublicKey] = epk
		}
	}

	if j.Protected != nil {
		protectedJSON, err := json.Marshal(j.Protected)
		if err != nil {
			return nil, fmt.Errorf("jwe: encode protected header: %w", err)
		}
		j.protected = encodeSegment(protectedJSON)
	}
	if len(j.AAD) > 0 {
		j.aad, j.hasAAD = encodeSegment(j.AAD), true
	}
	if j.IV, err = randomBytes(content.ivSize); err != nil {
		return nil, err
	}
	if j.Ciphertext, j.Tag, err = content.seal(cek, j.IV, plaintext, []byte(j.authenticatedData())); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *JSON) wire() jsonWire {
	wire := jsonWire{}
	if protected := j.encodedProtected(); protected != "" {
		wire.Protected = &protected
	}
	if len(j.Unprotected) > 0 {
		wire.Unprotected = j.Unprotected
	}
	if aad, ok := j.encodedAAD(); ok {
		wire.AAD = &aad
	}
	iv, ciphertext, tag := encodeSegment(j.IV), encodeSegment(j.Ciphertext), encodeSegment(j.Tag)
	wire.IV, wire.Ciphertext, wire.Tag = &iv, &ciphertext, &tag
	return wire
}

func (r Recipient) wire() jsonWireRecip {
	var entry jsonWireRecip
	if len(r.Header) > 0 {
		entry.Header = r.Header
	}
	if len(r.EncryptedKey) > 0 {
		key := encodeSegment(r.EncryptedKey)
		entry.EncryptedKey = &key
	}
	return entry
}

// General returns the JWE in the general JSON Serialization.
//
// https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
func (j *JSON) General() ([]byte, error) {
	if err := j.check(); err != nil {
		return nil, err
	}
	wire := j.wire()
	for _, r := range j.Recipients {
		wire.Recipients = append(wire.Recipients, r.wire())
	}
	return json.Marshal(wire)
}

// Flattened returns the JWE in the flattened JSON Serialization, which
// holds exactly one recipient and so fails otherwise.
//
// https://www.rfc-editor.org/rfc/rfc7516#section-7.2.2
func (j *JSON) Flattened() ([]byte, error) {
	if len(j.Recipients) != 1 {
		return nil, fmt.Errorf("jwe: flattened syntax holds one recipient, have %d", len(j.Recipients))
	}
	if err := j.check(); err != nil {
		return nil, err
	}
	wire := j.wire()
	entry := j.Recipients[0].wire()
	wire.Header, wire.EncryptedKey = entry.Header, entry.EncryptedKey
	return json.Marshal(wire)
}
