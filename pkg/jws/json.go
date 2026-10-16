package jws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/picatz/jose/internal/strictjson"
	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
)

// ErrNoValidSignature reports that no signature of a JWS JSON Serialization
// verified with the given key.
var ErrNoValidSignature = errors.New("jws: no signature verifies with the key")

// JSON is a JWS in the JSON Serialization: one payload with one or more
// signatures, each with its own header. Unlike the compact serialization,
// it can carry several signatures (for example, one per signer or per key
// during a rotation) and header parameters that are not integrity protected.
//
// The general syntax lists signatures under "signatures"; the flattened
// syntax inlines the only signature. [ParseJSON] reads both, and
// [JSON.General] and [JSON.Flattened] write them.
//
// https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2
type JSON struct {
	// Payload is the secured content.
	Payload []byte

	// Signatures are the signatures over Payload, in order.
	Signatures []JSONSignature

	// payload is the base64url encoding of Payload as received, so
	// verification covers the exact bytes another implementation signed.
	payload string
}

// JSONSignature is one signature of a [JSON] JWS.
//
// https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1
type JSONSignature struct {
	// Protected holds the integrity-protected header parameters; the
	// signature covers them.
	Protected Header

	// Unprotected holds header parameters the signature does not cover,
	// such as a "kid" hint. Treat them as untrusted.
	Unprotected Header

	// Signature is the signature or MAC value.
	Signature []byte

	// protected is the base64url encoding of Protected as received or
	// signed.
	protected string
}

// Header returns the JOSE Header of the signature: the union of its
// protected and unprotected parameters, which RFC 7515 §7.2.1 requires to
// be disjoint.
func (s JSONSignature) Header() Header {
	union := make(Header, len(s.Protected)+len(s.Unprotected))
	for name, value := range s.Unprotected {
		union[name] = value
	}
	for name, value := range s.Protected {
		union[name] = value
	}
	return union
}

// JSONSigner describes one signature for [SignJSON].
type JSONSigner struct {
	// Protected must hold "alg". Put every parameter a verifier relies on
	// here, since only these are integrity protected.
	Protected Header

	// Unprotected may hold hints such as "kid"; it may be nil.
	Unprotected Header

	// Key signs, as for [Signature.Sign]: a [crypto.Signer] for asymmetric
	// algorithms, or a []byte or string secret for HMAC.
	Key any
}

// SignJSON signs payload once for each signer and returns the JWS in JSON
// Serialization. Each signer's protected header must carry "alg", and
// "alg" "none" is refused: an unsecured JWS has no place among signatures.
func SignJSON(payload []byte, signers ...JSONSigner) (*JSON, error) {
	if len(signers) == 0 {
		return nil, errors.New("jws: SignJSON needs at least one signer")
	}
	encodedPayload := encodeSegment(payload)
	signed := &JSON{Payload: payload, payload: encodedPayload}
	for index, signer := range signers {
		if err := checkJSONHeaders(signer.Protected, signer.Unprotected); err != nil {
			return nil, fmt.Errorf("jws: signer %d: %w", index, err)
		}
		alg, err := signer.Protected.Algorithm()
		if err != nil {
			return nil, fmt.Errorf("jws: signer %d: protected header needs alg: %w", index, err)
		}
		if alg == jwa.None {
			return nil, fmt.Errorf("jws: signer %d: alg %q cannot sign", index, alg)
		}
		protectedJSON, err := json.Marshal(signer.Protected)
		if err != nil {
			return nil, fmt.Errorf("jws: signer %d: marshal protected header: %w", index, err)
		}
		entry := JSONSignature{
			Protected:   signer.Protected,
			Unprotected: signer.Unprotected,
			protected:   encodeSegment(protectedJSON),
		}
		signature, err := new(Signature).signInput(alg, signer.Key, entry.protected+"."+encodedPayload)
		if err != nil {
			return nil, fmt.Errorf("jws: signer %d: %w", index, err)
		}
		entry.Signature = signature
		signed.Signatures = append(signed.Signatures, entry)
	}
	return signed, nil
}

// compact returns the signature as a compact [Signature] over the exact
// encoded protected header and payload, so Verify reuses the compact code
// path. The alg it verifies with comes from the signature's whole JOSE
// Header.
func (s JSONSignature) compact(encodedPayload string, payload []byte) *Signature {
	return &Signature{
		Header:    s.Header(),
		Payload:   payload,
		Signature: s.Signature,
		raw:       s.protected + "." + encodedPayload + "." + encodeSegment(s.Signature),
	}
}

// jsonWire is the JSON Serialization in either syntax.
type jsonWire struct {
	Payload    *string        `json:"payload"`
	Signatures []jsonWireSig  `json:"signatures,omitempty"`
	Protected  *string        `json:"protected,omitempty"`
	Header     map[string]any `json:"header,omitempty"`
	Signature  *string        `json:"signature,omitempty"`
}

type jsonWireSig struct {
	Protected *string        `json:"protected,omitempty"`
	Header    map[string]any `json:"header,omitempty"`
	Signature *string        `json:"signature"`
}

// ParseJSON parses a JWS in the general or flattened JSON Serialization.
// It checks the structure, not the signatures: call [JSON.Verify].
//
// As RFC 7515 requires, every signature must have a header with "alg", its
// protected and unprotected parameter names must not overlap (§7.2.1),
// and "crit" must be protected and name only understood extensions
// (§4.1.11), so any "crit" is refused. Detached payloads (RFC 7515
// Appendix F) and unencoded payloads (RFC 7797) are not supported.
func ParseJSON(data []byte) (*JSON, error) {
	if err := strictjson.CheckDuplicates(data); err != nil {
		return nil, fmt.Errorf("jws: invalid JSON serialization: %w", err)
	}
	var wire jsonWire
	// Members this package does not understand are ignored, as RFC 7515
	// §7.2.1 requires.
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&wire); err != nil {
		return nil, fmt.Errorf("jws: invalid JSON serialization: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("jws: trailing data after JSON serialization")
	}
	if wire.Payload == nil {
		return nil, errors.New("jws: JSON serialization has no payload (detached payloads are not supported)")
	}
	flattened := wire.Protected != nil || wire.Header != nil || wire.Signature != nil
	switch {
	case flattened && wire.Signatures != nil:
		return nil, errors.New("jws: JSON serialization mixes general and flattened syntax")
	case flattened:
		wire.Signatures = []jsonWireSig{{Protected: wire.Protected, Header: wire.Header, Signature: wire.Signature}}
	case len(wire.Signatures) == 0:
		return nil, errors.New("jws: JSON serialization has no signatures")
	}
	payload, err := decodeSegment(*wire.Payload, "payload")
	if err != nil {
		return nil, err
	}
	parsed := &JSON{Payload: payload, payload: *wire.Payload}
	for index, entry := range wire.Signatures {
		signature, err := parseJSONSignature(entry)
		if err != nil {
			return nil, fmt.Errorf("jws: signature %d: %w", index, err)
		}
		parsed.Signatures = append(parsed.Signatures, signature)
	}
	return parsed, nil
}

func parseJSONSignature(entry jsonWireSig) (JSONSignature, error) {
	if entry.Signature == nil {
		return JSONSignature{}, errors.New("missing signature")
	}
	if entry.Protected == nil && entry.Header == nil {
		return JSONSignature{}, errors.New("missing header: needs protected or header")
	}
	var signature JSONSignature
	if entry.Protected != nil {
		protectedJSON, err := decodeSegment(*entry.Protected, "protected header")
		if err != nil {
			return JSONSignature{}, err
		}
		if !utf8.Valid(protectedJSON) {
			return JSONSignature{}, errors.New("protected header is not valid UTF-8")
		}
		if signature.Protected, err = parseHeaderStrict(protectedJSON); err != nil {
			return JSONSignature{}, fmt.Errorf("protected header: %w", err)
		}
		signature.protected = *entry.Protected
	}
	if entry.Header != nil {
		signature.Unprotected = Header(entry.Header)
	}
	if err := checkJSONHeaders(signature.Protected, signature.Unprotected); err != nil {
		return JSONSignature{}, err
	}
	alg, err := signature.Header().Algorithm()
	if err != nil {
		return JSONSignature{}, fmt.Errorf("missing or invalid alg: %w", err)
	}
	if signature.Signature, err = decodeSegment(*entry.Signature, "signature"); err != nil {
		return JSONSignature{}, err
	}
	switch {
	case alg == jwa.None:
		return JSONSignature{}, fmt.Errorf("alg %q is unsecured; refusing it", alg)
	case len(signature.Signature) == 0:
		return JSONSignature{}, errors.New("empty signature")
	}
	return signature, nil
}

// checkJSONHeaders applies the header rules common to signing and
// parsing: disjoint names (RFC 7515 §7.2.1) and "crit" only in the
// protected header (§4.1.11), where no extension is understood.
func checkJSONHeaders(protected, unprotected Header) error {
	for name := range unprotected {
		if _, ok := protected[name]; ok {
			return fmt.Errorf("header parameter %q is both protected and unprotected", name)
		}
	}
	if _, ok := unprotected[header.Critical]; ok {
		return errors.New(`"crit" must be integrity protected`)
	}
	// The unencoded payload option (RFC 7797) is supported only for a
	// detached compact JWS; see ParseDetached.
	for _, h := range []Header{protected, unprotected} {
		if _, ok := h[header.Base64URLEncodePayload]; ok {
			return fmt.Errorf("header parameter %q is not supported in the JSON serialization", header.Base64URLEncodePayload)
		}
	}
	return processCriticalHeaders(protected)
}

// Verify checks the signatures against key in order and returns the index
// of the first that verifies, so a verifier can then read that signature's
// protected header. Signatures whose algorithm does not suit key, or is
// not in allowed when allowed is given, are skipped. It returns
// [ErrNoValidSignature] when none verifies.
//
// Verification covers Payload and each Protected header as they are now:
// the encodings a parsed JWS arrived with are used only while those fields
// still hold what was parsed.
//
// Verify does not say which signer a valid signature belongs to beyond key
// itself: treat Unprotected parameters, such as a "kid", as hints only.
func (j *JSON) Verify(key any, allowed ...jwa.Algorithm) (int, error) {
	if key == nil {
		return -1, errors.New("jws: Verify needs a key")
	}
	payload := j.encodedPayload()
	for index, signature := range j.Signatures {
		protected, err := signature.encodedProtected()
		if err != nil {
			continue
		}
		signature.protected = protected
		alg, err := signature.Header().Algorithm()
		if err != nil || alg == jwa.None || (len(allowed) > 0 && !slices.Contains(allowed, alg)) {
			continue
		}
		if signature.compact(payload, j.Payload).Verify(key) == nil {
			return index, nil
		}
	}
	return -1, ErrNoValidSignature
}

// General returns the JWS in the general JSON Serialization.
//
// https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1
func (j *JSON) General() ([]byte, error) {
	if len(j.Signatures) == 0 {
		return nil, errors.New("jws: no signatures to serialize")
	}
	payload := j.encodedPayload()
	wire := jsonWire{Payload: &payload}
	for _, signature := range j.Signatures {
		entry, err := signature.wire()
		if err != nil {
			return nil, err
		}
		wire.Signatures = append(wire.Signatures, entry)
	}
	return json.Marshal(wire)
}

// Flattened returns the JWS in the flattened JSON Serialization, which
// holds exactly one signature. ACME (RFC 8555 §6.2) uses this syntax.
//
// https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.2
func (j *JSON) Flattened() ([]byte, error) {
	if len(j.Signatures) != 1 {
		return nil, fmt.Errorf("jws: flattened syntax holds one signature, have %d", len(j.Signatures))
	}
	entry, err := j.Signatures[0].wire()
	if err != nil {
		return nil, err
	}
	payload := j.encodedPayload()
	return json.Marshal(jsonWire{Payload: &payload, Protected: entry.Protected, Header: entry.Header, Signature: entry.Signature})
}

// Compact returns signature index in the compact serialization. It fails
// when that signature has unprotected header parameters, which the compact
// serialization cannot carry.
func (j *JSON) Compact(index int) (string, error) {
	if index < 0 || index >= len(j.Signatures) {
		return "", fmt.Errorf("jws: no signature %d", index)
	}
	signature := j.Signatures[index]
	if len(signature.Unprotected) > 0 {
		return "", errors.New("jws: the compact serialization cannot carry unprotected header parameters")
	}
	if len(signature.Protected) == 0 {
		return "", errors.New("jws: the compact serialization needs a protected header with alg")
	}
	entry, err := signature.wire()
	if err != nil {
		return "", err
	}
	return *entry.Protected + "." + j.encodedPayload() + "." + *entry.Signature, nil
}

func (s JSONSignature) wire() (jsonWireSig, error) {
	var entry jsonWireSig
	protected, err := s.encodedProtected()
	if err != nil {
		return jsonWireSig{}, err
	}
	if protected != "" {
		entry.Protected = &protected
	}
	if len(s.Unprotected) > 0 {
		entry.Header = s.Unprotected
	}
	signature := encodeSegment(s.Signature)
	entry.Signature = &signature
	return entry, nil
}

// encodedProtected returns the protected header's encoding: the one it was
// parsed or signed with while Protected still holds what that encoding
// says, else a fresh encoding of Protected.
func (s JSONSignature) encodedProtected() (string, error) {
	if len(s.Protected) == 0 {
		return "", nil
	}
	if s.protected != "" {
		if decoded, err := base64.Decode(s.protected); err == nil {
			if parsed, err := parseHeaderStrict(decoded); err == nil && reflect.DeepEqual(parsed, s.Protected) {
				return s.protected, nil
			}
		}
	}
	protectedJSON, err := json.Marshal(s.Protected)
	if err != nil {
		return "", fmt.Errorf("jws: marshal protected header: %w", err)
	}
	return encodeSegment(protectedJSON), nil
}

// encodedPayload returns the payload's encoding as received while Payload
// still holds those bytes, else a fresh encoding of Payload.
func (j *JSON) encodedPayload() string {
	if j.payload != "" {
		if decoded, err := base64.Decode(j.payload); err == nil && bytes.Equal(decoded, j.Payload) {
			return j.payload
		}
	}
	return encodeSegment(j.Payload)
}

// encodeSegment base64url-encodes b; empty input encodes as "".
func encodeSegment(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	encoded, _ := base64.Encode(b)
	return encoded
}

func decodeSegment(segment, what string) ([]byte, error) {
	if segment == "" {
		return []byte{}, nil
	}
	if strings.ContainsAny(segment, "=+/") {
		return nil, fmt.Errorf("jws: %s is not unpadded base64url", what)
	}
	decoded, err := base64.Decode(segment)
	if err != nil {
		return nil, fmt.Errorf("jws: decode %s: %w", what, err)
	}
	return decoded, nil
}
