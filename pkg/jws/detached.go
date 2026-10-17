package jws

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
)

// unencodedPayload reports whether h asks for an unencoded payload
// ("b64": false, RFC 7797 §3). Because "b64" changes what is signed, a
// header carrying it must list it in "crit" (RFC 7797 §6), whatever its
// value; a header that does not is refused.
func unencodedPayload(h Header) (bool, error) {
	value, ok := h[header.Base64URLEncodePayload]
	if !ok {
		return false, nil
	}
	b64, ok := value.(bool)
	if !ok {
		return false, fail(ErrFormat, "header parameter %q must be a boolean", header.Base64URLEncodePayload)
	}
	if !listsCritical(h, header.Base64URLEncodePayload) {
		return false, fail(ErrFormat, "header parameter %q must be listed in %q", header.Base64URLEncodePayload, header.Critical)
	}
	return !b64, nil
}

// listsCritical reports whether name appears in the "crit" array of h.
func listsCritical(h Header, name string) bool {
	crit, ok := h[header.Critical].([]any)
	if !ok {
		// A header built in Go may hold []string rather than decoded JSON.
		names, ok := h[header.Critical].([]string)
		return ok && slices.Contains(names, name)
	}
	return slices.Contains(crit, any(name))
}

// ParseDetached parses a compact JWS whose payload travels separately
// (RFC 7515 Appendix F): input is "header..signature" and payload holds the
// payload octets as they were signed.
//
// ParseDetached also accepts the unencoded payload option ("b64": false,
// listed in "crit", RFC 7797), which is how detached content such as HTTP
// message bodies is usually signed. Calling ParseDetached is the opt-in:
// [Parse] still refuses "b64". Verify the result with [Signature.Verify] as
// usual; it covers payload exactly as given.
func ParseDetached(input string, payload []byte) (*Signature, error) {
	encodedHeader, signature, ok := splitDetached(input)
	if !ok {
		return nil, fail(ErrFormat, `invalid detached JWS: want "header..signature"`)
	}

	headerBytes, err := base64url.Decode(encodedHeader)
	if err != nil {
		return nil, fail(ErrFormat, "failed to decode header: %w", err)
	}
	// encoding/json would replace invalid UTF-8 with U+FFFD, exposing a
	// header that differs from the signed bytes.
	if !utf8.Valid(headerBytes) {
		return nil, fail(ErrFormat, "header is not valid UTF-8")
	}
	h, err := parseHeaderStrict(headerBytes)
	if err != nil {
		return nil, fail(ErrFormat, "failed to parse header: %w", err)
	}
	unencoded, err := unencodedPayload(h)
	if err != nil {
		return nil, err
	}
	if !unencoded {
		// An encoded payload rebuilds the attached form, so Parse applies
		// every check it applies to any other compact JWS.
		encodedPayload := ""
		if len(payload) > 0 {
			encodedPayload = base64url.Encode(payload)
		}
		return Parse(encodedHeader + "." + encodedPayload + "." + signature)
	}

	if _, err := h.Algorithm(); err != nil {
		return nil, fail(ErrAlgorithm, "missing or invalid algorithm parameter: %w", err)
	}
	if err := h.ValidateCriticalHeaders([]string{header.Base64URLEncodePayload}); err != nil {
		return nil, fail(ErrFormat, "critical header validation failed: %w", err)
	}
	sig, err := base64url.Decode(signature)
	if err != nil {
		return nil, fail(ErrFormat, "failed to decode signature: %w", err)
	}
	if len(sig) == 0 {
		return nil, fail(ErrFormat, "unencoded JWS has no signature")
	}
	return &Signature{
		Header:        h,
		Payload:       slices.Clone(payload),
		Signature:     sig,
		encodedHeader: encodedHeader,
		unencoded:     true,
	}, nil
}

// splitDetached splits "header..signature".
func splitDetached(input string) (encodedHeader, signature string, ok bool) {
	encodedHeader, rest, found := strings.Cut(input, "..")
	if !found || encodedHeader == "" || rest == "" || strings.Contains(rest, ".") || strings.Contains(encodedHeader, ".") {
		return "", "", false
	}
	return encodedHeader, rest, true
}

// Detached returns the compact serialization with the payload left out,
// "header..signature" (RFC 7515 Appendix F). Send the payload some other
// way and verify with [ParseDetached].
func (t *Signature) Detached() (string, error) {
	compact, err := t.compact()
	if err != nil {
		return "", err
	}
	first := strings.IndexByte(compact, '.')
	last := strings.LastIndexByte(compact, '.')
	if first < 0 || last == first {
		return "", fail(ErrFormat, "invalid compact JWS")
	}
	return compact[:first] + "." + compact[last:], nil
}
