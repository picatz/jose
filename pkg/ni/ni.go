// Package ni implements Named Information URIs (RFC 6920): a digest of some
// bytes written as a URI such as "ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk".
//
// A ni URI names content by what it is rather than where it lives, which
// makes it a safe way for one token to refer to another: change a single
// byte of the referenced token and the URI no longer matches. Pair [Sum]
// with [URI.Matches], or [Parse] a URI received from someone else.
//
// Only full-length digests are supported; the truncated algorithms in the
// registry ("sha-256-32" and so on) are refused because they are too short
// to bind content.
//
// https://www.rfc-editor.org/rfc/rfc6920.html
package ni

import (
	"crypto"
	_ "crypto/sha256" // sha-256
	_ "crypto/sha3"   // sha3-256, sha3-384, sha3-512
	_ "crypto/sha512" // sha-384, sha-512
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/picatz/jose/pkg/base64"
)

// ErrFormat means a string is not a supported ni URI.
var ErrFormat = errors.New("ni: malformed URI")

// algorithms maps the Named Information Hash Algorithm Registry names this
// package accepts to their hashes.
//
// https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg
var algorithms = map[string]crypto.Hash{
	"sha-256":  crypto.SHA256,
	"sha-384":  crypto.SHA384,
	"sha-512":  crypto.SHA512,
	"sha3-256": crypto.SHA3_256,
	"sha3-384": crypto.SHA3_384,
	"sha3-512": crypto.SHA3_512,
}

// AlgorithmName returns the registry name of h, such as "sha-256", or an
// error if this package does not support h.
func AlgorithmName(h crypto.Hash) (string, error) {
	for name, candidate := range algorithms {
		if candidate == h {
			return name, nil
		}
	}
	return "", fmt.Errorf("ni: unsupported hash %v", h)
}

// URI is a parsed Named Information URI.
type URI struct {
	// Authority is the optional authority (RFC 6920 §3), usually empty.
	// It says where the content might be found and is not covered by the
	// digest.
	Authority string
	// Hash is the digest algorithm.
	Hash crypto.Hash
	// Digest is the raw digest value.
	Digest []byte
}

// Sum returns the ni URI of data under h, with no authority.
func Sum(h crypto.Hash, data []byte) (URI, error) {
	if _, err := AlgorithmName(h); err != nil {
		return URI{}, err
	}
	digest := h.New()
	digest.Write(data)
	return URI{Hash: h, Digest: digest.Sum(nil)}, nil
}

// Parse parses a ni URI. It refuses query parameters, unsupported or
// truncated algorithms, padding, and digests of the wrong length.
//
// https://www.rfc-editor.org/rfc/rfc6920.html#section-3
func Parse(s string) (URI, error) {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok || !strings.EqualFold(scheme, "ni") {
		return URI{}, fmt.Errorf("%w: want \"ni://[authority]/alg;value\"", ErrFormat)
	}
	authority, path, ok := strings.Cut(rest, "/")
	if !ok {
		return URI{}, fmt.Errorf("%w: missing path", ErrFormat)
	}
	if strings.ContainsAny(path, "?#") {
		return URI{}, fmt.Errorf("%w: query and fragment are not supported", ErrFormat)
	}
	name, value, ok := strings.Cut(path, ";")
	if !ok {
		return URI{}, fmt.Errorf("%w: missing \";\" between algorithm and value", ErrFormat)
	}
	h, ok := algorithms[name]
	if !ok {
		return URI{}, fmt.Errorf("%w: unsupported algorithm %q", ErrFormat, name)
	}
	digest, err := base64.Decode(value)
	if err != nil || strings.ContainsRune(value, '=') {
		return URI{}, fmt.Errorf("%w: value is not unpadded base64url", ErrFormat)
	}
	if len(digest) != h.Size() {
		return URI{}, fmt.Errorf("%w: %s digest is %d bytes, want %d", ErrFormat, name, len(digest), h.Size())
	}
	return URI{Authority: authority, Hash: h, Digest: digest}, nil
}

// String returns the URI in its canonical form: lowercase scheme, the
// registry algorithm name, and an unpadded base64url value.
func (u URI) String() string {
	name, err := AlgorithmName(u.Hash)
	if err != nil {
		return ""
	}
	value, err := base64.Encode(u.Digest)
	if err != nil {
		return ""
	}
	return "ni://" + u.Authority + "/" + name + ";" + value
}

// Matches reports whether data has this digest. The comparison takes
// constant time in the digest length.
func (u URI) Matches(data []byte) bool {
	if _, err := AlgorithmName(u.Hash); err != nil || len(u.Digest) != u.Hash.Size() {
		return false
	}
	digest := u.Hash.New()
	digest.Write(data)
	return subtle.ConstantTimeCompare(digest.Sum(nil), u.Digest) == 1
}
