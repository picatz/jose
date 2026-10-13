// Package dpophttp connects DPoP (RFC 9449) to net/http: an
// [http.RoundTripper] that attaches proofs to client requests, and helpers
// that read a proof and a DPoP-bound access token from a server request.
//
// It is separate from [dpop] so that programs which only mint or verify
// proofs do not link an HTTP stack.
package dpophttp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/picatz/jose/pkg/dpop"
)

// ProofForRequest returns a proof from s for r, using r.Method (GET when
// empty) and r.URL, which must be absolute, as it is for client requests.
func ProofForRequest(s *dpop.Signer, r *http.Request, opts dpop.ProofOptions) (string, error) {
	if s == nil || r == nil || r.URL == nil {
		return "", fmt.Errorf("dpophttp: nil signer or request")
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	return s.Proof(method, r.URL.String(), opts)
}

// FromRequest returns the proof in r's DPoP header. It rejects requests
// with no proof or with more than one DPoP header (RFC 9449 §4.3 step 1).
// Errors wrap [dpop.ErrInvalidProof].
func FromRequest(r *http.Request) (string, error) {
	values := r.Header.Values(dpop.HeaderName)
	switch len(values) {
	case 0:
		return "", fmt.Errorf("%w: missing %s header", dpop.ErrInvalidProof, dpop.HeaderName)
	case 1:
		if values[0] == "" {
			return "", fmt.Errorf("%w: empty %s header", dpop.ErrInvalidProof, dpop.HeaderName)
		}
		return values[0], nil
	default:
		return "", fmt.Errorf("%w: more than one %s header", dpop.ErrInvalidProof, dpop.HeaderName)
	}
}

// AccessTokenFromRequest returns the access token from an
// "Authorization: DPoP <token>" header. The scheme is matched
// case-insensitively.
//
// https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
func AccessTokenFromRequest(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", fmt.Errorf("dpophttp: want exactly one Authorization header, got %d", len(values))
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, dpop.AuthorizationScheme) || token == "" || strings.ContainsAny(token, " \t") {
		return "", fmt.Errorf("dpophttp: Authorization header does not use the %s scheme", dpop.AuthorizationScheme)
	}
	return token, nil
}
