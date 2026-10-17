// Package dpop implements OAuth 2.0 Demonstrating Proof of Possession
// (DPoP) as defined in RFC 9449.
//
// A DPoP proof is a short-lived JWT, signed by a key the client holds, that
// binds one HTTP request (method and target URI) to that key. Servers bind
// access tokens and authorization codes to the key's JWK Thumbprint ("jkt"),
// so a stolen token is useless without the private key.
//
// The package has three parts:
//
//   - [Signer] mints proofs with any [crypto.Signer], so the proof key can
//     live in hardware (PIV, TPM, Secure Enclave) and never be exported.
//   - [Verifier] checks a proof against a request, following every step of
//     RFC 9449 §4.3, with optional nonce (§8, §9) and replay (§11.1) checks.
//   - Package [github.com/picatz/jose/pkg/dpop/dpophttp] connects both to
//     net/http: a client Transport that attaches proofs and retries once
//     when a server asks for a fresh nonce, and server request helpers.
//
// This package does not import net/http.
//
// # What DPoP does not do
//
// A proof covers the method and the target URI without its query or
// fragment. It does not sign headers, the query or the body, does not
// authenticate the client to the authorization server, and is not a
// substitute for TLS (RFC 9449 §11). A verified proof shows possession of a
// key; whether that key may act is the caller's authorization decision.
package dpop

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"

	"github.com/picatz/jose/internal/base64url"
)

// Media type, header and error names.
const (
	// Type is the "typ" header value of every proof.
	// https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2
	Type = "dpop+jwt"

	// HeaderName carries the proof on a request.
	// https://www.rfc-editor.org/rfc/rfc9449.html#section-4.1
	HeaderName = "DPoP"

	// NonceHeaderName carries a server-supplied nonce on a response.
	// https://www.rfc-editor.org/rfc/rfc9449.html#section-8
	NonceHeaderName = "DPoP-Nonce"

	// AuthorizationScheme is the HTTP authentication scheme for
	// DPoP-bound access tokens.
	// https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
	AuthorizationScheme = "DPoP"

	// TokenType is the "token_type" an authorization server returns for a
	// DPoP-bound access token.
	// https://www.rfc-editor.org/rfc/rfc9449.html#section-5
	TokenType = "DPoP"

	// ErrorInvalidProof is the OAuth error code for a rejected proof.
	// https://www.rfc-editor.org/rfc/rfc9449.html#section-5
	ErrorInvalidProof = "invalid_dpop_proof"

	// ErrorUseNonce is the OAuth error code asking the client to retry with
	// the nonce in the DPoP-Nonce response header.
	// https://www.rfc-editor.org/rfc/rfc9449.html#section-8
	ErrorUseNonce = "use_dpop_nonce"
)

// Claim names used in proofs and in DPoP-bound access tokens.
const (
	// https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2
	ClaimJWTID           = "jti"
	ClaimHTTPMethod      = "htm"
	ClaimHTTPURI         = "htu"
	ClaimIssuedAt        = "iat"
	ClaimAccessTokenHash = "ath"
	ClaimNonce           = "nonce"

	// ClaimConfirmation ("cnf") holds ConfirmationThumbprint ("jkt") in a
	// DPoP-bound JWT access token.
	// https://www.rfc-editor.org/rfc/rfc9449.html#section-6.1
	ClaimConfirmation      = "cnf"
	ConfirmationThumbprint = "jkt"
)

var (
	// ErrInvalidProof wraps every reason a proof is rejected. Servers
	// respond with [ErrorInvalidProof].
	ErrInvalidProof = errors.New("dpop: invalid proof")

	// ErrUseNonce means the proof lacked the nonce the server requires, or
	// carried a stale one. Servers respond with [ErrorUseNonce] and a fresh
	// DPoP-Nonce header. It also matches [ErrInvalidProof].
	ErrUseNonce = fmt.Errorf("%w: missing or stale nonce", ErrInvalidProof)

	// ErrReplay means the proof's "jti" was already used. It also matches
	// [ErrInvalidProof].
	ErrReplay = fmt.Errorf("%w: replayed", ErrInvalidProof)

	// ErrBinding means the proof key does not match the key the access
	// token or authorization code is bound to. It also matches
	// [ErrInvalidProof].
	ErrBinding = fmt.Errorf("%w: key does not match the token binding", ErrInvalidProof)
)

// AccessTokenHash returns the "ath" value for an access token: the
// base64url SHA-256 hash of its ASCII encoding.
//
// https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	s := base64url.Encode(sum[:])
	return s
}

// Confirmation returns the "cnf" claim value that binds a JWT access token
// to the key with JWK Thumbprint jkt.
//
// https://www.rfc-editor.org/rfc/rfc9449.html#section-6.1
func Confirmation(jkt string) map[string]any {
	return map[string]any{ConfirmationThumbprint: jkt}
}

// BoundThumbprint returns the "jkt" member of the "cnf" claim in a JWT
// access token's claims. Pass the result as [Request.Thumbprint] when
// verifying the proof that accompanies the token.
//
// https://www.rfc-editor.org/rfc/rfc9449.html#section-6.1
func BoundThumbprint(claims map[string]any) (string, error) {
	cnf, ok := claims[ClaimConfirmation].(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: access token has no %q claim", ErrBinding, ClaimConfirmation)
	}
	jkt, ok := cnf[ConfirmationThumbprint].(string)
	if !ok || jkt == "" {
		return "", fmt.Errorf("%w: %q has no %q member", ErrBinding, ClaimConfirmation, ConfirmationThumbprint)
	}
	return jkt, nil
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	return maps.Clone(m)
}
