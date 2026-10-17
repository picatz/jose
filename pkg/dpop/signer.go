package dpop

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
)

// Signer mints DPoP proofs with one key. It is safe for concurrent use if
// the underlying [crypto.Signer] is.
type Signer struct {
	key        crypto.Signer
	alg        jwa.Algorithm
	jwk        jwk.Value
	thumbprint string
	now        func() time.Time
}

// SignerOption configures a [Signer].
type SignerOption func(*Signer) error

// WithAlgorithm sets the JWS algorithm instead of the one [jwa.ForKey]
// picks, for example RS256 for an RSA key when a server does not accept
// PS256. It must be an asymmetric algorithm that matches the key.
func WithAlgorithm(alg jwa.Algorithm) SignerOption {
	return func(s *Signer) error {
		if !jwa.IsAsymmetricSignature(alg) {
			return fmt.Errorf("dpop: %q is not an asymmetric signature algorithm", alg)
		}
		s.alg = alg
		return nil
	}
}

// WithClock sets the clock used for "iat"; the default is [time.Now].
func WithClock(now func() time.Time) SignerOption {
	return func(s *Signer) error {
		if now == nil {
			return fmt.Errorf("dpop: nil clock")
		}
		s.now = now
		return nil
	}
}

// NewSigner returns a Signer for key. The key's public half is embedded in
// every proof as the "jwk" header, so it must be an ECDSA (P-256, P-384,
// P-521), Ed25519 or RSA (2048 bits or more) key. NewSigner does not call
// key.Sign.
func NewSigner(key crypto.Signer, opts ...SignerOption) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("dpop: nil key")
	}
	s := &Signer{key: key, now: time.Now}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	if s.alg == "" {
		alg, err := jwa.ForKey(key)
		if err != nil {
			return nil, fmt.Errorf("dpop: %w", err)
		}
		s.alg = alg
	}
	value, err := jwk.PublicValue(key)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	if value[jwk.KeyType] == jwk.KeyTypeOKP && value[jwk.Curve] != jwk.CurveEd25519 {
		return nil, fmt.Errorf("dpop: %s keys cannot sign", value[jwk.Curve])
	}
	tp, err := thumbprint.GenerateString(value, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	s.jwk, s.thumbprint = value, tp
	return s, nil
}

// Algorithm returns the JWS algorithm of every proof.
func (s *Signer) Algorithm() jwa.Algorithm { return s.alg }

// Thumbprint returns the base64url SHA-256 JWK Thumbprint of the proof
// key: the "jkt" a server binds tokens to, and the "dpop_jkt"
// authorization request parameter (RFC 9449 §10).
func (s *Signer) Thumbprint() string { return s.thumbprint }

// JWK returns a copy of the public JWK embedded in every proof.
func (s *Signer) JWK() jwk.Value { return cloneMap(s.jwk) }

// ProofOptions are the optional parts of a proof.
type ProofOptions struct {
	// AccessToken, when set, adds its hash as "ath". Set it whenever the
	// request carries a DPoP-bound access token (RFC 9449 §7).
	AccessToken string
	// Nonce is the latest DPoP-Nonce the server supplied, if any.
	Nonce string
}

// Proof returns a compact proof for an HTTP request with the given method
// and target URI. The query and fragment of uri are dropped and the rest is
// normalized with [TargetURI].
//
// Each proof gets a fresh 128-bit "jti" and the current "iat". Proofs are
// single-use: send a new one with every request.
//
// https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2
func (s *Signer) Proof(method, uri string, opts ProofOptions) (string, error) {
	if method == "" || strings.ContainsAny(method, " \t\r\n") {
		return "", fmt.Errorf("dpop: invalid HTTP method %q", method)
	}
	htu, err := TargetURI(uri)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("dpop: jti: %w", err)
	}
	jtiString := base64url.Encode(jti)

	claims := map[string]any{
		jwt.JWTID:       jtiString,
		ClaimHTTPMethod: method,
		ClaimHTTPURI:    htu,
		jwt.IssuedAt:    s.now().Unix(),
	}
	if opts.AccessToken != "" {
		claims[ClaimAccessTokenHash] = AccessTokenHash(opts.AccessToken)
	}
	if opts.Nonce != "" {
		claims[ClaimNonce] = opts.Nonce
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("dpop: encode claims: %w", err)
	}
	signed, err := jws.New(jws.Header{
		header.Type:       Type,
		header.Algorithm:  s.alg,
		header.JSONWebKey: s.JWK(),
	}, payload, s.key)
	if err != nil {
		return "", fmt.Errorf("dpop: sign proof: %w", err)
	}
	return signed.String(), nil
}
