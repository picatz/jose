package jwt

import (
	"fmt"

	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
)

// thumbprintMember is the "jkt" member of a "cnf" claim: the base64url
// SHA-256 JWK Thumbprint of the confirmed key.
const thumbprintMember = "jkt"

// ConfirmationFor returns the value of a "cnf" claim that binds a token to
// key: {"jkt": <RFC 7638 JWK Thumbprint>}. Use it as the value of
// [Confirmation].
//
// key is a public signing key, a private key, or any [crypto.Signer]; the
// thumbprint is always of the public half. Keys that cannot sign, such as
// X25519 keys, are refused, because a confirmation key must be able to prove
// possession.
//
//	claims[jwt.Confirmation], err = jwt.ConfirmationFor(holderKey)
//
// https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1
// https://www.rfc-editor.org/rfc/rfc9449.html#section-6.1
// https://www.rfc-editor.org/rfc/rfc7638.html
func ConfirmationFor(key any) (map[string]any, error) {
	if _, err := jwa.ForKey(key); err != nil {
		return nil, fmt.Errorf("jwt: confirmation key must be a signing key, so it can prove possession: %w", err)
	}
	jkt, err := thumbprint.FromPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("jwt: confirmation key: %w", err)
	}
	return map[string]any{thumbprintMember: jkt}, nil
}

// ConfirmedThumbprint returns the JWK Thumbprint the claims set is bound to:
// the "jkt" member of its "cnf" claim. It reports false unless "cnf" is a
// JSON object whose only member is "jkt", a non-empty string, so a token
// cannot carry a second confirmation method (such as an mTLS "x5t#S256")
// that a caller checking only "jkt" would silently fail to enforce.
//
// https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1
// https://www.rfc-editor.org/rfc/rfc9449.html#section-6.1
func (c ClaimsSet) ConfirmedThumbprint() (string, bool) {
	cnf, _ := c[Confirmation].(map[string]any)
	if len(cnf) != 1 {
		return "", false
	}
	jkt, ok := cnf[thumbprintMember].(string)
	if !ok || jkt == "" {
		return "", false
	}
	return jkt, true
}
