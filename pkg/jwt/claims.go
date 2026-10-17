package jwt

// Registered claim names.
//
// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1
const (
	Issuer         = "iss" // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1
	Subject        = "sub" // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2
	Audience       = "aud" // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	ExpirationTime = "exp" // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
	NotBefore      = "nbf" // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.5
	IssuedAt       = "iat" // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6
	ID             = "jti" // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
)

// ClaimsSet is the JSON object of claims a JWT carries: claim names mapped to
// their values. Index it directly:
//
//	sub, _ := claims[jwt.Subject].(string)
//
// A ClaimsSet decoded by [Parse] or a [Verifier] holds the types
// encoding/json produces, except that "exp", "nbf" and "iat" are int64 and
// "aud" is a string or a []string.
//
// https://www.rfc-editor.org/rfc/rfc7519.html#section-4
type ClaimsSet map[string]any
