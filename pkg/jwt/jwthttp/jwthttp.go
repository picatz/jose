// Package jwthttp carries JWTs in HTTP Authorization headers as bearer
// tokens (RFC 6750 §2.1). It is separate from package jwt so that programs
// that only sign and verify tokens link no HTTP code.
//
// https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
package jwthttp

import (
	"errors"
	"net/http"
	"strings"

	"github.com/picatz/jose/pkg/jwt"
)

// ErrNoBearerToken means a request carries no bearer token in its
// Authorization header.
var ErrNoBearerToken = errors.New("jwthttp: no bearer token in the Authorization header")

// BearerToken returns the token from a request's "Authorization: Bearer"
// header. The scheme name is matched without regard to case.
//
// The token is untrusted: parse and verify it before using it.
func BearerToken(r *http.Request) (string, error) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return "", ErrNoBearerToken
	}
	return token, nil
}

// Token is what [SetBearerToken] accepts: a compact token or a [jwt.Token].
type Token interface {
	string | *jwt.Token
}

// SetBearerToken sets a request's Authorization header to carry token as
// a bearer token.
func SetBearerToken[T Token](r *http.Request, token T) {
	var value string
	switch t := any(token).(type) {
	case string:
		value = t
	case *jwt.Token:
		value = t.String()
	}
	r.Header.Set("Authorization", "Bearer "+value)
}
