package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/picatz/jose/pkg/base64"
)

// There are three classes of JWT Claim Names:
//
//  1. Registered Claim Names
//  2. Public Claim Names
//  3. Private Claim Names
type (
	ClaimName = string

	Registered = ClaimName // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
	Public     = ClaimName // https://datatracker.ietf.org/doc/html/rfc7519#section-4.2
	Private    = ClaimName // https://datatracker.ietf.org/doc/html/rfc7519#section-4.3
)

// ClaimValue is a piece of information asserted about a subject, represented
// as a name/value pair consisting of a ClaimName and a ClaimValue.
type ClaimValue any

// Registered Claim Names
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
const (
	Issuer         Registered = "iss" // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Subject        Registered = "sub" // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Audience       Registered = "aud" // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	ExpirationTime Registered = "exp" // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	NotBefore      Registered = "nbf" // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	IssuedAt       Registered = "iat" // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	JWTID          Registered = "jti" // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
)

// ClaimsSet is a JSON object that contains the claims in a JWT.
//
// A claim is a piece of information asserted about a subject, represented
// as a name/value pair consisting of a Claim Name and a Claim Value.
type ClaimsSet map[ClaimName]ClaimValue

// String returns the string representation of the ClaimsSet as a base64 encoded JSON object.
// If the ClaimsSet cannot be encoded, it returns a string representation of the error.
func (claims ClaimsSet) String() string {
	buff := bytes.NewBuffer(nil)

	err := json.NewEncoder(buff).Encode(claims)
	if err != nil {
		return fmt.Sprintf("<invalid-claims-set %q: %#v>", err, claims)
	}

	return base64.Encode(buff.Bytes())
}

// Get returns the ClaimValue for the given ClaimName.
func (claims ClaimsSet) Get(name ClaimName) (ClaimValue, error) {
	value, ok := claims[name]
	if !ok {
		return nil, fmt.Errorf("claim %q not found in claims set", name)
	}
	return value, nil
}

// Set sets the ClaimValue for the given ClaimName.
func (claims ClaimsSet) Set(name ClaimName, value ClaimValue) {
	claims[name] = value
}

// Names returns the ClaimNames in the ClaimsSet in sorted order.
func (claims ClaimsSet) Names() []ClaimName {
	var names []ClaimName

	for name := range claims {
		names = append(names, name)
	}

	sort.SliceStable(names, func(i, j int) bool {
		return names[i] > names[j]
	})

	return names
}

// GetCalimValue returns the ClaimValue for the given ClaimName of type T.
//
// It returns an error if the ClaimValue is not of type T, or if the ClaimName
// is not found in the ClaimsSet.
func GetCalimValue[T any](claims ClaimsSet, name ClaimName) (T, error) {
	var empty T

	value, err := claims.Get(name)
	if err != nil {
		return empty, err
	}

	valueT, ok := value.(T)
	if !ok {
		var empty T
		return empty, fmt.Errorf("invalid claim value type for %q: %T", name, value)
	}

	return valueT, nil
}
