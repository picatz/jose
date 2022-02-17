package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/picatz/jose/pkg/base64"
)

// There are three classes of JWT Claim Names:
// 1. Registered Claim Names
// 2. Public Claim Names
// 3. Private Claim Names
type (
	ClaimName string

	Registered = ClaimName
	Public     = ClaimName
	Private    = ClaimName
)

// ClaimValue is a piece of information asserted about a subject, represented
// as a name/value pair consisting of a ClaimName and a ClaimValue.
type ClaimValue interface{}

// Registered Claim Names
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
const (
	Issuer         Registered = "iss"
	Subject        Registered = "sub"
	Audience       Registered = "aud"
	ExpirationTime Registered = "exp"
	NotBefore      Registered = "nbf"
	IssuedAt       Registered = "iat"
	JWTID          Registered = "jti"
)

// ClaimsSet is a JSON object that contains the claims conveyed by the JWT.
//
// A claim is a piece of information asserted about a subject, represented
// as a name/value pair consisting of a Claim Name and a Claim Value.
type ClaimsSet map[ClaimName]ClaimValue

func (claims ClaimsSet) String() string {
	buff := bytes.NewBuffer(nil)

	err := json.NewEncoder(buff).Encode(claims)
	if err != nil {
		return fmt.Sprintf("<invalid-claims-set %q: %#v>", err, claims)
	}

	return base64.Encode(buff.Bytes())
}

func (claims ClaimsSet) Get(name ClaimName) (ClaimValue, error) {
	value, ok := claims[name]
	if !ok {
		return nil, fmt.Errorf("claim %q not found in claims set", name)
	}
	return value, nil
}

func (claims ClaimsSet) Set(name ClaimName, value ClaimValue) {
	claims[name] = value
}

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
