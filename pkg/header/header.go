package header

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/jwa"
)

// There are three classes of Header Parameter names: Registered Header
// Parameter names, Public Header Parameter names, and Private Header
// Parameter names.
//
// https://datatracker.ietf.org/doc/html/rfc7515#section-4
type (
	ParamaterName = string

	Registered = ParamaterName
	Public     = ParamaterName
	Private    = ParamaterName
)

// Registered Header Paramater Names
//
// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1
const (
	Type                            Registered = "typ"
	Algorithm                       Registered = "alg"
	JWKSetURL                       Registered = "jku"
	JSONWebKey                      Registered = "jwk"
	X509URL                         Registered = "x5u"
	X509CertificateChain            Registered = "x5c"
	X509CertificateSHA1Thumbprint   Registered = "x5t"
	X509CertificateSHA256Thumbprint Registered = "x5tX#S256"
	ContentType                     Registered = "cty"
	Critical                        Registered = "crit"

	// https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2
	Encryption Registered = "enc"

	// https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3
	Zip Registered = "zip"

	// https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.6
	KeyID Registered = "kid"
)

const TypeJWT = "JWT"

// Parameters is a JSON object containing the parameters describing
// the cryptographic operations and parameters employed.
//
// The JOSE (JSON Object Signing and Encryption) Parameters is comprised
// of a set of Parameters Parameters.
type Parameters map[ParamaterName]any

func (h Parameters) Base64URLString() (string, error) {
	buff := bytes.NewBuffer(nil)
	err := json.NewEncoder(buff).Encode(h)
	if err != nil {
		return "", fmt.Errorf("failed to encode JOSE header base64 URL string: %w", err)
	}
	return base64.Encode(buff.Bytes()), nil
}

func (h Parameters) Type() (string, error) {
	value, ok := h[Type]
	if !ok {
		return "", fmt.Errorf("header does not contain a %q paramater", Type)
	}
	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("header paramater %q is not a string, is %T", Type, value)
	}
	return strValue, nil
}

func (h Parameters) Algorithm() (jwa.Algorithm, error) {
	value, ok := h[Algorithm]
	if !ok {
		return "", fmt.Errorf("header does not contain a %q paramater", Algorithm)
	}

	alg, ok := value.(jwa.Algorithm)
	if ok {
		return alg, nil
	}

	return "", fmt.Errorf("header paramater %q is invalid type %T", Algorithm, value)
}

func (h Parameters) SymetricAlgorithm() (bool, error) {
	alg, err := h.Algorithm()
	if err != nil {
		return false, err
	}

	switch jwa.Algorithm(alg) {
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return true, nil
	}

	return false, nil
}

func (h Parameters) AsymetricAlgorithm() (bool, error) {
	alg, err := h.Algorithm()
	if err != nil {
		return false, err
	}

	switch jwa.Algorithm(alg) {
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return false, nil
	case jwa.PS256, jwa.PS384, jwa.PS512:
		return true, nil
	case jwa.ES256, jwa.ES384, jwa.ES512:
		return true, nil
	case jwa.RS256, jwa.RS384, jwa.RS512:
		return true, nil
	}

	return false, nil
}

func (h Parameters) Get(param ParamaterName) (interface{}, error) {
	value, ok := h[param]
	if !ok {
		return "", fmt.Errorf("header does not contain a %q paramater", Type)
	}
	return value, nil
}
