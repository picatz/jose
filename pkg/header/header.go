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

// Registered header paramater names used in JWS and JWE.
//
// # IANA Registry
//
// https://www.iana.org/assignments/jose/jose.xhtml
//
// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1
const (
	// Algorithm "alg" is the algorithm intended for use with the JWS or JWE.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1
	Algorithm Registered = "alg"

	// JWKSetURL "jku" is a URL that refers to a resource for a set of JSON-encoded public keys,
	// one of which corresponds to the key used to digitally sign the JWS or encrypt the JWE.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2
	JWKSetURL Registered = "jku"

	// JSONWebKey "jwk" is the public key that corresponds to the key used to digitally sign
	// the JWS or encrypt the JWE.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3
	JSONWebKey Registered = "jwk"

	// KeyID "kid" is a hint indicating which key was used to secure the JWS or JWE.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4
	KeyID Registered = "kid"

	// X509URL "x5u" is a URL that refers to a resource for the X.509 public key certificate
	// or certificate chain corresponding to the key used to digitally sign the JWS or encrypt the JWE.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5
	X509URL Registered = "x5u"

	// X509CertificateChain "x5c" is the X.509 public key certificate or certificate chain
	// corresponding to the key used to digitally sign the JWS or encrypt the JWE.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6
	X509CertificateChain Registered = "x5c"

	// X509CertificateSHA1Thumbprint "x5t" is the base64url-encoded SHA-1 thumbprint (a.k.a. digest)
	// of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign the JWS or encrypt the JWE.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7
	X509CertificateSHA1Thumbprint Registered = "x5t"

	// X509CertificateSHA256Thumbprint "x5t#S256" is the base64url-encoded SHA-256 thumbprint (a.k.a. digest)
	// of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign the JWS or encrypt the JWE.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8
	X509CertificateSHA256Thumbprint Registered = "x5tX#S256"

	// Type "typ" is the [media type] of this complete JOSE object (JWS or JWE).
	//
	// [media type]: https://www.iana.org/assignments/media-types/media-types.xhtml
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9
	Type Registered = "typ"

	// ContentType "cty" is the media type of the secured content (the payload).
	//
	// [media type]: https://www.iana.org/assignments/media-types/media-types.xhtml
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10
	ContentType Registered = "cty"

	// Critical "crit" is a list of header parameter names that have
	// values that MUST be integrity protected by the JWS signer.
	//
	// https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11
	Critical Registered = "crit"

	// EncryptionAlgorithm "enc" is the encryption algorithm used to encrypt
	// the "plaintext" to produce the "ciphertext".
	//
	// https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2
	Encryption Registered = "enc"

	// Zip "zip" is the compression algorithm used to compress the "plaintext"
	// before encryption.
	//
	// https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3
	Zip Registered = "zip"
)

// TypeJWT "JWT" is the media type used by JWS and JWE to represent
// a JSON object using JWS or JWE JSON Serialization.
//
// # Example
//
//	header := header.Parameters{
//		header.Type:      header.TypeJWT,
//		header.Algorithm: jwa.HS256,
//	}
//
// https://www.rfc-editor.org/rfc/rfc7515.html#section-3.3
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
