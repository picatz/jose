package header

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/jwa"
)

var (
	// ErrParamaterNotFound is returned when a paramater is not found in the header.
	ErrParamaterNotFound = errors.New("header: paramater not found")

	// ErrInvalidParamaterType is returned when a paramater is not the expected type.
	ErrInvalidParamaterType = errors.New("header: invalid paramater type")

	// ErrFailedToEncodeHeader is returned when the header fails to be encoded.
	ErrFailedToEncodeHeader = errors.New("header: failed to base64 URL encode")
)

// ParamaterName is one of three types: registered, public, or private.
//
// https://datatracker.ietf.org/doc/html/rfc7515#section-4
type (
	ParamaterName = string

	// Registered header paramater names from the IANA registry.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1
	Registered = ParamaterName

	// Public header paramater names that are not registered,
	// but should be collision resistant.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.2
	Public = ParamaterName

	// Private header paramater names for use in private agreements.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.3
	Private = ParamaterName
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

// Parameters is a JSON object containing the parameters describing
// the cryptographic operations and parameters employed.
//
// The JOSE (JSON Object Signing and Encryption) Header is comprised
// of a set of Header Parameters.
//
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
type Parameters map[ParamaterName]any

// Base64URLString returns the JOSE header as a base64 URL encoded string
// suitable for use in a JWS or JWE.
func (h Parameters) Base64URLString() (string, error) {
	buff := bytes.NewBuffer(nil)
	err := json.NewEncoder(buff).Encode(h)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrFailedToEncodeHeader, err)
	}
	return base64.Encode(buff.Bytes()), nil
}

// Type returns the media type of this complete JOSE object (JWS or JWE).
func (h Parameters) Type() (string, error) {
	value, ok := h[Type]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrParamaterNotFound, Type)
	}
	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q: is type %T, not string", ErrInvalidParamaterType, Type, value)
	}
	return strValue, nil
}

// Algorithm returns the algorithm intended for use with the JWS or JWE;
// the algorithm used to digitally sign the JWS or encrypt the JWE.
func (h Parameters) Algorithm() (jwa.Algorithm, error) {
	value, ok := h[Algorithm]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrParamaterNotFound, Algorithm)
	}

	alg, ok := value.(jwa.Algorithm)
	if ok {
		return alg, nil
	}

	return "", fmt.Errorf("%w: %q: is type %T, not algorithm", ErrInvalidParamaterType, Algorithm, value)
}

// SymetricAlgorithm returns the symetric algorithm used in the header,
// if the algorithm is symetric. If the algorithm is not symetric, then
// the function returns false.
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

// AsymetricAlgorithm returns the symetric algorithm used in the header,
// if the algorithm is asymetric. If the algorithm is not asymetric, then
// the function returns false.
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

// Get returns the value for a given paramater name from the set of JOSE header paramaters.
//
// This is a convenience function for accessing the value of a paramater from the JOSE header
// without having to check if the paramater exists in the header first. This function will
// return an error if the paramater does not exist in the header.
func (h Parameters) Get(param ParamaterName) (any, error) {
	value, ok := h[param]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrParamaterNotFound, param)
	}
	return value, nil
}
