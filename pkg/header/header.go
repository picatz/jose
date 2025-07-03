package header

import (
	"errors"
	"fmt"
	"slices"

	"github.com/picatz/jose/pkg/jwa"
)

var (
	// ErrParameterNotFound is returned when a parameter is not found in the header.
	ErrParameterNotFound = errors.New("header: parameter not found")

	// ErrInvalidParameterType is returned when a parameter is not the expected type.
	ErrInvalidParameterType = errors.New("header: invalid parameter type")

	// ErrFailedToEncodeHeader is returned when the header fails to be encoded.
	ErrFailedToEncodeHeader = errors.New("header: failed to base64 URL encode")

	// ErrCriticalHeaderValidation is returned when critical header validation fails.
	ErrCriticalHeaderValidation = errors.New("header: critical header validation failed")
)

// ParameterName is one of three types: registered, public, or private.
//
// https://datatracker.ietf.org/doc/html/rfc7515#section-4
type (
	ParameterName = string

	// Registered header parameter names from the IANA registry.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1
	Registered = ParameterName

	// Public header parameter names that are not registered,
	// but should be collision resistant.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.2
	Public = ParameterName

	// Private header parameter names for use in private agreements.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.3
	Private = ParameterName
)

// Registered header parameter names used in JWS and JWE.
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
	X509CertificateSHA256Thumbprint Registered = "x5t#S256"

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
type Parameters map[ParameterName]any

// Type returns the media type of this complete JOSE object (JWS or JWE).
func (h Parameters) Type() (string, error) {
	return Get[string](h, Type)
}

// Algorithm returns the algorithm intended for use with the JWS or JWE;
// the algorithm used to digitally sign the JWS or encrypt the JWE.
func (h Parameters) Algorithm() (jwa.Algorithm, error) {
	return Get[jwa.Algorithm](h, Algorithm)
}

// SymmetricAlgorithm returns true if the algorithm used in the header is
// symmetric. If the algorithm is not symmetric, the function returns false.
func (h Parameters) SymmetricAlgorithm() (bool, error) {
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

// AsymmetricAlgorithm returns true if the algorithm used in the header is
// asymmetric. If the algorithm is not asymmetric, the function returns false.
func (h Parameters) AsymmetricAlgorithm() (bool, error) {
	alg, err := h.Algorithm()
	if err != nil {
		return false, err
	}

	switch jwa.Algorithm(alg) {
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
func (h Parameters) Get(param ParameterName) (any, error) {
	return Get[any](h, param)
}

func Get[T any](h Parameters, param ParameterName) (T, error) {
	var zero T

	value, ok := h[param]
	if !ok {
		return zero, fmt.Errorf("%w: %q", ErrParameterNotFound, param)
	}

	typedValue, ok := value.(T)
	if !ok {
		return zero, fmt.Errorf("%w: %q: is type %T, not %T", ErrInvalidParameterType, param, value, zero)
	}

	return typedValue, nil
}

// Has returns true if the given parameter name exists in the set of JOSE header parameters.
func (h Parameters) Has(param ParameterName) bool {
	_, ok := h[param]
	return ok
}

// StandardParameters returns a slice of all standard JOSE header parameter names
// as defined by RFC 7515 (JWS) and RFC 7516 (JWE).
//
// Per RFC 7515 Section 4.1.11, these parameters MUST NOT be included in the
// "crit" (Critical) header parameter list.
func StandardParameters() []string {
	return []string{
		Algorithm,
		JWKSetURL,
		JSONWebKey,
		KeyID,
		X509URL,
		X509CertificateChain,
		X509CertificateSHA1Thumbprint,
		X509CertificateSHA256Thumbprint,
		Type,
		ContentType,
		Critical,
		Encryption, // JWE specific
		Zip,        // JWE specific
	}
}

// IsStandardParameter returns true if the parameter name is defined as a standard
// parameter by RFC 7515 (JWS) or RFC 7516 (JWE).
func IsStandardParameter(name string) bool {
	standardParams := StandardParameters()
	return slices.Contains(standardParams, name)
}

// ValidateCriticalHeaders validates critical headers per RFC 7515 section 4.1.11.
// If a "crit" header is present, it must contain only extension header parameter names
// that the application understands and can process.
//
// This function implements the complete RFC 7515 critical header validation:
// 1. Validates "crit" is an array of strings
// 2. Ensures the array is not empty
// 3. Checks no standard parameters are marked as critical
// 4. Verifies all critical parameters are present in the header
// 5. Validates all critical parameters are supported by the application
func (h Parameters) ValidateCriticalHeaders(supportedCriticalHeaders []string) error {
	// Check if the header has a "crit" (critical) parameter
	critValue, err := h.Get(Critical)
	if err != nil {
		// If there's no "crit" header, validation passes
		if errors.Is(err, ErrParameterNotFound) {
			return nil
		}
		return fmt.Errorf("failed to get critical parameter: %w", err)
	}

	// The "crit" header must be an array of strings
	critArray, ok := critValue.([]any)
	if !ok {
		return fmt.Errorf("critical header parameter \"crit\" must be an array")
	}

	// RFC 7515 section 4.1.11: The "crit" header parameter MUST NOT be empty
	if len(critArray) == 0 {
		return fmt.Errorf("critical header parameter \"crit\" must not be empty")
	}

	// Convert to string slice and validate each critical header
	critHeaders := make([]string, len(critArray))
	for i, v := range critArray {
		critHeader, ok := v.(string)
		if !ok {
			return fmt.Errorf("critical header parameter names must be strings")
		}
		critHeaders[i] = critHeader
	}

	// RFC 7515 section 4.1.11: The "crit" header parameter MUST NOT include
	// any header parameter names that are defined by RFC 7515 or RFC 7516
	for _, critHeader := range critHeaders {
		if IsStandardParameter(critHeader) {
			return fmt.Errorf("critical header parameter %q is a standard header and cannot be marked as critical", critHeader)
		}
	}

	// Validate each critical header parameter
	for _, critHeader := range critHeaders {
		// RFC 7515 section 4.1.11: Critical header parameter names MUST be understood
		if supportedCriticalHeaders != nil && !slices.Contains(supportedCriticalHeaders, critHeader) {
			return fmt.Errorf("unsupported critical header parameter: %q", critHeader)
		}

		// Verify that the critical header parameter is actually present in the header
		if !h.Has(critHeader) {
			return fmt.Errorf("critical header parameter %q is missing from header", critHeader)
		}
	}

	return nil
}
