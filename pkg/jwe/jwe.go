package jwe

import (
	"github.com/picatz/jose/pkg/header"
)

// Registered header parameter names used in JWE.
//
// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1
const (
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1
	Algorithm header.ParameterName = "alg"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
	EncryptionAlgorithm header.ParameterName = "enc"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3
	CompressionAlgorithm header.ParameterName = "zip"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.4
	JWKSetURL header.ParameterName = "jku"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.5
	JSONWebKey header.ParameterName = "jwk"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6
	KeyID header.ParameterName = "kid"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.7
	X509URL header.ParameterName = "x5u"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.8
	X509CertificateChain header.ParameterName = "x5c"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.9
	X509CertificateSHA1Thumbprint header.ParameterName = "x5t"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.10
	X509CertificateSHA256Thumbprint header.ParameterName = "x5t#S256"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.11
	Type header.ParameterName = "typ"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.12
	ContentType header.ParameterName = "cty"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.13
	Critical header.ParameterName = "crit"
)
