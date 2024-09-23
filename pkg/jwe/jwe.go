package jwe

import (
	"github.com/picatz/jose/pkg/header"
)

// Registered header paramater names used in JWE.
//
// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1
const (
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1
	Algorithm header.ParamaterName = "alg"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
	EncryptionAlgorithm header.ParamaterName = "enc"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3
	CompressionAlgorithm header.ParamaterName = "zip"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.4
	JWKSetURL header.ParamaterName = "jku"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.5
	JSONWebKey header.ParamaterName = "jwk"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6
	KeyID header.ParamaterName = "kid"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.7
	X509URL header.ParamaterName = "x5u"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.8
	X509CertificateChain header.ParamaterName = "x5c"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.9
	X509CertificateSHA1Thumbprint header.ParamaterName = "x5t"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.10
	X509CertificateSHA256Thumbprint header.ParamaterName = "x5t#S256"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.11
	Type header.ParamaterName = "typ"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.12
	ContentType header.ParamaterName = "cty"
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.13
	Critical header.ParamaterName = "crit"
)
