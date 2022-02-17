package jwe

import (
	"github.com/picatz/jose/pkg/header"
)

type Header = header.Parameters

const (
	Algorithm                       header.ParamaterName = "alg"
	EncryptionAlgorithm             header.ParamaterName = "enc"
	CompressionAlgorithm            header.ParamaterName = "zip"
	JWKSetURL                       header.ParamaterName = "jku"
	JSONWebKey                      header.ParamaterName = "jwk"
	KeyID                           header.ParamaterName = "kid"
	X509URL                         header.ParamaterName = "x5u"
	X509CertificateChain            header.ParamaterName = "x5c"
	X509CertificateSHA1Thumbprint   header.ParamaterName = "x5t"
	X509CertificateSHA256Thumbprint header.ParamaterName = "x5t#S256"
	Type                            header.ParamaterName = "typ"
	ContentType                     header.ParamaterName = "cty"
	Critical                        header.ParamaterName = "crt"
)
