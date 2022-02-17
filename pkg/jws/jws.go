package jws

import (
	"github.com/picatz/jose/pkg/header"
)

// Header is a JSON object containing the parameters describing
// the cryptographic operations and parameters employed.
//
// The JOSE (JSON Object Signing and Encryption) Header is comprised
// of a set of Header Parameters.
type Header = header.Parameters
