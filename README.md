# JOSE [![Go Reference](https://pkg.go.dev/badge/github.com/picatz/jose.svg)](https://pkg.go.dev/github.com/picatz/jose) [![Go Report Card](https://goreportcard.com/badge/github.com/picatz/jose)](https://goreportcard.com/report/github.com/picatz/jose) [![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0) 

JavaScript Object Signing and Encryption ([JOSE](https://datatracker.ietf.org/wg/jose/documents/)) implemented in Go.

## Installation

```console
$ go get github.com/picatz/jose@latest
```

## Example Usage

```go
// Create a public/private key pair (ECDSA)
private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
	panic(err)
}

// Create a JWT token, sign it with the private key.
token, err := jwt.New(
	header.Parameters{
		header.Type:      jwt.Type,
		header.Algorithm: jwa.ES256,
	},
	jwt.ClaimsSet{
		"sub":  "1234567890",
		"name": "John Doe",
	},
	private,
)
if err != nil {
	panic(err)
}

mux := http.NewServeMux()

mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	bearerToken, err := jwt.FromHTTPAuthorizationHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err = jwt.ParseAndVerify(bearerToken, jwt.WithKey(&private.PublicKey))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	sub, err := token.Claims.Get(jwt.Subject)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if sub != "1234567890" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	name, err := token.Claims.Get("name")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Welcome back, %s!", name)))
})

fmt.Println("Listening on http://127.0.0.1:8080")

fmt.Printf("Try running: curl http://127.0.0.1:8080 -H 'Authorization: Bearer %s' -v\n", token)

err = http.ListenAndServe("127.0.0.1:8080", mux)
if err != nil {
	panic(err)
}
```

## RFCs

- [RFC7515](https://datatracker.ietf.org/doc/html/rfc7515) (**JWS**) JSON Web Signature
- [RFC7516](https://datatracker.ietf.org/doc/html/rfc7516) (**JWE**) JSON Web Encryption
- [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517) (**JWK**) JSON Web Key
- [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518) (**JWA**) JSON Web Algorithms
- [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) (**JWT**) JSON Web Token

## History

[JOSE](https://datatracker.ietf.org/wg/jose/documents/) was developed by an IETF [working group](https://www.ietf.org/how/wgs/), 
 started in 2011. The group set out to develop a [JSON](https://datatracker.ietf.org/doc/html/rfc4627) syntax that could be 
used by applications to describe "secure data objects". It has become a well-known, standardized mechanism for integrity protection 
and encryption, as well as the format for keys and algorithm identifiers to support interoperability of security services for 
protocols that use JSON.
