# JOSE [![Go Reference](https://pkg.go.dev/badge/github.com/picatz/jose.svg)](https://pkg.go.dev/github.com/picatz/jose) [![Go Report Card](https://goreportcard.com/badge/github.com/picatz/jose)](https://goreportcard.com/report/github.com/picatz/jose) [![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0) 

JavaScript Object Signing and Encryption ([JOSE](https://datatracker.ietf.org/wg/jose/documents/)) implemented in Go.

## Installation

```console
$ go get github.com/picatz/jose@latest
```

## Example Usage

```go
raw := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.UOXSwO9AAuqSpOCt-PDjMmek7SmKOR7v35rmMzeyYfM" 

token, _ := jwt.ParseAndVerify(raw, jwt.WithKey("supersecret"))

sub, _ := token.Claims.Get(jwt.Subject)
iat, _ := token.Claims.Get(jwt.IssuedAt)
name, _ := token.Claims.Get("name")
```

```go
const (
	symmetricKeyID = "test"
	symmetricKey   = keyutil.NewSymmetricKey(64) 
)

token, _ := jwt.New(
	header.Parameters{
		header.Type:      jwt.Type,
		header.Algorithm: jwa.HS256,
	}, jwt.ClaimsSet{
		jwt.Subject:           "1234567890",
		jwk.KeyID:             symmetricKeyID,
		jwt.ClaimName("name"): "John Doe",
	},
	symmetricKey,
)

_, err := jwt.ParseAndVerify(token.String(), jwt.WithIdentifiableKey(symmetricKeyID, symmetricKey))
```

```go
token := &jwt.Token{
	Header: jws.Header{
		header.Type:      jwt.Type,
		header.Algorithm: jwa.HS256,
	},
	Claims: jwt.ClaimsSet{
		jwt.Subject:  "1234567890",
		jwt.Issuer:   "test",
		jwt.IssuedAt: time.Now(),
	},
}

signature, err := token.Sign("supersecret")

fmt.Println(token)
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9Cg.eyJpYXQiOiIyMDIyLTAyLTE3VDAxOjI5OjQyLjkwMzAzMTY3NFoiLCJpc3MiOiJ0ZXN0Iiwic3ViIjoiMTIzNDU2Nzg5MCJ9Cg.hV13TckmXoXIL1-7gUhZNFvDgGJe7y5EVKpWzmWlvx0
```

```go
token, _ := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.UOXSwO9AAuqSpOCt-PDjMmek7SmKOR7v35rmMzeyYfM")

err := token.VerifySignature(ecdsaPublicKey)
```

```go
token, _ := jwt.ParseString("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg")

err := token.VerifySignature(rsaPublicKey)
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
used by applications to describe "secure data objects". It has become a well known, standardized mechanism for integrity protection 
and encryption, as well as the format for keys and algorithm identifiers to support interoperability of security services for 
protocols that use JSON.
