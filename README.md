# jose

JavaScript Object Signing and Encryption ([JOSE](https://datatracker.ietf.org/wg/jose/documents/)) implemented in Go.

## Example Usage

```go
token, _ := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.UOXSwO9AAuqSpOCt-PDjMmek7SmKOR7v35rmMzeyYfM")

err := token.VerifySignature(jwt.SecretKey("supersecret"))

sub, _ := token.Claims.Get(jwt.Subject)
iat, _ := token.Claims.Get(jwt.IssuedAt)
name, _ := token.Claims.Get("name")
```

```go
token := &jwt.Token{
	Header: jws.Header{
		header.Type:      header.TypeJWT,
		header.Algorithm: jwa.HS256,
	},
	Claims: jwt.ClaimsSet{
		jwt.Subject:  "1234567890",
		jwt.Issuer:   "test",
		jwt.IssuedAt: time.Now(),
	},
}

signature, err := token.Sign(jwt.SecretKey("supersecret"))

fmt.Println(token)
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9Cg.eyJpYXQiOiIyMDIyLTAyLTE3VDAxOjI5OjQyLjkwMzAzMTY3NFoiLCJpc3MiOiJ0ZXN0Iiwic3ViIjoiMTIzNDU2Nzg5MCJ9Cg.hV13TckmXoXIL1-7gUhZNFvDgGJe7y5EVKpWzmWlvx0
```

```go
token, _ := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.UOXSwO9AAuqSpOCt-PDjMmek7SmKOR7v35rmMzeyYfM")

err := token.VerifySignature(jwt.ECDSAPublicKey(publicKey))
```

```go
token, _ := jwt.ParseString("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg")

err := token.VerifySignature(jwt.RSAPublicKey(publicKey))
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
