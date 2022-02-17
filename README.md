# jose

JavaScript Object Signing and Encryption [JOSE](https://datatracker.ietf.org/wg/jose/documents/) implemented in Go.

## RFCs

- [RFC7515](https://datatracker.ietf.org/doc/html/rfc7515) JSON Web Signature (JWS)
- [RFC7516](https://datatracker.ietf.org/doc/html/rfc7516) JSON Web Encryption (JWE)
- [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517) JSON Web Key (JWK)
- [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518) JSON Web Algorithms (JWA)
- [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) JSON Web Token (JWT)

## History

[JOSE](https://datatracker.ietf.org/wg/jose/documents/) was developed by an IETF [working group](https://www.ietf.org/how/wgs/), 
 started in 2011. The group set out to develop a [JSON](https://datatracker.ietf.org/doc/html/rfc4627) syntax that could be 
used by applications to describe "secure data objects". It has become a well known, standardized mechanism for integrity protection 
and encryption, as well as the format for keys and algorithm identifiers to support interoperability of security services for 
protocols that use JSON.

## Example Usage

```go
token, err := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.UOXSwO9AAuqSpOCt-PDjMmek7SmKOR7v35rmMzeyYfM")

err = token.VerifySignature(jwt.AllowedAlgorithms(jwa.HS256), jwt.SecretKey("supersecret"))

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
