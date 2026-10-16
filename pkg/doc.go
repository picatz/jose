// Package jose implements JavaScript Object Signing and Encryption (JOSE) related functionality.
//
// Related RFCs:
//   - RFC7515 https://datatracker.ietf.org/doc/html/rfc7515 JWS, JSON Web Signature
//   - RFC7516 https://datatracker.ietf.org/doc/html/rfc7516 JWE, JSON Web Encryption
//   - RFC7517 https://datatracker.ietf.org/doc/html/rfc7517 JWK, JSON Web Key
//   - RFC7518 https://datatracker.ietf.org/doc/html/rfc7518 JWA, JSON Web Algorithms
//   - RFC7519 https://datatracker.ietf.org/doc/html/rfc7519 JWT, JSON Web Token
//   - RFC6920 https://datatracker.ietf.org/doc/html/rfc6920 Named Information URIs (package ni)
//   - RFC7638 https://datatracker.ietf.org/doc/html/rfc7638 JWK Thumbprint
//   - RFC7800 https://datatracker.ietf.org/doc/html/rfc7800 Proof-of-Possession Key Semantics ("cnf")
//   - RFC8037 https://datatracker.ietf.org/doc/html/rfc8037 OKP keys (Ed25519, X25519)
//   - RFC8693 https://datatracker.ietf.org/doc/html/rfc8693 Token Exchange ("act" lineage)
//   - RFC9278 https://datatracker.ietf.org/doc/html/rfc9278 JWK Thumbprint URI
//   - RFC9449 https://datatracker.ietf.org/doc/html/rfc9449 DPoP, Demonstrating Proof of Possession
//
// Package jwtchain composes these into attenuation chains: tokens any
// holder can narrow offline and a verifier can check back to the issuer.
//
// Related Information:
//   - https://datatracker.ietf.org/wg/jose/charter/
package jose
