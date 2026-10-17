package jwa

// Key management algorithms for JWE ("alg").
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1
const (
	// RSAOAEP is RSAES OAEP using SHA-1 and MGF1 with SHA-1.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3
	RSAOAEP Algorithm = "RSA-OAEP"
	// RSAOAEP256 is RSAES OAEP using SHA-256 and MGF1 with SHA-256.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3
	RSAOAEP256 Algorithm = "RSA-OAEP-256"

	// A128KW, A192KW and A256KW wrap the content encryption key with AES Key
	// Wrap (RFC 3394) under a shared key.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.4
	A128KW Algorithm = "A128KW"
	A192KW Algorithm = "A192KW"
	A256KW Algorithm = "A256KW"

	// Direct uses a shared symmetric key as the content encryption key.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.5
	Direct Algorithm = "dir"

	// ECDHES derives the content encryption key with ephemeral-static ECDH
	// and the Concat KDF.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6
	ECDHES Algorithm = "ECDH-ES"
	// ECDHESA128KW, ECDHESA192KW and ECDHESA256KW derive a key-wrapping key
	// with ECDH-ES and wrap a random content encryption key with it.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6
	ECDHESA128KW Algorithm = "ECDH-ES+A128KW"
	ECDHESA192KW Algorithm = "ECDH-ES+A192KW"
	ECDHESA256KW Algorithm = "ECDH-ES+A256KW"
)

// ContentEncryption identifies a JWE content encryption algorithm ("enc").
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1
type ContentEncryption string

// Content encryption algorithms for JWE ("enc").
const (
	// A128CBCHS256, A192CBCHS384 and A256CBCHS512 are AES-CBC with
	// HMAC-SHA-2 truncated tags, composed as an AEAD.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2
	A128CBCHS256 ContentEncryption = "A128CBC-HS256"
	A192CBCHS384 ContentEncryption = "A192CBC-HS384"
	A256CBCHS512 ContentEncryption = "A256CBC-HS512"

	// A128GCM, A192GCM and A256GCM are AES in Galois/Counter Mode with a
	// 96-bit IV and a 128-bit tag.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-5.3
	A128GCM ContentEncryption = "A128GCM"
	A192GCM ContentEncryption = "A192GCM"
	A256GCM ContentEncryption = "A256GCM"
)
