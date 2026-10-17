package jws_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
)

// Example demonstrates basic JWS usage for signing arbitrary payloads
func Example() {
	// Generate a key for signing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// Create JWS header
	header := jws.Header{
		header.Algorithm: jwa.ES256,
		header.Type:      "JWS",
		header.KeyID:     "my-key-1",
	}

	// Any payload can be signed - not just JWT claims
	payload := []byte(`{"message": "Hello, JWS World!", "data": [1, 2, 3]}`)

	// Create and sign JWS token
	token, err := jws.New(header, payload, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Get compact serialization
	jwsString := token.String()
	fmt.Printf("JWS Token: %s\n", jwsString[:50]+"...")

	// Parse the JWS back
	parsedToken, err := jws.Parse(jwsString)
	if err != nil {
		log.Fatal(err)
	}

	// Verify signature
	err = parsedToken.Verify(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Payload: %s\n", string(parsedToken.Payload))
	alg, _ := parsedToken.Header.Algorithm()
	fmt.Printf("Algorithm: %v\n", alg)
	fmt.Println("Signature verified successfully!")
}

// ExampleNew_textPayload demonstrates JWS with simple text payload
func ExampleNew_textPayload() {
	// HMAC key for symmetric signing
	key := []byte("my-secret-key-that-is-32-bytes!")

	// Create JWS for plain text
	header := jws.Header{
		header.Algorithm: jwa.HS256,
	}

	payload := []byte("This is a simple text message that will be signed.")

	token, err := jws.New(header, payload, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original: %s\n", string(payload))
	fmt.Printf("JWS: %s\n", token.String())

	// Verify
	err = token.Verify(key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Text message signature verified!")
}

// ExampleNew_emptyPayload demonstrates JWS with empty payload
func ExampleNew_emptyPayload() {
	key := []byte("my-secret-key-that-is-32-bytes!")

	header := jws.Header{
		header.Algorithm: jwa.HS256,
	}

	// Empty payload is valid in JWS (unlike JWT which requires claims)
	token, err := jws.New(header, []byte{}, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Empty payload JWS: %s\n", token.String())

	// Verify
	err = token.Verify(key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Empty payload signature verified!")
}

// ExampleNew_unsecured shows an unsecured JWS (algorithm "none"), which
// can be created but never verifies.
func ExampleNew_unsecured() {
	header := jws.Header{
		header.Algorithm: jwa.None,
	}

	payload := []byte("This message has no signature")

	token, err := jws.New(header, payload, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Unsecured JWS: %s\n", token.String())

	// An unsecured JWS carries no signature, so Verify always refuses it.
	if err := token.Verify(nil); err != nil {
		fmt.Println("Verify refused it:", err)
	}

	// Output:
	// Unsecured JWS: eyJhbGciOiJub25lIn0.VGhpcyBtZXNzYWdlIGhhcyBubyBzaWduYXR1cmU.
	// Verify refused it: jws: unsecured JWS (alg "none") has no signature to verify
}

// ExampleSignJSON signs one payload for two verifiers and checks it the way
// a receiver holding only one of the keys would.
func ExampleSignJSON() {
	current := []byte("current-key-of-at-least-32-bytes")
	next := []byte("next-key-also-at-least-32-bytes!")

	signed, err := jws.SignJSON([]byte(`{"hello":"world"}`),
		jws.JSONSigner{Protected: jws.Header{header.Algorithm: jwa.HS256, header.KeyID: "current"}, Key: current},
		jws.JSONSigner{Protected: jws.Header{header.Algorithm: jwa.HS256, header.KeyID: "next"}, Key: next},
	)
	if err != nil {
		log.Fatal(err)
	}
	general, err := signed.General()
	if err != nil {
		log.Fatal(err)
	}

	received, err := jws.ParseJSON(general)
	if err != nil {
		log.Fatal(err)
	}
	index, err := received.Verify(next)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(received.Signatures[index].Protected[header.KeyID], string(received.Payload))

	// Output:
	// next {"hello":"world"}
}

// A detached JWS leaves the payload out of the token, so the content can
// travel on its own, here signed as is with "b64": false (RFC 7797).
func ExampleParseDetached() {
	key := []byte("example-hs256-secret-of-32-bytes")
	body := []byte(`{"amount":"10.00"}`)

	signed, err := jws.New(jws.Header{
		header.Algorithm:              jwa.HS256,
		header.Base64URLEncodePayload: false,
		header.Critical:               []string{header.Base64URLEncodePayload},
	}, body, key)
	if err != nil {
		panic(err)
	}
	token, err := signed.Detached()
	if err != nil {
		panic(err)
	}

	received, err := jws.ParseDetached(token, body)
	if err != nil {
		panic(err)
	}
	fmt.Println(received.Verify(key) == nil)
	// Output: true
}

// Detached leaves the payload out of the token ("header..signature", RFC 7515
// Appendix F), so large or already-transported content is not sent twice.
// The receiver supplies the payload to [jws.ParseDetached].
func ExampleSignature_Detached() {
	key := []byte("example-hs256-secret-of-32-bytes")
	content := []byte("a large document sent separately")

	signed, err := jws.New(jws.Header{header.Algorithm: jwa.HS256}, content, key)
	if err != nil {
		panic(err)
	}
	token, err := signed.Detached()
	if err != nil {
		panic(err)
	}
	fmt.Println(token)

	received, err := jws.ParseDetached(token, content)
	if err != nil {
		panic(err)
	}
	fmt.Println("verified:", received.Verify(key) == nil)

	// A different payload does not verify.
	other, _ := jws.ParseDetached(token, []byte("a different document"))
	fmt.Println("tampered:", errors.Is(other.Verify(key), jws.ErrSignature))
	// Output:
	// eyJhbGciOiJIUzI1NiJ9..ChpjPdfOblqqHxheocvJtMC8QEB45LV0vDrqCDtAwSU
	// verified: true
	// tampered: true
}
