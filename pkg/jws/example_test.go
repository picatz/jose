package jws_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// ExampleNew_unsecured demonstrates unsecured JWS (algorithm "none")
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

	// Verify (no key needed for "none" algorithm)
	err = token.Verify(nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Unsecured JWS verified!")

	// Output:
	// Unsecured JWS: eyJhbGciOiJub25lIn0.VGhpcyBtZXNzYWdlIGhhcyBubyBzaWduYXR1cmU.
	// Unsecured JWS verified!
}
