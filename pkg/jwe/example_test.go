package jwe_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwe"
)

// Encrypt to a recipient's X25519 key with ECDH-ES and decrypt with the
// matching private key. A hardware key that implements jwe.KeyAgreement
// decrypts the same way.
func Example() {
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	compact, err := jwe.Encrypt(header.Parameters{
		header.Algorithm:           jwa.ECDHESA256KW,
		header.EncryptionAlgorithm: jwa.A256GCM,
		header.KeyID:               "recipient-1",
	}, []byte("meet at the usual place"), recipient.PublicKey())
	if err != nil {
		panic(err)
	}

	plaintext, message, err := jwe.Decrypter{
		Key:         recipient,
		Algorithms:  []jwa.Algorithm{jwa.ECDHESA256KW},
		Encryptions: []jwa.ContentEncryption{jwa.A256GCM},
	}.Decrypt(compact)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext), message.Header[header.KeyID])
	// Output: meet at the usual place recipient-1
}

// A Decrypter holds the recipient's key and the policy for what it accepts.
// Anything outside the policy is refused before any key is used.
func ExampleDecrypter() {
	key := []byte("0123456789abcdef") // 16 bytes: A128KW

	compact, err := jwe.Encrypt(header.Parameters{
		header.Algorithm:           jwa.A128KW,
		header.EncryptionAlgorithm: jwa.A128GCM,
	}, []byte("hello"), key)
	if err != nil {
		panic(err)
	}

	plaintext, _, err := jwe.Decrypter{
		Key:        key,
		Algorithms: []jwa.Algorithm{jwa.A128KW},
	}.Decrypt(compact)
	fmt.Println(string(plaintext), err)

	// A Decrypter that only expects ECDH-ES refuses the message.
	_, _, err = jwe.Decrypter{
		Key:        key,
		Algorithms: []jwa.Algorithm{jwa.ECDHES},
	}.Decrypt(compact)
	fmt.Println(err)
	// Output:
	// hello <nil>
	// jwe: algorithm not allowed: "A128KW"
}

// EncryptJSON encrypts once for several recipients, each with their own key
// and key management algorithm. Each recipient decrypts with their own
// Decrypter, and DecryptJSON reports which recipient entry opened.
func ExampleEncryptJSON() {
	shared := []byte("0123456789abcdef")
	bob, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	j, err := jwe.EncryptJSON(
		header.Parameters{header.EncryptionAlgorithm: jwa.A128GCM},
		nil,
		[]byte("for both of you"),
		nil, // no additional authenticated data
		jwe.RecipientKey{Header: header.Parameters{header.Algorithm: jwa.A128KW, header.KeyID: "alice"}, Key: shared},
		jwe.RecipientKey{Header: header.Parameters{header.Algorithm: jwa.ECDHESA128KW, header.KeyID: "bob"}, Key: bob.PublicKey()},
	)
	if err != nil {
		panic(err)
	}
	wire, err := j.General() // what goes on the wire
	if err != nil {
		panic(err)
	}

	for _, d := range []jwe.Decrypter{
		{Key: shared, Algorithms: []jwa.Algorithm{jwa.A128KW}}, // a []byte key names its algorithms
		{Key: bob},
	} {
		received, err := jwe.ParseJSON(wire)
		if err != nil {
			panic(err)
		}
		plaintext, index, err := d.DecryptJSON(received)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(plaintext), received.Header(index)[header.KeyID])
	}
	// Output:
	// for both of you alice
	// for both of you bob
}
