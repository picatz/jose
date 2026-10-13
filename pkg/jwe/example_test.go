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
		jwe.Algorithm:           jwa.ECDHESA256KW,
		jwe.EncryptionAlgorithm: jwa.A256GCM,
		jwe.KeyID:               "recipient-1",
	}, []byte("meet at the usual place"), recipient.PublicKey())
	if err != nil {
		panic(err)
	}

	plaintext, message, err := jwe.Decrypt(compact, recipient, jwe.DecryptOptions{
		Algorithms:  []jwa.Algorithm{jwa.ECDHESA256KW},
		Encryptions: []jwa.ContentEncryption{jwa.A256GCM},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext), message.Header[jwe.KeyID])
	// Output: meet at the usual place recipient-1
}
