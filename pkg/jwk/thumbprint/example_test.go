package thumbprint_test

import (
	"crypto/ed25519"
	"fmt"

	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
)

// RFC 8037 Appendix A.2 and A.3: the thumbprint of an Ed25519 public key.
func ExampleFromPublicKey() {
	x, _ := jwk.PublicKey(jwk.Key{
		jwk.KeyType: jwk.KeyTypeOKP,
		jwk.Curve:   jwk.CurveEd25519,
		jwk.X:       "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	})

	jkt, err := thumbprint.FromPublicKey(x.(ed25519.PublicKey))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(jkt)
	// Output: kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
}

// A JWK Thumbprint URI names a key in a string claim such as "sub" (RFC 9278).
func ExampleURN() {
	key := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))

	urn, err := thumbprint.URN(key)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(urn[:len(thumbprint.URNPrefix)])
	// Output: urn:ietf:params:oauth:jwk-thumbprint:sha-256:
}
