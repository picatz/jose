package jwk_test

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/picatz/jose/pkg/jwk"
)

// RFC 7517 Appendix A.1: turn a JWK into a standard library key.
func ExamplePublicKey() {
	key, err := jwk.PublicKey(jwk.Key{
		jwk.KeyType: jwk.KeyTypeEC,
		jwk.Curve:   jwk.CurveP256,
		jwk.X:       "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		jwk.Y:       "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(key.(*ecdsa.PublicKey).Curve.Params().Name)
	// Output: P-256
}

// PublicValue is the inverse of PublicKey: it also accepts a private key or
// crypto.Signer, and never includes private members.
func ExamplePublicValue() {
	private, _ := jwk.PrivateKey(jwk.Key{
		jwk.KeyType: jwk.KeyTypeOKP,
		jwk.Curve:   jwk.CurveEd25519,
		jwk.D:       "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
		jwk.X:       "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	})

	public, err := jwk.PublicValue(private)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(public[jwk.KeyType], public[jwk.Curve], public[jwk.X], jwk.IsPrivate(public))
	// Output: OKP Ed25519 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo false
}

func ExampleParseSet() {
	set, err := jwk.ParseSet([]byte(`{"keys":[{"kty":"oct","kid":"a","k":"AAAA"}]}`))
	if err != nil {
		fmt.Println(err)
		return
	}
	_, found := set.Get("a")
	_, missing := set.Get("b")
	fmt.Println(found, missing)

	_, err = jwk.ParseSet([]byte(`{"keys":[{"kid":"a"},{"kid":"a"}]}`))
	fmt.Println(err)
	// Output:
	// true false
	// jwk: malformed key set: duplicate kid "a"
}
