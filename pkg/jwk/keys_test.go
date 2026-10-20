package jwk_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwk/thumbprint"
)

// RFC 7518 §6.2.1.2: coordinates are always the full width of the curve,
// even when the integer has leading zero bytes.
func TestPublicValueUsesFixedWidthCoordinates(t *testing.T) {
	var key *ecdsa.PrivateKey
	for range 4096 {
		candidate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if candidate.X.BitLen() <= 248 || candidate.Y.BitLen() <= 248 {
			key = candidate
			break
		}
	}
	if key == nil {
		t.Skip("no short coordinate found")
	}
	for name, value := range map[string]func() (jwk.Key, error){
		"private key": func() (jwk.Key, error) { return jwk.PublicValue(key) },
		"public key":  func() (jwk.Key, error) { return jwk.PublicValue(&key.PublicKey) },
	} {
		v, err := value()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, member := range []string{jwk.X, jwk.Y} {
			b, err := base64url.Decode(v[member].(string))
			if err != nil {
				t.Fatal(err)
			}
			if len(b) != 32 {
				t.Fatalf("%s: %s is %d bytes, want 32", name, member, len(b))
			}
		}
		back, err := jwk.PublicKey(v)
		if err != nil {
			t.Fatal(err)
		}
		if !key.PublicKey.Equal(back) {
			t.Fatalf("%s: round trip changed the key", name)
		}
	}
}

func TestPublicKeyRejectsOffCurvePoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jwk.PublicValue(key)
	if err != nil {
		t.Fatal(err)
	}
	y, _ := base64url.Decode(v[jwk.Y].(string))
	y[len(y)-1] ^= 1
	v[jwk.Y] = base64url.Encode(y)
	if _, err := jwk.PublicKey(v); !errors.Is(err, jwk.ErrInvalidKey) {
		t.Fatalf("PublicKey(off-curve) = %v, want ErrInvalidKey", err)
	}
}

func TestPublicKeyRejectsMalformedMembers(t *testing.T) {
	cases := map[string]jwk.Key{
		"missing kty":     {jwk.N: "AQAB"},
		"numeric n":       {jwk.KeyType: "RSA", jwk.N: 12, jwk.E: "AQAB"},
		"even exponent":   {jwk.KeyType: "RSA", jwk.N: "0vx7", jwk.E: "Ag"},
		"huge exponent":   {jwk.KeyType: "RSA", jwk.N: "0vx7", jwk.E: "AQAAAAAB"},
		"P-224":           {jwk.KeyType: "EC", jwk.Curve: "P-224", jwk.X: "AA", jwk.Y: "AA"},
		"long coordinate": {jwk.KeyType: "EC", jwk.Curve: "P-256", jwk.X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", jwk.Y: "AA"},
		"short Ed25519":   {jwk.KeyType: "OKP", jwk.Curve: "Ed25519", jwk.X: "AAAA"},
		"Ed448":           {jwk.KeyType: "OKP", jwk.Curve: "Ed448", jwk.X: "AAAA"},
		"oct":             {jwk.KeyType: "oct", jwk.K: "AAAA"},
	}
	for name, v := range cases {
		if _, err := jwk.PublicKey(v); !errors.Is(err, jwk.ErrInvalidKey) {
			t.Errorf("%s: PublicKey = %v, want ErrInvalidKey", name, err)
		}
	}
}

func TestPrivateKeyRoundTrips(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ecValue, _ := jwk.PublicValue(ecKey)
	ecD := make([]byte, 48)
	ecKey.D.FillBytes(ecD)
	ecValue[jwk.D] = base64url.Encode(ecD)

	edValue, _ := jwk.PublicValue(edKey)
	edValue[jwk.D] = base64url.Encode(edKey.Seed())

	xValue, _ := jwk.PublicValue(xKey)
	xValue[jwk.D] = base64url.Encode(xKey.Bytes())

	for name, tc := range map[string]struct {
		value  jwk.Key
		public crypto.PublicKey
	}{
		"EC":      {ecValue, &ecKey.PublicKey},
		"Ed25519": {edValue, edKey.Public()},
		"X25519":  {xValue, xKey.PublicKey()},
	} {
		private, err := jwk.PrivateKey(tc.value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var public crypto.PublicKey
		switch k := private.(type) {
		case crypto.Signer:
			public = k.Public()
		case *ecdh.PrivateKey:
			public = k.PublicKey()
		}
		if !tc.public.(interface{ Equal(crypto.PublicKey) bool }).Equal(public) {
			t.Fatalf("%s: private key does not match", name)
		}
		if !jwk.IsPrivate(tc.value) {
			t.Fatalf("%s: IsPrivate = false", name)
		}
	}

	// A private scalar that does not match the public point is rejected.
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	other.D.FillBytes(ecD)
	ecValue[jwk.D] = base64url.Encode(ecD)
	if _, err := jwk.PrivateKey(ecValue); !errors.Is(err, jwk.ErrInvalidKey) {
		t.Fatalf("mismatched EC private key: %v", err)
	}
}

func TestPrivateKeyRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := jwk.PublicValue(key)
	v[jwk.D] = base64url.Encode(key.D.Bytes())
	v[jwk.P] = base64url.Encode(key.Primes[0].Bytes())
	v[jwk.Q] = base64url.Encode(key.Primes[1].Bytes())
	private, err := jwk.PrivateKey(v)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(private) {
		t.Fatal("RSA private key changed in round trip")
	}
	v[jwk.OtherPrimes] = []any{}
	if _, err := jwk.PrivateKey(v); err == nil {
		t.Fatal("accepted a multi-prime RSA key")
	}
}

// RFC 8037 Appendix A.3.
func TestThumbprintOKP(t *testing.T) {
	v := jwk.Key{jwk.KeyType: "OKP", jwk.Curve: "Ed25519", jwk.X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	got, err := thumbprint.GenerateString(v, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if want := "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"; got != want {
		t.Fatalf("thumbprint = %s, want %s", got, want)
	}
	public, err := jwk.PublicKey(v)
	if err != nil {
		t.Fatal(err)
	}
	if fromKey, err := thumbprint.FromPublicKey(public); err != nil || fromKey != got {
		t.Fatalf("FromPublicKey = %s, %v", fromKey, err)
	}
}

func TestThumbprintRejectsMalformedMembers(t *testing.T) {
	for name, v := range map[string]jwk.Key{
		"numeric": {jwk.KeyType: "RSA", jwk.N: 1, jwk.E: "AQAB"},
		"escape":  {jwk.KeyType: "OKP", jwk.Curve: "Ed25519", jwk.X: `a"b`},
		"missing": {jwk.KeyType: "EC", jwk.Curve: "P-256", jwk.X: "AA"},
		"unknown": {jwk.KeyType: "XYZ"},
		"no type": {jwk.X: "AA"},
	} {
		if _, err := thumbprint.Generate(v, crypto.SHA256); !errors.Is(err, thumbprint.ErrInvalidKey) {
			t.Errorf("%s: Generate = %v, want ErrInvalidKey", name, err)
		}
	}
}

func TestPublicKeyRejectsOversizedRSA(t *testing.T) {
	n := make([]byte, jwk.MaxRSAModulusBytes+1)
	n[0], n[len(n)-1] = 0xc5, 0x01
	encoded := base64url.Encode(n)
	maximal := base64url.Encode(n[:jwk.MaxRSAModulusBytes])
	if _, err := jwk.PublicKey(jwk.Key{jwk.KeyType: "RSA", jwk.N: encoded, jwk.E: "AQAB"}); !errors.Is(err, jwk.ErrInvalidKey) {
		t.Fatalf("PublicKey() of a %d-bit modulus error = %v, want ErrInvalidKey", len(n)*8, err)
	}
	if _, err := jwk.PublicKey(jwk.Key{jwk.KeyType: "RSA", jwk.N: maximal, jwk.E: "AQAB"}); err != nil {
		t.Fatalf("PublicKey() of an 8192-bit modulus error = %v", err)
	}
}

// An empty "n" or "e" is a malformed key, not a panic.
func TestPublicKeyRejectsEmptyRSAMembers(t *testing.T) {
	for _, v := range []jwk.Key{
		{jwk.KeyType: "RSA", jwk.N: "", jwk.E: "AQAB"},
		{jwk.KeyType: "RSA", jwk.N: "AQAB", jwk.E: ""},
	} {
		if _, err := jwk.PublicKey(v); !errors.Is(err, jwk.ErrInvalidKey) {
			t.Errorf("PublicKey(%v) error = %v, want ErrInvalidKey", v, err)
		}
	}
}
