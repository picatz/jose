package keyutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"
)

var (
	testEdDSAPublicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAzpgjKSr9E032DX+foiOxq1QDsbzjLxagTN+yVpGWZB4=
-----END PUBLIC KEY-----
	`)

	testEdDSAPrivateKey = []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFdZWoDdFny5SMnP9Fyfr8bafi/B527EVZh8JJjDTIFO
-----END PRIVATE KEY-----
	`)

	testECDSAPublicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYD54V/vp+54P9DXarYqx4MPcm+HK
RIQzNasYSoRQHQ/6S6Ps8tpMcT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END PUBLIC KEY-----
	`)

	testECDSAPrivateKey = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAh5qA3rmqQQuu0vbKV/+zouz/y/Iy2pLpIcWUSyImSwoAoGCCqGSM49
AwEHoUQDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpM
cT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END EC PRIVATE KEY-----
	`)

	testRSAPublicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7
mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp
HssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2
XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy
7wIDAQAB
-----END PUBLIC KEY-----
	`)

	testRSAPrivateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----
	`)
)

func TestNewSymmetricKey(t *testing.T) {
	size := 256
	key, err := NewSymmetricKey(size)
	if err != nil {
		t.Fatalf("NewSymmetricKey() error = %v", err)
	}
	if len(key) != size {
		t.Fatalf("len(key) = %v, want %v", len(key), size)
	}
}

func TestNewSymmetricKeyEqual(t *testing.T) {
	key1, err := NewSymmetricKey(256)
	if err != nil {
		t.Fatalf("NewSymmetricKey() error = %v", err)
	}

	key2, err := NewSymmetricKey(512)
	if err != nil {
		t.Fatalf("NewSymmetricKey() error = %v", err)
	}

	if !SymmetricKeysEqual(key1, key1) {
		t.Fatal("SymmetricKeysEqual(key1, key1) = false, want true")
	}
	if !SymmetricKeysEqual(key2, key2) {
		t.Fatal("SymmetricKeysEqual(key2, key2) = false, want true")
	}
	if SymmetricKeysEqual(key1, key2) {
		t.Fatal("SymmetricKeysEqual(key1, key2) = true, want false")
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	key := testRSAPublicKey

	publicKey, err := ParseRSAPublicKey(bytes.NewReader(key))
	if err != nil {
		t.Fatalf("ParseRSAPublicKey() error = %v", err)
	}
	if publicKey == nil {
		t.Fatal("publicKey = nil, want non-nil")
	}
	if publicKey.Size() != 256 {
		t.Fatalf("publicKey.Size() = %v, want %v", publicKey.Size(), 256)
	}
	if publicKey.E != 65537 {
		t.Fatalf("publicKey.E = %v, want %v", publicKey.E, 65537)
	}
	if publicKey.N == nil {
		t.Fatal("publicKey.N = nil, want non-nil")
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	key := testRSAPrivateKey

	privateKey, err := ParseRSAPrivateKey(bytes.NewReader(key))
	if err != nil {
		t.Fatalf("ParseRSAPrivateKey() error = %v", err)
	}
	if privateKey == nil {
		t.Fatal("privateKey = nil, want non-nil")
	}

	if privateKey.D == nil {
		t.Fatal("privateKey.D = nil, want non-nil")
	}
	if privateKey.N == nil {
		t.Fatal("privateKey.N = nil, want non-nil")
	}
	if privateKey.E == 0 {
		t.Fatal("privateKey.E = 0, want non-zero")
	}
	if privateKey.Size() != 256 {
		t.Fatalf("privateKey.Size() = %v, want %v", privateKey.Size(), 256)
	}
	if len(privateKey.Primes) == 0 {
		t.Fatal("privateKey.Primes is empty")
	}
	if privateKey.PublicKey.Size() != 256 {
		t.Fatalf("privateKey.PublicKey.Size() = %v, want %v", privateKey.PublicKey.Size(), 256)
	}
	if privateKey.PublicKey.E != 65537 {
		t.Fatalf("privateKey.PublicKey.E = %v, want %v", privateKey.PublicKey.E, 65537)
	}
	if privateKey.PublicKey.N == nil {
		t.Fatal("privateKey.PublicKey.N = nil, want non-nil")
	}
}

func TestParseECDSAPublicKey(t *testing.T) {
	key := testECDSAPublicKey

	publicKey, err := ParseECDSAPublicKey(bytes.NewReader(key))
	if err != nil {
		t.Fatalf("ParseECDSAPublicKey() error = %v", err)
	}
	if publicKey == nil {
		t.Fatal("publicKey = nil, want non-nil")
	}
	if publicKey.Curve != elliptic.P256() {
		t.Fatalf("publicKey.Curve = %v, want P-256", publicKey.Curve.Params().Name)
	}
	if publicKey.X == nil {
		t.Fatal("publicKey.X = nil, want non-nil")
	}
	if publicKey.Y == nil {
		t.Fatal("publicKey.Y = nil, want non-nil")
	}
}

func TestParseECDSAPrivateKey(t *testing.T) {
	key := testECDSAPrivateKey

	privateKey, err := ParseECDSAPrivateKey(bytes.NewReader(key))
	if err != nil {
		t.Fatalf("ParseECDSAPrivateKey() error = %v", err)
	}
	if privateKey == nil {
		t.Fatal("privateKey = nil, want non-nil")
	}
	if privateKey.Curve != elliptic.P256() {
		t.Fatalf("privateKey.Curve = %v, want P-256", privateKey.Curve.Params().Name)
	}
	if privateKey.D == nil {
		t.Fatal("privateKey.D = nil, want non-nil")
	}
	if privateKey.X == nil {
		t.Fatal("privateKey.X = nil, want non-nil")
	}
	if privateKey.Y == nil {
		t.Fatal("privateKey.Y = nil, want non-nil")
	}
}

func TestParseEdDSAPublicKey(t *testing.T) {
	key := testEdDSAPublicKey

	publicKey, err := ParseEdDSAPublicKey(bytes.NewReader(key))
	if err != nil {
		t.Fatalf("ParseEdDSAPublicKey() error = %v", err)
	}
	if publicKey == nil {
		t.Fatal("publicKey = nil, want non-nil")
	}
	if len(publicKey) == 0 {
		t.Fatal("publicKey is empty")
	}
}

func TestParseEdDSAPrivateKey(t *testing.T) {
	key := testEdDSAPrivateKey
	privateKey, err := ParseEdDSAPrivateKey(bytes.NewReader(key))
	if err != nil {
		t.Fatalf("ParseEdDSAPrivateKey() error = %v", err)
	}
	if privateKey == nil {
		t.Fatal("privateKey = nil, want non-nil")
	}
	if len(privateKey) == 0 {
		t.Fatal("privateKey is empty")
	}
}

func TestParsePrivateKey(t *testing.T) {
	tests := []struct {
		name  string
		key   []byte
		check func(t *testing.T, key any, err error)
	}{
		{
			name: "RS256",
			key:  testRSAPrivateKey,
			check: func(t *testing.T, key any, err error) {
				if err != nil {
					t.Fatalf("ParsePrivateKey() error = %v", err)
				}
				if key == nil {
					t.Fatal("key = nil, want non-nil")
				}
				rsaKey, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("key type = %T, want *rsa.PrivateKey", key)
				}
				if rsaKey == nil {
					t.Fatal("rsaKey = nil, want non-nil")
				}
				if rsaKey.Size() != 256 {
					t.Fatalf("rsaKey.Size() = %v, want %v", rsaKey.Size(), 256)
				}
				if rsaKey.D == nil {
					t.Fatal("rsaKey.D = nil, want non-nil")
				}
				if rsaKey.N == nil {
					t.Fatal("rsaKey.N = nil, want non-nil")
				}
				if rsaKey.E == 0 {
					t.Fatal("rsaKey.E = 0, want non-zero")
				}
				if len(rsaKey.Primes) == 0 {
					t.Fatal("rsaKey.Primes is empty")
				}
				if rsaKey.PublicKey.Size() != 256 {
					t.Fatalf("rsaKey.PublicKey.Size() = %v, want %v", rsaKey.PublicKey.Size(), 256)
				}
				if rsaKey.PublicKey.E != 65537 {
					t.Fatalf("rsaKey.PublicKey.E = %v, want %v", rsaKey.PublicKey.E, 65537)
				}
				if rsaKey.PublicKey.N == nil {
					t.Fatal("rsaKey.PublicKey.N = nil, want non-nil")
				}
			},
		},
		{
			name: "ES256",
			key:  testECDSAPrivateKey,
			check: func(t *testing.T, key any, err error) {
				if err != nil {
					t.Fatalf("ParsePrivateKey() error = %v", err)
				}
				if key == nil {
					t.Fatal("key = nil, want non-nil")
				}
				ecdsaKey, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("key type = %T, want *ecdsa.PrivateKey", key)
				}
				if ecdsaKey == nil {
					t.Fatal("ecdsaKey = nil, want non-nil")
				}
				if ecdsaKey.Curve != elliptic.P256() {
					t.Fatalf("ecdsaKey.Curve = %v, want P-256", ecdsaKey.Curve.Params().Name)
				}
				if ecdsaKey.D == nil {
					t.Fatal("ecdsaKey.D = nil, want non-nil")
				}
				if ecdsaKey.X == nil {
					t.Fatal("ecdsaKey.X = nil, want non-nil")
				}
				if ecdsaKey.Y == nil {
					t.Fatal("ecdsaKey.Y = nil, want non-nil")
				}
			},
		},
		{
			name: "EdDSA",
			key:  testEdDSAPrivateKey,
			check: func(t *testing.T, key any, err error) {
				if err != nil {
					t.Fatalf("ParsePrivateKey() error = %v", err)
				}
				if key == nil {
					t.Fatal("key = nil, want non-nil")
				}
				edKey, ok := key.(ed25519.PrivateKey)
				if !ok {
					t.Fatalf("key type = %T, want ed25519.PrivateKey", key)
				}
				if len(edKey) == 0 {
					t.Fatal("edKey is empty")
				}
			},
		},
		{
			name: "invalid",
			key:  []byte("..."),
			check: func(t *testing.T, key any, err error) {
				if err == nil {
					t.Fatal("ParsePrivateKey() error = nil, want non-nil")
				}
				if key != nil {
					t.Fatalf("key = %v, want nil", key)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := ParsePrivateKey(bytes.NewReader(test.key))

			test.check(t, key, err)
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	tests := []struct {
		name  string
		key   []byte
		check func(t *testing.T, key any, err error)
	}{
		{
			name: "RS256",
			key:  testRSAPublicKey,
			check: func(t *testing.T, key any, err error) {
				if err != nil {
					t.Fatalf("ParsePublicKey() error = %v", err)
				}
				if key == nil {
					t.Fatal("key = nil, want non-nil")
				}
				rsaKey, ok := key.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("key type = %T, want *rsa.PublicKey", key)
				}
				if rsaKey == nil {
					t.Fatal("rsaKey = nil, want non-nil")
				}
				if rsaKey.Size() != 256 {
					t.Fatalf("rsaKey.Size() = %v, want %v", rsaKey.Size(), 256)
				}
				if rsaKey.E != 65537 {
					t.Fatalf("rsaKey.E = %v, want %v", rsaKey.E, 65537)
				}
				if rsaKey.N == nil {
					t.Fatal("rsaKey.N = nil, want non-nil")
				}
			},
		},
		{
			name: "ES256",
			key:  testECDSAPublicKey,
			check: func(t *testing.T, key any, err error) {
				if err != nil {
					t.Fatalf("ParsePublicKey() error = %v", err)
				}
				if key == nil {
					t.Fatal("key = nil, want non-nil")
				}
				ecdsaKey, ok := key.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("key type = %T, want *ecdsa.PublicKey", key)
				}
				if ecdsaKey == nil {
					t.Fatal("ecdsaKey = nil, want non-nil")
				}
				if ecdsaKey.Curve != elliptic.P256() {
					t.Fatalf("ecdsaKey.Curve = %v, want P-256", ecdsaKey.Curve.Params().Name)
				}
				if ecdsaKey.X == nil {
					t.Fatal("ecdsaKey.X = nil, want non-nil")
				}
				if ecdsaKey.Y == nil {
					t.Fatal("ecdsaKey.Y = nil, want non-nil")
				}
			},
		},
		{
			name: "EdDSA",
			key:  testEdDSAPublicKey,
			check: func(t *testing.T, key any, err error) {
				if err != nil {
					t.Fatalf("ParsePublicKey() error = %v", err)
				}
				if key == nil {
					t.Fatal("key = nil, want non-nil")
				}
				edKey, ok := key.(ed25519.PublicKey)
				if !ok {
					t.Fatalf("key type = %T, want ed25519.PublicKey", key)
				}
				if len(edKey) == 0 {
					t.Fatal("edKey is empty")
				}
			},
		},
		{
			name: "invalid",
			key:  []byte("..."),
			check: func(t *testing.T, key any, err error) {
				if err == nil {
					t.Fatal("ParsePublicKey() error = nil, want non-nil")
				}
				if key != nil {
					t.Fatalf("key = %v, want nil", key)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := ParsePublicKey(bytes.NewReader(test.key))

			test.check(t, key, err)
		})
	}
}

func TestNewKeyPairs(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		pub, priv, err := NewRSAKeyPair()
		if err != nil {
			t.Fatalf("NewRSAKeyPair() error = %v", err)
		}
		if pub == nil {
			t.Fatal("pub = nil, want non-nil")
		}
		if priv == nil {
			t.Fatal("priv = nil, want non-nil")
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		pub, priv, err := NewECDSAKeyPair()
		if err != nil {
			t.Fatalf("NewECDSAKeyPair() error = %v", err)
		}
		if pub == nil {
			t.Fatal("pub = nil, want non-nil")
		}
		if priv == nil {
			t.Fatal("priv = nil, want non-nil")
		}
	})

	t.Run("EdDSA", func(t *testing.T) {
		pub, priv, err := NewEdDSAKeyPair()
		if err != nil {
			t.Fatalf("NewEdDSAKeyPair() error = %v", err)
		}
		if pub == nil {
			t.Fatal("pub = nil, want non-nil")
		}
		if priv == nil {
			t.Fatal("priv = nil, want non-nil")
		}
	})
}
