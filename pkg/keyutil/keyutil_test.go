package keyutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	require.Equal(t, size, len(key))
}

func TestNewSymmetricKeyEqual(t *testing.T) {
	key1, err := NewSymmetricKey(256)
	require.NoError(t, err)

	key2, err := NewSymmetricKey(512)
	require.NoError(t, err)

	require.True(t, SymmetricKeysEqual(key1, key1))
	require.True(t, SymmetricKeysEqual(key2, key2))
	require.False(t, SymmetricKeysEqual(key1, key2))
}

func TestParseRSAPublicKey(t *testing.T) {
	key := testRSAPublicKey

	publicKey, err := ParseRSAPublicKey(bytes.NewReader(key))
	require.NoError(t, err)
	require.NotNil(t, publicKey)
	require.Equal(t, 256, publicKey.Size())
	require.Equal(t, 65537, publicKey.E)
	require.NotZero(t, publicKey.N)
}

func TestParseRSAPrivateKey(t *testing.T) {
	key := testRSAPrivateKey

	privateKey, err := ParseRSAPrivateKey(bytes.NewReader(key))
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	require.NotNil(t, privateKey.D)
	require.NotNil(t, privateKey.N)
	require.NotZero(t, privateKey.E)
	require.Equal(t, 256, privateKey.Size())
	require.NotEmpty(t, privateKey.Primes)
	require.NotNil(t, privateKey.PublicKey)
	require.Equal(t, 256, privateKey.PublicKey.Size())
	require.Equal(t, 65537, privateKey.PublicKey.E)
	require.NotZero(t, privateKey.PublicKey.N)
}

func TestParseECDSAPublicKey(t *testing.T) {
	key := testECDSAPublicKey

	publicKey, err := ParseECDSAPublicKey(bytes.NewReader(key))
	require.NoError(t, err)
	require.NotNil(t, publicKey)
	require.Equal(t, publicKey.Curve, elliptic.P256())
	require.NotZero(t, publicKey.X)
	require.NotZero(t, publicKey.Y)
}

func TestParseECDSAPrivateKey(t *testing.T) {
	key := testECDSAPrivateKey

	privateKey, err := ParseECDSAPrivateKey(bytes.NewReader(key))
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.Equal(t, privateKey.Curve, elliptic.P256())
	require.NotZero(t, privateKey.D)
	require.NotZero(t, privateKey.X)
	require.NotZero(t, privateKey.Y)
}

func TestParseEdDSAPublicKey(t *testing.T) {
	key := testEdDSAPublicKey

	publicKey, err := ParseEdDSAPublicKey(bytes.NewReader(key))
	require.NoError(t, err)
	require.NotNil(t, publicKey)
	require.NotEmpty(t, publicKey)
}

func TestParseEdDSAPrivateKey(t *testing.T) {
	key := testEdDSAPrivateKey
	privateKey, err := ParseEdDSAPrivateKey(bytes.NewReader(key))
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.NotEmpty(t, privateKey)
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
				require.NoError(t, err)
				require.NotNil(t, key)
				rsaKey, ok := key.(*rsa.PrivateKey)
				require.True(t, ok)
				require.NotNil(t, rsaKey)
				require.Equal(t, 256, rsaKey.Size())
				require.NotNil(t, rsaKey.D)
				require.NotNil(t, rsaKey.N)
				require.NotZero(t, rsaKey.E)
				require.NotEmpty(t, rsaKey.Primes)
				require.NotNil(t, rsaKey.PublicKey)
				require.Equal(t, 256, rsaKey.PublicKey.Size())
				require.Equal(t, 65537, rsaKey.PublicKey.E)
				require.NotZero(t, rsaKey.PublicKey.N)
			},
		},
		{
			name: "ES256",
			key:  testECDSAPrivateKey,
			check: func(t *testing.T, key any, err error) {
				require.NoError(t, err)
				require.NotNil(t, key)
				ecdsaKey, ok := key.(*ecdsa.PrivateKey)
				require.True(t, ok)
				require.NotNil(t, ecdsaKey)
				require.Equal(t, elliptic.P256(), ecdsaKey.Curve)
				require.NotZero(t, ecdsaKey.D)
				require.NotZero(t, ecdsaKey.X)
				require.NotZero(t, ecdsaKey.Y)
			},
		},
		{
			name: "EdDSA",
			key:  testEdDSAPrivateKey,
			check: func(t *testing.T, key any, err error) {
				require.NoError(t, err)
				require.NotNil(t, key)
				edKey, ok := key.(ed25519.PrivateKey)
				require.True(t, ok)
				require.NotEmpty(t, edKey)
			},
		},
		{
			name: "invalid",
			key:  []byte("..."),
			check: func(t *testing.T, key any, err error) {
				require.Error(t, err)
				require.Nil(t, key)
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
				require.NoError(t, err)
				require.NotNil(t, key)
				rsaKey, ok := key.(*rsa.PublicKey)
				require.True(t, ok)
				require.NotNil(t, rsaKey)
				require.Equal(t, 256, rsaKey.Size())
				require.Equal(t, 65537, rsaKey.E)
				require.NotZero(t, rsaKey.N)
			},
		},
		{
			name: "ES256",
			key:  testECDSAPublicKey,
			check: func(t *testing.T, key any, err error) {
				require.NoError(t, err)
				require.NotNil(t, key)
				ecdsaKey, ok := key.(*ecdsa.PublicKey)
				require.True(t, ok)
				require.NotNil(t, ecdsaKey)
				require.Equal(t, elliptic.P256(), ecdsaKey.Curve)
				require.NotZero(t, ecdsaKey.X)
				require.NotZero(t, ecdsaKey.Y)
			},
		},
		{
			name: "EdDSA",
			key:  testEdDSAPublicKey,
			check: func(t *testing.T, key any, err error) {
				require.NoError(t, err)
				require.NotNil(t, key)
				edKey, ok := key.(ed25519.PublicKey)
				require.True(t, ok)
				require.NotEmpty(t, edKey)
			},
		},
		{
			name: "invalid",
			key:  []byte("..."),
			check: func(t *testing.T, key any, err error) {
				require.Error(t, err)
				require.Nil(t, key)
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
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.NotNil(t, priv)
	})

	t.Run("ECDSA", func(t *testing.T) {
		pub, priv, err := NewECDSAKeyPair()
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.NotNil(t, priv)
	})

	t.Run("EdDSA", func(t *testing.T) {
		pub, priv, err := NewEdDSAKeyPair()
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.NotNil(t, priv)
	})
}
