package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"

	"github.com/stretchr/testify/require"
)

// https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1
var testHMACSecretKey = []byte{
	3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
	143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
	46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
	98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
	208, 128, 163,
}

// Test RSA and ECDSA key-pairs cribbed lovingly from https://github.com/dgrijalva/jwt-go
var (
	testRSASHA256PublicKey = func() *rsa.PublicKey {
		var key = []byte(`
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

		var err error

		// Parse PEM block
		var block *pem.Block
		if block, _ = pem.Decode(key); block == nil {
			panic(fmt.Errorf("failed to decode test RSA public key"))
		}

		// Parse the key
		var parsedKey interface{}
		if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				parsedKey = cert.PublicKey
			} else {
				panic(fmt.Errorf("failed to parse test RSA public key: %w", err))
			}
		}

		var pkey *rsa.PublicKey
		var ok bool
		if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
			panic(fmt.Errorf("parsed RSA public key %T is invalid", parsedKey))
		}

		return pkey
	}()

	testRSASHA256PrviateKey = func() *rsa.PrivateKey {
		var key = []byte(`
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

		var err error

		// Parse PEM block
		var block *pem.Block
		if block, _ = pem.Decode(key); block == nil {
			panic(fmt.Errorf("failed to decode RSA private key PEM block: %w", err))
		}

		var parsedKey interface{}
		if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				panic(fmt.Errorf("failed to decode RSA private key: %w", err))
			}
		}

		var pkey *rsa.PrivateKey
		var ok bool
		if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
			panic(fmt.Errorf("parsed RSA private key %T is invalid", parsedKey))
		}

		return pkey
	}()

	testECDSAPublicKey = func() *ecdsa.PublicKey {
		key := []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYD54V/vp+54P9DXarYqx4MPcm+HK
RIQzNasYSoRQHQ/6S6Ps8tpMcT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END PUBLIC KEY-----
	`)

		var err error

		// Parse PEM block
		var block *pem.Block
		if block, _ = pem.Decode(key); block == nil {
			panic(fmt.Errorf("failed to parse ECDSA public key PEM block"))
		}

		// Parse the key
		var parsedKey interface{}
		if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			cert, err := x509.ParseCertificate(block.Bytes)

			if err != nil {
				panic(err)
			}
			parsedKey = cert.PublicKey
		}

		var pkey *ecdsa.PublicKey
		var ok bool
		if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
			panic(fmt.Errorf("invalid parsed ECDSA public key type: %T", parsedKey))
		}

		return pkey
	}()

	testECDSAPrivateKey = func() *ecdsa.PrivateKey {
		key := []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAh5qA3rmqQQuu0vbKV/+zouz/y/Iy2pLpIcWUSyImSwoAoGCCqGSM49
AwEHoUQDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpM
cT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END EC PRIVATE KEY-----
	`)

		var err error

		// Parse PEM block
		var block *pem.Block
		if block, _ = pem.Decode(key); block == nil {
			panic(fmt.Errorf("failed to parse ECDSA private key PEM block"))
		}

		// Parse the key
		var parsedKey interface{}
		if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				panic(fmt.Errorf("failed to parse ECDSA private key: %w", err))
			}
		}

		var pkey *ecdsa.PrivateKey
		var ok bool
		pkey, ok = parsedKey.(*ecdsa.PrivateKey)
		if !ok {
			panic(fmt.Errorf("invalid parsed ECDSA private key type: %T", parsedKey))
		}

		return pkey
	}()

	testEdDSAPublicKey = func() ed25519.PublicKey {
		key := []byte(`
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAzpgjKSr9E032DX+foiOxq1QDsbzjLxagTN+yVpGWZB4=
-----END PUBLIC KEY-----
	`)

		// Parse PEM block
		var block *pem.Block
		if block, _ = pem.Decode(key); block == nil {
			panic(fmt.Errorf("failed to parse EdDSA public key PEM block"))
		}

		// Parse the key
		asn1PubKey := struct {
			ObjectIdentifier struct {
				ObjectIdentifier asn1.ObjectIdentifier
			}
			PublicKey asn1.BitString
		}{}

		if _, err := asn1.Unmarshal(block.Bytes, &asn1PubKey); err != nil {
			panic(fmt.Errorf("failed to parse EdDSA public key ANS.1"))
		}

		return ed25519.PublicKey(asn1PubKey.PublicKey.Bytes)
	}()

	testEdDSAPrivateKey = func() ed25519.PrivateKey {
		key := []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFdZWoDdFny5SMnP9Fyfr8bafi/B527EVZh8JJjDTIFO
-----END PRIVATE KEY-----
	`)

		// Parse PEM block
		var block *pem.Block
		if block, _ = pem.Decode(key); block == nil {
			panic(fmt.Errorf("failed to parse EdDSA private key PEM block"))
		}

		asn1PrivKey := struct {
			Version          int
			ObjectIdentifier struct {
				ObjectIdentifier asn1.ObjectIdentifier
			}
			PrivateKey []byte
		}{}

		if _, err := asn1.Unmarshal(block.Bytes, &asn1PrivKey); err != nil {
			panic(fmt.Errorf("failed to parse EdDSA private key ANS.1"))
		}

		seed := asn1PrivKey.PrivateKey[2:]
		if len(seed) != ed25519.SeedSize {
			panic(fmt.Errorf("invalid EdDSA seed length: %d", len(seed)))
		}

		return ed25519.NewKeyFromSeed(seed)
	}()
)

func newToken(t *testing.T, params header.Parameters, claims ClaimsSet, key any) (*Token, error) {
	var (
		token *Token
		err   error
	)

	switch key := key.(type) {
	case *rsa.PrivateKey:
		token, err = New(params, claims, key)
	case *ecdsa.PrivateKey:
		token, err = New(params, claims, key)
	case ed25519.PrivateKey:
		token, err = New(params, claims, key)
	case []byte:
		token, err = New(params, claims, key)
	case string:
		token, err = New(params, claims, key)
	default:
		return nil, fmt.Errorf("unsupported signing key type: %T", key)
	}

	return token, err
}

func TestTokenString(t *testing.T) {
	token := &Token{
		Header: jws.Header{
			header.Type:      Type,
			header.Algorithm: jwa.HS256,
		},
		Claims: ClaimsSet{
			Subject: "test",
			Issuer:  "test",
		},
	}

	t.Logf("before sign: %s", token)

	sig, err := token.Sign(testHMACSecretKey)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	t.Logf("after sign: %s", token)
}

func TestParseStringAndVerify(t *testing.T) {
	tests := []struct {
		Name    string
		Input   string
		Error   bool
		Require func(t *testing.T, token *Token)
	}{
		{
			Name:  "emtpy",
			Error: true,
		},
		{
			Name:  "invalid data",
			Input: "eqwfixwjwwkgjiw.ufo....",
			Error: true,
		},
		{
			Name:  "JOSE header with claims and ECDSA SHA256 signature",
			Input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ",
			Error: false,
			Require: func(t *testing.T, token *Token) {
				require.Equal(t, jwa.ES256, token.Header[header.Algorithm])
				require.Equal(t, Type, token.Header[header.Type])
				require.NotEmpty(t, token.Claims)
				require.NotEmpty(t, token.Signature)
				require.Equal(t, token.raw, token.String())

				sig, err := token.ECDSASignature(crypto.SHA256, testECDSAPrivateKey)
				require.NoError(t, err)
				require.NotEmpty(t, sig)
				require.Equal(t, len(sig), len(token.Signature))
				// while the length should be equal, each run should not have equal values
				require.NotEqual(t, sig, token.Signature)

				err = token.VerifyECDSASignature(crypto.SHA256, testECDSAPublicKey)
				require.NoError(t, err)

				err = token.Verify(WithKey(testECDSAPublicKey))
				require.NoError(t, err)
			},
		},
		{
			Name:  "JOSE header with claims and ECDSA SHA256 signature, but only RS256 is enabled",
			Input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ",
			Error: false,
			Require: func(t *testing.T, token *Token) {
				require.Equal(t, jwa.ES256, token.Header[header.Algorithm])
				require.Equal(t, Type, token.Header[header.Type])
				require.NotEmpty(t, token.Claims)
				require.NotEmpty(t, token.Signature)
				require.Equal(t, token.raw, token.String())

				err := token.Verify(WithKey(testECDSAPublicKey), WithAllowedAlgorithms(jwa.RS256))
				require.Error(t, err)
			},
		},
		{
			Name:  "JOSE header with claims and RSA SHA256 signature",
			Input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			Error: false,
			Require: func(t *testing.T, token *Token) {
				require.Equal(t, jwa.RS256, token.Header[header.Algorithm])
				require.Equal(t, Type, token.Header[header.Type])
				require.NotEmpty(t, token.Claims)
				require.NotEmpty(t, token.Signature)
				require.Equal(t, token.raw, token.String())

				sig, err := token.RSASignature(crypto.SHA256, testRSASHA256PrviateKey)
				require.NoError(t, err)
				require.NotEmpty(t, sig)
				require.Equal(t, len(sig), len(token.Signature))
				require.Equal(t, sig, token.Signature)

				require.Equal(t, base64.Encode(sig), base64.Encode(token.Signature))

				err = token.VerifyRSASignature(crypto.SHA256, testRSASHA256PublicKey)
				require.NoError(t, err)

				err = token.Verify(WithKey(testRSASHA256PublicKey))
				require.NoError(t, err)
			},
		},
		{
			Name:  "JOSE header only",
			Input: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
			Error: true, // too short
		},
		{
			Name:  "JOSE header with claims",
			Input: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`,
			Error: true, // no signature
		},
		{
			Name:  "JOSE header with claims and HMAC SHA256 signature",
			Input: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
			Require: func(t *testing.T, token *Token) {
				require.Equal(t, jwa.HS256, token.Header[header.Algorithm])
				require.Equal(t, Type, token.Header[header.Type])
				require.Equal(t, int64(1300819380), token.Claims[ExpirationTime])
				require.Equal(t, "joe", token.Claims[Issuer])
				require.Equal(t, true, token.Claims["http://example.com/is_root"])
				require.NotEmpty(t, token.Signature)
				require.Equal(t, token.raw, token.String())

				sig, err := token.HMACSignature(crypto.SHA256, testHMACSecretKey)
				require.NoError(t, err)
				require.NotEmpty(t, sig)
				require.True(t, hmac.Equal([]byte(sig), token.Signature))

				err = token.VerifyHMACSignature(crypto.SHA256, testHMACSecretKey)
				require.NoError(t, err)

				// Token is expired
				err = token.Verify(WithKey(testHMACSecretKey), WithAllowedAlgorithms(jwa.HS256))
				require.Error(t, err)
			},
		},
		{
			Name:  "JOSE header with claims and EdDSA signature",
			Input: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.U3ChCsJwStNnEdE_wgkh5elQHIKPYfdi4BZoy8CWQNAaFymND_-6fwghDC4bQRrcotXjD6WZDaSrJ_W7uVoBBQ",
			Error: false,
			Require: func(t *testing.T, token *Token) {
				require.Equal(t, jwa.EdDSA, token.Header[header.Algorithm])
				require.Equal(t, Type, token.Header[header.Type])
				require.NotEmpty(t, token.Claims)
				require.NotEmpty(t, token.Signature)
				require.Equal(t, token.raw, token.String())

				sig, err := token.EdDSASignature(testEdDSAPrivateKey)
				require.NoError(t, err)
				require.NotEmpty(t, sig)
				require.Equal(t, len(sig), len(token.Signature))
				require.Equal(t, sig, token.Signature)

				err = token.VerifyEdDSASignature(testEdDSAPublicKey)
				require.NoError(t, err)

				err = token.Verify(WithKey(testEdDSAPublicKey), WithAllowedAlgorithms(jwa.EdDSA))
				require.NoError(t, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			token, err := ParseString(test.Input)
			if test.Error {
				require.Error(t, err)
				require.Nil(t, token)
			} else {
				require.NoError(t, err)
				require.NotNil(t, token)
				test.Require(t, token)
			}
		})
	}

}

func TestSignJWT(t *testing.T) {
	token := &Token{
		Header: header.Parameters{
			header.Type:      "JWT",
			header.Algorithm: jwa.RS256,
		},
		Claims: ClaimsSet{
			Subject: "test",
		},
	}

	sig, err := token.Sign(testRSASHA256PrviateKey)
	require.NoError(t, err)
	require.NotNil(t, sig)
	require.Equal(t, token.Signature, sig)
}

func TestNew(t *testing.T) {
	tests := []struct {
		Name                    string
		Error                   bool
		Header                  header.Parameters
		Claims                  ClaimsSet
		SigningKey              interface{}
		VerifyKey               interface{}
		AllowedVerifyAlgorithms []jwa.Algorithm
	}{
		{
			Name: "RSA SHA256",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.RS256,
			},
			Claims: ClaimsSet{
				Subject: "test",
			},
			SigningKey:              testRSASHA256PrviateKey,
			VerifyKey:               testRSASHA256PublicKey,
			AllowedVerifyAlgorithms: DefaultAllowedAlogrithms(),
		},
		{
			Name: "RSA PSS SHA256",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.PS256,
			},
			Claims: ClaimsSet{
				Subject: "test",
			},
			SigningKey:              testRSASHA256PrviateKey,
			VerifyKey:               testRSASHA256PublicKey,
			AllowedVerifyAlgorithms: DefaultAllowedAlogrithms(),
		},
		{
			Name: "ECDSA SHA256",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.ES256,
			},
			Claims: ClaimsSet{
				Subject: "test",
			},
			SigningKey:              testECDSAPrivateKey,
			VerifyKey:               testECDSAPublicKey,
			AllowedVerifyAlgorithms: DefaultAllowedAlogrithms(),
		},
		{
			Name: "HMAC SHA256",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.HS256,
			},
			Claims: ClaimsSet{
				Subject: "test",
			},
			SigningKey:              testHMACSecretKey,
			VerifyKey:               testHMACSecretKey,
			AllowedVerifyAlgorithms: []jwa.Algorithm{jwa.HS256},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			token, err := newToken(t, test.Header, test.Claims, test.SigningKey)

			if test.Error {
				require.Error(t, err)
				require.Nil(t, token)
			} else {
				require.NoError(t, err)
				require.NotNil(t, token)

				verifyOpts := []VerifyOption{
					WithAllowedAlgorithms(test.AllowedVerifyAlgorithms...),
				}

				if test.VerifyKey != nil {
					switch verifyKey := test.VerifyKey.(type) {
					case *rsa.PublicKey:
						verifyOpts = append(verifyOpts, WithKey(verifyKey))
					case *ecdsa.PublicKey:
						verifyOpts = append(verifyOpts, WithKey(verifyKey))
					case ed25519.PublicKey:
						verifyOpts = append(verifyOpts, WithKey(verifyKey))
					case []byte:
						verifyOpts = append(verifyOpts, WithKey(verifyKey))
					case string:
						verifyOpts = append(verifyOpts, WithKey(verifyKey))
					default:
						t.Fatalf("unsupported verify key type: %T", verifyKey)
					}
				}

				err = token.Verify(verifyOpts...)
				require.NoError(t, err)
			}
		})
	}

}

func TestNewExpired(t *testing.T) {
	tests := []struct {
		Name       string
		Header     header.Parameters
		Claims     ClaimsSet
		SigningKey interface{}
		Error      bool
		Expired    bool
		Expires    bool
	}{
		{
			Name: "expired",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.RS256,
			},
			Claims: ClaimsSet{
				Subject:        "test",
				IssuedAt:       time.Now().Unix(),
				ExpirationTime: time.Now().Add(-time.Hour).Unix(),
			},
			SigningKey: testRSASHA256PrviateKey,
			Expired:    true,
			Expires:    true,
		},
		{
			Name: "not expired",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.RS256,
			},
			Claims: ClaimsSet{
				Subject:        "test",
				IssuedAt:       time.Now().Unix(),
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
			},
			SigningKey: testRSASHA256PrviateKey,
			Expired:    false,
			Expires:    true,
		},
		{
			Name: "not expires",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.RS256,
			},
			Claims: ClaimsSet{
				Subject:  "test",
				IssuedAt: time.Now().Unix(),
			},
			SigningKey: testRSASHA256PrviateKey,
			Expired:    false,
			Expires:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			token, err := newToken(t, test.Header, test.Claims, test.SigningKey)
			require.NoError(t, err)
			require.NotNil(t, token)

			expires, err := token.Expires()
			require.NoError(t, err)

			if test.Expires {
				require.True(t, expires)
			} else {
				require.False(t, expires)
			}

			expired, err := token.Expired(time.Now)
			require.NoError(t, err)

			if test.Expired {
				require.True(t, expired)
			} else {
				require.False(t, expired)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		Name       string
		Header     header.Parameters
		Claims     ClaimsSet
		SigningKey interface{}
		VerifyKey  interface{}
		Error      bool
	}{
		{
			Name: "RSA SHA256",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.RS256,
			},
			Claims: ClaimsSet{
				Subject:        "test",
				IssuedAt:       time.Now().Unix(),
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
			},
			SigningKey: testRSASHA256PrviateKey,
			VerifyKey:  testRSASHA256PublicKey,
		},
		{
			Name: "RSA SHA256 no expiration",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.RS256,
			},
			Claims: ClaimsSet{
				Subject: "test",
			},
			SigningKey: testRSASHA256PrviateKey,
			VerifyKey:  testRSASHA256PublicKey,
		},
		{
			Name: "RSA SHA256 expired",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.RS256,
			},
			Claims: ClaimsSet{
				Subject:        "test",
				IssuedAt:       time.Now().Unix(),
				ExpirationTime: time.Now().Add(-time.Hour).Unix(),
			},
			SigningKey: testRSASHA256PrviateKey,
			VerifyKey:  testRSASHA256PublicKey,
			Error:      true,
		},
		{
			Name: "RSA SHA256 unable to use yet",
			Header: header.Parameters{
				header.Type:      "JWT",
				header.Algorithm: jwa.RS256,
			},
			Claims: ClaimsSet{
				Subject:   "test",
				IssuedAt:  time.Now().Unix(),
				NotBefore: time.Now().Add(30 * time.Second).Unix(),
			},
			SigningKey: testRSASHA256PrviateKey,
			VerifyKey:  testRSASHA256PublicKey,
			Error:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			token, err := newToken(t, test.Header, test.Claims, test.SigningKey)
			require.NoError(t, err)
			require.NotNil(t, token)

			verifyOpts := []VerifyOption{}

			if test.VerifyKey != nil {
				switch verifyKey := test.VerifyKey.(type) {
				case *rsa.PublicKey:
					verifyOpts = append(verifyOpts, WithKey(verifyKey))
				case *ecdsa.PublicKey:
					verifyOpts = append(verifyOpts, WithKey(verifyKey))
				case ed25519.PublicKey:
					verifyOpts = append(verifyOpts, WithKey(verifyKey))
				case []byte:
					verifyOpts = append(verifyOpts, WithKey(verifyKey))
				case string:
					verifyOpts = append(verifyOpts, WithKey(verifyKey))
				default:
					t.Fatalf("unsupported verify key type: %T", verifyKey)
				}
			}

			err = token.Verify(verifyOpts...)
			if test.Error {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// go test -fuzz FuzzParseString
func FuzzParseString(f *testing.F) {
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.")
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0")
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.eyJzdWIiOiJ0ZXN0In0")
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.z.z")
	f.Add("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ")
	f.Add("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ.")
	f.Add("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.U3ChCsJwStNnEdE_wgkh5elQHIKPYfdi4BZoy8CWQNAaFymND_-6fwghDC4bQRrcotXjD6WZDaSrJ_W7uVoBBQ")
	f.Add("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg")

	f.Fuzz(func(t *testing.T, data string) {
		_, err := ParseString(data)
		if err != nil {
			t.Skip()
		}
	})
}

var parseStringResult *Token

func BenchmarkParseString(b *testing.B) {
	s := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"

	var err error

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parseStringResult, err = ParseString(s)
		require.NoError(b, err)
	}
}

var computeStringResult string

func Benchmark_computeString(b *testing.B) {
	t := &Token{
		Header: header.Parameters{
			header.Type:      "JWT",
			header.Algorithm: jwa.RS256,
		},
		Claims: ClaimsSet{
			Subject: "test",
		},
		Signature: []byte("feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		computeStringResult = t.computeString()
	}

	b.StopTimer()
}
