package jwt_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/keyutil"
)

// keyPair is a simple struct that holds a public and private key
// of any type.
type keyPair[P, S any] struct {
	public  P // Public key.
	private S // Private (secret) key.
}

// keySource is a function that returns a public and private key pair
// of any type. This works nicely with the keyutil package's functions.
type keySource[P, S any] func() (P, S, error)

// testNewKeyPair is a helper function that creates a new key pair
// from the given source function. It returns the new key pair that
// can be used in tests to sign (private key) and verify (public key)
// tokens that are created.
func testNewKeyPair[P, S any](t *testing.T, source keySource[P, S]) *keyPair[P, S] {
	t.Helper()

	public, private, err := source()
	if err != nil {
		t.Fatalf("source() error = %v", err)
	}

	return &keyPair[P, S]{
		public:  public,
		private: private,
	}
}

// https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1
var testHMACSecretKey = []byte{
	3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
	143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
	46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
	98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
	208, 128, 163,
}

// testToken returns a new token value with the given parameters, claims, and key.
// If the key is not a supported type, an error is returned.
func testToken(t *testing.T, params header.Parameters, claims jwt.ClaimsSet, key any) *jwt.Token {
	t.Helper()

	var (
		token *jwt.Token
		err   error
	)

	switch key := key.(type) {
	case *rsa.PrivateKey:
		token, err = jwt.New(params, claims, key)
	case *ecdsa.PrivateKey:
		token, err = jwt.New(params, claims, key)
	case ed25519.PrivateKey:
		token, err = jwt.New(params, claims, key)
	case []byte:
		token, err = jwt.New(params, claims, key)
	case string:
		token, err = jwt.New(params, claims, key)
	default:
		t.Fatalf("potentially unsupported signing key type: %T", key)
	}

	if err != nil {
		t.Fatalf("jwt.New() error = %v", err)
	}
	if token == nil {
		t.Fatal("token = nil, want non-nil")
	}

	return token
}

func TestTokenString(t *testing.T) {
	token := &jwt.Token{
		Header: jws.Header{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.HS256,
		},
		Claims: jwt.ClaimsSet{
			jwt.Subject: "test",
			jwt.Issuer:  "test",
		},
	}

	t.Logf("before sign: %s", token)

	if strings.Count(token.String(), ".") != 1 {
		t.Fatalf("strings.Count(token.String(), \".\") = %v, want %v", strings.Count(token.String(), "."), 1)
	}
	if len(token.Signature) != 0 {
		t.Fatalf("token.Signature = %v, want empty", token.Signature)
	}
	if !strings.HasPrefix(token.String(), "eyJ") {
		t.Fatalf("token.String() = %q, want prefix %q", token.String(), "eyJ")
	}

	sig, err := token.Sign(testHMACSecretKey)
	if err != nil {
		t.Fatalf("token.Sign() error = %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("sig is empty")
	}

	t.Logf("after sign: %s", token)

	if strings.Count(token.String(), ".") != 2 {
		t.Fatalf("strings.Count(token.String(), \".\") = %v, want %v", strings.Count(token.String(), "."), 2)
	}
	if len(token.Signature) == 0 {
		t.Fatal("token.Signature is empty")
	}
	if !strings.HasPrefix(token.String(), "eyJ") {
		t.Fatalf("token.String() = %q, want prefix %q", token.String(), "eyJ")
	}
}

func TestParseStringAndVerify(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)
	ecdsaKeyPair := testNewKeyPair(t, keyutil.NewECDSAKeyPair)
	eddsaKeyPair := testNewKeyPair(t, keyutil.NewEdDSAKeyPair)

	rsaToken := testToken(t,
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.RS256,
		},
		jwt.ClaimsSet{
			jwt.Subject: "test",
			jwt.Issuer:  "test",
		},
		rsaKeyPair.private,
	)

	ecdsaToken := testToken(t,
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.ES256,
		},
		jwt.ClaimsSet{
			jwt.Subject: "test",
			jwt.Issuer:  "test",
		},
		ecdsaKeyPair.private,
	)

	eddsaToken := testToken(t,
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.EdDSA,
		},
		jwt.ClaimsSet{
			jwt.Subject: "test",
			jwt.Issuer:  "test",
		},
		eddsaKeyPair.private,
	)

	tests := []struct {
		name  string
		input string
		check func(t *testing.T, token *jwt.Token, err error)
	}{
		{
			name: "empty",
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err == nil {
					t.Fatal("ParseString() error = nil, want non-nil")
				}
				if token != nil {
					t.Fatalf("token = %v, want nil", token)
				}
			},
		},
		{
			name:  "invalid data",
			input: "eqwfixwjwwkgjiw.ufo....",
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err == nil {
					t.Fatal("ParseString() error = nil, want non-nil")
				}
				if token != nil {
					t.Fatalf("token = %v, want nil", token)
				}
			},
		},
		{
			name:  "JOSE header with claims and ECDSA SHA256 signature",
			input: ecdsaToken.String(),
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err != nil {
					t.Fatalf("ParseString() error = %v", err)
				}
				if token.Header[header.Algorithm] != jwa.ES256 {
					t.Fatalf("token.Header[header.Algorithm] = %v, want %v", token.Header[header.Algorithm], jwa.ES256)
				}
				if token.Header[header.Type] != jwt.Type {
					t.Fatalf("token.Header[header.Type] = %v, want %v", token.Header[header.Type], jwt.Type)
				}
				if len(token.Claims) == 0 {
					t.Fatal("token.Claims is empty")
				}
				if len(token.Signature) == 0 {
					t.Fatal("token.Signature is empty")
				}

				sig, err := token.ECDSASignature(crypto.SHA256, ecdsaKeyPair.private)
				if err != nil {
					t.Fatalf("token.ECDSASignature() error = %v", err)
				}
				if len(sig) == 0 {
					t.Fatal("sig is empty")
				}
				if len(token.Signature) != len(sig) {
					t.Fatalf("len(token.Signature) = %v, want %v", len(token.Signature), len(sig))
				}
				if bytes.Equal(sig, token.Signature) {
					t.Fatalf("ECDSASignature() = %x, want it to differ from token.Signature", sig)
				}

				if err := token.VerifyECDSASignature(crypto.SHA256, ecdsaKeyPair.public); err != nil {
					t.Fatalf("token.VerifyECDSASignature() error = %v", err)
				}

				if err := token.Verify(jwt.WithKey(ecdsaKeyPair.public)); err != nil {
					t.Fatalf("token.Verify() error = %v", err)
				}
			},
		},
		{
			name:  "JOSE header with claims and ECDSA SHA256 signature, but only RS256 is enabled",
			input: ecdsaToken.String(),
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err != nil {
					t.Fatalf("ParseString() error = %v", err)
				}
				if token.Header[header.Algorithm] != jwa.ES256 {
					t.Fatalf("token.Header[header.Algorithm] = %v, want %v", token.Header[header.Algorithm], jwa.ES256)
				}
				if token.Header[header.Type] != jwt.Type {
					t.Fatalf("token.Header[header.Type] = %v, want %v", token.Header[header.Type], jwt.Type)
				}
				if len(token.Claims) == 0 {
					t.Fatal("token.Claims is empty")
				}
				if len(token.Signature) == 0 {
					t.Fatal("token.Signature is empty")
				}

				if err := token.Verify(jwt.WithKey(ecdsaKeyPair.public), jwt.WithAllowedAlgorithms(jwa.RS256)); err == nil {
					t.Fatal("token.Verify() error = nil, want non-nil")
				}
			},
		},
		{
			name:  "JOSE header with claims and RSA SHA256 signature",
			input: rsaToken.String(),
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err != nil {
					t.Fatalf("ParseString() error = %v", err)
				}
				if token.Header[header.Algorithm] != jwa.RS256 {
					t.Fatalf("token.Header[header.Algorithm] = %v, want %v", token.Header[header.Algorithm], jwa.RS256)
				}
				if token.Header[header.Type] != jwt.Type {
					t.Fatalf("token.Header[header.Type] = %v, want %v", token.Header[header.Type], jwt.Type)
				}
				if len(token.Claims) == 0 {
					t.Fatal("token.Claims is empty")
				}
				if len(token.Signature) == 0 {
					t.Fatal("token.Signature is empty")
				}

				sig, err := token.RSASignature(crypto.SHA256, rsaKeyPair.private)
				if err != nil {
					t.Fatalf("token.RSASignature() error = %v", err)
				}
				if len(sig) == 0 {
					t.Fatal("sig is empty")
				}
				if len(token.Signature) != len(sig) {
					t.Fatalf("len(token.Signature) = %v, want %v", len(token.Signature), len(sig))
				}
				if !bytes.Equal(token.Signature, sig) {
					t.Fatalf("token.Signature = %x, want %x", token.Signature, sig)
				}

				sigEnc, err := base64.Encode(sig)
				if err != nil {
					t.Fatalf("base64.Encode() error = %v", err)
				}
				if len(sigEnc) == 0 {
					t.Fatal("sigEnc is empty")
				}

				tokenSigEnc, err := base64.Encode(token.Signature)
				if err != nil {
					t.Fatalf("base64.Encode() error = %v", err)
				}
				if tokenSigEnc != sigEnc {
					t.Fatalf("tokenSigEnc = %v, want %v", tokenSigEnc, sigEnc)
				}

				if err := token.VerifyRSASignature(crypto.SHA256, rsaKeyPair.public); err != nil {
					t.Fatalf("token.VerifyRSASignature() error = %v", err)
				}

				if err := token.Verify(jwt.WithKey(rsaKeyPair.public)); err != nil {
					t.Fatalf("token.Verify() error = %v", err)
				}
			},
		},
		{
			name:  "JOSE header only", // too short
			input: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err == nil {
					t.Fatal("ParseString() error = nil, want non-nil")
				}
				if token != nil {
					t.Fatalf("token = %v, want nil", token)
				}
			},
		},
		{
			name:  "JOSE header with claims", // no signature
			input: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`,
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err == nil {
					t.Fatal("ParseString() error = nil, want non-nil")
				}
				if token != nil {
					t.Fatalf("token = %v, want nil", token)
				}
			},
		},
		{
			name:  "JOSE header with claims and HMAC SHA256 signature",
			input: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err != nil {
					t.Fatalf("ParseString() error = %v", err)
				}
				if token.Header[header.Algorithm] != jwa.HS256 {
					t.Fatalf("token.Header[header.Algorithm] = %v, want %v", token.Header[header.Algorithm], jwa.HS256)
				}
				if token.Header[header.Type] != jwt.Type {
					t.Fatalf("token.Header[header.Type] = %v, want %v", token.Header[header.Type], jwt.Type)
				}
				if token.Claims[jwt.ExpirationTime] != int64(1300819380) {
					t.Fatalf("token.Claims[jwt.ExpirationTime] = %v, want %v", token.Claims[jwt.ExpirationTime], int64(1300819380))
				}
				if token.Claims[jwt.Issuer] != "joe" {
					t.Fatalf("token.Claims[jwt.Issuer] = %q, want %q", token.Claims[jwt.Issuer], "joe")
				}
				if token.Claims["http://example.com/is_root"] != true {
					t.Fatalf("token.Claims[\"http://example.com/is_root\"] = %v, want %v", token.Claims["http://example.com/is_root"], true)
				}
				if len(token.Signature) == 0 {
					t.Fatal("token.Signature is empty")
				}

				sig, err := token.HMACSignature(crypto.SHA256, testHMACSecretKey)
				if err != nil {
					t.Fatalf("token.HMACSignature() error = %v", err)
				}
				if len(sig) == 0 {
					t.Fatal("sig is empty")
				}
				if !hmac.Equal([]byte(sig), token.Signature) {
					t.Fatalf("HMACSignature() = %x, want %x", sig, token.Signature)
				}

				err = token.VerifyHMACSignature(crypto.SHA256, testHMACSecretKey)
				if err != nil {
					t.Fatalf("token.VerifyHMACSignature() error = %v", err)
				}

				// Token is expired
				err = token.Verify(jwt.WithKey(testHMACSecretKey), jwt.WithAllowedAlgorithms(jwa.HS256))
				if err == nil {
					t.Fatal("token.Verify() error = nil, want non-nil")
				}
			},
		},
		{
			name:  "JOSE header with claims and EdDSA signature",
			input: eddsaToken.String(),
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err != nil {
					t.Fatalf("ParseString() error = %v", err)
				}
				if token.Header[header.Algorithm] != jwa.EdDSA {
					t.Fatalf("token.Header[header.Algorithm] = %v, want %v", token.Header[header.Algorithm], jwa.EdDSA)
				}
				if token.Header[header.Type] != jwt.Type {
					t.Fatalf("token.Header[header.Type] = %v, want %v", token.Header[header.Type], jwt.Type)
				}
				if len(token.Claims) == 0 {
					t.Fatal("token.Claims is empty")
				}
				if len(token.Signature) == 0 {
					t.Fatal("token.Signature is empty")
				}

				sig, err := token.EdDSASignature(eddsaKeyPair.private)
				if err != nil {
					t.Fatalf("token.EdDSASignature() error = %v", err)
				}
				if len(sig) == 0 {
					t.Fatal("sig is empty")
				}
				if len(token.Signature) != len(sig) {
					t.Fatalf("len(token.Signature) = %v, want %v", len(token.Signature), len(sig))
				}
				if !bytes.Equal(token.Signature, sig) {
					t.Fatalf("token.Signature = %x, want %x", token.Signature, sig)
				}

				err = token.VerifyEdDSASignature(eddsaKeyPair.public)
				if err != nil {
					t.Fatalf("token.VerifyEdDSASignature() error = %v", err)
				}

				err = token.Verify(jwt.WithKey(eddsaKeyPair.public), jwt.WithAllowedAlgorithms(jwa.EdDSA))
				if err != nil {
					t.Fatalf("token.Verify() error = %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := jwt.ParseString(test.input)
			test.check(t, token, err)
		})
	}
}

func TestSignJWT(t *testing.T) {
	keyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)

	token := &jwt.Token{
		Header: header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.RS256,
		},
		Claims: jwt.ClaimsSet{
			jwt.Subject: "test",
		},
	}

	sig, err := token.Sign(keyPair.private)
	if err != nil {
		t.Fatalf("token.Sign() error = %v", err)
	}
	if sig == nil {
		t.Fatal("sig = nil, want non-nil")
	}
	if !bytes.Equal(sig, token.Signature) {
		t.Fatalf("sig = %x, want %x", sig, token.Signature)
	}
}

func TestNew(t *testing.T) {
	var (
		rsaKeyPair   = testNewKeyPair(t, keyutil.NewRSAKeyPair)
		ecdsaKeyPair = testNewKeyPair(t, keyutil.NewECDSAKeyPair)
		eddsaKeyPair = testNewKeyPair(t, keyutil.NewEdDSAKeyPair)
		hmacKey      = testHMACSecretKey
	)

	tests := []struct {
		name                    string
		header                  header.Parameters
		claims                  jwt.ClaimsSet
		signingKey              any
		verifyKey               any
		allowedVerifyAlgorithms []jwa.Algorithm
		allowedAudiences        []string
	}{
		{
			name: "RSA SHA256",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			signingKey:              rsaKeyPair.private,
			verifyKey:               rsaKeyPair.public,
			allowedVerifyAlgorithms: jwt.DefaultAllowedAlgorithms(),
		},
		{
			name: "RSA SHA256 with audience as string",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject:  "test",
				jwt.Audience: "test",
			},
			signingKey:              rsaKeyPair.private,
			verifyKey:               rsaKeyPair.public,
			allowedVerifyAlgorithms: jwt.DefaultAllowedAlgorithms(),
			allowedAudiences:        []string{"test"},
		},
		{
			name: "RSA SHA256 with audience as an array",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject:  "test",
				jwt.Audience: []string{"test"},
			},
			signingKey:              rsaKeyPair.private,
			verifyKey:               rsaKeyPair.public,
			allowedVerifyAlgorithms: jwt.DefaultAllowedAlgorithms(),
			allowedAudiences:        []string{"test"},
		},
		{
			name: "RSA PSS SHA256",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.PS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			signingKey:              rsaKeyPair.private,
			verifyKey:               rsaKeyPair.public,
			allowedVerifyAlgorithms: jwt.DefaultAllowedAlgorithms(),
		},
		{
			name: "ECDSA SHA256",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.ES256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			signingKey:              ecdsaKeyPair.private,
			verifyKey:               ecdsaKeyPair.public,
			allowedVerifyAlgorithms: jwt.DefaultAllowedAlgorithms(),
		},
		{
			name: "EdDSA",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.EdDSA,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			signingKey:              eddsaKeyPair.private,
			verifyKey:               eddsaKeyPair.public,
			allowedVerifyAlgorithms: jwt.DefaultAllowedAlgorithms(),
		},
		{
			name: "HMAC SHA256",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.HS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			signingKey:              hmacKey,
			verifyKey:               hmacKey,
			allowedVerifyAlgorithms: []jwa.Algorithm{jwa.HS256},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := testToken(t, test.header, test.claims, test.signingKey)

			verifyOpts := []jwt.VerifyOption{
				jwt.WithAllowedAlgorithms(test.allowedVerifyAlgorithms...),
			}

			if test.verifyKey != nil {
				switch verifyKey := test.verifyKey.(type) {
				case *rsa.PublicKey:
					verifyOpts = append(verifyOpts, jwt.WithKey(verifyKey))
				case *ecdsa.PublicKey:
					verifyOpts = append(verifyOpts, jwt.WithKey(verifyKey))
				case ed25519.PublicKey:
					verifyOpts = append(verifyOpts, jwt.WithKey(verifyKey))
				case []byte:
					verifyOpts = append(verifyOpts, jwt.WithKey(verifyKey))
				default:
					t.Fatalf("potentially unsupported verify key type: %T", verifyKey)
				}
			}

			if len(test.allowedAudiences) > 0 {
				verifyOpts = append(verifyOpts, jwt.WithAllowedAudiences(test.allowedAudiences...))
			}

			err := token.Verify(verifyOpts...)
			if err != nil {
				t.Fatalf("token.Verify() error = %v", err)
			}
		})
	}

}

func TestNewExpired(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)

	tests := []struct {
		name       string
		header     header.Parameters
		claims     jwt.ClaimsSet
		signingKey any
		expired    bool
		expires    bool
	}{
		{
			name: "expired",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.IssuedAt:       time.Now().Unix(),
				jwt.ExpirationTime: time.Now().Add(-time.Hour).Unix(),
			},
			signingKey: rsaKeyPair.private,
			expired:    true,
			expires:    true,
		},
		{
			name: "not expired",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.IssuedAt:       time.Now().Unix(),
				jwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			},
			signingKey: rsaKeyPair.private,
			expired:    false,
			expires:    true,
		},
		{
			name: "not expires",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject:  "test",
				jwt.IssuedAt: time.Now().Unix(),
			},
			signingKey: rsaKeyPair.private,
			expired:    false,
			expires:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := testToken(t, test.header, test.claims, test.signingKey)

			expires, err := token.Expires()
			if err != nil {
				t.Fatalf("token.Expires() error = %v", err)
			}

			if test.expires {
				if !expires {
					t.Fatal("expires = false, want true")
				}
			} else {
				if expires {
					t.Fatal("expires = true, want false")
				}
			}

			expired, err := token.Expired(time.Now)
			if err != nil {
				t.Fatalf("token.Expired() error = %v", err)
			}

			if test.expired {
				if !expired {
					t.Fatal("expired = false, want true")
				}
			} else {
				if expired {
					t.Fatal("expired = true, want false")
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, keyutil.NewRSAKeyPair)

	checkSuccess := func(t *testing.T, token *jwt.Token, err error) {
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if token == nil {
			t.Fatal("token = nil, want non-nil")
		}
	}

	checkFailure := func(t *testing.T, token *jwt.Token, err error) {
		if err == nil {
			t.Fatal("Verify() error = nil, want non-nil")
		}
		if token == nil {
			t.Fatal("token = nil, want non-nil")
		}
	}

	tests := []struct {
		name       string
		header     header.Parameters
		claims     jwt.ClaimsSet
		signingKey any
		verifyKey  any
		check      func(t *testing.T, token *jwt.Token, err error)
	}{
		{
			name: "RSA SHA256",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.IssuedAt:       time.Now().Unix(),
				jwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			},
			signingKey: rsaKeyPair.private,
			verifyKey:  rsaKeyPair.public,
			check:      checkSuccess,
		},
		{
			name: "RSA SHA256 no expiration",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject: "test",
			},
			signingKey: rsaKeyPair.private,
			verifyKey:  rsaKeyPair.public,
			check:      checkSuccess,
		},
		{
			name: "RSA SHA256 expired",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.IssuedAt:       time.Now().Unix(),
				jwt.ExpirationTime: time.Now().Add(-time.Hour).Unix(),
			},
			signingKey: rsaKeyPair.private,
			verifyKey:  rsaKeyPair.public,
			check:      checkFailure,
		},
		{
			name: "RSA SHA256 unable to use yet",
			header: header.Parameters{
				header.Type:      jwt.Type,
				header.Algorithm: jwa.RS256,
			},
			claims: jwt.ClaimsSet{
				jwt.Subject:   "test",
				jwt.IssuedAt:  time.Now().Unix(),
				jwt.NotBefore: time.Now().Add(30 * time.Second).Unix(),
			},
			signingKey: rsaKeyPair.private,
			verifyKey:  rsaKeyPair.public,
			check:      checkFailure,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := testToken(t, test.header, test.claims, test.signingKey)

			verifyOpts := []jwt.VerifyOption{}

			if test.verifyKey != nil {
				switch verifyKey := test.verifyKey.(type) {
				case *rsa.PublicKey:
					verifyOpts = append(verifyOpts, jwt.WithKey(verifyKey))
				case *ecdsa.PublicKey:
					verifyOpts = append(verifyOpts, jwt.WithKey(verifyKey))
				case ed25519.PublicKey:
					verifyOpts = append(verifyOpts, jwt.WithKey(verifyKey))
				case []byte:
					verifyOpts = append(verifyOpts, jwt.WithKey(verifyKey))
				case string:
					verifyOpts = append(verifyOpts, jwt.WithKey(verifyKey))
				default:
					t.Fatalf("unsupported verify key type: %T", verifyKey)
				}
			}

			err := token.Verify(verifyOpts...)

			test.check(t, token, err)
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
		_, err := jwt.ParseString(data)
		if err != nil {
			t.Skip()
		}
	})
}

var parseStringResult *jwt.Token

func BenchmarkParseString(b *testing.B) {
	s := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"

	var err error

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parseStringResult, err = jwt.ParseString(s)
		if err != nil {
			b.Fatalf("jwt.ParseString() error = %v", err)
		}
	}
}
