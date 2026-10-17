package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
)

// keyPair is a simple struct that holds a public and private key
// of any type.
type keyPair[P, S any] struct {
	public  P // Public key.
	private S // Private (secret) key.
}

// keySource is a function that returns a public and private key pair
// of any type. This works with the testNew*KeyPair helpers below.
type keySource[P, S any] func() (P, S, error)

func testNewRSAKeyPair() (*rsa.PublicKey, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return &key.PublicKey, key, nil
}

func testNewECDSAKeyPair() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &key.PublicKey, key, nil
}

func testNewEdDSAKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

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

	// An unsigned token has no signature segment.
	if strings.Count(token.String(), ".") != 1 {
		t.Fatalf("strings.Count(token.String(), \".\") = %v, want %v", strings.Count(token.String(), "."), 1)
	}
	if len(token.Signature) != 0 {
		t.Fatalf("token.Signature = %v, want empty", token.Signature)
	}
	if !strings.HasPrefix(token.String(), "eyJ") {
		t.Fatalf("token.String() = %q, want prefix %q", token.String(), "eyJ")
	}

	signed, err := jwt.New(token.Header, token.Claims, testHMACSecretKey)
	if err != nil {
		t.Fatalf("jwt.New() error = %v", err)
	}

	if strings.Count(signed.String(), ".") != 2 {
		t.Fatalf("strings.Count(signed.String(), \".\") = %v, want %v", strings.Count(signed.String(), "."), 2)
	}
	if len(signed.Signature) == 0 {
		t.Fatal("signed.Signature is empty")
	}
	if !strings.HasPrefix(signed.String(), "eyJ") {
		t.Fatalf("signed.String() = %q, want prefix %q", signed.String(), "eyJ")
	}
}

// sigOnlyVerifier returns a [jwt.Verifier] for key that checks the JOSE
// layer and signature but skips the claim policy a test does not exercise:
// issuer, audience and the "exp" requirement. HMAC algorithms must be
// listed in algs, as the Verifier never accepts them by default.
func sigOnlyVerifier(key any, algs ...jwa.Algorithm) *jwt.Verifier {
	if secret, ok := key.(string); ok {
		key = []byte(secret)
	}
	v := &jwt.Verifier{
		Keys:          jwt.Keys{{Public: key}},
		AnyIssuer:     true,
		AnyAudience:   true,
		AllowNoExpiry: true,
	}
	if len(algs) > 0 {
		v.Algorithms = algs
	}
	return v
}

func verifyToken(v *jwt.Verifier, token string) error {
	_, err := v.Verify(context.Background(), token)
	return err
}

func TestParseAndVerify(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)
	ecdsaKeyPair := testNewKeyPair(t, testNewECDSAKeyPair)
	eddsaKeyPair := testNewKeyPair(t, testNewEdDSAKeyPair)

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
					t.Fatal("Parse() error = nil, want non-nil")
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
					t.Fatal("Parse() error = nil, want non-nil")
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
					t.Fatalf("Parse() error = %v", err)
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

				if err := verifyToken(sigOnlyVerifier(ecdsaKeyPair.public), ecdsaToken.String()); err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
			},
		},
		{
			name:  "JOSE header with claims and ECDSA SHA256 signature, but only RS256 is enabled",
			input: ecdsaToken.String(),
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
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

				if err := verifyToken(sigOnlyVerifier(ecdsaKeyPair.public, jwa.RS256), ecdsaToken.String()); !errors.Is(err, jwt.ErrFormat) {
					t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrFormat)
				}
			},
		},
		{
			name:  "JOSE header with claims and RSA SHA256 signature",
			input: rsaToken.String(),
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
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

				if err := verifyToken(sigOnlyVerifier(rsaKeyPair.public), rsaToken.String()); err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
			},
		},
		{
			name:  "JOSE header only", // too short
			input: `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`,
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err == nil {
					t.Fatal("Parse() error = nil, want non-nil")
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
					t.Fatal("Parse() error = nil, want non-nil")
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
					t.Fatalf("Parse() error = %v", err)
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

				// The RFC 7515 Appendix A.1 token expired in 2011.
				hmacVerifier := sigOnlyVerifier(testHMACSecretKey, jwa.HS256)
				hmacVerifier.Now = func() time.Time { return time.Unix(1300819380, 0).Add(time.Hour) }
				hmacVerifier.Leeway = time.Second
				if err := verifyToken(hmacVerifier, token.String()); !errors.Is(err, jwt.ErrExpired) {
					t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrExpired)
				}

				// Before expiry it verifies, so the refusal above is about time.
				hmacVerifier.Now = func() time.Time { return time.Unix(1300819380, 0).Add(-time.Hour) }
				if err := verifyToken(hmacVerifier, token.String()); err != nil {
					t.Fatalf("Verify() before expiry error = %v", err)
				}

				// HMAC is never accepted unless the caller lists it.
				if err := verifyToken(sigOnlyVerifier(testHMACSecretKey), token.String()); !errors.Is(err, jwt.ErrFormat) {
					t.Fatalf("Verify() with default algorithms error = %v, want %v", err, jwt.ErrFormat)
				}
			},
		},
		{
			name:  "JOSE header with claims and EdDSA signature",
			input: eddsaToken.String(),
			check: func(t *testing.T, token *jwt.Token, err error) {
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
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

				if err := verifyToken(sigOnlyVerifier(eddsaKeyPair.public, jwa.EdDSA), eddsaToken.String()); err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := jwt.Parse(test.input)
			test.check(t, token, err)
		})
	}
}

func TestNew(t *testing.T) {
	var (
		rsaKeyPair   = testNewKeyPair(t, testNewRSAKeyPair)
		ecdsaKeyPair = testNewKeyPair(t, testNewECDSAKeyPair)
		eddsaKeyPair = testNewKeyPair(t, testNewEdDSAKeyPair)
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
			allowedVerifyAlgorithms: jwt.DefaultAlgorithms,
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
			allowedVerifyAlgorithms: jwt.DefaultAlgorithms,
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
			allowedVerifyAlgorithms: jwt.DefaultAlgorithms,
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
			allowedVerifyAlgorithms: jwt.DefaultAlgorithms,
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
			allowedVerifyAlgorithms: jwt.DefaultAlgorithms,
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
			allowedVerifyAlgorithms: jwt.DefaultAlgorithms,
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

			verifier := sigOnlyVerifier(test.verifyKey, test.allowedVerifyAlgorithms...)
			if len(test.allowedAudiences) > 0 {
				verifier.AnyAudience = false
				verifier.Audience = test.allowedAudiences[0]
			}

			if err := verifyToken(verifier, token.String()); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			// A verifier for a different audience refuses the same token.
			if len(test.allowedAudiences) > 0 {
				verifier.Audience = "other"
				if err := verifyToken(verifier, token.String()); !errors.Is(err, jwt.ErrClaims) {
					t.Fatalf("Verify() for another audience error = %v, want %v", err, jwt.ErrClaims)
				}
			}
		})
	}

}

func TestNewExpired(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)

	tests := []struct {
		name   string
		claims jwt.ClaimsSet
		// verifyErr is the sentinel Verify must wrap, or nil to accept.
		verifyErr error
		// allowNoExpiry lets the verifier accept a token without "exp".
		allowNoExpiry bool
	}{
		{
			name: "expired",
			claims: jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.IssuedAt:       time.Now().Unix(),
				jwt.ExpirationTime: time.Now().Add(-time.Hour).Unix(),
			},
			verifyErr: jwt.ErrExpired,
		},
		{
			name: "not expired",
			claims: jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.IssuedAt:       time.Now().Unix(),
				jwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			},
		},
		{
			name: "does not expire, refused by default",
			claims: jwt.ClaimsSet{
				jwt.Subject:  "test",
				jwt.IssuedAt: time.Now().Unix(),
			},
			verifyErr: jwt.ErrClaims,
		},
		{
			name: "does not expire, accepted when the verifier opts in",
			claims: jwt.ClaimsSet{
				jwt.Subject:  "test",
				jwt.IssuedAt: time.Now().Unix(),
			},
			allowNoExpiry: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := testToken(t,
				header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
				test.claims, rsaKeyPair.private)

			verifier := sigOnlyVerifier(rsaKeyPair.public)
			verifier.AllowNoExpiry = test.allowNoExpiry

			err := verifyToken(verifier, token.String())
			if test.verifyErr == nil {
				if err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.verifyErr) || !errors.Is(err, jwt.ErrInvalidToken) {
				t.Fatalf("Verify() error = %v, want %v and %v", err, test.verifyErr, jwt.ErrInvalidToken)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	rsaKeyPair := testNewKeyPair(t, testNewRSAKeyPair)

	tests := []struct {
		name      string
		claims    jwt.ClaimsSet
		verifyErr error
	}{
		{
			name: "RSA SHA256",
			claims: jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.IssuedAt:       time.Now().Unix(),
				jwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			},
		},
		{
			name: "RSA SHA256 expired",
			claims: jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.IssuedAt:       time.Now().Unix(),
				jwt.ExpirationTime: time.Now().Add(-time.Hour).Unix(),
			},
			verifyErr: jwt.ErrExpired,
		},
		{
			name: "RSA SHA256 unable to use yet",
			claims: jwt.ClaimsSet{
				jwt.Subject:        "test",
				jwt.IssuedAt:       time.Now().Unix(),
				jwt.NotBefore:      time.Now().Add(time.Hour).Unix(),
				jwt.ExpirationTime: time.Now().Add(2 * time.Hour).Unix(),
			},
			verifyErr: jwt.ErrNotYetValid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := testToken(t,
				header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.RS256},
				test.claims, rsaKeyPair.private)

			parsed, err := sigOnlyVerifier(rsaKeyPair.public).Verify(context.Background(), token.String())
			if test.verifyErr == nil {
				if err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
				if parsed == nil {
					t.Fatal("token = nil, want non-nil")
				}
				return
			}
			if !errors.Is(err, test.verifyErr) {
				t.Fatalf("Verify() error = %v, want %v", err, test.verifyErr)
			}
			if parsed != nil {
				t.Fatalf("token = %v, want nil on refusal", parsed)
			}
		})
	}
}

// go test -fuzz FuzzParse
func FuzzParse(f *testing.F) {
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.")
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0")
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.eyJzdWIiOiJ0ZXN0In0")
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.z.z")
	f.Add("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ")
	f.Add("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ.")
	f.Add("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.U3ChCsJwStNnEdE_wgkh5elQHIKPYfdi4BZoy8CWQNAaFymND_-6fwghDC4bQRrcotXjD6WZDaSrJ_W7uVoBBQ")
	f.Add("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg")

	f.Fuzz(func(t *testing.T, data string) {
		_, err := jwt.Parse(data)
		if err != nil {
			t.Skip()
		}
	})
}

var parseResult *jwt.Token

func BenchmarkParse(b *testing.B) {
	s := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"

	var err error

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parseResult, err = jwt.Parse(s)
		if err != nil {
			b.Fatalf("jwt.Parse() error = %v", err)
		}
	}
}
