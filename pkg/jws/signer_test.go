package jws_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jws"
)

// opaqueSigner hides the concrete key type, the way a PIV, TPM or Secure
// Enclave signer would, so only the crypto.Signer interface is reachable.
type opaqueSigner struct{ signer crypto.Signer }

func (s opaqueSigner) Public() crypto.PublicKey { return s.signer.Public() }
func (s opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signer.Sign(r, digest, opts)
}

func mustECDSA(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSignWithOpaqueSigner(t *testing.T) {
	rsaKey := mustRSA(t, 2048)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		alg    jwa.Algorithm
		signer crypto.Signer
	}{
		{jwa.ES256, mustECDSA(t, elliptic.P256())},
		{jwa.ES384, mustECDSA(t, elliptic.P384())},
		{jwa.ES512, mustECDSA(t, elliptic.P521())},
		{jwa.RS256, rsaKey},
		{jwa.PS256, rsaKey},
		{jwa.PS512, rsaKey},
		{jwa.EdDSA, edKey},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			payload := []byte(`{"hello":"hardware"}`)
			signed, err := jws.New(jws.Header{header.Algorithm: tc.alg}, payload, opaqueSigner{tc.signer})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			parsed, err := jws.Parse(signed.String())
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if err := parsed.Verify(tc.signer.Public()); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if alg, err := jwa.ForKey(tc.signer); err != nil {
				t.Fatalf("ForKey: %v", err)
			} else if tc.alg == jwa.ES256 || tc.alg == jwa.ES384 || tc.alg == jwa.ES512 || tc.alg == jwa.EdDSA {
				if alg != tc.alg {
					t.Fatalf("ForKey = %s, want %s", alg, tc.alg)
				}
			} else if alg != jwa.PS256 {
				t.Fatalf("ForKey(RSA) = %s, want PS256", alg)
			}
		})
	}
}

// RFC 7518 §3.4: each ECDSA algorithm names exactly one curve.
func TestECDSACurveMustMatchAlgorithm(t *testing.T) {
	p384 := mustECDSA(t, elliptic.P384())
	if _, err := jws.New(jws.Header{header.Algorithm: jwa.ES256}, []byte("x"), p384); err == nil {
		t.Fatal("signed ES256 with a P-384 key")
	}

	p256 := mustECDSA(t, elliptic.P256())
	signed, err := jws.New(jws.Header{header.Algorithm: jwa.ES256}, []byte("x"), p256)
	if err != nil {
		t.Fatal(err)
	}
	// Relabel the token as ES384 and offer a P-384 key: the curve check, not
	// only the signature length, must reject it.
	parsed, err := jws.Parse(signed.String())
	if err != nil {
		t.Fatal(err)
	}
	parsed.Header[header.Algorithm] = jwa.ES384
	if err := parsed.Verify(&p384.PublicKey); err == nil {
		t.Fatal("verified ES384 with a mismatched signature")
	}
}

// RFC 7518 §3.5: the PSS salt is as long as the hash output.
func TestPSSSaltLengthEqualsHash(t *testing.T) {
	key := mustRSA(t, 2048)
	signed, err := jws.New(jws.Header{header.Algorithm: jwa.PS256}, []byte("salted"), key)
	if err != nil {
		t.Fatal(err)
	}
	input := signed.String()[:strings.LastIndexByte(signed.String(), '.')]
	sum := sha256.Sum256([]byte(input))
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, sum[:], signed.Signature, &rsa.PSSOptions{SaltLength: sha256.Size}); err != nil {
		t.Fatalf("salt is not hash-length: %v", err)
	}

	// A maximum-length salt is a different PSS profile and must not verify.
	long, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	if err != nil {
		t.Fatal(err)
	}
	forged, err := jws.Parse(input + "." + mustEncode(t, long))
	if err != nil {
		t.Fatal(err)
	}
	if err := forged.Verify(&key.PublicKey); err == nil {
		t.Fatal("verified a PSS signature with a maximum-length salt")
	}
}

// A parsed JWS must be verified over the bytes it arrived with, not over a
// re-serialization of its header (RFC 7515 §5.2).
func TestVerifyUsesReceivedEncoding(t *testing.T) {
	key := mustECDSA(t, elliptic.P256())
	protected := mustEncode(t, []byte(`{"typ":"JWT", "alg":"ES256"}`))
	payload := mustEncode(t, []byte(`{"sub":"order matters"}`))
	input := protected + "." + payload

	signer, err := jws.New(jws.Header{header.Algorithm: jwa.ES256}, []byte("unused"), key)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.SignECDSA(crypto.SHA256, key, input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jws.Parse(input + "." + mustEncode(t, signature))
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(&key.PublicKey); err != nil {
		t.Fatalf("Verify of a non-canonical header failed: %v", err)
	}

	// Re-signing covers the current header, not the received encoding.
	parsed.Header["kid"] = "rotated"
	if _, err := parsed.Sign(key); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(parsed.String(), protected+".") {
		t.Fatal("re-signed token kept the old protected header")
	}
	reparsed, err := jws.Parse(parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := reparsed.Verify(&key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if reparsed.Header["kid"] != "rotated" {
		t.Fatalf("kid = %v", reparsed.Header["kid"])
	}
}

func TestSignRejectsWrongKeyType(t *testing.T) {
	ec := mustECDSA(t, elliptic.P256())
	for _, alg := range []jwa.Algorithm{jwa.RS256, jwa.PS256, jwa.EdDSA} {
		if _, err := jws.New(jws.Header{header.Algorithm: alg}, []byte("x"), ec); err == nil {
			t.Errorf("%s signed with an ECDSA key", alg)
		}
	}
	if _, err := jws.New(jws.Header{header.Algorithm: jwa.RS256}, []byte("x"), mustRSA(t, 1024)); err == nil {
		t.Error("RS256 signed with a 1024-bit key")
	}
}

type cookbookSignature struct {
	Input struct {
		Payload string    `json:"payload"`
		Key     jwk.Value `json:"key"`
		Alg     string    `json:"alg"`
	} `json:"input"`
	Output struct {
		Compact string `json:"compact"`
	} `json:"output"`
}

// RFC 7520 §4 vectors from the JOSE Cookbook.
func TestCookbookSignatures(t *testing.T) {
	files, err := filepath.Glob("testdata/cookbook/4_*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no cookbook vectors: %v", err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var vector cookbookSignature
			if err := json.Unmarshal(raw, &vector); err != nil {
				t.Fatal(err)
			}
			var verifyKey any
			if vector.Input.Key[jwk.KeyType] == jwk.KeyTypeOct {
				verifyKey, err = jwk.HMACSecretKey(vector.Input.Key)
			} else {
				verifyKey, err = jwk.PublicKey(vector.Input.Key)
			}
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := jws.Parse(vector.Output.Compact)
			if err != nil {
				t.Fatal(err)
			}
			if err := parsed.Verify(verifyKey); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if string(parsed.Payload) != vector.Input.Payload {
				t.Fatal("payload mismatch")
			}

			// Sign the same payload with the cookbook's private key.
			if vector.Input.Key[jwk.KeyType] == jwk.KeyTypeOct {
				return
			}
			private, err := jwk.PrivateKey(vector.Input.Key)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := jws.New(jws.Header{header.Algorithm: vector.Input.Alg}, []byte(vector.Input.Payload), opaqueSigner{private.(crypto.Signer)})
			if err != nil {
				t.Fatal(err)
			}
			again, err := jws.Parse(signed.String())
			if err != nil {
				t.Fatal(err)
			}
			if err := again.Verify(verifyKey); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func mustEncode(t *testing.T, b []byte) string {
	t.Helper()
	s, err := base64.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
