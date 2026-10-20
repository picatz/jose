package jwa_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/picatz/jose/pkg/jwa"
)

func TestAlgorithmClassification(t *testing.T) {
	tests := []struct {
		alg                 jwa.Algorithm
		symmetric           bool
		keyManagement       bool
		asymmetricSignature bool
	}{
		{jwa.HS256, true, false, false},
		{jwa.HS384, true, false, false},
		{jwa.HS512, true, false, false},
		{jwa.RS256, false, false, true},
		{jwa.RS384, false, false, true},
		{jwa.RS512, false, false, true},
		{jwa.PS256, false, false, true},
		{jwa.PS384, false, false, true},
		{jwa.PS512, false, false, true},
		{jwa.ES256, false, false, true},
		{jwa.ES384, false, false, true},
		{jwa.ES512, false, false, true},
		{jwa.EdDSA, false, false, true},
		{jwa.None, false, false, false},
		{jwa.ES256K, false, false, false},
		{jwa.RSAOAEP, false, true, false},
		{jwa.RSAOAEP256, false, true, false},
		{jwa.A128KW, true, true, false},
		{jwa.A192KW, true, true, false},
		{jwa.A256KW, true, true, false},
		{jwa.Direct, true, true, false},
		{jwa.ECDHES, false, true, false},
		{jwa.ECDHESA128KW, false, true, false},
		{jwa.ECDHESA192KW, false, true, false},
		{jwa.ECDHESA256KW, false, true, false},
		{"", false, false, false},
		{"hs256", false, false, false},
		{"RSA1_5", false, false, false},
		{"unknown", false, false, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			if got := tt.alg.IsSymmetric(); got != tt.symmetric {
				t.Errorf("IsSymmetric() = %v, want %v", got, tt.symmetric)
			}
			if got := tt.alg.IsKeyManagement(); got != tt.keyManagement {
				t.Errorf("IsKeyManagement() = %v, want %v", got, tt.keyManagement)
			}
			if got := jwa.IsAsymmetricSignature(tt.alg); got != tt.asymmetricSignature {
				t.Errorf("IsAsymmetricSignature() = %v, want %v", got, tt.asymmetricSignature)
			}
		})
	}
}

func TestContentEncryption(t *testing.T) {
	tests := []struct {
		enc  jwa.ContentEncryption
		want bool
	}{
		{jwa.A128CBCHS256, true},
		{jwa.A192CBCHS384, true},
		{jwa.A256CBCHS512, true},
		{jwa.A128GCM, true},
		{jwa.A192GCM, true},
		{jwa.A256GCM, true},
		{"", false},
		{"a128gcm", false},
		{"A128CBC", false},
		{"RSA-OAEP", false},
	}
	for _, tt := range tests {
		t.Run(string(tt.enc), func(t *testing.T) {
			if got := tt.enc.IsContentEncryption(); got != tt.want {
				t.Errorf("IsContentEncryption() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestForKey(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSmall, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)

	tests := []struct {
		name    string
		key     any
		want    jwa.Algorithm
		wantErr error
	}{
		{"P-256 private", p256, jwa.ES256, nil},
		{"P-256 public", &p256.PublicKey, jwa.ES256, nil},
		{"P-384 private", p384, jwa.ES384, nil},
		{"P-521 public", &p521.PublicKey, jwa.ES512, nil},
		{"P-224", p224, "", jwa.ErrUnknownAlgorithm},
		{"Ed25519 private", edPriv, jwa.EdDSA, nil},
		{"Ed25519 public", edPub, jwa.EdDSA, nil},
		{"RSA 2048 private", rsa2048, jwa.PS256, nil},
		{"RSA 2048 public", &rsa2048.PublicKey, jwa.PS256, nil},
		{"RSA 1024", rsaSmall, "", jwa.ErrAlgorithmNotAllowed},
		{"HMAC secret", []byte("secret"), "", jwa.ErrUnknownAlgorithm},
		{"nil", nil, "", jwa.ErrUnknownAlgorithm},
		{"nil RSA private", (*rsa.PrivateKey)(nil), "", jwa.ErrUnknownAlgorithm},
		{"nil RSA public", (*rsa.PublicKey)(nil), "", jwa.ErrUnknownAlgorithm},
		{"nil ECDSA private", (*ecdsa.PrivateKey)(nil), "", jwa.ErrUnknownAlgorithm},
		{"nil ECDSA public", (*ecdsa.PublicKey)(nil), "", jwa.ErrUnknownAlgorithm},
		{"string", "secret", "", jwa.ErrUnknownAlgorithm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jwa.ForKey(tt.key)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ForKey() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ForKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
