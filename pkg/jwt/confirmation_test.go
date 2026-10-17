package jwt_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/picatz/jose/pkg/jwk/thumbprint"
	"github.com/picatz/jose/pkg/jwt"
)

func TestConfirmationFor(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	want, err := thumbprint.FromPublicKey(ec.Public())
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]any{"public": ec.Public(), "private": ec, "signer": priv, "ed public": pub} {
		got, err := jwt.ConfirmationFor(key)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := got["jkt"].(string); !ok || len(got) != 1 {
			t.Errorf("%s: %v", name, got)
		}
		if name != "ed public" && name != "signer" && got["jkt"] != want {
			t.Errorf("%s: jkt = %v, want %v", name, got["jkt"], want)
		}
	}
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	for _, bad := range []any{x, x.PublicKey(), "key", nil} {
		if _, err := jwt.ConfirmationFor(bad); err == nil {
			t.Errorf("ConfirmationFor(%T) succeeded", bad)
		}
	}
}

func TestConfirmedThumbprint(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.ClaimsSet
		want   string
		ok     bool
	}{
		{"ok", jwt.ClaimsSet{"cnf": map[string]any{"jkt": "abc"}}, "abc", true},
		{"missing", jwt.ClaimsSet{}, "", false},
		{"not object", jwt.ClaimsSet{"cnf": "jkt"}, "", false},
		{"empty", jwt.ClaimsSet{"cnf": map[string]any{"jkt": ""}}, "", false},
		{"not string", jwt.ClaimsSet{"cnf": map[string]any{"jkt": 1}}, "", false},
		{"other member", jwt.ClaimsSet{"cnf": map[string]any{"kid": "x"}}, "", false},
		{"extra member", jwt.ClaimsSet{"cnf": map[string]any{"jkt": "abc", "kid": "x"}}, "", false},
	}
	for _, tt := range tests {
		got, ok := tt.claims.ConfirmedThumbprint()
		if got != tt.want || ok != tt.ok {
			t.Errorf("%s: got %q, %v", tt.name, got, ok)
		}
	}
}
