package dpop_test

import (
	"context"
	"strings"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jws"
)

func TestVerifyStrictClaims(t *testing.T) {
	key := newP256(t)
	public, _ := jwk.PublicValue(key)
	h := jws.Header{header.Type: dpop.Type, header.Algorithm: jwa.ES256, header.JSONWebKey: public}
	req := dpop.Request{Method: "POST", URI: "https://as.example/token"}
	v := dpop.Verifier{Now: clock}
	const good = `"jti":"abc","htm":"POST","htu":"https://as.example/token","iat":1800000000`

	sign := func(payload string) string {
		s, err := jws.New(h, []byte(payload), key)
		if err != nil {
			t.Fatal(err)
		}
		return s.String()
	}
	if _, err := v.Verify(context.Background(), sign("{"+good+"}"), req); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	for name, payload := range map[string]string{
		"duplicate member": `{` + good + `,"htm":"GET"}`,
		"invalid utf-8":    `{` + good + `,"x":"` + "\xff" + `"}`,
		"trailing data":    `{` + good + `} {}`,
	} {
		if _, err := v.Verify(context.Background(), sign(payload), req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A padded or otherwise non-canonical spelling of a valid proof.
	proof := sign("{" + good + "}")
	parts := strings.Split(proof, ".")
	sig, _ := base64url.Decode(parts[2])
	for name, p := range map[string]string{
		"padded":     proof + "=",
		"empty sig":  parts[0] + "." + parts[1] + ".",
		"four parts": proof + ".x",
		"std base64": parts[0] + "." + parts[1] + "." + strings.NewReplacer("-", "+", "_", "/").Replace(base64url.Encode(sig)) + "!",
	} {
		if _, err := v.Verify(context.Background(), p, req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzTargetURI(f *testing.F) {
	for _, s := range []string{
		"https://Example.com:443/a/../b?q=1#f", "http://[::1]:80/%7e%2f", "https://u:p@h/", "ftp://h/",
		"https://h", "/relative", "https://h/%zz", "", "https://h/a/./b/../../..//",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := dpop.TargetURI(raw)
		if err != nil {
			return
		}
		again, err := dpop.TargetURI(got)
		if err != nil || again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q, %v", raw, got, again, err)
		}
		if strings.ContainsAny(got, "?#") {
			t.Fatalf("query or fragment kept: %q", got)
		}
	})
}

func FuzzVerify(f *testing.F) {
	key := newP256(f)
	s := newSigner(f, key)
	proof, err := s.Proof("POST", "https://as.example/token", dpop.ProofOptions{AccessToken: "t", Nonce: "n"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(proof)
	f.Add("")
	f.Add("a.b.c")
	v := dpop.Verifier{Now: clock}
	req := dpop.Request{Method: "POST", URI: "https://as.example/token"}
	f.Fuzz(func(t *testing.T, proof string) {
		p, err := v.Verify(context.Background(), proof, req)
		if err == nil && p == nil {
			t.Fatal("nil proof without error")
		}
	})
}

func TestTargetURIRejectsZone(t *testing.T) {
	if got, err := dpop.TargetURI("http://[fe80::1%25eth0]/"); err == nil {
		t.Fatalf("TargetURI accepted a zoned host: %q", got)
	}
}
