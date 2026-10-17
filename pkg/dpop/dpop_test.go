package dpop_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jws"
)

// opaqueSigner exposes only crypto.Signer, like a hardware key.
type opaqueSigner struct{ crypto.Signer }

func newP256(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

var fixedNow = time.Unix(1_800_000_000, 0)

func clock() time.Time { return fixedNow }

func newSigner(t testing.TB, key crypto.Signer, opts ...dpop.SignerOption) *dpop.Signer {
	t.Helper()
	s, err := dpop.NewSigner(key, append([]dpop.SignerOption{dpop.WithClock(clock)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// RFC 9449 §4.1, Figure 3 (non-normative example proof) and §6.1.
func TestRFCExampleProof(t *testing.T) {
	const proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
	v := dpop.Verifier{Now: func() time.Time { return time.Unix(1562262616, 0) }}
	p, err := v.Verify(context.Background(), proof, dpop.Request{
		Method:     http.MethodPost,
		URI:        "https://server.example.com/token",
		Thumbprint: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.JTI != "-BwC3ESc6acc2lTc" {
		t.Fatalf("jti = %q", p.JTI)
	}
}

func TestSignAndVerify(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, tc := range map[string]struct {
		key  crypto.Signer
		opts []dpop.SignerOption
		alg  jwa.Algorithm
	}{
		"ES256":       {key: newP256(t), alg: jwa.ES256},
		"ES384":       {key: p384, alg: jwa.ES384},
		"EdDSA":       {key: edKey, alg: jwa.EdDSA},
		"PS256":       {key: rsaKey, alg: jwa.PS256},
		"RS256":       {key: rsaKey, opts: []dpop.SignerOption{dpop.WithAlgorithm(jwa.RS256)}, alg: jwa.RS256},
		"opaque P256": {key: opaqueSigner{newP256(t)}, alg: jwa.ES256},
	} {
		t.Run(name, func(t *testing.T) {
			signer := newSigner(t, tc.key, tc.opts...)
			if signer.Algorithm() != tc.alg {
				t.Fatalf("alg = %s, want %s", signer.Algorithm(), tc.alg)
			}
			proof, err := signer.Proof(http.MethodGet, "https://API.example.com:443/v1/items?page=2#top", dpop.ProofOptions{
				AccessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
				Nonce:       "eyJ7S_zG.eyJH0-Z.HX4w-7v",
			})
			if err != nil {
				t.Fatal(err)
			}
			v := dpop.Verifier{Now: clock, Replay: dpop.NewMemoryReplayCache(16, clock)}
			req := dpop.Request{
				Method:      http.MethodGet,
				URI:         "https://api.example.com/v1/items",
				AccessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
				Thumbprint:  signer.Thumbprint(),
				Nonce:       "eyJ7S_zG.eyJH0-Z.HX4w-7v",
			}
			p, err := v.Verify(context.Background(), proof, req)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if p.URI != "https://api.example.com/v1/items" {
				t.Fatalf("htu = %q", p.URI)
			}
			if p.Thumbprint != signer.Thumbprint() || p.Algorithm != tc.alg {
				t.Fatalf("proof = %+v", p)
			}
			if !p.IssuedAt.Equal(fixedNow) {
				t.Fatalf("iat = %v", p.IssuedAt)
			}
			if _, err := v.Verify(context.Background(), proof, req); !errors.Is(err, dpop.ErrReplay) {
				t.Fatalf("second use: err = %v, want ErrReplay", err)
			}
		})
	}
}

func TestNewSignerRejectsUnusableKeys(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := dpop.NewSigner(small); err == nil {
		t.Error("accepted a 1024-bit RSA key")
	}
	if _, err := dpop.NewSigner(nil); err == nil {
		t.Error("accepted a nil key")
	}
	if _, err := dpop.NewSigner(newP256(t), dpop.WithAlgorithm(jwa.HS256)); err == nil {
		t.Error("accepted HS256")
	}
	if _, err := dpop.NewSigner(newP256(t), dpop.WithAlgorithm(jwa.None)); err == nil {
		t.Error("accepted none")
	}
}

// craft signs arbitrary header and claims with key, for negative tests.
func craft(t *testing.T, key crypto.Signer, h jws.Header, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jws.New(h, payload, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed.String()
}

func TestVerifyRejects(t *testing.T) {
	key := newP256(t)
	public, _ := jwk.PublicValue(key)
	private := jwk.Value{}
	for k, v := range public {
		private[k] = v
	}
	d := make([]byte, 32)
	key.D.FillBytes(d)
	private[jwk.D] = base64url.Encode(d)

	goodHeader := func() jws.Header {
		return jws.Header{header.Type: dpop.Type, header.Algorithm: jwa.ES256, header.JSONWebKey: public}
	}
	goodClaims := func() map[string]any {
		return map[string]any{"jti": "abc", "htm": "POST", "htu": "https://as.example/token", "iat": fixedNow.Unix()}
	}
	req := dpop.Request{Method: "POST", URI: "https://as.example/token"}
	v := dpop.Verifier{Now: clock}

	cases := map[string]struct {
		proof string
		req   dpop.Request
		want  error
	}{}
	add := func(name string, mutate func(h jws.Header, c map[string]any), r dpop.Request, want error) {
		h, c := goodHeader(), goodClaims()
		mutate(h, c)
		cases[name] = struct {
			proof string
			req   dpop.Request
			want  error
		}{craft(t, key, h, c), r, want}
	}
	add("typ JWT", func(h jws.Header, _ map[string]any) { h[header.Type] = "JWT" }, req, dpop.ErrInvalidProof)
	add("no typ", func(h jws.Header, _ map[string]any) { delete(h, header.Type) }, req, dpop.ErrInvalidProof)
	add("no jwk", func(h jws.Header, _ map[string]any) { delete(h, header.JSONWebKey) }, req, dpop.ErrInvalidProof)
	add("private jwk", func(h jws.Header, _ map[string]any) { h[header.JSONWebKey] = private }, req, dpop.ErrInvalidProof)
	add("no jti", func(_ jws.Header, c map[string]any) { delete(c, "jti") }, req, dpop.ErrInvalidProof)
	add("no htm", func(_ jws.Header, c map[string]any) { delete(c, "htm") }, req, dpop.ErrInvalidProof)
	add("no iat", func(_ jws.Header, c map[string]any) { delete(c, "iat") }, req, dpop.ErrInvalidProof)
	add("string iat", func(_ jws.Header, c map[string]any) { c["iat"] = "1800000000" }, req, dpop.ErrInvalidProof)
	add("wrong method", func(_ jws.Header, c map[string]any) { c["htm"] = "GET" }, req, dpop.ErrInvalidProof)
	add("lowercase method", func(_ jws.Header, c map[string]any) { c["htm"] = "post" }, req, dpop.ErrInvalidProof)
	add("wrong uri", func(_ jws.Header, c map[string]any) { c["htu"] = "https://as.example/other" }, req, dpop.ErrInvalidProof)
	add("wrong host", func(_ jws.Header, c map[string]any) { c["htu"] = "https://evil.example/token" }, req, dpop.ErrInvalidProof)
	add("http downgrade", func(_ jws.Header, c map[string]any) { c["htu"] = "http://as.example/token" }, req, dpop.ErrInvalidProof)
	add("too old", func(_ jws.Header, c map[string]any) { c["iat"] = fixedNow.Add(-6 * time.Minute).Unix() }, req, dpop.ErrInvalidProof)
	add("future", func(_ jws.Header, c map[string]any) { c["iat"] = fixedNow.Add(time.Minute).Unix() }, req, dpop.ErrInvalidProof)
	add("missing nonce", func(jws.Header, map[string]any) {}, dpop.Request{Method: "POST", URI: req.URI, Nonce: "n-1"}, dpop.ErrUseNonce)
	add("stale nonce", func(_ jws.Header, c map[string]any) { c["nonce"] = "n-0" }, dpop.Request{Method: "POST", URI: req.URI, Nonce: "n-1"}, dpop.ErrUseNonce)
	add("missing ath", func(jws.Header, map[string]any) {}, dpop.Request{Method: "POST", URI: req.URI, AccessToken: "tok"}, dpop.ErrInvalidProof)
	add("wrong ath", func(_ jws.Header, c map[string]any) { c["ath"] = dpop.AccessTokenHash("other") }, dpop.Request{Method: "POST", URI: req.URI, AccessToken: "tok"}, dpop.ErrInvalidProof)
	add("wrong key binding", func(jws.Header, map[string]any) {}, dpop.Request{Method: "POST", URI: req.URI, Thumbprint: "not-the-key"}, dpop.ErrBinding)

	// Signed by a different key than the embedded jwk.
	other := newP256(t)
	cases["key substitution"] = struct {
		proof string
		req   dpop.Request
		want  error
	}{craft(t, other, goodHeader(), goodClaims()), req, dpop.ErrInvalidProof}

	// HMAC and "none" are never acceptable, even if listed.
	secret := []byte(strings.Repeat("k", 32))
	hs, err := jws.New(jws.Header{header.Type: dpop.Type, header.Algorithm: jwa.HS256, header.JSONWebKey: public}, mustJSON(t, goodClaims()), secret)
	if err != nil {
		t.Fatal(err)
	}
	cases["HS256"] = struct {
		proof string
		req   dpop.Request
		want  error
	}{hs.String(), req, dpop.ErrInvalidProof}
	none := mustEncode(t, mustJSON(t, map[string]any{"typ": dpop.Type, "alg": "none", "jwk": public})) + "." + mustEncode(t, mustJSON(t, goodClaims())) + "."
	cases["none"] = struct {
		proof string
		req   dpop.Request
		want  error
	}{none, req, dpop.ErrInvalidProof}
	cases["oversized"] = struct {
		proof string
		req   dpop.Request
		want  error
	}{strings.Repeat("a", dpop.DefaultMaxSize+1), req, dpop.ErrInvalidProof}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			verifier := v
			if name == "HS256" || name == "none" {
				verifier.Algorithms = []jwa.Algorithm{jwa.HS256, jwa.None, jwa.ES256}
			}
			_, err := verifier.Verify(context.Background(), tc.proof, tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// The baseline passes, so each case above fails for its own reason.
	if _, err := v.Verify(context.Background(), craft(t, key, goodHeader(), goodClaims()), req); err != nil {
		t.Fatalf("baseline: %v", err)
	}
}

// A failing proof must not consume its jti, or an attacker who sees a
// proof could burn it by replaying it with a mismatched request first.
func TestRejectedProofDoesNotConsumeJTI(t *testing.T) {
	signer := newSigner(t, newP256(t))
	proof, err := signer.Proof("POST", "https://as.example/token", dpop.ProofOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v := dpop.Verifier{Now: clock, Replay: dpop.NewMemoryReplayCache(4, clock)}
	if _, err := v.Verify(context.Background(), proof, dpop.Request{Method: "GET", URI: "https://as.example/token"}); err == nil {
		t.Fatal("verified with the wrong method")
	}
	if _, err := v.Verify(context.Background(), proof, dpop.Request{Method: "POST", URI: "https://as.example/token"}); err != nil {
		t.Fatalf("legitimate use after a rejected attempt: %v", err)
	}
}

func TestMemoryReplayCacheFailsClosed(t *testing.T) {
	now := fixedNow
	cache := dpop.NewMemoryReplayCache(2, func() time.Time { return now })
	ctx := context.Background()
	for _, jti := range []string{"a", "b"} {
		if seen, err := cache.Seen(ctx, jti, now.Add(time.Minute)); seen || err != nil {
			t.Fatalf("%s: %v %v", jti, seen, err)
		}
	}
	if _, err := cache.Seen(ctx, "c", now.Add(time.Minute)); !errors.Is(err, dpop.ErrReplayCacheFull) {
		t.Fatalf("full cache: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if seen, err := cache.Seen(ctx, "c", now.Add(time.Minute)); seen || err != nil {
		t.Fatalf("after expiry: %v %v", seen, err)
	}
	if seen, _ := cache.Seen(ctx, "c", now.Add(time.Minute)); !seen {
		t.Fatal("replay not detected")
	}
}

func TestTargetURI(t *testing.T) {
	for in, want := range map[string]string{
		"https://Server.Example.COM/token":           "https://server.example.com/token",
		"https://server.example.com:443/token":       "https://server.example.com/token",
		"http://server.example.com:80":               "http://server.example.com/",
		"https://server.example.com:8443/a?b=c#d":    "https://server.example.com:8443/a",
		"https://server.example.com/a/./b/../c":      "https://server.example.com/a/c",
		"https://server.example.com/%7euser/%2fx%2F": "https://server.example.com/~user/%2Fx%2F",
		"HTTPS://[2001:DB8::1]:443/x":                "https://[2001:db8::1]/x",
		"https://[2001:db8::1]:8443/x":               "https://[2001:db8::1]:8443/x",
	} {
		got, err := dpop.TargetURI(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("TargetURI(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"/token", "ftp://x/y", "https://user:pw@x/y", "mailto:a@b", ""} {
		if _, err := dpop.TargetURI(bad); err == nil {
			t.Errorf("TargetURI(%q) accepted", bad)
		}
	}
}

func TestBoundThumbprint(t *testing.T) {
	claims := map[string]any{"cnf": map[string]any{"jkt": "jkt-1"}}
	if got, err := dpop.BoundThumbprint(claims); err != nil || got != "jkt-1" {
		t.Errorf("BoundThumbprint = %q, %v", got, err)
	}
	if _, err := dpop.BoundThumbprint(map[string]any{}); !errors.Is(err, dpop.ErrBinding) {
		t.Errorf("BoundThumbprint(no cnf) = %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustEncode(t *testing.T, b []byte) string {
	t.Helper()
	s := base64url.Encode(b)
	return s
}
