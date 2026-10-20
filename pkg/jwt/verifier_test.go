package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/josetest"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
)

var verifierNow = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

type verifierFixture struct {
	key      *ecdsa.PrivateKey
	verifier *jwt.Verifier
}

func newVerifierFixture(t *testing.T) *verifierFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &verifierFixture{key: key, verifier: &jwt.Verifier{
		Keys:     jwt.Keys{{ID: "k1", Public: key.Public()}},
		Types:    []string{"at+jwt"},
		Issuer:   "https://issuer.example",
		Audience: "https://api.example",
		Now:      func() time.Time { return verifierNow },
	}}
}

// claims returns valid claims for the fixture's verifier.
func (f *verifierFixture) claims() map[string]any {
	return map[string]any{
		"iss": "https://issuer.example",
		"sub": "alice",
		"aud": []string{"https://api.example", "https://other.example"},
		"exp": verifierNow.Add(5 * time.Minute).Unix(),
		"iat": verifierNow.Unix(),
	}
}

func sign(t *testing.T, h jws.Header, claims any, key any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := jws.New(h, payload, key)
	if err != nil {
		t.Fatal(err)
	}
	return signature.String()
}

func (f *verifierFixture) sign(t *testing.T, mutate func(h jws.Header, c map[string]any)) string {
	t.Helper()
	h := jws.Header{header.Algorithm: jwa.ES256, header.Type: "at+jwt", header.KeyID: "k1"}
	c := f.claims()
	if mutate != nil {
		mutate(h, c)
	}
	return sign(t, h, c, f.key)
}

func TestVerifierAccepts(t *testing.T) {
	f := newVerifierFixture(t)
	token, err := f.verifier.Verify(t.Context(), f.sign(t, func(h jws.Header, c map[string]any) {
		c["scope"] = "read"
		c["nbf"] = verifierNow.Add(-time.Minute).Unix()
		c["extra"] = map[string]any{"n": 1}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if token.Claims[jwt.Subject] != "alice" || token.Claims[jwt.ExpirationTime] != verifierNow.Add(5*time.Minute).Unix() {
		t.Fatalf("claims: %#v", token.Claims)
	}
	if aud, _ := token.Claims[jwt.Audience].([]string); len(aud) != 2 {
		t.Fatalf("aud is not a []string: %#v", token.Claims[jwt.Audience])
	}
	if extra, _ := token.Claims["extra"].(map[string]any); extra["n"] != float64(1) {
		t.Fatalf("nested numbers are not float64: %#v", token.Claims["extra"])
	}
	if token.String() == "" || token.Header[header.KeyID] != "k1" {
		t.Fatalf("token: %+v", token)
	}

	// The media type compares without case and with an optional prefix.
	if _, err := f.verifier.Verify(t.Context(), f.sign(t, func(h jws.Header, _ map[string]any) {
		h[header.Type] = "application/AT+JWT"
	})); err != nil {
		t.Fatal(err)
	}
	// A single-string audience is accepted.
	if _, err := f.verifier.Verify(t.Context(), f.sign(t, func(_ jws.Header, c map[string]any) {
		c["aud"] = "https://api.example"
	})); err != nil {
		t.Fatal(err)
	}
	// Within leeway of expiry.
	if _, err := f.verifier.Verify(t.Context(), f.sign(t, func(_ jws.Header, c map[string]any) {
		c["exp"] = verifierNow.Add(-10 * time.Second).Unix()
	})); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierRefuses(t *testing.T) {
	f := newVerifierFixture(t)
	other := josetest.Key(t, jwa.ES256)
	for name, tc := range map[string]struct {
		token string
		want  error
	}{
		"expired":         {f.sign(t, func(_ jws.Header, c map[string]any) { c["exp"] = verifierNow.Add(-time.Minute).Unix() }), jwt.ErrExpired},
		"no exp":          {f.sign(t, func(_ jws.Header, c map[string]any) { delete(c, "exp") }), jwt.ErrClaims},
		"exp string":      {f.sign(t, func(_ jws.Header, c map[string]any) { c["exp"] = "soon" }), jwt.ErrClaims},
		"exp negative":    {f.sign(t, func(_ jws.Header, c map[string]any) { c["exp"] = -1 }), jwt.ErrClaims},
		"not yet":         {f.sign(t, func(_ jws.Header, c map[string]any) { c["nbf"] = verifierNow.Add(time.Minute).Unix() }), jwt.ErrNotYetValid},
		"issued later":    {f.sign(t, func(_ jws.Header, c map[string]any) { c["iat"] = verifierNow.Add(time.Minute).Unix() }), jwt.ErrNotYetValid},
		"issuer":          {f.sign(t, func(_ jws.Header, c map[string]any) { c["iss"] = "https://evil.example" }), jwt.ErrClaims},
		"iss number":      {f.sign(t, func(_ jws.Header, c map[string]any) { c["iss"] = 7 }), jwt.ErrClaims},
		"no issuer":       {f.sign(t, func(_ jws.Header, c map[string]any) { delete(c, "iss") }), jwt.ErrClaims},
		"audience":        {f.sign(t, func(_ jws.Header, c map[string]any) { c["aud"] = "https://other.example" }), jwt.ErrClaims},
		"no audience":     {f.sign(t, func(_ jws.Header, c map[string]any) { delete(c, "aud") }), jwt.ErrClaims},
		"aud number":      {f.sign(t, func(_ jws.Header, c map[string]any) { c["aud"] = []any{"https://api.example", 1} }), jwt.ErrClaims},
		"sub number":      {f.sign(t, func(_ jws.Header, c map[string]any) { c["sub"] = 7 }), jwt.ErrClaims},
		"type":            {f.sign(t, func(h jws.Header, _ map[string]any) { h[header.Type] = "JWT" }), jwt.ErrFormat},
		"no type":         {f.sign(t, func(h jws.Header, _ map[string]any) { delete(h, header.Type) }), jwt.ErrFormat},
		"empty kid":       {f.sign(t, func(h jws.Header, _ map[string]any) { h[header.KeyID] = "" }), jwt.ErrFormat},
		"other kid":       {f.sign(t, func(h jws.Header, _ map[string]any) { h[header.KeyID] = "k2" }), jwt.ErrSignature},
		"unknown crit":    {f.sign(t, func(h jws.Header, _ map[string]any) { h[header.Critical] = []string{"exp"}; h["exp"] = 1 }), jwt.ErrFormat},
		"b64 header":      {f.sign(t, func(h jws.Header, _ map[string]any) { h[header.Critical] = []string{"b64"}; h["b64"] = true }), jwt.ErrFormat},
		"other key":       {sign(t, jws.Header{header.Algorithm: jwa.ES256, header.Type: "at+jwt"}, f.claims(), other), jwt.ErrSignature},
		"hmac by default": {sign(t, jws.Header{header.Algorithm: jwa.HS256, header.Type: "at+jwt"}, f.claims(), make([]byte, 32)), jwt.ErrFormat},
		"too large":       {f.sign(t, func(_ jws.Header, c map[string]any) { c["pad"] = strings.Repeat("x", jwt.DefaultMaxSize) }), jwt.ErrFormat},
		"not compact":     {"a.b", jwt.ErrFormat},
		"unsecured":       {unsecured(t, f.claims()), jwt.ErrFormat},
		"padded":          {padded(f.sign(t, nil)), jwt.ErrFormat},
		"duplicate":       {duplicateClaims(t, f.key), jwt.ErrFormat},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.verifier.Verify(t.Context(), tc.token)
			if !errors.Is(err, tc.want) || !errors.Is(err, jwt.ErrInvalidToken) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			t.Log(err)
		})
	}
}

func unsecured(t *testing.T, claims any) string {
	t.Helper()
	h := base64url.Encode([]byte(`{"alg":"none","typ":"at+jwt"}`))
	payload, _ := json.Marshal(claims)
	p := base64url.Encode(payload)
	return h + "." + p + "."
}

// padded gives the same token a second string form: base64url padding,
// which RFC 7515 §2 leaves out.
func padded(token string) string { return token + "=" }

func duplicateClaims(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	payload := []byte(`{"iss":"https://issuer.example","aud":"https://api.example","exp":` +
		fmt.Sprint(verifierNow.Add(time.Minute).Unix()) + `,"iss":"https://evil.example"}`)
	signature, err := jws.New(jws.Header{header.Algorithm: jwa.ES256, header.Type: "at+jwt"}, payload, key)
	if err != nil {
		t.Fatal(err)
	}
	return signature.String()
}

// The time claims are judged only after the signature verifies, so an
// attacker cannot learn from a forged token whether its claims would pass
// (and a forged token with a past "exp" is a signature failure, not an
// expiry). This replaces a test that required the opposite order: expiry
// before the key source was consulted.
func TestVerifierChecksSignatureBeforeTime(t *testing.T) {
	f := newVerifierFixture(t)
	expired := func(_ jws.Header, c map[string]any) { c["exp"] = verifierNow.Add(-time.Hour).Unix() }

	// Genuine but expired: ErrExpired.
	if _, err := f.verifier.Verify(t.Context(), f.sign(t, expired)); !errors.Is(err, jwt.ErrExpired) {
		t.Fatalf("signed expired token: %v, want ErrExpired", err)
	}
	// Forged (signature of another token) and expired: ErrSignature.
	genuine := strings.Split(f.sign(t, nil), ".")
	forged := strings.Split(f.sign(t, expired), ".")
	forged[2] = genuine[2]
	_, err := f.verifier.Verify(t.Context(), strings.Join(forged, "."))
	if !errors.Is(err, jwt.ErrSignature) || errors.Is(err, jwt.ErrExpired) {
		t.Fatalf("forged expired token: %v, want ErrSignature and not ErrExpired", err)
	}
	// Forged with a malformed time claim: also only ErrSignature.
	forged = strings.Split(f.sign(t, func(_ jws.Header, c map[string]any) { c["exp"] = "soon" }), ".")
	forged[2] = genuine[2]
	if _, err := f.verifier.Verify(t.Context(), strings.Join(forged, ".")); !errors.Is(err, jwt.ErrSignature) {
		t.Fatalf("forged token with bad exp: %v, want ErrSignature", err)
	}
	// Signed with a malformed time claim: ErrClaims.
	if _, err := f.verifier.Verify(t.Context(), f.sign(t, func(_ jws.Header, c map[string]any) { c["exp"] = "soon" })); !errors.Is(err, jwt.ErrClaims) {
		t.Fatalf("signed token with bad exp: %v, want ErrClaims", err)
	}

	calls := 0
	f.verifier.Keys = keySourceFunc(func(context.Context, string) ([]jwt.Key, error) {
		calls++
		return nil, fmt.Errorf("offline: %w", context.Canceled)
	})
	_, err = f.verifier.Verify(t.Context(), f.sign(t, nil))
	if !errors.Is(err, jwt.ErrKeysUnavailable) || errors.Is(err, jwt.ErrInvalidToken) || calls != 1 {
		t.Fatalf("key source failure: %v after %d lookups", err, calls)
	}
	// The cause is kept in the chain.
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("key source failure lost its cause: %v", err)
	}
}

// The JWS layer's error stays in the chain.
func TestVerifierKeepsParseCause(t *testing.T) {
	f := newVerifierFixture(t)
	parts := strings.Split(f.sign(t, nil), ".")
	// A header that is canonical base64url but not a JSON object.
	parts[0] = base64url.Encode([]byte("[]"))
	_, err := f.verifier.Verify(t.Context(), strings.Join(parts, "."))
	if !errors.Is(err, jwt.ErrFormat) || !errors.Is(err, jws.ErrFormat) {
		t.Fatalf("malformed header: %v, want jwt.ErrFormat and jws.ErrFormat", err)
	}
}

type keySourceFunc func(context.Context, string) ([]jwt.Key, error)

func (f keySourceFunc) Keys(ctx context.Context, kid string) ([]jwt.Key, error) { return f(ctx, kid) }

func TestVerifierBoundsCandidateKeys(t *testing.T) {
	f := newVerifierFixture(t)
	var keys jwt.Keys
	for range jwt.MaxCandidateKeys {
		wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		keys = append(keys, jwt.Key{Public: wrong.Public()})
	}
	f.verifier.Keys = append(keys, jwt.Key{Public: f.key.Public()})
	if _, err := f.verifier.Verify(t.Context(), f.sign(t, func(h jws.Header, _ map[string]any) { delete(h, header.KeyID) })); !errors.Is(err, jwt.ErrSignature) {
		t.Fatalf("tried more than %d keys: %v", jwt.MaxCandidateKeys, err)
	}
	// A key pinned to another algorithm is skipped without counting.
	f.verifier.Keys = jwt.Keys{{Algorithm: jwa.ES384, Public: f.key.Public()}}
	if _, err := f.verifier.Verify(t.Context(), f.sign(t, nil)); !errors.Is(err, jwt.ErrSignature) {
		t.Fatalf("used a key pinned to ES384: %v", err)
	}
}

func TestVerifierOptions(t *testing.T) {
	f := newVerifierFixture(t)

	t.Run("hmac when listed", func(t *testing.T) {
		secret := make([]byte, 32)
		v := *f.verifier
		v.Algorithms = []jwa.Algorithm{jwa.HS256}
		v.Keys = jwt.Keys{{Public: secret}}
		if _, err := v.Verify(t.Context(), sign(t, jws.Header{header.Algorithm: jwa.HS256, header.Type: "at+jwt"}, f.claims(), secret)); err != nil {
			t.Fatal(err)
		}
		// The asymmetric key is not usable as an HMAC secret.
		v.Keys = jwt.Keys{{Public: f.key.Public()}}
		if _, err := v.Verify(t.Context(), sign(t, jws.Header{header.Algorithm: jwa.HS256, header.Type: "at+jwt"}, f.claims(), secret)); !errors.Is(err, jwt.ErrSignature) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("any issuer and audience", func(t *testing.T) {
		v := *f.verifier
		v.Issuer, v.AnyIssuer, v.Audience, v.AnyAudience = "", true, "", true
		if _, err := v.Verify(t.Context(), f.sign(t, func(_ jws.Header, c map[string]any) { delete(c, "iss"); delete(c, "aud") })); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no expiry", func(t *testing.T) {
		v := *f.verifier
		v.AllowNoExpiry = true
		if _, err := v.Verify(t.Context(), f.sign(t, func(_ jws.Header, c map[string]any) { delete(c, "exp") })); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("understood crit", func(t *testing.T) {
		v := *f.verifier
		v.Critical = []string{"urn:example:bound"}
		if _, err := v.Verify(t.Context(), f.sign(t, func(h jws.Header, _ map[string]any) {
			h[header.Critical] = []string{"urn:example:bound"}
			h["urn:example:bound"] = true
		})); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("default types", func(t *testing.T) {
		v := *f.verifier
		v.Types = nil
		for _, typ := range []any{"JWT", nil} {
			token := f.sign(t, func(h jws.Header, _ map[string]any) {
				delete(h, header.Type)
				if typ != nil {
					h[header.Type] = typ
				}
			})
			if _, err := v.Verify(t.Context(), token); err != nil {
				t.Fatalf("typ %v: %v", typ, err)
			}
		}
		if _, err := v.Verify(t.Context(), f.sign(t, nil)); !errors.Is(err, jwt.ErrFormat) {
			t.Fatalf("accepted at+jwt by default: %v", err)
		}
	})
	t.Run("leeway", func(t *testing.T) {
		v := *f.verifier
		v.Leeway = time.Nanosecond
		if _, err := v.Verify(t.Context(), f.sign(t, func(_ jws.Header, c map[string]any) { c["exp"] = verifierNow.Add(-time.Second).Unix() })); !errors.Is(err, jwt.ErrExpired) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("misconfigured", func(t *testing.T) {
		for name, v := range map[string]*jwt.Verifier{
			"nil":         nil,
			"no keys":     {Issuer: "i", Audience: "a"},
			"no issuer":   {Keys: jwt.Keys{}, Audience: "a"},
			"no audience": {Keys: jwt.Keys{}, Issuer: "i"},
		} {
			if _, err := v.Verify(t.Context(), f.sign(t, nil)); err == nil || errors.Is(err, jwt.ErrInvalidToken) {
				t.Errorf("%s: got %v, want a configuration error", name, err)
			}
		}
	})
}

func TestKeysFromSet(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	value, err := jwk.PublicValue(public)
	if err != nil {
		t.Fatal(err)
	}
	signing := clone(value, map[string]any{"kid": "sig", "alg": "EdDSA", "use": "sig"})
	encryption := clone(value, map[string]any{"kid": "enc", "use": "enc"})
	wrapping := clone(value, map[string]any{"kid": "wrap", "key_ops": []any{"wrapKey"}})
	keys, err := jwt.KeysFromSet(&jwk.Set{Keys: []jwk.Key{signing, encryption, wrapping}})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != "sig" || keys[0].Algorithm != jwa.EdDSA {
		t.Fatalf("keys: %+v", keys)
	}
	if got, _ := keys.Keys(t.Context(), "other"); len(got) != 0 {
		t.Fatalf("kid filter: %+v", got)
	}

	privateValue, _ := jwk.PublicValue(public)
	privateValue["d"] = base64url.Encode(private.Seed())
	for name, set := range map[string]*jwk.Set{
		"private":   {Keys: []jwk.Key{privateValue}},
		"symmetric": {Keys: []jwk.Key{{"kty": "oct", "k": "AAAA"}}},
		"broken":    {Keys: []jwk.Key{{"kty": "EC", "crv": "P-256"}}},
	} {
		if _, err := jwt.KeysFromSet(set); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// RFC 7517 §5: keys with an unrecognized "kty" are ignored, so one new key
// type does not make the whole set unusable.
func TestKeysFromSetIgnoresUnknownKeyType(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	value, err := jwk.PublicValue(public)
	if err != nil {
		t.Fatal(err)
	}
	good := clone(value, map[string]any{"kid": "sig"})
	future := jwk.Key{"kty": "AKP", "kid": "pq"}
	keys, err := jwt.KeysFromSet(&jwk.Set{Keys: []jwk.Key{future, good}})
	if err != nil || len(keys) != 1 || keys[0].ID != "sig" {
		t.Fatalf("unknown kty next to a good key: %+v, %v", keys, err)
	}
	if _, err := jwt.KeysFromSet(&jwk.Set{Keys: []jwk.Key{future}}); !errors.Is(err, jwk.ErrFormat) {
		t.Fatalf("only unknown kty: error = %v, want ErrFormat", err)
	}
	broken := jwk.Key{"kty": "EC", "crv": "P-256", "kid": "ec"}
	if _, err := jwt.KeysFromSet(&jwk.Set{Keys: []jwk.Key{future, good, broken}}); !errors.Is(err, jwk.ErrInvalidKey) {
		t.Fatalf("known kty but malformed: error = %v, want ErrInvalidKey", err)
	}
}

// A curve no signature here uses is ignored like an unknown kty.
func TestKeysFromSetIgnoresUnknownCurve(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	value, err := jwk.PublicValue(public)
	if err != nil {
		t.Fatal(err)
	}
	good := clone(value, map[string]any{"kid": "sig"})
	for _, other := range []jwk.Key{
		{"kty": "EC", "crv": "secp256k1", "x": "AAAA", "y": "AAAA", "kid": "k1"},
		{"kty": "OKP", "crv": "Ed448", "x": "AAAA", "kid": "ed448"},
		{"kty": "OKP", "crv": "X25519", "x": "AAAA", "kid": "ecdh"},
	} {
		keys, err := jwt.KeysFromSet(&jwk.Set{Keys: []jwk.Key{other, good}})
		if err != nil || len(keys) != 1 || keys[0].ID != "sig" {
			t.Fatalf("%v next to a good key: %+v, %v", other["crv"], keys, err)
		}
	}
}

func clone(v jwk.Key, extra map[string]any) jwk.Key {
	out := jwk.Key{}
	for k, value := range v {
		out[k] = value
	}
	for k, value := range extra {
		out[k] = value
	}
	return out
}

func ExampleVerifier() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	claims, _ := json.Marshal(map[string]any{
		"iss": "https://issuer.example",
		"sub": "alice",
		"aud": "https://api.example",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	signed, _ := jws.New(jws.Header{header.Algorithm: jwa.ES256, header.Type: "at+jwt"}, claims, key)

	verifier := &jwt.Verifier{
		Keys:     jwt.Keys{{Public: key.Public()}},
		Types:    []string{"at+jwt"},
		Issuer:   "https://issuer.example",
		Audience: "https://api.example",
	}
	token, err := verifier.Verify(context.Background(), signed.String())
	if err != nil {
		fmt.Println("refused:", err)
		return
	}
	fmt.Println(token.Claims[jwt.Subject])
	// Output: alice
}

func TestNewRefusesUnsecuredTokens(t *testing.T) {
	_, err := jwt.New(header.Parameters{header.Type: jwt.Type, header.Algorithm: jwa.None}, jwt.ClaimsSet{"sub": "alice"}, []byte{})
	if err == nil {
		t.Fatal("minted an unsecured token")
	}
}

// A parsed token re-minted with changed claims is signed over the new
// claims, so the old signature cannot vouch for them.
func TestResignedTokenCoversNewClaims(t *testing.T) {
	f := newVerifierFixture(t)
	original, err := jwt.Parse(f.sign(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	original.Claims[jwt.Subject] = "mallory"
	params := header.Parameters{header.Algorithm: jwa.ES256, header.Type: jwt.Type, header.KeyID: "k1"}
	resigned, err := jwt.New(params, original.Claims, f.key)
	if err != nil {
		t.Fatal(err)
	}
	v := *f.verifier
	v.Types = nil
	token, err := v.Verify(t.Context(), resigned.String())
	if err != nil || token.Claims[jwt.Subject] != "mallory" {
		t.Fatalf("re-minted token: %v %v", err, token)
	}
	// The old signature does not cover the new claims.
	segments := strings.Split(resigned.String(), ".")
	old := strings.Split(f.sign(t, nil), ".")
	if _, err := v.Verify(t.Context(), segments[0]+"."+segments[1]+"."+old[2]); !errors.Is(err, jwt.ErrSignature) {
		t.Fatalf("old signature accepted for new claims: %v", err)
	}
}
