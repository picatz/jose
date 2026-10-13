package dpophttp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/dpop/dpophttp"
)

func TestHTTPHelpers(t *testing.T) {
	r := httptest.NewRequest("GET", "https://rs.example/x", nil)
	if _, err := dpophttp.FromRequest(r); err == nil {
		t.Error("accepted a request without a proof")
	}
	r.Header.Add(dpop.HeaderName, "a")
	if got, err := dpophttp.FromRequest(r); err != nil || got != "a" {
		t.Errorf("FromRequest = %q, %v", got, err)
	}
	r.Header.Add(dpop.HeaderName, "b")
	if _, err := dpophttp.FromRequest(r); err == nil {
		t.Error("accepted two DPoP headers")
	}
	r.Header.Set("Authorization", "dpop tok-123")
	if got, err := dpophttp.AccessTokenFromRequest(r); err != nil || got != "tok-123" {
		t.Errorf("AccessTokenFromRequest = %q, %v", got, err)
	}
	r.Header.Set("Authorization", "Bearer tok-123")
	if _, err := dpophttp.AccessTokenFromRequest(r); err == nil {
		t.Error("accepted a Bearer token")
	}

	if _, err := dpophttp.FromRequest(httptest.NewRequest("GET", "https://rs.example/x", nil)); !errors.Is(err, dpop.ErrInvalidProof) {
		t.Errorf("missing proof error = %v", err)
	}
}

// End to end: a resource server that requires a nonce, and a client
// Transport that learns it and retries once.
func TestTransportRetriesWithNonce(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := dpop.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	const token = "at-123"
	const nonce = "server-nonce-1"
	var calls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		proof, err := dpophttp.FromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		access, err := dpophttp.AccessTokenFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		v := dpop.Verifier{}
		_, err = v.Verify(r.Context(), proof, dpop.Request{
			Method:      r.Method,
			URI:         server.URL + r.URL.Path,
			AccessToken: access,
			Thumbprint:  signer.Thumbprint(),
			Nonce:       nonce,
		})
		if errors.Is(err, dpop.ErrUseNonce) {
			w.Header().Set(dpop.NonceHeaderName, nonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Write(append([]byte("ok:"), body...))
	}))
	defer server.Close()

	client := &http.Client{Transport: &dpophttp.Transport{
		Signer:      signer,
		Base:        server.Client().Transport,
		AccessToken: func(*http.Request) (string, error) { return token, nil },
	}}
	resp, err := client.Post(server.URL+"/resource?x=1", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok:payload" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (one rejection, one retry)", calls.Load())
	}

	// The nonce is remembered: the next request succeeds first time.
	resp, err = client.Get(server.URL + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || calls.Load() != 3 {
		t.Fatalf("status %d calls %d", resp.StatusCode, calls.Load())
	}
}
