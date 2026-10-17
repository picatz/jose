package dpophttp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/dpop/dpophttp"
)

// A client Transport attaches a fresh proof to every request and binds it
// to the access token.
func ExampleTransport() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof, err := dpophttp.FromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		token, _ := dpophttp.AccessTokenFromRequest(r)
		_, err = (&dpop.Verifier{}).Verify(r.Context(), proof, dpop.Request{
			Method:      r.Method,
			URI:         "http://" + r.Host + r.URL.Path,
			AccessToken: token,
		})
		fmt.Println("proof verified:", err == nil, "token:", token)
	}))
	defer srv.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := dpop.NewSigner(key)
	if err != nil {
		panic(err)
	}
	client := &http.Client{Transport: &dpophttp.Transport{
		Signer: signer,
		AccessToken: func(*http.Request) (string, error) {
			return "access-token", nil
		},
	}}
	resp, err := client.Get(srv.URL + "/resource")
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	// Output: proof verified: true token: access-token
}
