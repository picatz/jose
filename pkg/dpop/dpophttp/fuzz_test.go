package dpophttp_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/dpop/dpophttp"
)

// FuzzAccessTokenFromRequest checks that AccessTokenFromRequest never
// panics and returns only a single non-empty word that follows the DPoP
// scheme in a lone Authorization header.
func FuzzAccessTokenFromRequest(f *testing.F) {
	for _, s := range []string{
		"DPoP abc.def", "dpop abc", "DPOP abc", "DPoP ", "DPoP", "DPoP  abc", "DPoP a b", "DPoP a\tb",
		"Bearer abc", "", " ", "DPoP abc\r\n", "DPoP \x00",
	} {
		f.Add(s, uint8(1))
	}
	f.Add("DPoP abc", uint8(0))
	f.Add("DPoP abc", uint8(2))
	f.Fuzz(func(t *testing.T, value string, count uint8) {
		r := &http.Request{Header: http.Header{}}
		for range count % 4 {
			r.Header.Add("Authorization", value)
		}
		token, err := dpophttp.AccessTokenFromRequest(r)
		if err != nil {
			if token != "" {
				t.Fatalf("AccessTokenFromRequest() = %q with error %v", token, err)
			}
			return
		}
		if count%4 != 1 {
			t.Fatalf("accepted %d Authorization headers", count%4)
		}
		if token == "" || strings.ContainsAny(token, " \t") {
			t.Fatalf("AccessTokenFromRequest() = %q, want one non-empty word", token)
		}
		scheme, rest, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, dpop.AuthorizationScheme) || rest != token {
			t.Fatalf("AccessTokenFromRequest(%q) = %q, want the part after the DPoP scheme", value, token)
		}
	})
}

// FuzzFromRequest checks that FromRequest never panics, returns the one
// DPoP header verbatim, and wraps dpop.ErrInvalidProof when it refuses.
func FuzzFromRequest(f *testing.F) {
	f.Add("eyJhbGciOiJFUzI1NiJ9.e30.AA", uint8(1))
	f.Add("", uint8(1))
	f.Add("a.b.c", uint8(0))
	f.Add("a.b.c", uint8(2))
	f.Fuzz(func(t *testing.T, value string, count uint8) {
		r := &http.Request{Header: http.Header{}}
		for range count % 4 {
			r.Header.Add(dpop.HeaderName, value)
		}
		proof, err := dpophttp.FromRequest(r)
		if err != nil {
			if !errors.Is(err, dpop.ErrInvalidProof) {
				t.Fatalf("FromRequest() error = %v, want ErrInvalidProof", err)
			}
			return
		}
		if count%4 != 1 || proof != value || proof == "" {
			t.Fatalf("FromRequest() = %q for %d headers of %q", proof, count%4, value)
		}
	})
}
