package jwthttp_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/jwt/jwthttp"
)

// FuzzBearerToken checks that BearerToken never panics, that a token it
// returns is a single non-empty word taken verbatim from the header, and
// that SetBearerToken output always reads back unchanged.
func FuzzBearerToken(f *testing.F) {
	for _, s := range []string{
		"Bearer abc.def.ghi", "bearer abc", "BEARER abc", "Bearer ", "Bearer", "Bearer  abc", "Bearer a b",
		"Bearer a\tb", "Basic abc", "", " ", "Bearer\tabc", "Bearer abc\r\n", "Bearer \x00", "DPoP abc",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		r := &http.Request{Header: http.Header{}}
		r.Header["Authorization"] = []string{value}
		token, err := jwthttp.BearerToken(r)
		if err != nil {
			if token != "" {
				t.Fatalf("BearerToken() = %q with error %v", token, err)
			}
			return
		}
		if token == "" || strings.ContainsAny(token, " \t") {
			t.Fatalf("BearerToken() = %q, want one non-empty word", token)
		}
		scheme, rest, _ := strings.Cut(value, " ")
		if !strings.EqualFold(scheme, "Bearer") || rest != token {
			t.Fatalf("BearerToken(%q) = %q, want the part after the Bearer scheme", value, token)
		}
		out := &http.Request{Header: http.Header{}}
		jwthttp.SetBearerToken(out, token)
		if again, err := jwthttp.BearerToken(out); err != nil || again != token {
			t.Fatalf("SetBearerToken round trip = %q, %v, want %q", again, err, token)
		}
	})
}
