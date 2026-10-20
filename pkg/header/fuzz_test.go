package header_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/picatz/jose/pkg/header"
)

// FuzzValidateCriticalHeaders checks that ValidateCriticalHeaders never
// panics, that it refuses with ErrCriticalHeaderValidation, and that a
// header it accepts has every critical name understood, present and not a
// standard parameter (RFC 7515 §4.1.11).
func FuzzValidateCriticalHeaders(f *testing.F) {
	for _, s := range []string{
		`{"alg":"HS256"}`,
		`{"alg":"HS256","crit":["x-a"],"x-a":1}`,
		`{"alg":"HS256","crit":["x-a","x-b"],"x-a":1,"x-b":null}`,
		`{"alg":"HS256","crit":["x-a"]}`,
		`{"alg":"HS256","crit":[]}`,
		`{"alg":"HS256","crit":["alg"]}`,
		`{"alg":"HS256","crit":["x-c"],"x-c":1}`,
		`{"alg":"HS256","crit":"x-a","x-a":1}`,
		`{"alg":"HS256","crit":[1]}`,
		`{"alg":"HS256","crit":null}`,
		`[]`, `null`, `{`,
	} {
		f.Add([]byte(s))
	}
	supported := []string{"x-a", "x-b"}
	f.Fuzz(func(t *testing.T, data []byte) {
		var h header.Parameters
		if json.Unmarshal(data, &h) != nil {
			return
		}
		err := h.ValidateCriticalHeaders(supported)
		if err != nil {
			if !errors.Is(err, header.ErrCriticalHeaderValidation) {
				t.Fatalf("error = %v, want ErrCriticalHeaderValidation", err)
			}
			return
		}
		if !h.Has(header.Critical) {
			return
		}
		names, ok := h[header.Critical].([]any)
		if !ok || len(names) == 0 {
			t.Fatalf("accepted a malformed crit %#v", h[header.Critical])
		}
		for _, name := range names {
			s, ok := name.(string)
			if !ok || !slices.Contains(supported, s) || header.IsStandardParameter(s) || !h.Has(s) {
				t.Fatalf("accepted crit name %#v", name)
			}
		}
		if h.ValidateCriticalHeaders(nil) == nil {
			t.Fatal("a crit header passed with no understood extensions")
		}
	})
}
