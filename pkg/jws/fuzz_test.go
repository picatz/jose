package jws_test

import (
	"encoding/base64"
	"slices"

	"bytes"
	"encoding/json"
	"errors"
	"github.com/picatz/jose/pkg/header"
	"os"
	"path/filepath"
	"testing"

	"github.com/picatz/jose/pkg/jws"
)

// cookbookOutputs returns every compact, JSON and flattened JSON output of
// the RFC 7520 vectors under dir, as fuzz seeds.
func cookbookOutputs(f *testing.F, dir string) (compact, serialized []string) {
	f.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		f.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		var vector struct {
			Output map[string]json.RawMessage `json:"output"`
		}
		if err := json.Unmarshal(data, &vector); err != nil {
			f.Fatal(err)
		}
		for name, raw := range vector.Output {
			switch name {
			case "compact":
				var s string
				if json.Unmarshal(raw, &s) == nil {
					compact = append(compact, s)
				}
			case "json", "json_flat":
				serialized = append(serialized, string(raw))
			}
		}
	}
	return compact, serialized
}

// FuzzParse checks that Parse never panics and that a parsed JWS keeps the
// exact bytes it was given, which signature verification relies on.
func FuzzParse(f *testing.F) {
	compact, _ := cookbookOutputs(f, "testdata/cookbook")
	for _, seed := range compact {
		f.Add(seed)
	}
	f.Add("eyJhbGciOiJub25lIn0.YQ.")
	f.Fuzz(func(t *testing.T, input string) {
		signed, err := jws.Parse(input)
		if err != nil {
			return
		}
		if got := signed.String(); got != input {
			t.Fatalf("String() = %q, want the parsed input %q", got, input)
		}
		// A detached JWS always carries a signature, so unsecured ones are
		// left out of this check.
		if len(signed.Signature) == 0 {
			return
		}
		if detached, err := signed.Detached(); err == nil {
			if _, err := jws.ParseDetached(detached, signed.Payload); err != nil {
				t.Fatalf("ParseDetached(Detached()) error = %v", err)
			}
		}
	})
}

// FuzzParseJSON checks that ParseJSON never panics and that whatever it
// accepts serializes back to something it accepts with the same payload
// and signature count.
func FuzzParseJSON(f *testing.F) {
	_, serialized := cookbookOutputs(f, "testdata/cookbook")
	for _, seed := range serialized {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := jws.ParseJSON(data)
		if err != nil {
			return
		}
		general, err := parsed.General()
		if err != nil {
			t.Fatalf("General() error = %v", err)
		}
		again, err := jws.ParseJSON(general)
		if err != nil {
			t.Fatalf("ParseJSON(General()) error = %v\n%s", err, general)
		}
		if !bytes.Equal(again.Payload, parsed.Payload) || len(again.Signatures) != len(parsed.Signatures) {
			t.Fatal("round trip changed the payload or the signature count")
		}
	})
}

// FuzzParseDetached checks that ParseDetached never panics, that a parsed
// detached JWS serializes back to the input, and that Verify only ever
// fails with one of the package sentinels.
func FuzzParseDetached(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiJ9..5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ", []byte("$.02"))
	f.Add("eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY", []byte("$.02"))
	f.Add("eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9..s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0", []byte("payload"))
	f.Add("eyJhbGciOiJub25lIn0..AA", []byte(""))
	f.Add("a..b", []byte(nil))
	f.Fuzz(func(t *testing.T, input string, payload []byte) {
		signed, err := jws.ParseDetached(input, payload)
		if err != nil {
			if !errors.Is(err, jws.ErrFormat) && !errors.Is(err, jws.ErrAlgorithm) {
				t.Fatalf("ParseDetached(%q) = %v, want ErrFormat or ErrAlgorithm", input, err)
			}
			return
		}
		got, err := signed.Detached()
		if err != nil {
			t.Fatalf("Detached() error = %v", err)
		}
		if got != input {
			t.Fatalf("Detached() = %q, want the input %q", got, input)
		}
		err = signed.Verify([]byte("fuzz-secret-key-that-is-long-enough-for-hmac-512-algorithms!!"))
		if err != nil && !errors.Is(err, jws.ErrSignature) && !errors.Is(err, jws.ErrAlgorithm) && !errors.Is(err, jws.ErrFormat) {
			t.Fatalf("Verify() = %v, want a package sentinel", err)
		}
	})
}

// FuzzParseCritical checks that ParseCritical never panics, that whatever
// it accepts lists only understood "crit" names (plus "b64", which this
// package implements), and that Parse, which understands nothing else,
// never disagrees with it about the payload.
func FuzzParseCritical(f *testing.F) {
	understood := []string{"x-exp", "x-tenant"}
	token := func(header string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + ".YQ." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	}
	f.Add(token(`{"alg":"HS256"}`))
	f.Add(token(`{"alg":"HS256","crit":["x-exp"],"x-exp":1}`))
	f.Add(token(`{"alg":"HS256","crit":["x-exp","x-tenant"],"x-exp":1,"x-tenant":"a"}`))
	f.Add(token(`{"alg":"HS256","crit":["b64"],"b64":false}`))
	f.Add(token(`{"alg":"HS256","crit":["x-other"],"x-other":1}`))
	f.Add(token(`{"alg":"HS256","crit":["x-exp"]}`))
	f.Add(token(`{"alg":"HS256","crit":[]}`))
	f.Add(token(`{"alg":"HS256","crit":["alg"]}`))
	f.Add(token(`{"alg":"HS256","crit":"x-exp","x-exp":1}`))
	f.Add(token(`{"alg":"HS256","crit":[1],"x-exp":1}`))
	f.Add("eyJhbGciOiJub25lIn0.YQ.")
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		signed, err := jws.ParseCritical(input, understood...)
		if err != nil {
			return
		}
		if crit, ok := signed.Header[header.Critical]; ok {
			names, ok := crit.([]any)
			if !ok || len(names) == 0 {
				t.Fatalf("accepted a malformed crit %#v", crit)
			}
			for _, name := range names {
				s, _ := name.(string)
				if s != "b64" && !slices.Contains(understood, s) {
					t.Fatalf("accepted crit name %#v that is not understood", name)
				}
				if !signed.Header.Has(s) {
					t.Fatalf("accepted crit name %q missing from the header", s)
				}
			}
		}
		if got := signed.String(); got != input && !signed.Header.Has("b64") {
			t.Fatalf("String() = %q, want the parsed input %q", got, input)
		}
		if plain, err := jws.Parse(input); err == nil && !bytes.Equal(plain.Payload, signed.Payload) {
			t.Fatalf("Parse and ParseCritical disagree on the payload: %q vs %q", plain.Payload, signed.Payload)
		}
	})
}
