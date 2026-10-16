package jws_test

import (
	"bytes"
	"encoding/json"
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

// FuzzParseDetached checks that ParseDetached never panics on any token
// and payload pair.
func FuzzParseDetached(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY", []byte("$.02"))
	f.Add("eyJhbGciOiJIUzI1NiJ9..5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ", []byte("$.02"))
	f.Fuzz(func(t *testing.T, input string, payload []byte) {
		_, _ = jws.ParseDetached(input, payload)
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
