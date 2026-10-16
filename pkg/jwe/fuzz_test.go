package jwe_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/picatz/jose/pkg/jwe"
)

// cookbookOutputs returns every compact, JSON and flattened JSON output of
// the RFC 7520 vectors in testdata/cookbook, as fuzz seeds.
func cookbookOutputs(f *testing.F) (compact, serialized []string) {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "cookbook", "*.json"))
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

// FuzzParse checks that Parse never panics.
func FuzzParse(f *testing.F) {
	compact, _ := cookbookOutputs(f)
	for _, seed := range compact {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = jwe.Parse(input)
	})
}

// FuzzParseJSON checks that ParseJSON never panics and that whatever it
// accepts serializes back to something it accepts with the same
// recipients and ciphertext.
func FuzzParseJSON(f *testing.F) {
	_, serialized := cookbookOutputs(f)
	for _, seed := range serialized {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := jwe.ParseJSON(data)
		if err != nil {
			return
		}
		general, err := parsed.General()
		if err != nil {
			t.Fatalf("General() error = %v", err)
		}
		again, err := jwe.ParseJSON(general)
		if err != nil {
			t.Fatalf("ParseJSON(General()) error = %v\n%s", err, general)
		}
		if len(again.Recipients) != len(parsed.Recipients) || string(again.Ciphertext) != string(parsed.Ciphertext) {
			t.Fatal("round trip changed the recipients or the ciphertext")
		}
	})
}
