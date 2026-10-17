package jwe_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwe"
	"github.com/picatz/jose/pkg/jwk"
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

// vectorDecrypters returns one Decrypter per distinct key in the testdata
// vectors (RSA, P-256, X25519, 16- and 32-byte symmetric keys), together
// with every compact JWE in them, as seeds. Symmetric keys name their
// algorithms, as the package requires.
func vectorDecrypters(f *testing.F) (decrypters []jwe.Decrypter, compacts []string) {
	f.Helper()
	files, _ := filepath.Glob(filepath.Join("testdata", "*", "*.json"))
	seen := map[string]bool{}
	add := func(raw json.RawMessage) {
		var v jwk.Key
		if json.Unmarshal(raw, &v) != nil || v == nil {
			return
		}
		var key any
		if v[jwk.KeyType] == jwk.KeyTypeOct {
			secret, _ := v[jwk.K].(string)
			k, err := base64url.Decode(secret)
			if err != nil || len(k) == 0 {
				return
			}
			key = k
		} else {
			k, err := jwk.PrivateKey(v)
			if err != nil {
				return
			}
			key = k
		}
		id, _ := json.Marshal(v)
		if seen[string(id)] {
			return
		}
		seen[string(id)] = true
		d := jwe.Decrypter{Key: key}
		if _, ok := key.([]byte); ok {
			d.Algorithms = []jwa.Algorithm{jwa.Direct, jwa.A128KW, jwa.A192KW, jwa.A256KW}
		}
		decrypters = append(decrypters, d)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		var vector struct {
			Key     json.RawMessage `json:"key"`
			Compact string          `json:"compact"`
			Input   struct {
				Key json.RawMessage `json:"key"`
			} `json:"input"`
			Output struct {
				Compact string `json:"compact"`
			} `json:"output"`
		}
		if err := json.Unmarshal(data, &vector); err != nil {
			f.Fatal(err)
		}
		for _, raw := range []json.RawMessage{vector.Key, vector.Input.Key} {
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) == nil {
				for _, one := range list {
					add(one)
				}
			} else {
				add(raw)
			}
		}
		for _, c := range []string{vector.Compact, vector.Output.Compact} {
			if c != "" {
				compacts = append(compacts, c)
			}
		}
	}
	if len(decrypters) == 0 {
		f.Fatal("no vector keys")
	}
	return decrypters, compacts
}

// FuzzDecrypt checks that Decrypter.Decrypt never panics, whatever the
// input and key type, and that every error is one of the package sentinels.
func FuzzDecrypt(f *testing.F) {
	decrypters, compacts := vectorDecrypters(f)
	for _, seed := range compacts {
		f.Add(seed)
	}
	f.Add(encodeHeaderFuzz(`{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"RSA","n":"","e":"AQAB"}}`) + "..AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA")
	sentinels := []error{jwe.ErrMalformed, jwe.ErrUnsupported, jwe.ErrNotAllowed, jwe.ErrDecryption}
	f.Fuzz(func(t *testing.T, input string) {
		for i, d := range decrypters {
			_, _, err := d.Decrypt(input)
			if err == nil {
				continue
			}
			ok := false
			for _, s := range sentinels {
				ok = ok || errors.Is(err, s)
			}
			if !ok {
				t.Fatalf("key %d (%T): error is not a package sentinel: %v", i, d.Key, err)
			}
		}
	})
}

func encodeHeaderFuzz(s string) string { return encodeHeader(s) }
