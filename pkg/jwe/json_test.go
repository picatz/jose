package jwe_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/base64"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwe"
	"github.com/picatz/jose/pkg/jwk"
)

// The RFC 7520 §5 vectors carry the same encrypted object in the general
// ("json") and flattened ("json_flat") syntax.
func TestCookbookJSONDecrypt(t *testing.T) {
	files, err := filepath.Glob("testdata/cookbook/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no cookbook vectors: %v", err)
	}
	for _, file := range files {
		raw := loadCookbookRaw(t, file)
		var vector struct {
			Input struct {
				Plaintext string    `json:"plaintext"`
				Key       jwk.Value `json:"key"`
				Alg       string    `json:"alg"`
				Enc       string    `json:"enc"`
			} `json:"input"`
			Output struct {
				JSON     json.RawMessage `json:"json"`
				JSONFlat json.RawMessage `json:"json_flat"`
			} `json:"output"`
		}
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatal(err)
		}
		for syntax, data := range map[string]json.RawMessage{"general": vector.Output.JSON, "flattened": vector.Output.JSONFlat} {
			t.Run(vector.Input.Alg+"/"+vector.Input.Enc+"/"+syntax, func(t *testing.T) {
				parsed, err := jwe.ParseJSON(data)
				if err != nil {
					t.Fatalf("ParseJSON: %v", err)
				}
				key := decryptionKey(t, vector.Input.Key)
				plaintext, index, err := parsed.Decrypt(key, jwe.DecryptOptions{})
				if vector.Input.Alg == "RSA1_5" {
					if !errors.Is(err, jwe.ErrUnsupported) {
						t.Fatalf("RSA1_5: err = %v, want ErrUnsupported", err)
					}
					return
				}
				if err != nil || index != 0 {
					t.Fatalf("Decrypt: index %d, %v", index, err)
				}
				if string(plaintext) != vector.Input.Plaintext {
					t.Fatal("plaintext mismatch")
				}
				// Re-serializing keeps the received encodings, so the
				// result still authenticates.
				for name, serialize := range map[string]func() ([]byte, error){"general": parsed.General, "flattened": parsed.Flattened} {
					out, err := serialize()
					if err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					again, err := jwe.ParseJSON(out)
					if err != nil {
						t.Fatalf("%s: reparse: %v", name, err)
					}
					if got, _, err := again.Decrypt(key, jwe.DecryptOptions{}); err != nil || string(got) != vector.Input.Plaintext {
						t.Fatalf("%s: re-serialized does not decrypt: %v", name, err)
					}
				}
			})
		}
	}
}

func loadCookbookRaw(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type multiKeys struct {
	kw     []byte
	ec     *ecdh.PrivateKey
	rsaKey *rsa.PrivateKey
}

func newMultiKeys(t *testing.T) multiKeys {
	t.Helper()
	kw := make([]byte, 16)
	rand.Read(kw)
	ec, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return multiKeys{kw, ec, r}
}

func (k multiKeys) encrypt(t *testing.T, aad []byte) *jwe.JSON {
	t.Helper()
	j, err := jwe.EncryptJSON(
		header.Parameters{jwe.EncryptionAlgorithm: jwa.A128GCM, jwe.Type: "example"},
		header.Parameters{"shared": "hint"},
		[]byte("for all of you"), aad,
		jwe.RecipientKey{Header: header.Parameters{jwe.Algorithm: jwa.A128KW, jwe.KeyID: "kw"}, Key: k.kw},
		jwe.RecipientKey{Header: header.Parameters{jwe.Algorithm: jwa.ECDHESA128KW, jwe.KeyID: "ec", jwe.AgreementPartyVInfo: "Qm9i"}, Key: k.ec.PublicKey()},
		jwe.RecipientKey{Header: header.Parameters{jwe.Algorithm: jwa.RSAOAEP256, jwe.KeyID: "rsa"}, Key: &k.rsaKey.PublicKey},
	)
	if err != nil {
		t.Fatalf("EncryptJSON: %v", err)
	}
	return j
}

func TestJSONMultipleRecipientsRoundTrip(t *testing.T) {
	k := newMultiKeys(t)
	for _, aad := range [][]byte{nil, []byte("context")} {
		j := k.encrypt(t, aad)
		if !j.Recipients[1].Header.Has(jwe.EphemeralPublicKey) || j.Protected.Has(jwe.EphemeralPublicKey) {
			t.Fatal("epk must be in the ECDH-ES recipient's header")
		}
		wire, err := j.General()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := j.Flattened(); err == nil {
			t.Fatal("Flattened accepted three recipients")
		}
		for want, key := range []any{k.kw, k.ec, k.rsaKey} {
			parsed, err := jwe.ParseJSON(wire)
			if err != nil {
				t.Fatal(err)
			}
			got, index, err := parsed.Decrypt(key, jwe.DecryptOptions{})
			if err != nil || index != want || string(got) != "for all of you" || !bytes.Equal(parsed.AAD, aad) {
				t.Fatalf("recipient %d: %q index %d err %v", want, got, index, err)
			}
		}
		stranger := make([]byte, 16)
		parsed, _ := jwe.ParseJSON(wire)
		if _, _, err := parsed.Decrypt(stranger, jwe.DecryptOptions{}); !errors.Is(err, jwe.ErrDecryption) {
			t.Fatalf("stranger: %v", err)
		}
		// Algorithm allow lists skip recipients.
		if _, index, err := parsed.Decrypt(k.rsaKey, jwe.DecryptOptions{Algorithms: []jwa.Algorithm{jwa.RSAOAEP256}}); err != nil || index != 2 {
			t.Fatalf("allow list: %d %v", index, err)
		}
		if _, _, err := parsed.Decrypt(k.kw, jwe.DecryptOptions{Algorithms: []jwa.Algorithm{jwa.A256KW}}); !errors.Is(err, jwe.ErrNotAllowed) {
			t.Fatalf("nothing allowed: %v", err)
		}
		if _, _, err := parsed.Decrypt(k.kw, jwe.DecryptOptions{Encryptions: []jwa.ContentEncryption{jwa.A256GCM}}); !errors.Is(err, jwe.ErrNotAllowed) {
			t.Fatalf("enc not allowed: %v", err)
		}
	}
}

func TestJSONFlattenedAndDirect(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	for name, recipient := range map[string]jwe.RecipientKey{
		"dir":     {Header: header.Parameters{jwe.Algorithm: jwa.Direct}, Key: key},
		"ECDH-ES": {Header: header.Parameters{jwe.Algorithm: jwa.ECDHES}},
	} {
		t.Run(name, func(t *testing.T) {
			var decrypt any = key
			if name == "ECDH-ES" {
				ec, _ := ecdh.X25519().GenerateKey(rand.Reader)
				recipient.Key, decrypt = ec.PublicKey(), ec
			}
			j, err := jwe.EncryptJSON(header.Parameters{jwe.EncryptionAlgorithm: jwa.A256GCM}, nil, []byte("one"), []byte("aad"), recipient)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := j.Flattened()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(wire, []byte("recipients")) {
				t.Fatal("flattened output has recipients")
			}
			parsed, err := jwe.ParseJSON(wire)
			if err != nil {
				t.Fatal(err)
			}
			if got, _, err := parsed.Decrypt(decrypt, jwe.DecryptOptions{}); err != nil || string(got) != "one" {
				t.Fatalf("%q %v", got, err)
			}
		})
	}
	// Two recipients with a content-key-fixing algorithm are refused.
	_, err := jwe.EncryptJSON(header.Parameters{jwe.EncryptionAlgorithm: jwa.A256GCM}, nil, []byte("x"), nil,
		jwe.RecipientKey{Header: header.Parameters{jwe.Algorithm: jwa.Direct}, Key: key},
		jwe.RecipientKey{Header: header.Parameters{jwe.Algorithm: jwa.A256KW}, Key: key})
	if err == nil {
		t.Fatal("dir with two recipients encrypted")
	}
}

// mutate decodes the general serialization, applies f, and re-encodes it.
func mutate(t *testing.T, wire []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func recipientsOf(m map[string]any) []any { return m["recipients"].([]any) }

func protectedWith(t *testing.T, m map[string]any, f func(h map[string]any)) {
	t.Helper()
	raw, _ := base64.Decode(m["protected"].(string))
	var h map[string]any
	json.Unmarshal(raw, &h)
	f(h)
	out, _ := json.Marshal(h)
	m["protected"], _ = base64.Encode(out)
}

func TestJSONParseRefusals(t *testing.T) {
	k := newMultiKeys(t)
	wire, err := k.encrypt(t, []byte("ctx")).General()
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(s string) string { e, _ := base64.Encode([]byte(s)); return e }
	cases := map[string][]byte{
		"duplicate top-level member":    bytes.Replace(wire, []byte(`{"protected"`), []byte(`{"iv":"AAAA","protected"`), 1),
		"duplicate in recipient header": bytes.Replace(wire, []byte(`"kid":"kw"`), []byte(`"kid":"kw","kid":"x"`), 1),
		"duplicate in unprotected":      bytes.Replace(wire, []byte(`"shared":"hint"`), []byte(`"shared":"hint","shared":"x"`), 1),
		"duplicate in protected": mutate(t, wire, func(m map[string]any) {
			m["protected"] = b64(`{"enc":"A128GCM","enc":"A256GCM"}`)
		}),
		"protected overlaps unprotected": mutate(t, wire, func(m map[string]any) {
			m["unprotected"].(map[string]any)["typ"] = "other"
		}),
		"recipient overlaps protected": mutate(t, wire, func(m map[string]any) {
			recipientsOf(m)[0].(map[string]any)["header"].(map[string]any)["typ"] = "other"
		}),
		"recipient overlaps unprotected": mutate(t, wire, func(m map[string]any) {
			recipientsOf(m)[0].(map[string]any)["header"].(map[string]any)["shared"] = "x"
		}),
		"crit in unprotected": mutate(t, wire, func(m map[string]any) {
			m["unprotected"].(map[string]any)["crit"] = []any{"shared"}
		}),
		"crit in recipient header": mutate(t, wire, func(m map[string]any) {
			recipientsOf(m)[0].(map[string]any)["header"].(map[string]any)["crit"] = []any{"x"}
		}),
		"zip in protected": mutate(t, wire, func(m map[string]any) {
			protectedWith(t, m, func(h map[string]any) { h["zip"] = "DEF" })
		}),
		"zip in recipient header": mutate(t, wire, func(m map[string]any) {
			recipientsOf(m)[0].(map[string]any)["header"].(map[string]any)["zip"] = "DEF"
		}),
		"enc per recipient": mutate(t, wire, func(m map[string]any) {
			recipientsOf(m)[0].(map[string]any)["header"].(map[string]any)["enc"] = "A128GCM"
		}),
		"enc missing": mutate(t, wire, func(m map[string]any) {
			protectedWith(t, m, func(h map[string]any) { delete(h, "enc") })
		}),
		"alg missing": mutate(t, wire, func(m map[string]any) {
			delete(recipientsOf(m)[2].(map[string]any)["header"].(map[string]any), "alg")
		}),
		"missing ciphertext": mutate(t, wire, func(m map[string]any) { delete(m, "ciphertext") }),
		"missing tag":        mutate(t, wire, func(m map[string]any) { delete(m, "tag") }),
		"missing iv":         mutate(t, wire, func(m map[string]any) { delete(m, "iv") }),
		"no recipients":      mutate(t, wire, func(m map[string]any) { m["recipients"] = []any{} }),
		"mixed syntax": mutate(t, wire, func(m map[string]any) {
			m["encrypted_key"] = "AAAA"
		}),
		"dir with other recipients": mutate(t, wire, func(m map[string]any) {
			recipientsOf(m)[0].(map[string]any)["header"].(map[string]any)["alg"] = "dir"
		}),
		"padded base64": mutate(t, wire, func(m map[string]any) { m["tag"] = m["tag"].(string) + "=" }),
		"trailing data": append(append([]byte(nil), wire...), []byte(` {}`)...),
		"not an object": []byte(`[]`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, err := jwe.ParseJSON(data)
			if err == nil {
				t.Fatalf("accepted: %+v", parsed)
			}
		})
	}

	// Unknown top-level members are ignored (RFC 7516 §7.2.1).
	extra := mutate(t, wire, func(m map[string]any) { m["future"] = map[string]any{"x": 1} })
	parsed, err := jwe.ParseJSON(extra)
	if err != nil {
		t.Fatalf("unknown member refused: %v", err)
	}
	if _, _, err := parsed.Decrypt(k.kw, jwe.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestJSONCritHandling(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	j, err := jwe.EncryptJSON(
		header.Parameters{jwe.EncryptionAlgorithm: jwa.A128GCM, jwe.Critical: []any{"exp-ext"}, "exp-ext": 1},
		nil, []byte("x"), nil,
		jwe.RecipientKey{Header: header.Parameters{jwe.Algorithm: jwa.A128KW}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Decrypt(key, jwe.DecryptOptions{}); !errors.Is(err, jwe.ErrUnsupported) {
		t.Fatalf("unknown crit: %v", err)
	}
	if got, _, err := j.Decrypt(key, jwe.DecryptOptions{SupportedCriticalHeaders: []string{"exp-ext"}}); err != nil || string(got) != "x" {
		t.Fatalf("understood crit: %q %v", got, err)
	}
	if _, err := jwe.EncryptJSON(header.Parameters{jwe.EncryptionAlgorithm: jwa.A128GCM}, header.Parameters{jwe.Critical: []any{"a"}, "a": 1}, nil, nil,
		jwe.RecipientKey{Header: header.Parameters{jwe.Algorithm: jwa.A128KW}, Key: key}); err == nil {
		t.Fatal("encrypted with unprotected crit")
	}
}

func TestJSONTamperingFailsUniformly(t *testing.T) {
	k := newMultiKeys(t)
	wire, err := k.encrypt(t, []byte("ctx")).General()
	if err != nil {
		t.Fatal(err)
	}
	flip := func(m map[string]any, name string) {
		b, _ := base64.Decode(m[name].(string))
		b[len(b)/2] ^= 0x80
		m[name], _ = base64.Encode(b)
	}
	cases := map[string]func(m map[string]any){
		"tag":        func(m map[string]any) { flip(m, "tag") },
		"ciphertext": func(m map[string]any) { flip(m, "ciphertext") },
		"iv":         func(m map[string]any) { flip(m, "iv") },
		"aad":        func(m map[string]any) { flip(m, "aad") },
		"aad removed": func(m map[string]any) {
			delete(m, "aad")
		},
		"aad added empty": func(m map[string]any) { m["aad"] = "" },
		"protected value": func(m map[string]any) {
			protectedWith(t, m, func(h map[string]any) { h["typ"] = "evil" })
		},
		"protected re-encoded": func(m map[string]any) {
			raw, _ := base64.Decode(m["protected"].(string))
			m["protected"], _ = base64.Encode(append([]byte(" "), raw...))
		},
		"encrypted key": func(m map[string]any) { flip(recipientsOf(m)[0].(map[string]any), "encrypted_key") },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, err := jwe.ParseJSON(mutate(t, wire, f))
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			keys := []any{k.kw, k.ec, k.rsaKey}
			if name == "encrypted key" {
				keys = keys[:1] // only that recipient's key is affected
			}
			for _, key := range keys {
				if _, _, err := parsed.Decrypt(key, jwe.DecryptOptions{}); !errors.Is(err, jwe.ErrDecryption) {
					t.Errorf("err = %v, want ErrDecryption", err)
				}
			}
		})
	}
}

func TestJSONEncMismatchAndWrongKeyType(t *testing.T) {
	k := newMultiKeys(t)
	wire, _ := k.encrypt(t, nil).General()
	// A recipient whose alg is swapped to one the key cannot serve fails
	// like any other wrong key.
	swapped := mutate(t, wire, func(m map[string]any) {
		recipientsOf(m)[0].(map[string]any)["header"].(map[string]any)["alg"] = "A256KW"
	})
	parsed, err := jwe.ParseJSON(swapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parsed.Decrypt(k.kw, jwe.DecryptOptions{}); !errors.Is(err, jwe.ErrDecryption) {
		t.Fatalf("swapped alg: %v", err)
	}
	// Unsupported algorithms are skipped, and reported when nothing else is left.
	rsa15 := mutate(t, wire, func(m map[string]any) {
		m["recipients"] = recipientsOf(m)[2:]
		recipientsOf(m)[0].(map[string]any)["header"].(map[string]any)["alg"] = "RSA1_5"
	})
	parsed, err = jwe.ParseJSON(rsa15)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parsed.Decrypt(k.rsaKey, jwe.DecryptOptions{}); !errors.Is(err, jwe.ErrUnsupported) {
		t.Fatalf("RSA1_5: %v", err)
	}
	// Mutating a parsed object is authenticated as it now stands.
	parsed, _ = jwe.ParseJSON(wire)
	parsed.Protected = header.Parameters{jwe.EncryptionAlgorithm: jwa.A128GCM, jwe.Type: "swapped"}
	if _, _, err := parsed.Decrypt(k.kw, jwe.DecryptOptions{}); !errors.Is(err, jwe.ErrDecryption) {
		t.Fatalf("modified Protected: %v", err)
	}
	if !strings.Contains(string(wire), `"recipients"`) {
		t.Fatal("general syntax expected")
	}
}
