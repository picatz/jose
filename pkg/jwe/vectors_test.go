package jwe_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwe"
	"github.com/picatz/jose/pkg/jwk"
)

func readJSONFile(t *testing.T, file string, v any) {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
}

func cookbookFile(t *testing.T, prefix string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "cookbook", prefix+".*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("cookbook vector %s: %v, %v", prefix, files, err)
	}
	return files[0]
}

// RFC 7520 §5.10 to §5.12 use the JSON Serialization to show additional
// authenticated data, a split between protected and unprotected headers,
// and an entirely unprotected header. All three are A128KW with A128GCM.
func TestRFC7520JSONSerializations(t *testing.T) {
	type vector struct {
		Input struct {
			Plaintext string  `json:"plaintext"`
			Key       jwk.Key `json:"key"`
			AAD       string  `json:"aad"`
		} `json:"input"`
		Output struct {
			JSON     json.RawMessage `json:"json"`
			JSONFlat json.RawMessage `json:"json_flat"`
		} `json:"output"`
	}
	for _, tc := range []struct {
		section     string
		protected   header.Parameters // nil: no protected header
		unprotected []string          // names expected in the shared unprotected header
		aad         bool
	}{
		{section: "5_10", protected: header.Parameters{"alg": "A128KW", "kid": "81b20965-8332-43d9-a468-82160ad91ac8", "enc": "A128GCM"}, aad: true},
		{section: "5_11", protected: header.Parameters{"enc": "A128GCM"}, unprotected: []string{"alg", "kid"}},
		{section: "5_12", unprotected: []string{"alg", "kid", "enc"}},
	} {
		t.Run(tc.section, func(t *testing.T) {
			var v vector
			readJSONFile(t, cookbookFile(t, tc.section), &v)
			key := decryptionKey(t, v.Input.Key)
			d := jwe.Decrypter{Key: key, Algorithms: []jwa.Algorithm{jwa.A128KW}, Encryptions: []jwa.ContentEncryption{jwa.A128GCM}}

			for syntax, data := range map[string]json.RawMessage{"general": v.Output.JSON, "flattened": v.Output.JSONFlat} {
				parsed, err := jwe.ParseJSON(data)
				if err != nil {
					t.Fatalf("%s: ParseJSON: %v", syntax, err)
				}
				plaintext, index, err := d.DecryptJSON(parsed)
				if err != nil || index != 0 {
					t.Fatalf("%s: DecryptJSON: index %d, %v", syntax, index, err)
				}
				if string(plaintext) != v.Input.Plaintext {
					t.Fatalf("%s: plaintext mismatch", syntax)
				}
				if len(tc.protected) == 0 {
					if len(parsed.Protected) != 0 {
						t.Fatalf("%s: unexpected protected header %v", syntax, parsed.Protected)
					}
				} else if !reflect.DeepEqual(parsed.Protected, tc.protected) {
					t.Fatalf("%s: protected = %v, want %v", syntax, parsed.Protected, tc.protected)
				}
				for _, name := range tc.unprotected {
					if !parsed.Unprotected.Has(name) && !parsed.Recipients[0].Header.Has(name) {
						t.Fatalf("%s: %q missing from the unprotected headers", syntax, name)
					}
				}
				if tc.aad {
					// The vector lists the AAD as the string it encodes.
					if string(parsed.AAD) != v.Input.AAD {
						t.Fatalf("%s: AAD = %s, want %s", syntax, parsed.AAD, v.Input.AAD)
					}
					// The AAD is authenticated: changing it breaks decryption.
					parsed.AAD = append(bytes.Clone(parsed.AAD), ' ')
					if _, _, err := d.DecryptJSON(parsed); !errors.Is(err, jwe.ErrDecryption) {
						t.Fatalf("%s: modified AAD: err = %v, want ErrDecryption", syntax, err)
					}
				} else if len(parsed.AAD) != 0 {
					t.Fatalf("%s: unexpected AAD", syntax)
				}
			}
		})
	}
}

// RFC 7520 §5.13 encrypts to three recipients: RSA1_5, ECDH-ES+A256KW and
// A256GCMKW. This package implements only the middle one, so the other two
// recipients are skipped (RSA1_5 and A256GCMKW are not decryptable here, and
// those two rows of the RFC example are therefore not exercised).
func TestRFC7520MultipleRecipients(t *testing.T) {
	var v struct {
		Input struct {
			Plaintext string    `json:"plaintext"`
			Key       []jwk.Key `json:"key"`
		} `json:"input"`
		Output struct {
			JSON json.RawMessage `json:"json"`
		} `json:"output"`
	}
	readJSONFile(t, cookbookFile(t, "5_13"), &v)
	if len(v.Input.Key) != 3 {
		t.Fatalf("got %d keys", len(v.Input.Key))
	}
	parsed, err := jwe.ParseJSON(v.Output.JSON)
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	if len(parsed.Recipients) != 3 {
		t.Fatalf("got %d recipients", len(parsed.Recipients))
	}
	for i, want := range []jwa.Algorithm{"RSA1_5", jwa.ECDHESA256KW, "A256GCMKW"} {
		if got, _ := parsed.Header(i).Algorithm(); got != want {
			t.Fatalf("recipient %d alg = %q, want %q", i, got, want)
		}
	}

	// Peregrin's P-384 key opens recipient 1 and only that one.
	peregrin := decryptionKey(t, v.Input.Key[1])
	plaintext, index, err := decrypterFor(peregrin).DecryptJSON(parsed)
	if err != nil || index != 1 {
		t.Fatalf("ECDH-ES+A256KW recipient: index %d, %v", index, err)
	}
	if string(plaintext) != v.Input.Plaintext {
		t.Fatal("plaintext mismatch")
	}

	// Frodo's RSA key is for RSA1_5, and the oct key for A256GCMKW: neither
	// is implemented, and neither can open the ECDH-ES+A256KW recipient.
	for _, i := range []int{0, 2} {
		d := jwe.Decrypter{Key: decryptionKey(t, v.Input.Key[i]), Algorithms: []jwa.Algorithm{jwa.ECDHESA256KW}}
		if _, _, err := d.DecryptJSON(parsed); !errors.Is(err, jwe.ErrDecryption) {
			t.Errorf("key %d: err = %v, want ErrDecryption", i, err)
		}
	}
	// Allowing only the unimplemented algorithms says so.
	d := jwe.Decrypter{Key: decryptionKey(t, v.Input.Key[2]), Algorithms: []jwa.Algorithm{"A256GCMKW", "RSA1_5"}}
	if _, _, err := d.DecryptJSON(parsed); !errors.Is(err, jwe.ErrUnsupported) {
		t.Errorf("unimplemented only: err = %v, want ErrUnsupported", err)
	}
	// And excluding the one implemented recipient leaves nothing allowed.
	d = jwe.Decrypter{Key: peregrin, Algorithms: []jwa.Algorithm{jwa.A128KW}}
	if _, _, err := d.DecryptJSON(parsed); !errors.Is(err, jwe.ErrNotAllowed) {
		t.Errorf("none allowed: err = %v, want ErrNotAllowed", err)
	}
}

// RFC 7516 Appendix A.1 (RSAES-OAEP and AES GCM) and A.3 (AES Key Wrap and
// AES_128_CBC_HMAC_SHA_256): the published compact JWEs and keys.
func TestRFC7516AppendixVectors(t *testing.T) {
	for _, file := range []string{"rfc7516_a1.json", "rfc7516_a3.json"} {
		t.Run(file, func(t *testing.T) {
			var v struct {
				Plaintext string  `json:"plaintext"`
				Key       jwk.Key `json:"key"`
				Compact   string  `json:"compact"`
			}
			readJSONFile(t, filepath.Join("testdata", "rfc", file), &v)
			plaintext, m, err := decrypterFor(decryptionKey(t, v.Key)).Decrypt(v.Compact)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(plaintext) != v.Plaintext {
				t.Fatalf("plaintext = %q, want %q", plaintext, v.Plaintext)
			}
			if _, err := m.Algorithm(); err != nil {
				t.Fatal(err)
			}

			// Any change to the ciphertext is detected.
			parts := strings.Split(v.Compact, ".")
			parts[3] = flipFirstChar(parts[3])
			if _, _, err := (decrypterFor(decryptionKey(t, v.Key))).Decrypt(strings.Join(parts, ".")); !errors.Is(err, jwe.ErrDecryption) {
				t.Fatalf("tampered: err = %v, want ErrDecryption", err)
			}
		})
	}
}

func flipFirstChar(s string) string {
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}

// RFC 8037 Appendix A.6 gives an ECDH-ES key agreement with X25519 but no
// ciphertext: Bob's static key, Alice's ephemeral key and their shared
// secret, which is also RFC 7748 §6.1's (the expected value below is from
// RFC 7748, not re-read from RFC 8037). The matching full JWE is the
// curve25519 cookbook vector (TestCookbookDecrypt).
func TestRFC8037X25519KeyAgreement(t *testing.T) {
	var v struct {
		Input struct {
			Key jwk.Key `json:"key"`
		} `json:"input"`
		EncryptingKey struct {
			EPK jwk.Key `json:"epk"`
		} `json:"encrypting_key"`
	}
	readJSONFile(t, filepath.Join("testdata", "cookbook", "curve25519_ecdh-es.json"), &v)

	bob, err := jwk.PrivateKey(v.Input.Key)
	if err != nil {
		t.Fatal(err)
	}
	// Only Alice's public "x" is used: the cookbook file's "d" for the
	// ephemeral key does not belong to it.
	x, err := base64url.Decode(v.EncryptingKey.EPK["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	alice, err := ecdh.X25519().NewPublicKey(x)
	if err != nil {
		t.Fatal(err)
	}
	z, err := bob.(*ecdh.PrivateKey).ECDH(alice)
	if err != nil {
		t.Fatal(err)
	}
	const want = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	if hex.EncodeToString(z) != want {
		t.Fatalf("Z = %x, want %s", z, want)
	}
}
