package jwe_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwe"
)

// symmetricAlgs lists the algorithms a []byte key may be used for in tests.
var symmetricAlgs = []jwa.Algorithm{jwa.Direct, jwa.A128KW, jwa.A192KW, jwa.A256KW}

func encodeHeader(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// A compact protected header with a repeated member is refused, as in the
// JSON Serialization: encoding/json would keep the last "alg".
func TestParseRejectsDuplicateHeaderMembers(t *testing.T) {
	rest := "." + "." + "AAAAAAAAAAAAAAAA" + "." + "AA" + "." + "AAAAAAAAAAAAAAAAAAAAAA"
	for name, protected := range map[string]string{
		"alg":        `{"alg":"dir","alg":"A128KW","enc":"A128GCM"}`,
		"enc":        `{"alg":"dir","enc":"A128GCM","enc":"A256GCM"}`,
		"nested epk": `{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"OKP","x":"a","x":"b"}}`,
	} {
		_, err := jwe.Parse(encodeHeader(protected) + rest)
		if !errors.Is(err, jwe.ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
	if _, err := jwe.Parse(encodeHeader(`{"alg":"dir","enc":"A128GCM"}`) + rest); err != nil {
		t.Fatalf("control header: %v", err)
	}
}

func TestParseRejectsNonCanonicalSegments(t *testing.T) {
	good := encodeHeader(`{"alg":"dir","enc":"A128GCM"}`)
	for name, compact := range map[string]string{
		"padded header":     good + "=...." + "",
		"standard alphabet": good + "..+/AAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA",
		"trailing bits":     good + "..AAAAAAAAAAAAAAAAAB.AA.AAAAAAAAAAAAAAAAAAAAAA", // iv with non-zero unused bits
	} {
		if _, err := jwe.Parse(compact); !errors.Is(err, jwe.ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestDecrypterZeroValueAndDefaults(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	compact, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.A128KW, header.EncryptionAlgorithm: jwa.A128GCM}, []byte("x"), key)
	if err != nil {
		t.Fatal(err)
	}

	// Nil Encryptions allow the implemented set; a []byte key must name its
	// algorithms, so nil Algorithms are refused.
	if got, _, err := (decrypterFor(key)).Decrypt(compact); err != nil || string(got) != "x" {
		t.Fatalf("defaults: %q, %v", got, err)
	}
	if _, _, err := (jwe.Decrypter{Key: key}).Decrypt(compact); !errors.Is(err, jwe.ErrNotAllowed) {
		t.Fatalf("[]byte key, nil Algorithms: err = %v, want ErrNotAllowed", err)
	}
	m, err := jwe.Parse(compact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (jwe.Decrypter{Key: key}).DecryptMessage(m); !errors.Is(err, jwe.ErrNotAllowed) {
		t.Fatalf("DecryptMessage: err = %v, want ErrNotAllowed", err)
	}
	parsed, err := jwe.ParseJSON([]byte(`{"protected":"` + encodeHeader(`{"alg":"A128KW","enc":"A128GCM"}`) + `","encrypted_key":"AAAA","iv":"AAAAAAAAAAAAAAAA","ciphertext":"AA","tag":"AAAAAAAAAAAAAAAAAAAAAA"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (jwe.Decrypter{Key: key}).DecryptJSON(parsed); !errors.Is(err, jwe.ErrNotAllowed) {
		t.Fatalf("DecryptJSON: err = %v, want ErrNotAllowed", err)
	}
	// No key: a type error, never a panic and never a success.
	if _, _, err := (jwe.Decrypter{}).Decrypt(compact); !errors.Is(err, jwe.ErrUnsupported) {
		t.Fatalf("zero Decrypter: err = %v, want ErrUnsupported", err)
	}
	// An empty non-nil list allows nothing.
	if _, _, err := (jwe.Decrypter{Key: key, Algorithms: []jwa.Algorithm{}}).Decrypt(compact); !errors.Is(err, jwe.ErrNotAllowed) {
		t.Fatalf("empty Algorithms: err = %v, want ErrNotAllowed", err)
	}
	if _, _, err := (jwe.Decrypter{Key: key, Encryptions: []jwa.ContentEncryption{}}).Decrypt(compact); !errors.Is(err, jwe.ErrNotAllowed) {
		t.Fatalf("empty Encryptions: err = %v, want ErrNotAllowed", err)
	}
	// The refused algorithms stay refused under the defaults.
	for _, protected := range []string{
		`{"alg":"RSA1_5","enc":"A128GCM"}`,
		`{"alg":"PBES2-HS256+A128KW","enc":"A128GCM"}`,
		`{"alg":"A128GCMKW","enc":"A128GCM"}`,
		`{"alg":"A128KW","enc":"A128GCM","zip":"DEF"}`,
		`{"alg":"A128KW","enc":"XYZ"}`,
	} {
		forged := encodeHeader(protected) + ".AAAA.AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"
		d := jwe.Decrypter{Key: key, Algorithms: []jwa.Algorithm{"RSA1_5", "PBES2-HS256+A128KW", "A128GCMKW", jwa.A128KW}}
		if _, _, err := d.Decrypt(forged); !errors.Is(err, jwe.ErrUnsupported) {
			t.Errorf("%s: err = %v, want ErrUnsupported", protected, err)
		}
	}
}

func TestDecrypterCritical(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	compact, err := jwe.Encrypt(header.Parameters{
		header.Algorithm: jwa.A128KW, header.EncryptionAlgorithm: jwa.A128GCM,
		header.Critical: []any{"exp-ext"}, "exp-ext": 1,
	}, []byte("x"), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (decrypterFor(key)).Decrypt(compact); !errors.Is(err, jwe.ErrUnsupported) {
		t.Fatalf("unknown crit: err = %v, want ErrUnsupported", err)
	}
	if got, _, err := (jwe.Decrypter{Key: key, Algorithms: symmetricAlgs, Critical: []string{"exp-ext"}}).Decrypt(compact); err != nil || string(got) != "x" {
		t.Fatalf("understood crit: %q, %v", got, err)
	}
}

// DecryptMessage lets the caller pick the Decrypter from the parsed header.
func TestDecryptMessage(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	compact, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.A128KW, header.EncryptionAlgorithm: jwa.A128GCM, header.KeyID: "k1"}, []byte("x"), key)
	if err != nil {
		t.Fatal(err)
	}
	m, err := jwe.Parse(compact)
	if err != nil {
		t.Fatal(err)
	}
	if m.Header[header.KeyID] != "k1" {
		t.Fatal("kid not visible before decryption")
	}
	if got, err := (decrypterFor(key)).DecryptMessage(m); err != nil || string(got) != "x" {
		t.Fatalf("DecryptMessage: %q, %v", got, err)
	}
	if _, _, err := (jwe.Decrypter{}).DecryptJSON(&jwe.JSON{}); !errors.Is(err, jwe.ErrUnsupported) {
		t.Fatalf("DecryptJSON without key: err = %v", err)
	}
}

// decrypterFor returns a Decrypter for key, naming the symmetric algorithms
// explicitly when key is a []byte, as the package requires.
func decrypterFor(key any) jwe.Decrypter {
	if _, ok := key.([]byte); ok {
		return jwe.Decrypter{Key: key, Algorithms: symmetricAlgs}
	}
	return jwe.Decrypter{Key: key}
}

// An "epk" that is not an EC or OKP key must be refused as malformed, never
// handed to jwk (an RSA "epk" with an empty modulus once panicked there).
func TestEphemeralKeyTypeNarrowed(t *testing.T) {
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, epk := range []string{
		`{"kty":"RSA","n":"","e":"AQAB"}`,
		`{"kty":"oct","k":"AAAA"}`,
		`{"kty":5}`,
		`{}`,
	} {
		protected := encodeHeader(`{"alg":"ECDH-ES","enc":"A128GCM","epk":` + epk + `}`)
		compact := protected + "..AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"
		d := jwe.Decrypter{Key: p256}
		if _, _, err := d.Decrypt(compact); !errors.Is(err, jwe.ErrMalformed) {
			t.Errorf("Decrypt %s: err = %v, want ErrMalformed", epk, err)
		}
		m, err := jwe.Parse(compact)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DecryptMessage(m); !errors.Is(err, jwe.ErrMalformed) {
			t.Errorf("DecryptMessage %s: err = %v, want ErrMalformed", epk, err)
		}
		// DecryptJSON reports every per-recipient failure as ErrDecryption.
		wire := `{"protected":"` + protected + `","iv":"AAAAAAAAAAAAAAAA","ciphertext":"AA","tag":"AAAAAAAAAAAAAAAAAAAAAA"}`
		j, err := jwe.ParseJSON([]byte(wire))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.DecryptJSON(j); !errors.Is(err, jwe.ErrDecryption) {
			t.Errorf("DecryptJSON %s: err = %v, want ErrDecryption", epk, err)
		}
	}
}
