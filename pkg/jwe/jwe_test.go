package jwe_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwe"
	"github.com/picatz/jose/pkg/jwk"
)

type cookbookEncryption struct {
	Input struct {
		Plaintext string  `json:"plaintext"`
		Key       jwk.Key `json:"key"`
		Alg       string  `json:"alg"`
		Enc       string  `json:"enc"`
	} `json:"input"`
	Output struct {
		Compact string `json:"compact"`
	} `json:"output"`
}

func loadCookbook(t *testing.T, file string) cookbookEncryption {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var vector cookbookEncryption
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

// decryptionKey turns a cookbook JWK into the key type Decrypt takes.
func decryptionKey(t *testing.T, v jwk.Key) any {
	t.Helper()
	if v[jwk.KeyType] == jwk.KeyTypeOct {
		k, err := base64url.Decode(v[jwk.K].(string))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	private, err := jwk.PrivateKey(v)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func encryptionKey(t *testing.T, v jwk.Key) any {
	t.Helper()
	if v[jwk.KeyType] == jwk.KeyTypeOct {
		return decryptionKey(t, v)
	}
	public, err := jwk.PublicKey(v)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

// RFC 7520 §5 and the cookbook's X25519 example.
func TestCookbookDecrypt(t *testing.T) {
	files, err := filepath.Glob("testdata/cookbook/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no cookbook vectors: %v", err)
	}
	for _, file := range files {
		if strings.HasPrefix(filepath.Base(file), "5_13") {
			continue // several recipients: see TestRFC7520MultipleRecipients
		}
		vector := loadCookbook(t, file)
		if vector.Output.Compact == "" {
			continue // JSON Serialization only: see TestRFC7520JSONSerializations
		}
		t.Run(vector.Input.Alg+"/"+vector.Input.Enc, func(t *testing.T) {
			key := decryptionKey(t, vector.Input.Key)
			plaintext, message, err := decrypterFor(key).Decrypt(vector.Output.Compact)
			if vector.Input.Alg == "RSA1_5" {
				if !errors.Is(err, jwe.ErrUnsupported) {
					t.Fatalf("RSA1_5: err = %v, want ErrUnsupported", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(plaintext) != vector.Input.Plaintext {
				t.Fatal("plaintext mismatch")
			}
			if alg, _ := message.Algorithm(); string(alg) != vector.Input.Alg {
				t.Fatalf("alg = %s", alg)
			}

			// And the reverse: encrypt the same plaintext, decrypt it again.
			compact, err := jwe.Encrypt(header.Parameters{
				header.Algorithm:           vector.Input.Alg,
				header.EncryptionAlgorithm: vector.Input.Enc,
				header.KeyID:               "cookbook",
			}, []byte(vector.Input.Plaintext), encryptionKey(t, vector.Input.Key))
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			again, _, err := decrypterFor(key).Decrypt(compact)
			if err != nil {
				t.Fatalf("Decrypt(Encrypt): %v", err)
			}
			if string(again) != vector.Input.Plaintext {
				t.Fatal("round trip changed the plaintext")
			}
		})
	}
}

func TestRoundTripEveryAlgorithm(t *testing.T) {
	p256, _ := ecdh.P256().GenerateKey(rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	x25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encs := []jwa.ContentEncryption{jwa.A128GCM, jwa.A192GCM, jwa.A256GCM, jwa.A128CBCHS256, jwa.A192CBCHS384, jwa.A256CBCHS512}
	encKeySize := map[jwa.ContentEncryption]int{jwa.A128GCM: 16, jwa.A192GCM: 24, jwa.A256GCM: 32, jwa.A128CBCHS256: 32, jwa.A192CBCHS384: 48, jwa.A256CBCHS512: 64}

	type recipient struct {
		alg        jwa.Algorithm
		encrypt    any
		decrypt    any
		sharedSize int
	}
	recipients := []recipient{
		{alg: jwa.Direct},
		{alg: jwa.A128KW, sharedSize: 16},
		{alg: jwa.A192KW, sharedSize: 24},
		{alg: jwa.A256KW, sharedSize: 32},
		{alg: jwa.ECDHES, encrypt: p256.PublicKey(), decrypt: p256},
		{alg: jwa.ECDHES, encrypt: x25519.PublicKey(), decrypt: x25519},
		{alg: jwa.ECDHESA128KW, encrypt: &p521.PublicKey, decrypt: p521},
		{alg: jwa.ECDHESA192KW, encrypt: x25519.PublicKey(), decrypt: x25519},
		{alg: jwa.ECDHESA256KW, encrypt: p256.PublicKey(), decrypt: p256},
		{alg: jwa.RSAOAEP, encrypt: &rsaKey.PublicKey, decrypt: rsaKey},
		{alg: jwa.RSAOAEP256, encrypt: &rsaKey.PublicKey, decrypt: rsaKey},
	}
	for _, r := range recipients {
		for _, enc := range encs {
			t.Run(string(r.alg)+"/"+string(enc), func(t *testing.T) {
				encKey, decKey := r.encrypt, r.decrypt
				if r.alg == jwa.Direct || r.sharedSize > 0 {
					size := r.sharedSize
					if r.alg == jwa.Direct {
						size = encKeySize[enc]
					}
					shared := make([]byte, size)
					rand.Read(shared)
					encKey, decKey = shared, shared
				}
				for _, plaintext := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("sixteen bytes!!!"), 3)} {
					compact, err := jwe.Encrypt(header.Parameters{
						header.Algorithm:           r.alg,
						header.EncryptionAlgorithm: enc,
						jwe.AgreementPartyUInfo:    "QWxpY2U",
						jwe.AgreementPartyVInfo:    "Qm9i",
					}, plaintext, encKey)
					if err != nil {
						t.Fatalf("Encrypt: %v", err)
					}
					got, _, err := jwe.Decrypter{Key: decKey, Algorithms: []jwa.Algorithm{r.alg},
						Encryptions: []jwa.ContentEncryption{enc}}.Decrypt(compact)
					if err != nil {
						t.Fatalf("Decrypt: %v", err)
					}
					if !bytes.Equal(got, plaintext) {
						t.Fatalf("plaintext = %q, want %q", got, plaintext)
					}
				}
			})
		}
	}
}

func TestTamperingFailsUniformly(t *testing.T) {
	key, _ := ecdh.P256().GenerateKey(rand.Reader)
	compact, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.ECDHESA256KW, header.EncryptionAlgorithm: jwa.A256CBCHS512}, []byte("attack at dawn"), key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	for i := 1; i < 5; i++ {
		b, _ := base64url.Decode(parts[i])
		b[len(b)/2] ^= 0x80
		tampered := append([]string(nil), parts...)
		tampered[i] = base64url.Encode(b)
		if _, _, err := (decrypterFor(key)).Decrypt(strings.Join(tampered, ".")); !errors.Is(err, jwe.ErrDecryption) {
			t.Errorf("part %d: err = %v, want ErrDecryption", i, err)
		}
	}

	// The protected header is the AAD: re-encoding it breaks the tag.
	h, _ := base64url.Decode(parts[0])
	reencoded := base64url.Encode(append([]byte(" "), h...))
	if _, _, err := (decrypterFor(key)).Decrypt(reencoded + "." + strings.Join(parts[1:], ".")); !errors.Is(err, jwe.ErrDecryption) {
		t.Errorf("re-encoded header: err = %v, want ErrDecryption", err)
	}

	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, _, err := (decrypterFor(other)).Decrypt(compact); !errors.Is(err, jwe.ErrDecryption) {
		t.Errorf("wrong key: err = %v, want ErrDecryption", err)
	}
	wrongCurve, _ := ecdh.P384().GenerateKey(rand.Reader)
	if _, _, err := (decrypterFor(wrongCurve)).Decrypt(compact); !errors.Is(err, jwe.ErrDecryption) {
		t.Errorf("wrong curve: err = %v, want ErrDecryption", err)
	}
}

func TestRSAOAEPWrongKeyIsUniform(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 2048)
	b, _ := rsa.GenerateKey(rand.Reader, 2048)
	compact, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.RSAOAEP256, header.EncryptionAlgorithm: jwa.A256GCM}, []byte("x"), &a.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (decrypterFor(b)).Decrypt(compact); !errors.Is(err, jwe.ErrDecryption) {
		t.Fatalf("err = %v, want ErrDecryption", err)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.RSAOAEP256, header.EncryptionAlgorithm: jwa.A256GCM}, []byte("x"), &small.PublicKey); err == nil {
		t.Fatal("encrypted to a 1024-bit RSA key")
	}
}

func TestRejectsUnsafeHeaders(t *testing.T) {
	key := make([]byte, 32)
	if _, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.Direct, header.EncryptionAlgorithm: jwa.A256GCM, header.Zip: "DEF"}, []byte("x"), key); !errors.Is(err, jwe.ErrUnsupported) {
		t.Errorf("zip on encrypt: %v", err)
	}
	compact, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.Direct, header.EncryptionAlgorithm: jwa.A256GCM}, []byte("x"), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (jwe.Decrypter{Key: key, Algorithms: []jwa.Algorithm{jwa.A256KW}}).Decrypt(compact); !errors.Is(err, jwe.ErrNotAllowed) {
		t.Errorf("disallowed alg: %v", err)
	}
	if _, _, err := (jwe.Decrypter{Key: key, Encryptions: []jwa.ContentEncryption{jwa.A128GCM}}).Decrypt(compact); !errors.Is(err, jwe.ErrNotAllowed) {
		t.Errorf("disallowed enc: %v", err)
	}

	for name, h := range map[string]string{
		"zip":           `{"alg":"dir","enc":"A256GCM","zip":"DEF"}`,
		"crit":          `{"alg":"dir","enc":"A256GCM","crit":["x"],"x":1}`,
		"unknown alg":   `{"alg":"PBES2-HS256+A128KW","enc":"A256GCM"}`,
		"unknown enc":   `{"alg":"dir","enc":"A256CTR"}`,
		"private epk":   `{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"OKP","crv":"X25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`,
		"low-order epk": `{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"OKP","crv":"X25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`,
	} {
		protected := base64url.Encode([]byte(h))
		parts := strings.Split(compact, ".")
		parts[0] = protected
		x, _ := ecdh.X25519().GenerateKey(rand.Reader)
		var k any = key
		if strings.Contains(h, "ECDH-ES") {
			k = x
		}
		if _, _, err := (decrypterFor(k)).Decrypt(strings.Join(parts, ".")); err == nil {
			t.Errorf("%s: decrypted", name)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, input := range []string{
		"",
		"a.b.c",
		"a.b.c.d.e.f",
		"!!.a.a.a.a",
		"e30..aaaa.aaaa.aaaa", // {} lacks alg and enc
		"bnVsbA..aaaa.aaaa.aaaa",
	} {
		if _, err := jwe.Parse(input); !errors.Is(err, jwe.ErrMalformed) {
			t.Errorf("Parse(%q) = %v, want ErrMalformed", input, err)
		}
	}
}

// A hardware-style recipient: implements only the KeyAgreement interface.
type hardwareAgreement struct{ key *ecdh.PrivateKey }

func (h hardwareAgreement) PublicKey() *ecdh.PublicKey { return h.key.PublicKey() }
func (h hardwareAgreement) ECDH(remote *ecdh.PublicKey) ([]byte, error) {
	return h.key.ECDH(remote)
}

// A hardware-style RSA recipient: implements only crypto.Decrypter.
type hardwareDecrypter struct{ key *rsa.PrivateKey }

func (h hardwareDecrypter) Public() crypto.PublicKey { return h.key.Public() }
func (h hardwareDecrypter) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return h.key.Decrypt(r, msg, opts)
}

func TestOpaqueRecipients(t *testing.T) {
	ec, _ := ecdh.P384().GenerateKey(rand.Reader)
	compact, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.ECDHES, header.EncryptionAlgorithm: jwa.A256GCM}, []byte("sealed"), hardwareAgreement{ec})
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := (jwe.Decrypter{Key: hardwareAgreement{ec}}).Decrypt(compact); err != nil || string(got) != "sealed" {
		t.Fatalf("KeyAgreement: %q, %v", got, err)
	}

	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	compact, err = jwe.Encrypt(header.Parameters{header.Algorithm: jwa.RSAOAEP256, header.EncryptionAlgorithm: jwa.A128CBCHS256}, []byte("sealed"), &r.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := (jwe.Decrypter{Key: hardwareDecrypter{r}}).Decrypt(compact); err != nil || string(got) != "sealed" {
		t.Fatalf("Decrypter: %q, %v", got, err)
	}
}

// encoding/base64 skips CR and LF, which would give one token several
// valid strings. Parse must refuse them in every segment.
func TestParseRejectsLineBreaks(t *testing.T) {
	key := make([]byte, 16)
	compact, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.A128KW, header.EncryptionAlgorithm: jwa.A128GCM}, []byte("x"), key)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	for i, p := range parts {
		if len(p) < 3 {
			continue // empty segment: nothing to break
		}
		mutated := append([]string(nil), parts...)
		mutated[i] = p[:2] + "\r\n" + p[2:]
		if _, err := jwe.Parse(strings.Join(mutated, ".")); !errors.Is(err, jwe.ErrMalformed) {
			t.Errorf("segment %d: err = %v, want ErrMalformed", i, err)
		}
	}
}

// A tag of the wrong length is refused uniformly, whether it is a prefix of
// the right tag (truncated) or has extra bytes: truncating a tag weakens
// authentication.
func TestWrongLengthTagFailsUniformly(t *testing.T) {
	for enc, size := range map[jwa.ContentEncryption]int{
		jwa.A128GCM: 16, jwa.A256GCM: 32, jwa.A128CBCHS256: 32, jwa.A192CBCHS384: 48, jwa.A256CBCHS512: 64,
	} {
		t.Run(string(enc), func(t *testing.T) {
			key := make([]byte, size)
			rand.Read(key)
			compact, err := jwe.Encrypt(header.Parameters{header.Algorithm: jwa.Direct, header.EncryptionAlgorithm: enc}, []byte("attack at dawn"), key)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := decrypterFor(key).Decrypt(compact); err != nil {
				t.Fatalf("untouched: %v", err)
			}
			parts := strings.Split(compact, ".")
			tag, _ := base64url.Decode(parts[4])
			for name, bad := range map[string][]byte{
				"truncated by one": tag[:len(tag)-1],
				"half":             tag[:len(tag)/2],
				"extended":         append(append([]byte(nil), tag...), 0),
			} {
				parts[4] = base64url.Encode(bad)
				if _, _, err := decrypterFor(key).Decrypt(strings.Join(parts, ".")); !errors.Is(err, jwe.ErrDecryption) {
					t.Errorf("%s: err = %v, want ErrDecryption", name, err)
				}
			}
		})
	}
}
