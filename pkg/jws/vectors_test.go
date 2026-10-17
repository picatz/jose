package jws_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/picatz/jose/internal/base64url"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
)

func b64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64url.Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bigInt(t testing.TB, s string) *big.Int {
	t.Helper()
	return new(big.Int).SetBytes(b64(t, s))
}

// RFC 7515 Appendix A shares one payload, the JWT claims set of A.1.
const (
	rfc7515Payload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

	// https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2
	rfc7515A2 = "eyJhbGciOiJSUzI1NiJ9." + rfc7515Payload + "." +
		"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

	// https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3
	rfc7515A3 = "eyJhbGciOiJFUzI1NiJ9." + rfc7515Payload + "." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

	// https://www.rfc-editor.org/rfc/rfc7515#appendix-A.4 (payload "Payload")
	rfc7515A4 = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA." +
		"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"

	// https://www.rfc-editor.org/rfc/rfc7515#appendix-A.5 (unsecured)
	rfc7515A5 = "eyJhbGciOiJub25lIn0." + rfc7515Payload + "."

	// https://www.rfc-editor.org/rfc/rfc7515#appendix-A.6
	rfc7515A6 = `{"payload":"` + rfc7515Payload + `","signatures":[` +
		`{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"2010-12-29"},"signature":"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},` +
		`{"protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}]}`
)

// rfc7515RSAKey is the RSA key of RFC 7515 Appendix A.2.
func rfc7515RSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: bigInt(t, "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"),
			E: 65537,
		},
		D: bigInt(t, "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"),
		Primes: []*big.Int{
			bigInt(t, "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"),
			bigInt(t, "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"),
		},
	}
	if err := key.Validate(); err != nil {
		t.Fatalf("RFC 7515 A.2 key: %v", err)
	}
	key.Precompute()
	return key
}

func ecPublic(t testing.TB, curve elliptic.Curve, x, y string) *ecdsa.PublicKey {
	t.Helper()
	key := &ecdsa.PublicKey{Curve: curve, X: bigInt(t, x), Y: bigInt(t, y)}
	if !curve.IsOnCurve(key.X, key.Y) { //nolint:staticcheck // checking a published test vector
		t.Fatal("RFC 7515 EC key is not on its curve")
	}
	return key
}

func TestRFC7515AppendixA(t *testing.T) {
	rsaKey := rfc7515RSAKey(t)
	p256 := ecPublic(t, elliptic.P256(), "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
	p521 := ecPublic(t, elliptic.P521(),
		"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
		"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")

	tests := []struct {
		name  string
		token string
		alg   jwa.Algorithm
		key   any
	}{
		{"A.2 RS256", rfc7515A2, jwa.RS256, &rsaKey.PublicKey},
		{"A.3 ES256", rfc7515A3, jwa.ES256, p256},
		{"A.4 ES512", rfc7515A4, jwa.ES512, p521},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := jws.Parse(tt.token)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got, _ := parsed.Header.Algorithm(); got != tt.alg {
				t.Fatalf("alg = %q, want %q", got, tt.alg)
			}
			if err := parsed.Verify(tt.key); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if got := parsed.String(); got != tt.token {
				t.Fatalf("String() = %q, want the input", got)
			}

			// A different payload must fail with ErrSignature.
			segments := strings.Split(tt.token, ".")
			segments[1] = base64url.Encode([]byte("tampered"))
			tampered, err := jws.Parse(strings.Join(segments, "."))
			if err != nil {
				t.Fatal(err)
			}
			if err := tampered.Verify(tt.key); !errors.Is(err, jws.ErrSignature) {
				t.Fatalf("Verify(tampered) = %v, want ErrSignature", err)
			}
		})
	}

	// RSASSA-PKCS1-v1_5 is deterministic, so signing reproduces A.2.
	t.Run("A.2 sign", func(t *testing.T) {
		payload := b64(t, rfc7515Payload)
		signed, err := jws.New(jws.Header{header.Algorithm: jwa.RS256}, payload, rsaKey)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got := signed.String(); got != rfc7515A2 {
			t.Fatalf("String() = %q, want %q", got, rfc7515A2)
		}
	})

	// A.5 is an unsecured JWS: it parses, but never verifies.
	t.Run("A.5 unsecured", func(t *testing.T) {
		parsed, err := jws.Parse(rfc7515A5)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		for _, key := range []any{nil, []byte("any key at all, even a long one for HS256 use"), &rsaKey.PublicKey} {
			if err := parsed.Verify(key); !errors.Is(err, jws.ErrAlgorithm) {
				t.Fatalf("Verify(%T) = %v, want ErrAlgorithm", key, err)
			}
		}
	})

	// A.6 is the JSON serialization of A.2 and A.3 together.
	t.Run("A.6 JSON", func(t *testing.T) {
		parsed, err := jws.ParseJSON([]byte(rfc7515A6))
		if err != nil {
			t.Fatalf("ParseJSON() error = %v", err)
		}
		if len(parsed.Signatures) != 2 {
			t.Fatalf("%d signatures, want 2", len(parsed.Signatures))
		}
		if index, err := parsed.Verify(&rsaKey.PublicKey); err != nil || index != 0 {
			t.Fatalf("Verify(RSA) = %d, %v, want 0, nil", index, err)
		}
		if index, err := parsed.Verify(p256); err != nil || index != 1 {
			t.Fatalf("Verify(P-256) = %d, %v, want 1, nil", index, err)
		}
		if _, err := parsed.Verify(p521); !errors.Is(err, jws.ErrNoValidSignature) || !errors.Is(err, jws.ErrSignature) {
			t.Fatalf("Verify(P-521) = %v, want ErrNoValidSignature (an ErrSignature)", err)
		}
		if got := parsed.Signatures[0].Unprotected["kid"]; got != "2010-12-29" {
			t.Fatalf("kid = %v", got)
		}
	})
}

// RFC 8037 Appendix A.4: Ed25519 signing, with the key of A.1.
func TestRFC8037Ed25519(t *testing.T) {
	const token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	seed := b64(t, "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
	public := b64(t, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")

	private := ed25519.NewKeyFromSeed(seed)
	if !private.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(public)) {
		t.Fatal("RFC 8037 A.1 public key does not match its private key")
	}

	parsed, err := jws.Parse(token)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if err := parsed.Verify(ed25519.PublicKey(public)); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if string(parsed.Payload) != "Example of Ed25519 signing" {
		t.Fatalf("payload = %q", parsed.Payload)
	}

	// Ed25519 is deterministic, so signing reproduces the vector.
	signed, err := jws.New(jws.Header{header.Algorithm: jwa.EdDSA}, []byte("Example of Ed25519 signing"), private)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := signed.String(); got != token {
		t.Fatalf("String() = %q, want %q", got, token)
	}

	// An ECDSA key is the wrong kind of key for EdDSA.
	if err := parsed.Verify(ecPublic(t, elliptic.P256(), "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")); !errors.Is(err, jws.ErrAlgorithm) {
		t.Fatalf("Verify(wrong key type) = %v, want ErrAlgorithm", err)
	}
}

// RFC 7520 §4.5: a signature over detached content.
func TestRFC7520DetachedContent(t *testing.T) {
	data, err := os.ReadFile("testdata/detached/4_5.signature_with_detached_content.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Input struct {
			Payload string `json:"payload"`
			Key     struct {
				K string `json:"k"`
			} `json:"key"`
		} `json:"input"`
		Output struct {
			Compact string `json:"compact"`
		} `json:"output"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	key := b64(t, vector.Input.Key.K)
	payload := []byte(vector.Input.Payload)

	parsed, err := jws.ParseDetached(vector.Output.Compact, payload)
	if err != nil {
		t.Fatalf("ParseDetached() error = %v", err)
	}
	if err := parsed.Verify(key); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got, err := parsed.Detached(); err != nil || got != vector.Output.Compact {
		t.Fatalf("Detached() = %q, %v, want %q", got, err, vector.Output.Compact)
	}

	// HMAC is deterministic: building the same JWS reproduces the vector.
	built, err := jws.New(jws.Header{
		header.Algorithm: jwa.HS256,
		header.KeyID:     "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
	}, payload, key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got, err := built.Detached(); err != nil || got != vector.Output.Compact {
		t.Fatalf("built Detached() = %q, %v, want %q", got, err, vector.Output.Compact)
	}

	other, err := jws.ParseDetached(vector.Output.Compact, []byte("not the content"))
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Verify(key); !errors.Is(err, jws.ErrSignature) {
		t.Fatalf("Verify(other content) = %v, want ErrSignature", err)
	}
}

// Parsed and built headers hold the same Go types, so they compare equal.
func TestParsedHeaderMatchesBuilt(t *testing.T) {
	key := []byte("test-secret-key-that-is-long-enough-for-hmac-256")
	built := jws.Header{header.Algorithm: jwa.HS256, header.Type: "JWT"}
	signed, err := jws.New(built, []byte("x"), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jws.Parse(signed.String())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed.Header, built) {
		t.Fatalf("parsed header %#v != built %#v", parsed.Header, built)
	}
	if _, ok := parsed.Header[header.Algorithm].(jwa.Algorithm); !ok {
		t.Fatalf("alg is %T, want jwa.Algorithm", parsed.Header[header.Algorithm])
	}

	detached, err := signed.Detached()
	if err != nil {
		t.Fatal(err)
	}
	fromDetached, err := jws.ParseDetached(detached, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromDetached.Header, built) {
		t.Fatalf("detached header %#v != built %#v", fromDetached.Header, built)
	}

	serialized, err := jws.SignJSON([]byte("x"), jws.JSONSigner{Protected: built, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := serialized.Flattened()
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := jws.ParseJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromJSON.Signatures[0].Protected, built) {
		t.Fatalf("JSON header %#v != built %#v", fromJSON.Signatures[0].Protected, built)
	}
}

func TestErrorSentinels(t *testing.T) {
	key := []byte("test-secret-key-that-is-long-enough-for-hmac-256")
	good, err := jws.New(jws.Header{header.Algorithm: jwa.HS256}, []byte("x"), key)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(s string) string { return base64url.Encode([]byte(s)) }

	parseTests := []struct {
		name  string
		input string
		want  error
	}{
		{"empty", "", jws.ErrFormat},
		{"two parts", "a.b", jws.ErrFormat},
		{"four parts", "a.b.c.d", jws.ErrFormat},
		{"header not base64url", "!!.e30.", jws.ErrFormat},
		{"header not json", enc("nope") + ".e30.", jws.ErrFormat},
		{"duplicate alg", enc(`{"alg":"HS256","alg":"none"}`) + ".e30.", jws.ErrFormat},
		{"missing alg", enc(`{"typ":"JWT"}`) + ".e30.AA", jws.ErrAlgorithm},
		{"alg not a string", enc(`{"alg":5}`) + ".e30.AA", jws.ErrAlgorithm},
		{"payload not base64url", enc(`{"alg":"HS256"}`) + ".!!.AA", jws.ErrFormat},
		{"none with signature", enc(`{"alg":"none"}`) + ".e30.AA", jws.ErrFormat},
		{"unknown crit", enc(`{"alg":"HS256","crit":["x"],"x":1}`) + ".e30.AA", jws.ErrFormat},
		{"b64 without detached", enc(`{"alg":"HS256","b64":false,"crit":["b64"]}`) + ".e30.AA", jws.ErrFormat},
	}
	for _, tt := range parseTests {
		t.Run("Parse "+tt.name, func(t *testing.T) {
			_, err := jws.Parse(tt.input)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse() = %v, want %v", err, tt.want)
			}
		})
	}

	detachedTests := []struct {
		name  string
		input string
		want  error
	}{
		{"attached form", good.String(), jws.ErrFormat},
		{"not base64url", "!!..AA", jws.ErrFormat},
		{"missing alg", enc(`{"b64":false,"crit":["b64"]}`) + "..AA", jws.ErrAlgorithm},
		{"b64 not listed in crit", enc(`{"alg":"HS256","b64":false}`) + "..AA", jws.ErrFormat},
		{"b64 not boolean", enc(`{"alg":"HS256","b64":"no","crit":["b64"]}`) + "..AA", jws.ErrFormat},
	}
	for _, tt := range detachedTests {
		t.Run("ParseDetached "+tt.name, func(t *testing.T) {
			_, err := jws.ParseDetached(tt.input, []byte("x"))
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseDetached() = %v, want %v", err, tt.want)
			}
		})
	}

	jsonTests := []struct {
		name  string
		input string
		want  error
	}{
		{"not json", "{", jws.ErrFormat},
		{"no signatures", `{"payload":"e30"}`, jws.ErrFormat},
		{"unsecured", `{"payload":"e30","protected":"` + enc(`{"alg":"none"}`) + `","signature":"AA"}`, jws.ErrAlgorithm},
		{"missing alg", `{"payload":"e30","protected":"` + enc(`{"typ":"x"}`) + `","signature":"AA"}`, jws.ErrAlgorithm},
	}
	for _, tt := range jsonTests {
		t.Run("ParseJSON "+tt.name, func(t *testing.T) {
			_, err := jws.ParseJSON([]byte(tt.input))
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseJSON() = %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("Verify wrong key", func(t *testing.T) {
		if err := good.Verify([]byte("another-secret-key-that-is-long-enough!!")); !errors.Is(err, jws.ErrSignature) {
			t.Fatalf("Verify() = %v, want ErrSignature", err)
		}
	})
	t.Run("Verify short key", func(t *testing.T) {
		if err := good.Verify([]byte("short")); !errors.Is(err, jws.ErrAlgorithm) {
			t.Fatalf("Verify() = %v, want ErrAlgorithm", err)
		}
	})
	t.Run("Verify nil key", func(t *testing.T) {
		if err := good.Verify(nil); !errors.Is(err, jws.ErrAlgorithm) {
			t.Fatalf("Verify() = %v, want ErrAlgorithm", err)
		}
	})
	t.Run("Verify unsupported alg", func(t *testing.T) {
		s := &jws.Signature{Header: jws.Header{header.Algorithm: jwa.Algorithm("XX999")}}
		if err := s.Verify(key); !errors.Is(err, jws.ErrAlgorithm) {
			t.Fatalf("Verify() = %v, want ErrAlgorithm", err)
		}
	})
	t.Run("New unsupported alg", func(t *testing.T) {
		_, err := jws.New(jws.Header{header.Algorithm: jwa.Algorithm("XX999")}, nil, key)
		if !errors.Is(err, jws.ErrAlgorithm) {
			t.Fatalf("New() = %v, want ErrAlgorithm", err)
		}
	})
	t.Run("errors do not echo the key", func(t *testing.T) {
		secret := "super-secret-hmac-key-material-0123456789"
		s := &jws.Signature{Header: jws.Header{header.Algorithm: jwa.HS256}, Signature: []byte("bad")}
		err := s.Verify([]byte(secret))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("Verify() = %v", err)
		}
	})
}
