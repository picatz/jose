package jws_test

import (
	"crypto"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jws"
)

// cookbookJSON is an RFC 7520 §4 vector with JSON serializations. Key is
// one JWK, or a list for §4.8.
type cookbookJSON struct {
	Input struct {
		Payload string          `json:"payload"`
		Key     json.RawMessage `json:"key"`
	} `json:"input"`
	Output struct {
		Compact  string          `json:"compact"`
		JSON     json.RawMessage `json:"json"`
		JSONFlat json.RawMessage `json:"json_flat"`
	} `json:"output"`
}

func cookbookVerifyKey(t *testing.T, value jwk.Value) any {
	t.Helper()
	var (
		key any
		err error
	)
	if value[jwk.KeyType] == jwk.KeyTypeOct {
		key, err = jwk.HMACSecretKey(value)
	} else {
		key, err = jwk.PublicKey(value)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// RFC 7520 §4.1-4.4 and §4.6-4.8: every JSON and flattened JSON output
// parses and verifies, and §4.8's three signatures each verify with their
// own key.
func TestCookbookJSONSerialization(t *testing.T) {
	files, err := filepath.Glob("testdata/cookbook/4_*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no cookbook vectors: %v", err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var vector cookbookJSON
			if err := json.Unmarshal(raw, &vector); err != nil {
				t.Fatal(err)
			}
			var keys []jwk.Value
			if err := json.Unmarshal(vector.Input.Key, &keys); err != nil {
				var single jwk.Value
				if err := json.Unmarshal(vector.Input.Key, &single); err != nil {
					t.Fatal(err)
				}
				keys = []jwk.Value{single}
			}
			for _, output := range []json.RawMessage{vector.Output.JSON, vector.Output.JSONFlat} {
				if output == nil {
					continue
				}
				parsed, err := jws.ParseJSON(output)
				if err != nil {
					t.Fatalf("ParseJSON: %v", err)
				}
				if string(parsed.Payload) != vector.Input.Payload {
					t.Fatal("payload mismatch")
				}
				if len(parsed.Signatures) != len(keys) {
					t.Fatalf("%d signatures for %d keys", len(parsed.Signatures), len(keys))
				}
				for want, value := range keys {
					got, err := parsed.Verify(cookbookVerifyKey(t, value))
					if err != nil || got != want {
						t.Fatalf("Verify with key %d = %d, %v", want, got, err)
					}
				}
				// Re-serializing keeps the received encodings, so the result
				// still verifies.
				general, err := parsed.General()
				if err != nil {
					t.Fatal(err)
				}
				again, err := jws.ParseJSON(general)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := again.Verify(cookbookVerifyKey(t, keys[0])); err != nil {
					t.Fatalf("re-serialized: %v", err)
				}
				if vector.Output.Compact != "" {
					compact, err := parsed.Compact(0)
					if err != nil || compact != vector.Output.Compact {
						t.Fatalf("Compact(0) = %q, %v; want the cookbook's compact form", compact, err)
					}
				}
			}
		})
	}
}

func TestSignJSONMultipleSigners(t *testing.T) {
	ec, rsaKey, other := mustECDSA(t, elliptic.P256()), mustRSA(t, 2048), mustECDSA(t, elliptic.P256())
	secret := []byte(strings.Repeat("k", 32))
	payload := []byte(`{"iss":"https://issuer.example","rotation":true}`)
	signed, err := jws.SignJSON(payload,
		jws.JSONSigner{Protected: jws.Header{header.Algorithm: jwa.ES256}, Unprotected: jws.Header{header.KeyID: "ec-1"}, Key: opaqueSigner{ec}},
		jws.JSONSigner{Protected: jws.Header{header.Algorithm: jwa.PS256, header.KeyID: "rsa-1"}, Key: rsaKey},
		jws.JSONSigner{Protected: jws.Header{header.Algorithm: jwa.HS256}, Key: secret},
	)
	if err != nil {
		t.Fatal(err)
	}
	general, err := signed.General()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jws.ParseJSON(general)
	if err != nil {
		t.Fatal(err)
	}
	for want, key := range []any{&ec.PublicKey, &rsaKey.PublicKey, secret} {
		if got, err := parsed.Verify(key); err != nil || got != want {
			t.Fatalf("Verify(key %d) = %d, %v", want, got, err)
		}
	}
	if got := parsed.Signatures[0].Header()[header.KeyID]; got != "ec-1" {
		t.Fatalf("unprotected kid = %v", got)
	}
	if _, err := parsed.Verify(&other.PublicKey); !errors.Is(err, jws.ErrNoValidSignature) {
		t.Fatalf("Verify(unrelated key) = %v, want ErrNoValidSignature", err)
	}
	if _, err := parsed.Flattened(); err == nil {
		t.Fatal("Flattened accepted three signatures")
	}
	if _, err := parsed.Compact(0); err == nil {
		t.Fatal("Compact dropped an unprotected header")
	}
	compact, err := parsed.Compact(1)
	if err != nil {
		t.Fatal(err)
	}
	single, err := jws.Parse(compact)
	if err != nil || single.Verify(&rsaKey.PublicKey) != nil {
		t.Fatalf("Compact(1) does not verify: %v", err)
	}

	// Changing the payload breaks every signature.
	var wire map[string]any
	if err := json.Unmarshal(general, &wire); err != nil {
		t.Fatal(err)
	}
	wire["payload"] = mustEncode(t, []byte(`{"iss":"https://attacker.example"}`))
	tampered, _ := json.Marshal(wire)
	forged, err := jws.ParseJSON(tampered)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []any{&ec.PublicKey, &rsaKey.PublicKey, secret} {
		if _, err := forged.Verify(key); !errors.Is(err, jws.ErrNoValidSignature) {
			t.Fatalf("tampered payload verified: %v", err)
		}
	}
}

// ACME (RFC 8555 §6.2) sends flattened JWS with the key or account URL,
// nonce and URL protected, and an empty payload for POST-as-GET.
func TestFlattenedACMEStyle(t *testing.T) {
	key := mustECDSA(t, elliptic.P256())
	public, err := jwk.PublicValue(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{nil, []byte(`{"termsOfServiceAgreed":true}`)} {
		signed, err := jws.SignJSON(payload, jws.JSONSigner{
			Protected: jws.Header{header.Algorithm: jwa.ES256, "jwk": public, "nonce": "6S8IqOGY7eL2lsGoTZYifg", "url": "https://acme.example/new-account"},
			Key:       crypto.Signer(key),
		})
		if err != nil {
			t.Fatal(err)
		}
		flat, err := signed.Flattened()
		if err != nil {
			t.Fatal(err)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(flat, &members); err != nil {
			t.Fatal(err)
		}
		if _, ok := members["signatures"]; ok || members["protected"] == nil || members["payload"] == nil {
			t.Fatalf("not flattened: %s", flat)
		}
		if payload == nil && string(members["payload"]) != `""` {
			t.Fatalf("POST-as-GET payload = %s, want \"\"", members["payload"])
		}
		parsed, err := jws.ParseJSON(flat)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parsed.Verify(&key.PublicKey); err != nil {
			t.Fatal(err)
		}
		if parsed.Signatures[0].Protected["url"] != "https://acme.example/new-account" {
			t.Fatalf("protected url = %v", parsed.Signatures[0].Protected["url"])
		}
	}
}

func TestParseJSONRefusals(t *testing.T) {
	key := mustECDSA(t, elliptic.P256())
	signed, err := jws.SignJSON([]byte("content"), jws.JSONSigner{Protected: jws.Header{header.Algorithm: jwa.ES256}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	flat, err := signed.Flattened()
	if err != nil {
		t.Fatal(err)
	}
	var good map[string]any
	if err := json.Unmarshal(flat, &good); err != nil {
		t.Fatal(err)
	}
	with := func(edit func(map[string]any)) []byte {
		copy := map[string]any{}
		for name, value := range good {
			copy[name] = value
		}
		edit(copy)
		out, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	protectedWith := func(h jws.Header) string {
		out, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		return mustEncode(t, out)
	}
	for name, input := range map[string][]byte{
		"not JSON":          []byte("eyJhbGciOiJFUzI1NiJ9.Y29udGVudA.c2ln"),
		"trailing data":     append(append([]byte{}, flat...), []byte(` {}`)...),
		"no payload":        with(func(m map[string]any) { delete(m, "payload") }),
		"no signature":      with(func(m map[string]any) { delete(m, "signature") }),
		"no header":         with(func(m map[string]any) { delete(m, "protected") }),
		"mixed syntax":      with(func(m map[string]any) { m["signatures"] = []any{} }),
		"empty signatures":  []byte(`{"payload":"Y29udGVudA","signatures":[]}`),
		"padded payload":    with(func(m map[string]any) { m["payload"] = "Y29udGVudA==" }),
		"overlapping names": with(func(m map[string]any) { m["header"] = map[string]any{"alg": "ES256"} }),
		"unprotected crit":  with(func(m map[string]any) { m["header"] = map[string]any{"crit": []string{"exp"}} }),
		"protected crit": with(func(m map[string]any) {
			m["protected"] = protectedWith(jws.Header{"alg": "ES256", "crit": []string{"b64"}, "b64": false})
		}),
		"no alg":               with(func(m map[string]any) { m["protected"] = protectedWith(jws.Header{"kid": "1"}) }),
		"alg none":             with(func(m map[string]any) { m["protected"] = protectedWith(jws.Header{"alg": "none"}); m["signature"] = "" }),
		"empty signature":      with(func(m map[string]any) { m["signature"] = "" }),
		"protected not base64": with(func(m map[string]any) { m["protected"] = "!!" }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := jws.ParseJSON(input); err == nil {
				t.Fatalf("ParseJSON accepted %s", input)
			}
		})
	}
	// RFC 7515 §7.2.1: members that are not understood are ignored.
	extra, err := jws.ParseJSON(with(func(m map[string]any) { m["extension"] = map[string]any{"x": 1} }))
	if err != nil {
		t.Fatalf("ParseJSON with an extra member: %v", err)
	}
	if _, err := extra.Verify(&key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := jws.SignJSON([]byte("x"), jws.JSONSigner{Protected: jws.Header{header.Algorithm: jwa.None}}); err == nil {
		t.Fatal("SignJSON signed with alg none")
	}
	if _, err := jws.SignJSON([]byte("x"), jws.JSONSigner{Unprotected: jws.Header{header.Algorithm: jwa.ES256}, Key: key}); err == nil {
		t.Fatal("SignJSON accepted alg outside the protected header")
	}
	if _, err := jws.SignJSON([]byte("x")); err == nil {
		t.Fatal("SignJSON accepted no signers")
	}
}
