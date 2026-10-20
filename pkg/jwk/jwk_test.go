package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RFC 7517 Appendix A.1 public keys and A.3 symmetric keys.
const rfc7517Set = `
{"keys":[
  {"kty":"EC","crv":"P-256",
   "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
   "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
   "use":"enc","kid":"1"},
  {"kty":"RSA",
   "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
   "e":"AQAB","alg":"RS256","kid":"2011-04-29"},
  {"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"},
  {"kty":"oct",
   "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
   "kid":"HMAC key used in JWS spec Appendix A.1 example"}
]}`

func TestParseSetRFC7517(t *testing.T) {
	set, err := ParseSet([]byte(rfc7517Set))
	if err != nil {
		t.Fatalf("ParseSet() error = %v", err)
	}
	if err := set.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(set.Keys) != 4 {
		t.Fatalf("len(Keys) = %d, want 4", len(set.Keys))
	}

	ec, ok := set.Get("1")
	if !ok {
		t.Fatal(`Get("1") not found`)
	}
	pub, err := PublicKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := pub.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		t.Fatalf("EC key = %T", pub)
	}

	rk, ok := set.Get("2011-04-29")
	if !ok {
		t.Fatal("RSA key not found")
	}
	pub, err = PublicKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := pub.(*rsa.PublicKey); !ok || k.E != 65537 || k.N.BitLen() != 2048 {
		t.Fatalf("RSA key = %#v", pub)
	}

	if _, ok := set.Get("missing"); ok {
		t.Fatal(`Get("missing") found a key`)
	}
}

// RFC 7517 Appendix A.2: the EC private key whose public half is A.1's.
// PrivateKey checks that d matches the point, so a mistyped value fails.
func TestPrivateKeyRFC7517A2EC(t *testing.T) {
	key := Key{
		KeyType: "EC", Curve: "P-256",
		X:            "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		Y:            "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		D:            "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
		PublicKeyUse: "enc", KeyID: "1",
	}
	if err := Validate(key); err != nil {
		t.Fatal(err)
	}
	if !IsPrivate(key) {
		t.Fatal("IsPrivate = false")
	}
	if _, err := PrivateKey(key); err != nil {
		t.Fatal(err)
	}
}

// A key with "x5c", "x5t", "x5t#S256" and "x5u" members, as in RFC 7517
// Appendix B, keeps them as ordinary members. The values here are placeholders,
// not the RFC's certificate: members this package does not interpret must not
// break parsing.
func TestKeyIgnoresX509Members(t *testing.T) {
	input := `{"kty":"EC","crv":"P-256",
		"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"use":"sig","kid":"1b94c",
		"x5c":["MIIB"],"x5t":"AAAA","x5t#S256":"AAAA","x5u":"https://example.com/cert"}`
	var key Key
	if err := json.Unmarshal([]byte(input), &key); err != nil {
		t.Fatal(err)
	}
	if err := Validate(key); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{X509CertificateChain, X509CertificateSHA1Thumbprint, X509CertificateSHA256Thumbprint, X509URL} {
		if _, ok := key[name]; !ok {
			t.Errorf("member %q lost", name)
		}
	}
	public, err := PublicValue(mustPublic(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := public[X509CertificateChain]; ok {
		t.Error("PublicValue kept x5c")
	}
}

func mustPublic(t *testing.T, key Key) any {
	t.Helper()
	pub, err := PublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// walkKeys calls fn for every JWK (an object with "kty") in a JSON value.
func walkKeys(v any, path string, fn func(path string, key Key)) {
	switch v := v.(type) {
	case map[string]any:
		if _, ok := v[KeyType]; ok {
			fn(path, Key(v))
			return
		}
		for name, child := range v {
			walkKeys(child, path+"/"+name, fn)
		}
	case []any:
		for i, child := range v {
			walkKeys(child, path+"/"+string(rune('0'+i)), fn)
		}
	}
}

// RFC 7520 §3 keys (the JOSE Cookbook), as they appear in the JWS and JWE
// cookbook vectors: every key must validate, a private key must return its
// private form and agree with the published public members.
func TestCookbookKeys(t *testing.T) {
	var files []string
	for _, pattern := range []string{"../jws/testdata/cookbook/*.json", "../jwe/testdata/cookbook/*.json"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		t.Skip("cookbook vectors not found")
	}
	count := map[string]int{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		walkKeys(doc, "", func(path string, key Key) {
			if !strings.HasPrefix(path, "/input/key") {
				return // ephemeral keys in the outputs are not published keys
			}
			name := filepath.Base(file) + path
			if err := Validate(key); err != nil {
				t.Errorf("%s: Validate() error = %v", name, err)
				return
			}
			kty := key[KeyType].(string)
			count[kty]++
			if kty == KeyTypeOct {
				if _, err := PublicKey(key); !errors.Is(err, ErrInvalidKey) {
					t.Errorf("%s: PublicKey(oct) error = %v, want ErrInvalidKey", name, err)
				}
				return
			}
			pub, err := PublicKey(key)
			if err != nil {
				t.Errorf("%s: PublicKey() error = %v", name, err)
				return
			}
			published, err := PublicValue(pub)
			if err != nil {
				t.Errorf("%s: PublicValue() error = %v", name, err)
				return
			}
			if !IsPrivate(key) {
				return
			}
			private, err := PrivateKey(key)
			if err != nil {
				t.Errorf("%s: PrivateKey() error = %v", name, err)
				return
			}
			derived, err := PublicValue(private)
			if err != nil {
				t.Errorf("%s: PublicValue(private) error = %v", name, err)
				return
			}
			for member, want := range published {
				if derived[member] != want {
					t.Errorf("%s: public member %q = %v, want %v", name, member, derived[member], want)
				}
			}
			for member := range derived {
				// The RFC's public members agree with what the private
				// key derives, apart from leading-zero trimming already
				// normalized by PublicValue.
				if got, ok := key[member]; ok && got != derived[member] {
					t.Errorf("%s: member %q = %v, derived %v", name, member, got, derived[member])
				}
			}
		})
	}
	for _, kty := range []string{KeyTypeRSA, KeyTypeEC, KeyTypeOct} {
		if count[kty] == 0 {
			t.Errorf("no %s keys found in the cookbook vectors", kty)
		}
	}
}

// RFC 8037 Appendix A.1: the Ed25519 private key; PrivateKey checks d against x.
func TestPrivateKeyRFC8037A1(t *testing.T) {
	key := Key{
		KeyType: "OKP", Curve: "Ed25519",
		D: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
		X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	}
	if err := Validate(key); err != nil {
		t.Fatal(err)
	}
}

func TestParseSetErrors(t *testing.T) {
	for name, input := range map[string]string{
		"empty":            ``,
		"not an object":    `[]`,
		"no keys":          `{}`,
		"null keys":        `{"keys":null}`,
		"keys not array":   `{"keys":{}}`,
		"duplicate member": `{"keys":[],"keys":[]}`,
		"duplicate nested": `{"keys":[{"kty":"oct","kty":"oct","k":"AAAA"}]}`,
		"duplicate kid":    `{"keys":[{"kty":"oct","kid":"a","k":"AAAA"},{"kty":"oct","kid":"a","k":"AAAA"}]}`,
		"trailing data":    `{"keys":[]} {}`,
	} {
		if _, err := ParseSet([]byte(input)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: ParseSet() error = %v, want ErrFormat", name, err)
		}
	}
	// ParseSet does not look at the keys; Validate refuses a malformed key
	// of a known type. (A key of an unknown type is ignored since RFC 7517
	// §5 says so: see TestSetValidateIgnoresUnknownKeyType.)
	set, err := ParseSet([]byte(`{"keys":[{"kty":"EC","crv":"P-256"}, {"kty":"oct","k":"AAAA"}]}`))
	if err != nil || len(set.Keys) != 2 {
		t.Fatalf("ParseSet() = %v, %v", set, err)
	}
	if err := set.Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Validate() error = %v, want ErrInvalidKey", err)
	}
}

func TestSetValidate(t *testing.T) {
	if err := (&Set{}).Validate(); !errors.Is(err, ErrFormat) {
		t.Errorf("empty set error = %v, want ErrFormat", err)
	}
	dup := &Set{Keys: []Key{{KeyType: "oct", K: "AAAA", KeyID: "a"}, {KeyType: "oct", K: "AAAA", KeyID: "a"}}}
	if err := dup.Validate(); !errors.Is(err, ErrFormat) {
		t.Errorf("duplicate kid error = %v, want ErrFormat", err)
	}
	// A set of keys without kids is allowed.
	ok := &Set{Keys: []Key{{KeyType: "oct", K: "AAAA"}, {KeyType: "oct", K: "AAAA"}}}
	if err := ok.Validate(); err != nil {
		t.Errorf("kid-less set error = %v", err)
	}
	if _, found := ok.Get(""); found {
		t.Error(`Get("") matched a key without kid`)
	}
}

func TestValidate(t *testing.T) {
	const (
		x256 = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
		y256 = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
	)
	valid := []Key{
		{KeyType: "EC", Curve: "P-256", X: x256, Y: y256},
		{KeyType: "oct", K: "AAAA"},
		{KeyType: "OKP", Curve: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
	}
	for _, k := range valid {
		if err := Validate(k); err != nil {
			t.Errorf("Validate(%v) error = %v", k, err)
		}
	}
	invalid := map[string]Key{
		"nil":               nil,
		"no kty":            {X: x256},
		"kty not string":    {KeyType: 1},
		"unknown kty":       {KeyType: "XYZ"},
		"off curve":         {KeyType: "EC", Curve: "P-256", X: "dGVzdA", Y: "dGVzdA"},
		"unsupported curve": {KeyType: "EC", Curve: "secp256k1", X: x256, Y: y256},
		"missing y":         {KeyType: "EC", Curve: "P-256", X: x256},
		"private mismatch":  {KeyType: "EC", Curve: "P-256", X: x256, Y: y256, D: "AAAA"},
		"empty oct":         {KeyType: "oct", K: ""},
		"oct not base64":    {KeyType: "oct", K: "!!"},
		"oct wrong type":    {KeyType: "oct", K: 5},
		"rsa no e":          {KeyType: "RSA", N: "AQAB"},
		"short ed25519":     {KeyType: "OKP", Curve: "Ed25519", X: "AA"},
	}
	for name, k := range invalid {
		if err := Validate(k); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: Validate() error = %v, want ErrInvalidKey", name, err)
		}
	}
	if err := Validate(Key{KeyType: "EC"}); err == nil || !strings.HasPrefix(err.Error(), "jwk:") {
		t.Errorf("error = %v, want jwk: prefix", err)
	}
}

func TestMemberNames(t *testing.T) {
	for got, want := range map[string]string{
		KeyType: "kty", PublicKeyUse: "use", KeyOperations: "key_ops", Algorithm: "alg",
		KeyID: "kid", X509URL: "x5u", X509CertificateChain: "x5c",
		X509CertificateSHA1Thumbprint: "x5t", X509CertificateSHA256Thumbprint: "x5t#S256",
	} {
		if got != want {
			t.Errorf("constant = %q, want %q", got, want)
		}
	}
}

// RFC 7517 §5: keys with an unrecognized "kty" are ignored, so one new key
// type does not make the whole set unusable.
func TestSetValidateIgnoresUnknownKeyType(t *testing.T) {
	good := Key{KeyType: "oct", K: "AAAA", KeyID: "a"}
	future := Key{KeyType: "AKP", KeyID: "pq"}
	if err := (&Set{Keys: []Key{future, good}}).Validate(); err != nil {
		t.Errorf("unknown kty next to a good key: %v", err)
	}
	if err := (&Set{Keys: []Key{future}}).Validate(); !errors.Is(err, ErrFormat) {
		t.Errorf("only unknown kty: error = %v, want ErrFormat", err)
	}
	// A known kty must still be well formed, and a missing or non-string
	// kty is malformed, not unknown.
	for name, bad := range map[string]Key{
		"known but malformed": {KeyType: "EC", Curve: "P-256", KeyID: "ec"},
		"no kty":              {KeyID: "none"},
		"kty not string":      {KeyType: 1, KeyID: "num"},
	} {
		if err := (&Set{Keys: []Key{future, good, bad}}).Validate(); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: error = %v, want ErrInvalidKey", name, err)
		}
	}
}
