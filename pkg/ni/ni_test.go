package ni_test

import (
	"crypto"
	"errors"
	"testing"

	"github.com/picatz/jose/pkg/ni"
)

// https://www.rfc-editor.org/rfc/rfc6920.html#section-8.1
const helloWorld = "ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk"

func TestSumRFC6920Example(t *testing.T) {
	u, err := ni.Sum(crypto.SHA256, []byte("Hello World!"))
	if err != nil {
		t.Fatal(err)
	}
	if got := u.String(); got != helloWorld {
		t.Fatalf("String() = %q, want %q", got, helloWorld)
	}
	if !u.Matches([]byte("Hello World!")) || u.Matches([]byte("Hello World?")) {
		t.Fatal("Matches() disagrees with the digest")
	}
}

func TestParse(t *testing.T) {
	u, err := ni.Parse("NI://example.com/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk")
	if err != nil {
		t.Fatal(err)
	}
	if u.Authority != "example.com" || u.Hash != crypto.SHA256 || !u.Matches([]byte("Hello World!")) {
		t.Fatalf("Parse() = %+v", u)
	}
	if got, want := u.String(), "ni://example.com/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}

	for _, h := range []crypto.Hash{crypto.SHA384, crypto.SHA512, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512} {
		sum, err := ni.Sum(h, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		again, err := ni.Parse(sum.String())
		if err != nil || !again.Matches([]byte("x")) {
			t.Fatalf("round trip of %v: %v", h, err)
		}
	}
}

func TestParseRefusals(t *testing.T) {
	for name, input := range map[string]string{
		"empty":           "",
		"other scheme":    "nih:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
		"no path":         "ni://example.com",
		"no separator":    "ni:///sha-256f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
		"truncated alg":   "ni:///sha-256-32;f4OxZQ",
		"unknown alg":     "ni:///md5;XrY7u-Ae7tCTyyK7j1rNww",
		"uppercase alg":   "ni:///SHA-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
		"padding":         "ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk=",
		"standard base64": "ni:///sha-256;f4OxZX/x/FO5LcGBSKHWXfwtSx+j1ncoSt3SABJtkGk",
		"short digest":    "ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkA",
		"query":           helloWorld + "?ct=text/plain",
		"fragment":        helloWorld + "#x",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ni.Parse(input); !errors.Is(err, ni.ErrFormat) {
				t.Fatalf("Parse(%q) error = %v, want ErrFormat", input, err)
			}
		})
	}
}

func TestUnsupportedHash(t *testing.T) {
	if _, err := ni.Sum(crypto.SHA1, nil); err == nil {
		t.Fatal("Sum() accepted SHA-1")
	}
	if (ni.URI{Hash: crypto.SHA1, Digest: make([]byte, 20)}).Matches(nil) {
		t.Fatal("Matches() accepted SHA-1")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(helloWorld)
	f.Fuzz(func(t *testing.T, input string) {
		u, err := ni.Parse(input)
		if err != nil {
			return
		}
		again, err := ni.Parse(u.String())
		if err != nil || again.String() != u.String() {
			t.Fatalf("canonical form %q does not round trip: %v", u.String(), err)
		}
	})
}
