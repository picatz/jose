package base64url

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, in := range [][]byte{nil, {}, {0}, {0xff, 0xfe}, []byte("hello world"), bytes.Repeat([]byte{0xfb, 0xff}, 50)} {
		s := Encode(in)
		out, err := Decode(s)
		if err != nil {
			t.Fatalf("Decode(%q): %v", s, err)
		}
		if !bytes.Equal(in, out) {
			t.Fatalf("round trip %x -> %q -> %x", in, s, out)
		}
	}
	if Encode(nil) != "" {
		t.Fatal("empty input must encode to empty string")
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, s := range []string{"YQ==", "YQ=", "Y", "a+b/", "YR", "YQ Q"} {
		if _, err := Decode(s); err == nil {
			t.Errorf("Decode(%q) succeeded, want error", s)
		}
	}
	if b, err := Decode("YQ"); err != nil || string(b) != "a" {
		t.Errorf("Decode(YQ) = %q, %v", b, err)
	}
}

func TestDecodeRejectsLineBreaks(t *testing.T) {
	for _, s := range []string{"Y\nQ", "YQ\n", "Y\rQ", "\r\nYQ", "YW\r\nJj"} {
		if _, err := Decode(s); err == nil {
			t.Errorf("Decode(%q) succeeded, want error", s)
		}
	}
}
