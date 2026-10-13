package jwe

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3394 §4.1 and §4.6.
func TestKeyWrapVectors(t *testing.T) {
	for _, tc := range []struct{ kek, key, wrapped string }{
		{
			"000102030405060708090A0B0C0D0E0F",
			"00112233445566778899AABBCCDDEEFF",
			"1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5",
		},
		{
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21",
		},
	} {
		kek, key, want := unhex(t, tc.kek), unhex(t, tc.key), unhex(t, tc.wrapped)
		got, err := wrapKey(kek, key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("wrap = %X, want %X", got, want)
		}
		back, err := unwrapKey(kek, got)
		if err != nil || !bytes.Equal(back, key) {
			t.Fatalf("unwrap = %X, %v", back, err)
		}
		got[0] ^= 1
		if _, err := unwrapKey(kek, got); err == nil {
			t.Fatal("unwrapped a tampered key")
		}
	}
}
