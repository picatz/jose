package jwe

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/picatz/jose/pkg/jwa"
)

// RFC 7518 Appendix B.1 to B.3: AES_CBC_HMAC_SHA2 known-answer tests at the
// content-encryption level. The hex values were taken as data from the
// iotaledger/crypto.rs test fixtures (which cite the RFC); the B.3
// ciphertext was also compared against go-jose's copy of the same vector.
var cbcHMACVectors = []struct {
	name                                     string
	enc                                      jwa.ContentEncryption
	key, iv, aad, plaintext, ciphertext, tag string
}{
	{"B.1", jwa.A128CBCHS256,
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"1af38c2dc2b96ffdd86694092341bc04",
		"546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
		"41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
		"c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db",
		"652c3fa36b0a7c5b3219fab3a30bc1c4",
	},
	{"B.2", jwa.A192CBCHS384,
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		"1af38c2dc2b96ffdd86694092341bc04",
		"546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
		"41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
		"ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b226d1746214bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c2105bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927f280adc91ac0c4e79c7b11efc60054e3",
		"8490ac0e58949bfe51875d733f93ac2075168039ccc733d7",
	},
	{"B.3", jwa.A256CBCHS512,
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		"1af38c2dc2b96ffdd86694092341bc04",
		"546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
		"41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
		"4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f6",
		"4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5",
	},
}

func TestRFC7518AppendixBContentEncryption(t *testing.T) {
	for _, v := range cbcHMACVectors {
		t.Run(string(v.enc), func(t *testing.T) {
			dec := func(s string) []byte {
				b, err := hex.DecodeString(s)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			key, iv, aad, plaintext := dec(v.key), dec(v.iv), dec(v.aad), dec(v.plaintext)
			wantCiphertext, wantTag := dec(v.ciphertext), dec(v.tag)

			c, err := contentCipherFor(v.enc)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, tag, err := c.seal(key, iv, plaintext, aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ciphertext, wantCiphertext) || !bytes.Equal(tag, wantTag) {
				t.Fatalf("seal:\n ciphertext %x\n want       %x\n tag %x\n want %x", ciphertext, wantCiphertext, tag, wantTag)
			}
			got, err := c.open(key, iv, wantCiphertext, wantTag, aad)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("open = %q, %v", got, err)
			}
			bad := append([]byte(nil), wantTag...)
			bad[0] ^= 1
			if _, err := c.open(key, iv, wantCiphertext, bad, aad); !errors.Is(err, errDecryption) {
				t.Fatalf("bad tag: err = %v", err)
			}
		})
	}
}
