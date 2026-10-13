package jwe

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// defaultIV is the RFC 3394 §2.2.3.1 initial value.
var defaultIV = [8]byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

var errKeyUnwrap = errors.New("jwe: key unwrap failed")

// wrapKey implements the AES Key Wrap algorithm.
//
// https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.1
func wrapKey(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("jwe: key to wrap must be a multiple of 8 bytes and at least 16, got %d", len(plaintext))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plaintext) / 8
	r := make([]byte, len(plaintext))
	copy(r, plaintext)
	a := defaultIV
	var buf [16]byte
	for j := range 6 {
		for i := range n {
			copy(buf[:8], a[:])
			copy(buf[8:], r[i*8:i*8+8])
			block.Encrypt(buf[:], buf[:])
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(buf[:8])^t)
			copy(r[i*8:], buf[8:])
		}
	}
	return append(a[:], r...), nil
}

// unwrapKey implements the AES Key Unwrap algorithm, checking the integrity
// value in constant time.
//
// https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.2
func unwrapKey(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, errKeyUnwrap
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errKeyUnwrap
	}
	n := len(ciphertext)/8 - 1
	var a [8]byte
	copy(a[:], ciphertext[:8])
	r := make([]byte, n*8)
	copy(r, ciphertext[8:])
	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(a[:])^t)
			copy(buf[8:], r[i*8:i*8+8])
			block.Decrypt(buf[:], buf[:])
			copy(a[:], buf[:8])
			copy(r[i*8:], buf[8:])
		}
	}
	if subtle.ConstantTimeCompare(a[:], defaultIV[:]) != 1 {
		return nil, errKeyUnwrap
	}
	return r, nil
}

// concatKDF derives keyLen bytes from the shared secret z with the
// single-step KDF of NIST SP 800-56A, using SHA-256 and the OtherInfo layout
// JOSE specifies: AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo.
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2
func concatKDF(z []byte, algorithmID string, apu, apv []byte, keyLen int) []byte {
	lengthPrefixed := func(b []byte) []byte {
		out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
		return append(out, b...)
	}
	var otherInfo []byte
	otherInfo = append(otherInfo, lengthPrefixed([]byte(algorithmID))...)
	otherInfo = append(otherInfo, lengthPrefixed(apu)...)
	otherInfo = append(otherInfo, lengthPrefixed(apv)...)
	otherInfo = binary.BigEndian.AppendUint32(otherInfo, uint32(keyLen*8))

	out := make([]byte, 0, keyLen+sha256.Size)
	for counter := uint32(1); len(out) < keyLen; counter++ {
		h := sha256.New()
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)
		h.Write(c[:])
		h.Write(z)
		h.Write(otherInfo)
		out = h.Sum(out)
	}
	return out[:keyLen]
}
