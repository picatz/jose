package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/picatz/jose/pkg/jwa"
)

// errDecryption is the single error every content decryption failure
// returns, so callers learn nothing about which check failed.
var errDecryption = errors.New("jwe: decryption failed")

// contentCipher is one "enc" algorithm.
type contentCipher struct {
	keySize int
	ivSize  int
	tagSize int
	seal    func(key, iv, plaintext, aad []byte) (ciphertext, tag []byte, err error)
	open    func(key, iv, ciphertext, tag, aad []byte) ([]byte, error)
}

func contentCipherFor(enc jwa.ContentEncryption) (contentCipher, error) {
	switch enc {
	case jwa.A128GCM:
		return gcmCipher(16), nil
	case jwa.A192GCM:
		return gcmCipher(24), nil
	case jwa.A256GCM:
		return gcmCipher(32), nil
	case jwa.A128CBCHS256:
		return cbcHMACCipher(16, 16, sha256.New), nil
	case jwa.A192CBCHS384:
		return cbcHMACCipher(24, 24, sha512.New384), nil
	case jwa.A256CBCHS512:
		return cbcHMACCipher(32, 32, sha512.New), nil
	default:
		return contentCipher{}, fmt.Errorf("%w: unsupported content encryption %q", ErrUnsupported, enc)
	}
}

// AES GCM with a 96-bit IV and a 128-bit tag.
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-5.3
func gcmCipher(keySize int) contentCipher {
	aead := func(key []byte) (cipher.AEAD, error) {
		if len(key) != keySize {
			return nil, fmt.Errorf("jwe: content key is %d bytes, want %d", len(key), keySize)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	return contentCipher{
		keySize: keySize,
		ivSize:  12,
		tagSize: 16,
		seal: func(key, iv, plaintext, aad []byte) ([]byte, []byte, error) {
			gcm, err := aead(key)
			if err != nil {
				return nil, nil, err
			}
			sealed := gcm.Seal(nil, iv, plaintext, aad)
			split := len(sealed) - gcm.Overhead()
			return sealed[:split], sealed[split:], nil
		},
		open: func(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
			gcm, err := aead(key)
			if err != nil || len(iv) != gcm.NonceSize() || len(tag) != gcm.Overhead() {
				return nil, errDecryption
			}
			sealed := make([]byte, 0, len(ciphertext)+len(tag))
			sealed = append(append(sealed, ciphertext...), tag...)
			plaintext, err := gcm.Open(nil, iv, sealed, aad)
			if err != nil {
				return nil, errDecryption
			}
			return plaintext, nil
		},
	}
}

// AES_CBC_HMAC_SHA2: AES-CBC with PKCS #7 padding, authenticated by a
// truncated HMAC over AAD || IV || ciphertext || AL.
//
// https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.2
func cbcHMACCipher(encKeySize, tagSize int, newHash func() hash.Hash) contentCipher {
	keySize := 2 * encKeySize
	authTag := func(macKey, aad, iv, ciphertext []byte) []byte {
		mac := hmac.New(newHash, macKey)
		mac.Write(aad)
		mac.Write(iv)
		mac.Write(ciphertext)
		var al [8]byte
		binary.BigEndian.PutUint64(al[:], uint64(len(aad))*8)
		mac.Write(al[:])
		return mac.Sum(nil)[:tagSize]
	}
	return contentCipher{
		keySize: keySize,
		ivSize:  aes.BlockSize,
		tagSize: tagSize,
		seal: func(key, iv, plaintext, aad []byte) ([]byte, []byte, error) {
			if len(key) != keySize {
				return nil, nil, fmt.Errorf("jwe: content key is %d bytes, want %d", len(key), keySize)
			}
			macKey, encKey := key[:encKeySize], key[encKeySize:]
			block, err := aes.NewCipher(encKey)
			if err != nil {
				return nil, nil, err
			}
			pad := aes.BlockSize - len(plaintext)%aes.BlockSize
			ciphertext := make([]byte, len(plaintext)+pad)
			copy(ciphertext, plaintext)
			for i := len(plaintext); i < len(ciphertext); i++ {
				ciphertext[i] = byte(pad)
			}
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, ciphertext)
			return ciphertext, authTag(macKey, aad, iv, ciphertext), nil
		},
		open: func(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
			if len(key) != keySize || len(iv) != aes.BlockSize || len(tag) != tagSize ||
				len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
				return nil, errDecryption
			}
			macKey, encKey := key[:encKeySize], key[encKeySize:]
			// Authenticate before touching the padding (encrypt-then-MAC).
			if !hmac.Equal(tag, authTag(macKey, aad, iv, ciphertext)) {
				return nil, errDecryption
			}
			block, err := aes.NewCipher(encKey)
			if err != nil {
				return nil, errDecryption
			}
			plaintext := make([]byte, len(ciphertext))
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
			pad := int(plaintext[len(plaintext)-1])
			if pad == 0 || pad > aes.BlockSize {
				return nil, errDecryption
			}
			var bad byte
			for _, b := range plaintext[len(plaintext)-pad:] {
				bad |= b ^ byte(pad)
			}
			if subtle.ConstantTimeByteEq(bad, 0) != 1 {
				return nil, errDecryption
			}
			return plaintext[:len(plaintext)-pad], nil
		},
	}
}
