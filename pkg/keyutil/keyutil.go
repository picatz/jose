package keyutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
)

// SymmetricKeysEqual checks if the given keys are the same.
func SymmetricKeysEqual(key1 []byte, key2 []byte) bool {
	return subtle.ConstantTimeCompare(key1, key2) == 1
}

// NewSymmetricKey generates a new symmetric key of the given size.
func NewSymmetricKey(size int) ([]byte, error) {
	key := make([]byte, size)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new symmetic key: %w", err)
	}

	return key, nil
}

// ParseRSAPublicKey parses the PEM encoded RSA public key from the given reader.
func ParseRSAPublicKey(r io.Reader) (*rsa.PublicKey, error) {
	keyBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA public key from reader: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode RSA Public key PEM block: %w", err)
	}

	var parsedKey any

	parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, certErr := x509.ParseCertificate(block.Bytes)
		if certErr == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, fmt.Errorf("failed to decode RSA public key: %w", certErr)
		}
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid type %T for parse RSA public key", parsedKey)
	}

	return publicKey, nil
}

// ParseRSAPrivateKey parses the PEM encoded RSA private key from the given reader.
func ParseRSAPrivateKey(r io.Reader) (*rsa.PrivateKey, error) {
	keyBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA private key from reader: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode RSA private key PEM block: %w", err)
	}

	var parsedKey any

	parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p8, p8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if p8Err == nil {
			parsedKey = p8
		} else {
			return nil, fmt.Errorf("failed to decode RSA private key: %w", err)
		}
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid type %T for parse RSA private key", parsedKey)
	}

	return privateKey, nil
}

// ParseECDSAPublicKey parses the PEM encoded ECDSA public key from the given reader.
func ParseECDSAPublicKey(r io.Reader) (*ecdsa.PublicKey, error) {
	keyBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read ECDSA public key from reader: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode ECDSA Public key PEM block: %w", err)
	}

	var parsedKey any

	parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, certErr := x509.ParseCertificate(block.Bytes)
		if certErr == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, fmt.Errorf("failed to decode ECDSA public key: %w", certErr)
		}
	}

	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid type %T for parse RSA public key", parsedKey)
	}

	return publicKey, nil
}

// ParseECDSAPrivateKey parses the PEM encoded ECDSA private key from the given reader.
func ParseECDSAPrivateKey(r io.Reader) (*ecdsa.PrivateKey, error) {
	keyBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read ECDSA private key from reader: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode ECDSA private key PEM block: %w", err)
	}

	var parsedKey any

	parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		p8, p8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if p8Err == nil {
			parsedKey = p8
		} else {
			return nil, fmt.Errorf("failed to decode ECDSA private key: %w", err)
		}
	}

	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid type %T for parse ECDSA private key", parsedKey)
	}

	return privateKey, nil
}

// ParseEdDSAPublicKey parses the PEM encoded Ed25519 public key from the given reader.
func ParseEdDSAPublicKey(r io.Reader) (ed25519.PublicKey, error) {
	keyBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read EdDSA public key from reader: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode EdDSA Public key PEM block: %w", err)
	}

	asn1PubKey := struct {
		ObjectIdentifier struct {
			ObjectIdentifier asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}{}

	_, err = asn1.Unmarshal(block.Bytes, &asn1PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EdDSA public key ANS.1")
	}

	return ed25519.PublicKey(asn1PubKey.PublicKey.Bytes), nil
}

// ParseEdDSAPrivateKey parses the PEM encoded Ed25519 private key from the given reader.
func ParseEdDSAPrivateKey(r io.Reader) (ed25519.PrivateKey, error) {
	keyBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read EdDSA private key from reader: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode EdDSA private key PEM block: %w", err)
	}

	asn1PrivKey := struct {
		Version          int
		ObjectIdentifier struct {
			ObjectIdentifier asn1.ObjectIdentifier
		}
		PrivateKey []byte
	}{}

	_, err = asn1.Unmarshal(block.Bytes, &asn1PrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EdDSA private key ANS.1")
	}

	seed := asn1PrivKey.PrivateKey[2:]
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid EdDSA seed length: %d", len(seed))
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

// ParsePrivateKey parses the PEM encoded private key from the given reader.
func ParsePrivateKey(r io.Reader) (any, error) {
	keyBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key from reader: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM block: %w", err)
	}

	var parsedKey any

	parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return parsedKey, nil
	}

	parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return parsedKey, nil
	}

	parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return parsedKey, nil
	}

	parsedKey, err = ParseEdDSAPrivateKey(bytes.NewReader(keyBytes))
	if err == nil {
		return parsedKey, nil
	}

	return nil, fmt.Errorf("failed to parse private key, unknown type")
}

// ParsePublicKey parses the PEM encoded public key from the given reader.
func ParsePublicKey(r io.Reader) (any, error) {
	keyBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key from reader: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM block: %w", err)
	}

	var parsedKey any

	parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return parsedKey, nil
	}

	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)
	if err == nil {
		return cert.PublicKey, nil
	}

	// parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	// if err == nil {
	// return parsedKey, nil
	// }

	parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return parsedKey, nil
	}

	parsedKey, err = ParseEdDSAPrivateKey(bytes.NewReader(keyBytes))
	if err == nil {
		return parsedKey, nil
	}

	return nil, fmt.Errorf("failed to parse public key, unknown type")
}

// NewRSAKeyPair returns a new RSA key pair, or an error if one occurs.
func NewRSAKeyPair() (*rsa.PublicKey, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new RSA key pair: %w", err)
	}

	return &privateKey.PublicKey, privateKey, nil
}

// NewECDSAKeyPair returns a new ECDSA key pair, or an error if one occurs.
func NewECDSAKeyPair() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new ECDSA key pair: %w", err)
	}

	return &privateKey.PublicKey, privateKey, nil
}

// NewEdDSAKeyPair returns a new EdDSA key pair, or an error if one occurs.
func NewEdDSAKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new EdDSA key pair: %w", err)
	}

	return publicKey, privateKey, nil
}
