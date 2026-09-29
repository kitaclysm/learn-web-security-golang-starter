package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	split := len(sealed) - aead.Overhead()
	ciphertext := sealed[:split]
	authTag := sealed[split:]

	return EncryptedPayload{Nonce: nonce, AuthTag: authTag, Ciphertext: ciphertext}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(payload.Nonce) != aesgcm.NonceSize() || len(payload.AuthTag) != aesgcm.Overhead() {
		return nil, fmt.Errorf("failed to decrypt: Nonce [%v] or AuthTag [%v] wrong size", len(payload.Nonce), len(payload.AuthTag))
	}
	combined := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	combined = append(combined, payload.Ciphertext...)
	combined = append(combined, payload.AuthTag...)
	plaintext, err := aesgcm.Open(nil, payload.Nonce, combined, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
