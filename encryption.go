package cipherPayload

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

var (
	// ErrInvalidCiphertext indicates the payload is not valid base64 or fails
	// authentication (tampered, truncated, or sealed with another key).
	ErrInvalidCiphertext = errors.New("invalid ciphertext")

	// Deprecated: no longer returned; payloads are sealed with AES-GCM.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// Deprecated: no longer returned; payloads are sealed with AES-GCM.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// Deprecated: no longer returned; payloads are sealed with AES-GCM.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

type AES interface {
	Encrypt(plainText string) (string, error)
	Decrypt(encryptedText string) (string, error)
}

// DefaultAESEncryption seals payloads with AES-GCM. Every message gets a fresh
// random 96-bit nonce, so the encoded output is base64(nonce || ciphertext || tag).
// A key must not seal more than 2^32 messages, to keep nonce collisions negligible.
type DefaultAESEncryption struct {
	keys   KeyPairs
	logger logger
}

func NewAESEncryption(keys KeyPairs, debugMode ...bool) AES {
	isShowLog := false
	if len(debugMode) > 0 {
		isShowLog = bool(debugMode[0])
	}
	logger := newLogger(isShowLog)
	return &DefaultAESEncryption{
		keys:   keys,
		logger: logger,
	}
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func (d *DefaultAESEncryption) Encrypt(plainText string) (string, error) {
	serviceName := "Encryption - AES - Encrypt"
	d.logger.printf("info", serviceName)

	if plainText == "" {
		return "", nil
	}

	aead, err := newAEAD(d.keys.AESKeyForEncrypt)
	if err != nil {
		d.logger.printf("error", serviceName, err)
		return "", err
	}

	sealed := aead.Seal(nil, nil, []byte(plainText), nil)

	cipherText := base64.StdEncoding.EncodeToString(sealed)
	d.logger.printf("debug", "Encrypted:", cipherText)
	return cipherText, nil
}

func (d *DefaultAESEncryption) Decrypt(encryptedText string) (string, error) {
	serviceName := "Encryption - AES - Decrypt"
	d.logger.printf("info", serviceName)

	if encryptedText == "" {
		return "", nil
	}

	aead, err := newAEAD(d.keys.AESKeyForDecrypt)
	if err != nil {
		d.logger.printf("error", serviceName, err)
		return "", err
	}

	sealed, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		d.logger.printf("error", serviceName, err)
		return "", ErrInvalidCiphertext
	}

	out, err := aead.Open(nil, nil, sealed, nil)
	if err != nil {
		d.logger.printf("error", serviceName, err)
		return "", ErrInvalidCiphertext
	}

	plainText := string(out)
	d.logger.printf("debug", "Decrypted:", plainText)
	return plainText, nil
}
