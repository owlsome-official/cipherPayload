package cipherPayload

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// GCMEncryption implements Cipher using AES-GCM with a random 12-byte nonce per message.
// Wire format: base64( nonce[12] || ciphertext || tag[16] )
// Compatible with encrypt-tools (JS/TS) encryptGCM without AAD.
type GCMEncryption struct {
	keys   KeyPairs
	logger logger
}

func (g *GCMEncryption) Encrypt(plainText string) (string, error) {
	svc := "Encryption - AES-GCM - Encrypt"
	g.logger.printf("info", svc)

	if plainText == "" {
		return "", nil
	}

	block, err := aes.NewCipher(g.keys.AESKeyForEncrypt)
	if err != nil {
		g.logger.printf("error", svc, err)
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		g.logger.printf("error", svc, err)
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		g.logger.printf("error", svc, err)
		return "", err
	}

	// Seal appends ciphertext+tag to nonce, producing: nonce || ciphertext || tag
	sealed := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)

	cipherText := base64.StdEncoding.EncodeToString(sealed)
	g.logger.printf("debug", "Encrypted:", cipherText)
	return cipherText, nil
}

func (g *GCMEncryption) Decrypt(encryptedText string) (string, error) {
	svc := "Encryption - AES-GCM - Decrypt"
	g.logger.printf("info", svc)

	if encryptedText == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		g.logger.printf("error", svc, err)
		return "", err
	}

	block, err := aes.NewCipher(g.keys.AESKeyForDecrypt)
	if err != nil {
		g.logger.printf("error", svc, err)
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		g.logger.printf("error", svc, err)
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize+aesGCM.Overhead() {
		g.logger.printf("error", svc, ErrCiphertextTooShort)
		return "", ErrCiphertextTooShort
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		g.logger.printf("error", svc, ErrAuthenticationFailed)
		return "", ErrAuthenticationFailed
	}

	result := string(plaintext)
	g.logger.printf("debug", "Decrypted:", result)
	return result, nil
}
