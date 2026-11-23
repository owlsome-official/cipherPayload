package cipherPayload

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

// AES is the legacy interface kept for backward compatibility.
// Deprecated: Use Cipher interface with NewCipher instead.
type AES interface {
	Encrypt(plainText string) (string, error)
	Decrypt(encryptedText string) (string, error)
	pkcs7Unpad(b []byte, blocksize int) ([]byte, error)
	pkcs7Pad(b []byte, blocksize int) ([]byte, error)
}

// CBCEncryption implements both Cipher and AES using AES-CBC with PKCS#7 padding.
type CBCEncryption struct {
	keys   KeyPairs
	logger logger
}

// NewAESEncryption creates a CBC cipher.
// Deprecated: Use NewCipher(ModeCBC, keys, debugMode...) instead.
func NewAESEncryption(keys KeyPairs, debugMode ...bool) AES {
	isShowLog := false
	if len(debugMode) > 0 {
		isShowLog = debugMode[0]
	}
	logger := newLogger(isShowLog)
	return &CBCEncryption{
		keys:   keys,
		logger: logger,
	}
}

func (d *CBCEncryption) Encrypt(plainText string) (string, error) {
	serviceName := "Encryption - AES-CBC - Encrypt"
	d.logger.printf("info", serviceName)

	if plainText == "" {
		return "", nil
	}

	byteText := []byte(plainText)
	block, err := aes.NewCipher(d.keys.AESKeyForEncrypt)
	if err != nil {
		d.logger.printf("error", serviceName, err)
		return "", err
	}

	defer recoveryCatch()
	byteText, _ = d.pkcs7Pad(byteText, block.BlockSize())

	ciphertext := make([]byte, len(byteText))

	bm := cipher.NewCBCEncrypter(block, d.keys.AESIVForEncrypt)
	bm.CryptBlocks(ciphertext, byteText)

	cipherText := base64.StdEncoding.EncodeToString(ciphertext)
	d.logger.printf("debug", "Encrypted:", cipherText)
	return cipherText, nil
}

func (d *CBCEncryption) Decrypt(encryptedText string) (string, error) {
	serviceName := "Encryption - AES-CBC - Decrypt"
	d.logger.printf("info", serviceName)

	if encryptedText == "" {
		return "", nil
	}
	ciphertext, _ := base64.StdEncoding.DecodeString(encryptedText)
	block, err := aes.NewCipher(d.keys.AESKeyForDecrypt)
	if err != nil {
		d.logger.printf("error", serviceName, err)
		return "", err
	}

	defer recoveryCatch()
	bm := cipher.NewCBCDecrypter(block, d.keys.AESIVForDecrypt)
	bm.CryptBlocks(ciphertext, ciphertext)

	out, err := d.pkcs7Unpad(ciphertext, aes.BlockSize)
	if err != nil {
		d.logger.printf("error", serviceName, err)
		return "", err
	}

	plainText := string(out)
	d.logger.printf("debug", "Decrypted:", plainText)
	return plainText, nil
}

func (d CBCEncryption) pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

func (d CBCEncryption) pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}
