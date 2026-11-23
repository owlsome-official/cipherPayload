package cipherPayload

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCipherGCM(t *testing.T) {
	keys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher(ModeGCM, keys)
	require.IsType(t, &GCMEncryption{}, c)

	encrypted, err := c.Encrypt("test")
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, "test", decrypted)
}

func TestNewCipherCBC(t *testing.T) {
	keys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESIVForEncrypt:  []byte("1234567890123456"),
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
		AESIVForDecrypt:  []byte("1234567890123456"),
	}
	c := NewCipher(ModeCBC, keys)
	require.IsType(t, &CBCEncryption{}, c)

	encrypted, err := c.Encrypt("test")
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, "test", decrypted)
}

func TestNewCipherDefaultMode(t *testing.T) {
	keys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher("", keys)
	require.IsType(t, &GCMEncryption{}, c, "unknown mode should default to GCM")
}

func TestNewCipherWithDebugMode(t *testing.T) {
	keys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher(ModeGCM, keys, true)
	require.IsType(t, &GCMEncryption{}, c)

	encrypted, err := c.Encrypt("debug test")
	require.NoError(t, err)

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, "debug test", decrypted)
}

func TestNewAESEncryptionBackwardCompat(t *testing.T) {
	keys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESIVForEncrypt:  []byte("1234567890123456"),
		AESKeyForDecrypt: []byte("67890123456789012345678901234567"),
		AESIVForDecrypt:  []byte("6789012345678901"),
	}

	aesImpl := NewAESEncryption(keys)
	require.IsType(t, &CBCEncryption{}, aesImpl, "NewAESEncryption must return CBCEncryption for backward compat")

	encrypted, err := aesImpl.Encrypt("1234567890121")
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)
}

func TestCBCBackwardCompatKnownVector(t *testing.T) {
	keys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESIVForEncrypt:  []byte("1234567890123456"),
		AESKeyForDecrypt: []byte("67890123456789012345678901234567"),
		AESIVForDecrypt:  []byte("6789012345678901"),
	}

	cbc := NewCipher(ModeCBC, keys)

	// Known decryption vector from v1 tests
	decrypted, err := cbc.Decrypt("ldQtpqnEQarFB3RK1JMqSA==")
	require.NoError(t, err)
	require.Equal(t, "1234567890121", decrypted)
}

func TestGCMAndCBCPayloadsAreNotInterchangeable(t *testing.T) {
	sameKey := []byte("12345678901234567890123456789012")
	sameIV := []byte("1234567890123456")
	plaintext := "test payload"

	cbcKeys := KeyPairs{
		AESKeyForEncrypt: sameKey,
		AESIVForEncrypt:  sameIV,
		AESKeyForDecrypt: sameKey,
		AESIVForDecrypt:  sameIV,
	}
	gcmKeys := KeyPairs{
		AESKeyForEncrypt: sameKey,
		AESKeyForDecrypt: sameKey,
	}

	cbcCipher := NewCipher(ModeCBC, cbcKeys)
	gcmCipher := NewCipher(ModeGCM, gcmKeys)

	cbcEnc, err := cbcCipher.Encrypt(plaintext)
	require.NoError(t, err)

	gcmEnc, err := gcmCipher.Encrypt(plaintext)
	require.NoError(t, err)

	// GCM rejects CBC payload (authenticated: always detects wrong format)
	_, err = gcmCipher.Decrypt(cbcEnc)
	require.Error(t, err)

	// CBC may decode GCM payload to garbage (unauthenticated) or error on padding
	result, err := cbcCipher.Decrypt(gcmEnc)
	if err == nil {
		require.NotEqual(t, plaintext, result, "CBC decrypting GCM payload must not recover original plaintext")
	}
}

func TestConfigDefaultModeIsGCM(t *testing.T) {
	require.Equal(t, ModeGCM, ConfigDefault.Mode, "v2 default must be GCM")
}

func TestConfigDefaultFillsMode(t *testing.T) {
	cfg := configDefault(Config{})
	require.Equal(t, ModeGCM, cfg.Mode, "empty Mode must default to GCM")
}
