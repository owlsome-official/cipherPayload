package cipherPayload

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGCMEncryptDecryptRoundTrip(t *testing.T) {
	gcmKeys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"short text", "hello"},
		{"JSON payload", `{"firstname":"Chinnawat","lastname":"Chimdee"}`},
		{"unicode", "สวัสดีครับ 🇹🇭"},
		{"long payload", string(make([]byte, 4096))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCipher(ModeGCM, gcmKeys)
			encrypted, err := c.Encrypt(tt.plaintext)
			require.NoError(t, err)
			require.NotEmpty(t, encrypted)

			decrypted, err := c.Decrypt(encrypted)
			require.NoError(t, err)
			require.Equal(t, tt.plaintext, decrypted)
		})
	}
}

func TestGCMEncryptEmptyString(t *testing.T) {
	gcmKeys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher(ModeGCM, gcmKeys)

	result, err := c.Encrypt("")
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestGCMDecryptEmptyString(t *testing.T) {
	gcmKeys := KeyPairs{
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher(ModeGCM, gcmKeys)

	result, err := c.Decrypt("")
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestGCMEncryptProducesUniqueNonce(t *testing.T) {
	gcmKeys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher(ModeGCM, gcmKeys)
	plaintext := "same input every time"

	enc1, err := c.Encrypt(plaintext)
	require.NoError(t, err)

	enc2, err := c.Encrypt(plaintext)
	require.NoError(t, err)

	require.NotEqual(t, enc1, enc2, "same plaintext must produce different ciphertext (random nonce)")

	raw1, _ := base64.StdEncoding.DecodeString(enc1)
	raw2, _ := base64.StdEncoding.DecodeString(enc2)
	nonce1 := raw1[:12]
	nonce2 := raw2[:12]
	require.NotEqual(t, nonce1, nonce2, "nonces must be different")
}

func TestGCMDecryptTamperedCiphertext(t *testing.T) {
	gcmKeys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher(ModeGCM, gcmKeys)

	encrypted, err := c.Encrypt("secret data")
	require.NoError(t, err)

	raw, err := base64.StdEncoding.DecodeString(encrypted)
	require.NoError(t, err)

	// flip a byte in ciphertext area (after nonce)
	raw[15] ^= 0xff
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err = c.Decrypt(tampered)
	require.ErrorIs(t, err, ErrAuthenticationFailed)
}

func TestGCMDecryptCiphertextTooShort(t *testing.T) {
	gcmKeys := KeyPairs{
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher(ModeGCM, gcmKeys)

	short := base64.StdEncoding.EncodeToString(make([]byte, 10))
	_, err := c.Decrypt(short)
	require.ErrorIs(t, err, ErrCiphertextTooShort)
}

func TestGCMDecryptInvalidBase64(t *testing.T) {
	gcmKeys := KeyPairs{
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher(ModeGCM, gcmKeys)

	_, err := c.Decrypt("!!!not-base64!!!")
	require.Error(t, err)
}

func TestGCMInvalidKeySize(t *testing.T) {
	badKeys := KeyPairs{
		AESKeyForEncrypt: []byte("short"),
	}
	c := NewCipher(ModeGCM, badKeys)

	_, err := c.Encrypt("test")
	require.Error(t, err)
}

func TestGCMDecryptWrongKey(t *testing.T) {
	encKeys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
	}
	decKeys := KeyPairs{
		AESKeyForDecrypt: []byte("99999999999999999999999999999999"),
	}

	cEnc := NewCipher(ModeGCM, encKeys)
	encrypted, err := cEnc.Encrypt("secret")
	require.NoError(t, err)

	cDec := NewCipher(ModeGCM, decKeys)
	_, err = cDec.Decrypt(encrypted)
	require.ErrorIs(t, err, ErrAuthenticationFailed)
}

func TestGCMWireFormatLayout(t *testing.T) {
	gcmKeys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESKeyForDecrypt: []byte("12345678901234567890123456789012"),
	}
	c := NewCipher(ModeGCM, gcmKeys)

	encrypted, err := c.Encrypt("hello")
	require.NoError(t, err)

	raw, err := base64.StdEncoding.DecodeString(encrypted)
	require.NoError(t, err)

	// wire format: nonce(12) + ciphertext(5) + tag(16) = at least 33 bytes for "hello"
	require.GreaterOrEqual(t, len(raw), 12+16+1, "must contain nonce + tag + at least 1 byte ciphertext")

	// first 12 bytes are nonce
	nonce := raw[:12]
	require.Len(t, nonce, 12)
}

func TestGCMDualKeyPairsEncryptDecrypt(t *testing.T) {
	keys := KeyPairs{
		AESKeyForEncrypt: []byte("12345678901234567890123456789012"),
		AESKeyForDecrypt: []byte("67890123456789012345678901234567"),
	}

	cEnc := NewCipher(ModeGCM, KeyPairs{
		AESKeyForEncrypt: keys.AESKeyForEncrypt,
		AESKeyForDecrypt: keys.AESKeyForEncrypt,
	})
	encrypted, err := cEnc.Encrypt(`{"data":"test"}`)
	require.NoError(t, err)

	cDec := NewCipher(ModeGCM, KeyPairs{
		AESKeyForEncrypt: keys.AESKeyForDecrypt,
		AESKeyForDecrypt: keys.AESKeyForEncrypt,
	})
	decrypted, err := cDec.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, `{"data":"test"}`, decrypted)
}

func TestGCMKeySizes(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{"AES-128 (16 bytes)", 16, false},
		{"AES-192 (24 bytes)", 24, false},
		{"AES-256 (32 bytes)", 32, false},
		{"Invalid (15 bytes)", 15, true},
		{"Invalid (20 bytes)", 20, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			for i := range key {
				key[i] = byte('A' + i%26)
			}
			c := NewCipher(ModeGCM, KeyPairs{
				AESKeyForEncrypt: key,
				AESKeyForDecrypt: key,
			})

			encrypted, err := c.Encrypt("test")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			decrypted, err := c.Decrypt(encrypted)
			require.NoError(t, err)
			require.Equal(t, "test", decrypted)
		})
	}
}
