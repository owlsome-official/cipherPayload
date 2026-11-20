package cipherPayload

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	aesKeyForEncrypt []byte
	aesKeyForDecrypt []byte

	keys KeyPairs
)

func init() {
	setAValidConfig()
}

func setAValidConfig() {
	aesKeyForEncrypt = []byte("12345678901234567890123456789012")
	aesKeyForDecrypt = []byte("67890123456789012345678901234567")

	keys = KeyPairs{
		AESKeyForEncrypt: aesKeyForEncrypt,
		AESKeyForDecrypt: aesKeyForDecrypt,
	}
}

// loopbackKeys decrypts what keys encrypts, like a client talking to itself.
func loopbackKeys() KeyPairs {
	return KeyPairs{
		AESKeyForEncrypt: aesKeyForDecrypt,
		AESKeyForDecrypt: aesKeyForDecrypt,
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	setAValidConfig()
	d := NewAESEncryption(loopbackKeys())

	sealed, err := d.Encrypt("1234567890121")
	require.NoError(t, err)

	opened, err := d.Decrypt(sealed)
	require.NoError(t, err)
	require.Equal(t, "1234567890121", opened)
}

func TestEncryptIsRandomized(t *testing.T) {
	setAValidConfig()
	d := NewAESEncryption(keys)

	first, err := d.Encrypt("1234567890121")
	require.NoError(t, err)
	second, err := d.Encrypt("1234567890121")
	require.NoError(t, err)

	require.NotEqual(t, first, second)
}

func TestDecryptRejectsTamperedOrTruncatedPayload(t *testing.T) {
	setAValidConfig()
	d := NewAESEncryption(loopbackKeys())

	sealed, err := d.Encrypt(`{"taxId":"1234567890121"}`)
	require.NoError(t, err)
	raw, err := base64.StdEncoding.DecodeString(sealed)
	require.NoError(t, err)

	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0x01
	truncated := raw[:len(raw)-1]

	for name, payload := range map[string][]byte{"tampered": tampered, "truncated": truncated} {
		t.Run(name, func(t *testing.T) {
			opened, err := d.Decrypt(base64.StdEncoding.EncodeToString(payload))
			require.ErrorIs(t, err, ErrInvalidCiphertext)
			require.Empty(t, opened)
		})
	}

	t.Run("wrong key", func(t *testing.T) {
		wrongKey := KeyPairs{AESKeyForDecrypt: aesKeyForEncrypt}
		opened, err := NewAESEncryption(wrongKey).Decrypt(sealed)
		require.ErrorIs(t, err, ErrInvalidCiphertext)
		require.Empty(t, opened)
	})
}

type testCaseEncryption struct {
	name     string
	input    string
	expected string
}

func TestEncryptionAES(t *testing.T) {
	setAValidConfig()

	tests := []testCaseEncryption{
		{
			name:     "Encryption Success",
			input:    "1234567890121",
			expected: "",
		},
		{
			name:     "Encryption Success - Empty Case",
			input:    "",
			expected: "SOMETHING ELSE",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := test.input
			expected := test.expected

			d := NewAESEncryption(keys, false)
			actual, _ := d.Encrypt(input)

			require.NotEqual(t, expected, actual)
		})
	}

	setAValidConfig()
	// Fail Case
	aesKeyPairsBackup := keys
	t.Run("Fail Case", func(t *testing.T) {
		keys = KeyPairs{}
		input := "smtg"

		d := NewAESEncryption(keys)
		_, err := d.Encrypt(input)

		require.Error(t, err)
	})
	keys = aesKeyPairsBackup
}

func TestDecryptionAES(t *testing.T) {
	setAValidConfig()

	tests := []testCaseEncryption{
		{
			name:     "Decryption Success - Empty Case",
			input:    "",
			expected: "",
		},
		{
			name:     "Decryption Fail - Invalid",
			input:    "y/hNE1N17iI",
			expected: "",
		},
		{
			name:     "Decryption Failed",
			input:    "a",
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := test.input
			expected := test.expected

			d := NewAESEncryption(keys)
			actual, _ := d.Decrypt(input)

			require.Equal(t, expected, actual)
		})
	}

	setAValidConfig()
	// Fail Case
	aesKeyPairsBackup := keys
	t.Run("Fail Case", func(t *testing.T) {
		keys = KeyPairs{}
		input := "smtg"

		d := NewAESEncryption(keys)
		_, err := d.Decrypt(input)

		require.Error(t, err)
	})
	keys = aesKeyPairsBackup
}
