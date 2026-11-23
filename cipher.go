package cipherPayload

import "errors"

// CipherMode defines the encryption algorithm used by the middleware.
type CipherMode string

const (
	// ModeGCM uses AES-GCM with a random 12-byte nonce per message (authenticated encryption).
	ModeGCM CipherMode = "gcm"

	// ModeCBC uses AES-CBC with PKCS#7 padding and a fixed IV from KeyPairs (legacy).
	ModeCBC CipherMode = "cbc"
)

// Cipher is the primary encryption interface for v2.
// Implementations must be safe for concurrent use.
type Cipher interface {
	Encrypt(plainText string) (string, error)
	Decrypt(encryptedText string) (string, error)
}

var (
	// ErrCiphertextTooShort indicates the ciphertext is shorter than nonce + tag.
	ErrCiphertextTooShort = errors.New("ciphertext too short")

	// ErrAuthenticationFailed indicates GCM authentication tag verification failed.
	ErrAuthenticationFailed = errors.New("authentication failed: ciphertext has been tampered with")

	// ErrInvalidCipherMode indicates an unsupported cipher mode was provided.
	ErrInvalidCipherMode = errors.New("invalid cipher mode: use ModeGCM or ModeCBC")

	// ErrInvalidKeySize indicates the AES key is not 16, 24, or 32 bytes.
	ErrInvalidKeySize = errors.New("invalid AES key size: must be 16, 24, or 32 bytes")
)

// NewCipher creates a Cipher for the given mode.
// For ModeGCM, only AESKeyForEncrypt and AESKeyForDecrypt in KeyPairs are used;
// IV fields are ignored because GCM generates a random nonce per message.
// For ModeCBC, all four KeyPairs fields (key + IV) are required.
func NewCipher(mode CipherMode, keys KeyPairs, debugMode ...bool) Cipher {
	isShowLog := false
	if len(debugMode) > 0 {
		isShowLog = debugMode[0]
	}
	l := newLogger(isShowLog)

	switch mode {
	case ModeGCM:
		return &GCMEncryption{keys: keys, logger: l}
	case ModeCBC:
		return &CBCEncryption{keys: keys, logger: l}
	default:
		return &GCMEncryption{keys: keys, logger: l}
	}
}
