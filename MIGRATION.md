# Migrating from v1 to v2

## Overview

CipherPayload v2.0.0 adds **AES-GCM** (authenticated encryption) as the **new default** cipher mode while keeping full backward compatibility with **AES-CBC** (legacy).

### What Changed

| Area | v1 | v2 |
|------|----|----|
| Default cipher mode | AES-CBC | **AES-GCM** |
| Module path | `github.com/owlsome-official/cipherPayload` | `github.com/owlsome-official/cipherPayload/v2` |
| Config | No `Mode` field | New `Mode` field (`ModeGCM` / `ModeCBC`) |
| IV fields in GCM mode | Required | Ignored (nonce is random per message) |
| Wire format (GCM) | N/A | `base64(nonce[12] \|\| ciphertext \|\| tag[16])` |
| Wire format (CBC) | `base64(ciphertext)` | Unchanged |
| Factory function | `NewAESEncryption` | `NewCipher` (old function still works, deprecated) |
| Interface | `AES` | `Cipher` (old interface still works, deprecated) |

---

## Step 1: Update Import Path

```diff
import (
-   "github.com/owlsome-official/cipherPayload"
+   cipherPayload "github.com/owlsome-official/cipherPayload/v2"
)
```

Update `go.mod`:

```bash
go get github.com/owlsome-official/cipherPayload/v2@latest
```

---

## Step 2a: Keep Existing CBC Behavior (Minimum Change)

If you are not ready to switch clients to GCM, add `Mode: cipherPayload.ModeCBC` to preserve v1 behavior:

```diff
app.Use(cipherPayload.New(cipherPayload.Config{
+   Mode: cipherPayload.ModeCBC,
    KeyPairs: cipherPayload.KeyPairs{
        AESKeyForEncrypt: []byte("..."),
        AESIVForEncrypt:  []byte("..."),
        AESKeyForDecrypt: []byte("..."),
        AESIVForDecrypt:  []byte("..."),
    },
}))
```

All existing encrypted payloads remain compatible. No client changes needed.

---

## Step 2b: Switch to GCM (Recommended)

GCM is the default, so you only need to provide keys (IV fields are optional and ignored):

```go
app.Use(cipherPayload.New(cipherPayload.Config{
    // Mode defaults to ModeGCM
    KeyPairs: cipherPayload.KeyPairs{
        AESKeyForEncrypt: []byte("YOUR_32_BYTE_KEY"),
        AESKeyForDecrypt: []byte("YOUR_32_BYTE_KEY"),
    },
}))
```

### Why GCM?

- **Authenticated encryption**: detects tampered or corrupted payloads (CBC does not)
- **No padding oracle**: GCM eliminates PKCS#7 padding attack surface
- **Random nonce**: same plaintext produces different ciphertext each time (CBC with fixed IV is deterministic)
- **Compatible with [encrypt-tools](https://encrypt-tools.vercel.app/)** AES-GCM mode

---

## Step 3: Standalone Cipher Usage

If you use the encryption API directly (outside the middleware):

```diff
- d := cipherPayload.NewAESEncryption(keys)
+ d := cipherPayload.NewCipher(cipherPayload.ModeGCM, keys)

encrypted, err := d.Encrypt(plaintext)
decrypted, err := d.Decrypt(encrypted)
```

`NewAESEncryption` still works but is deprecated and always creates a CBC cipher.

---

## Step 4: Coordinate Client Rollout

**CBC and GCM payloads are NOT interchangeable.** Both client and server must use the same mode.

### Recommended rollout strategy:

1. **Deploy server** with `Mode: cipherPayload.ModeCBC` (same as v1 behavior)
2. **Verify** all existing clients work correctly
3. **Update clients** to use AES-GCM encryption/decryption
4. **Switch server** to `Mode: cipherPayload.ModeGCM` (or remove Mode to use default)
5. **Remove** old IV configuration if no longer needed

### Wire format reference:

| Mode | Wire format | JSON payload |
|------|-------------|--------------|
| GCM | `base64(nonce[12B] \|\| ciphertext \|\| tag[16B])` | `{"payload":"..."}` |
| CBC | `base64(PKCS7-padded ciphertext)` | `{"payload":"..."}` |

---

## Deprecated APIs

| Deprecated | Replacement |
|------------|-------------|
| `NewAESEncryption(keys)` | `NewCipher(ModeCBC, keys)` |
| `AES` interface | `Cipher` interface |
| `DefaultAESEncryption` struct | `CBCEncryption` struct |

Deprecated APIs will be removed in v3.
