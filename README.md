# CipherPayload

[![made-with-Go](https://img.shields.io/badge/Made%20with-Go-1f425f.svg)](http://golang.org) [![Go Reference](https://pkg.go.dev/badge/github.com/owlsome-official/cipherPayload/v2@v2.0.0.svg)](https://pkg.go.dev/github.com/owlsome-official/cipherPayload/v2@v2.0.0) [![GitHub issues](https://img.shields.io/github/issues/owlsome-official/cipherPayload)](https://github.com/owlsome-official/cipherPayload/issues) [![GitHub forks](https://img.shields.io/github/forks/owlsome-official/cipherPayload)](https://github.com/owlsome-official/cipherPayload/network) [![GitHub stars](https://img.shields.io/github/stars/owlsome-official/cipherPayload)](https://github.com/owlsome-official/cipherPayload/stargazers)

CipherPayload middleware for Fiber that encrypts and decrypts JSON payload in request and response body using **AES-GCM** (default, authenticated encryption) or **AES-CBC** (legacy).

> **v2.0.0 Breaking Change:** Default cipher mode changed from AES-CBC to AES-GCM. See [MIGRATION.md](./MIGRATION.md) for upgrade guide.

## Table of Contents

- [CipherPayload](#cipherpayload)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
    - [AES-GCM (Default, Recommended)](#aes-gcm-default-recommended)
    - [AES-CBC (Legacy)](#aes-cbc-legacy)
  - [Cipher Modes](#cipher-modes)
  - [Config](#config)
    - [Default Config](#default-config)
  - [KeyPairs](#keypairs)
  - [Standalone Usage](#standalone-usage)
  - [Payload Format](#payload-format)
    - [Request](#request)
    - [Response](#response)
  - [Example Usage](#example-usage)
  - [AES Encryption Tools](#aes-encryption-tools)
  - [Migration from v1](#migration-from-v1)

## Installation

```bash
go get -u github.com/owlsome-official/cipherPayload/v2
```

## Quick Start

```go
import (
  "github.com/gofiber/fiber/v2"
  cipherPayload "github.com/owlsome-official/cipherPayload/v2"
)
```

### AES-GCM (Default, Recommended)

```go
app.Use(cipherPayload.New(cipherPayload.Config{
  KeyPairs: cipherPayload.KeyPairs{
    AESKeyForEncrypt: []byte("YOUR_32_BYTE_KEY_FOR_ENCRYPT"),
    AESKeyForDecrypt: []byte("YOUR_32_BYTE_KEY_FOR_DECRYPT"),
  },
}))
```

GCM provides **authenticated encryption**: payloads that are tampered with, truncated, or encrypted with a different key are rejected. Each message uses a random 12-byte nonce.

### AES-CBC (Legacy)

```go
app.Use(cipherPayload.New(cipherPayload.Config{
  Mode: cipherPayload.ModeCBC,
  KeyPairs: cipherPayload.KeyPairs{
    AESKeyForEncrypt: []byte("YOUR_32_BYTE_KEY_FOR_ENCRYPT"),
    AESIVForEncrypt:  []byte("YOUR_16_BYTE_IV_FOR_ENCRYPT"),
    AESKeyForDecrypt: []byte("YOUR_32_BYTE_KEY_FOR_DECRYPT"),
    AESIVForDecrypt:  []byte("YOUR_16_BYTE_IV_FOR_DECRYPT"),
  },
}))
```

## Cipher Modes

| Mode | Algorithm | Authentication | Nonce/IV | Wire Format |
|------|-----------|----------------|----------|-------------|
| `ModeGCM` (default) | AES-GCM | Yes (128-bit tag) | Random 12B per message | `base64(nonce \|\| ciphertext \|\| tag)` |
| `ModeCBC` | AES-CBC + PKCS#7 | No | Fixed IV from config | `base64(padded ciphertext)` |

## Config

```go
type Config struct {
  // Optional. Default: nil
  Next func(c *fiber.Ctx) bool

  // Optional. Default: ModeGCM
  // ModeGCM: authenticated encryption with random nonce per message.
  // ModeCBC: legacy mode with PKCS#7 padding and fixed IV.
  Mode CipherMode

  // Required. Default: KeyPairs{}
  // For ModeGCM: only Key fields are required (IV fields are ignored).
  // For ModeCBC: all four fields (key + IV) are required.
  KeyPairs KeyPairs

  // Optional. Default: ["OPTIONS", "POST", "PUT", "DELETE"]
  AllowMethod []string

  // Optional. Default: false
  DebugMode bool

  // Optional. Default: false
  StrictMode bool

  // Optional. Default: true in ConfigDefault, false when omitted from a passed Config.
  // When true, requests whose path is /health or ends in /health skip encryption.
  ExcludeHealthAPI bool

  // Optional. Default: BadRequestResponse
  FailResponse func(c *fiber.Ctx, msg string) error

  // Optional. Default: InternalServerErrorResponse
  ErrorResponse func(c *fiber.Ctx, msg string) error
}
```

### Default Config

```go
var ConfigDefault = Config{
  Next:             nil,
  Mode:             ModeGCM,
  KeyPairs:         KeyPairs{},
  AllowMethod:      []string{"OPTIONS", "POST", "PUT", "DELETE"},
  DebugMode:        false,
  StrictMode:       false,
  ExcludeHealthAPI: true,
  FailResponse:     BadRequestResponse,
  ErrorResponse:    InternalServerErrorResponse,
}
```

## KeyPairs

```go
type KeyPairs struct {
  AESKeyForEncrypt []byte   // Required for all modes (16, 24, or 32 bytes)
  AESIVForEncrypt  []byte   // Required for ModeCBC only (16 bytes), ignored in ModeGCM
  AESKeyForDecrypt []byte   // Required for all modes (16, 24, or 32 bytes)
  AESIVForDecrypt  []byte   // Required for ModeCBC only (16 bytes), ignored in ModeGCM
}
```

## Standalone Usage

Use the encryption API directly without the Fiber middleware:

```go
// GCM
cipher := cipherPayload.NewCipher(cipherPayload.ModeGCM, cipherPayload.KeyPairs{
  AESKeyForEncrypt: key,
  AESKeyForDecrypt: key,
})
encrypted, err := cipher.Encrypt(plaintext)
decrypted, err := cipher.Decrypt(encrypted)

// CBC (legacy)
cipher := cipherPayload.NewCipher(cipherPayload.ModeCBC, cipherPayload.KeyPairs{
  AESKeyForEncrypt: key,
  AESIVForEncrypt:  iv,
  AESKeyForDecrypt: key,
  AESIVForDecrypt:  iv,
})
encrypted, err := cipher.Encrypt(plaintext)
decrypted, err := cipher.Decrypt(encrypted)
```

## Default Responses

When `StrictMode` is enabled, the middleware returns structured error responses:

```go
// 400 - Returned when payload is missing, empty, tampered, or cannot be decrypted.
func BadRequestResponse(c *fiber.Ctx, msg string) error

// 500 - Returned when response body cannot be encrypted.
func InternalServerErrorResponse(c *fiber.Ctx, msg string) error
```

Example error response:
```json
{ "status": "bad_request", "message": "Invalid Payload" }
```

You can override these with `FailResponse` and `ErrorResponse` in `Config`.

## Payload Format

### Request

```json
{
  "payload": "<base64 encrypted string>"
}
```

### Response

```json
{
  "payload": "<base64 encrypted string>"
}
```

The JSON envelope is the same for both modes. The base64 content differs:

- **GCM**: `base64(nonce[12B] || ciphertext || tag[16B])`
- **CBC**: `base64(PKCS#7 padded ciphertext)`

## Example Usage

Please go to [example/README.md](./example/README.md)

The example runs four servers:
- `:5000` - Plaintext API (no encryption)
- `:8000` - AES-GCM API (v2 default)
- `:8001` - AES-GCM + StrictMode (error showcase: 400/500 for invalid payloads)
- `:9000` - AES-CBC API (legacy)

## AES Encryption Tools

[https://encrypt-tools.vercel.app/](https://encrypt-tools.vercel.app/)

Use the **AES-GCM** mode (default page) to generate and verify GCM payloads.
Use the **Legacy** page for AES-CBC payloads.

GCM payloads from encrypt-tools (without AAD) are compatible with this library.

## Migration from v1

See [MIGRATION.md](./MIGRATION.md) for a step-by-step upgrade guide.
