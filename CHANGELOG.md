# Changelog

## [v2.0.0] - `2026-11-23`

### Breaking Changes

- **Default cipher mode is now AES-GCM** (was AES-CBC). Existing consumers must add `Mode: cipherPayload.ModeCBC` to preserve v1 behavior.
- **Module path changed** to `github.com/owlsome-official/cipherPayload/v2`. Update all import paths.
- **IV fields are ignored in GCM mode.** Only `AESKeyForEncrypt` and `AESKeyForDecrypt` are required.
- Middleware no longer panics on empty IV fields when `Mode` is `ModeGCM`.

### Added

- `ModeGCM` / `ModeCBC` cipher mode constants
- `Cipher` interface with `Encrypt(string) (string, error)` and `Decrypt(string) (string, error)`
- `GCMEncryption` struct: AES-GCM with random 12-byte nonce, 128-bit tag, `base64(nonce || ciphertext || tag)` wire format
- `CBCEncryption` struct: renamed from `DefaultAESEncryption`, same AES-CBC + PKCS#7 behavior
- `NewCipher(mode, keys, debugMode...)` factory function
- `Config.Mode` field for cipher mode selection
- New errors: `ErrCiphertextTooShort`, `ErrAuthenticationFailed`, `ErrInvalidCipherMode`, `ErrInvalidKeySize`
- `MIGRATION.md` with step-by-step upgrade guide
- Cross-compatibility with [encrypt-tools](https://encrypt-tools.vercel.app/) AES-GCM mode (no AAD)
- Example project: triple-server demo (plaintext :5000, GCM :8000, CBC :9000)

### Deprecated

- `NewAESEncryption` function (use `NewCipher(ModeCBC, keys)` instead)
- `AES` interface (use `Cipher` interface instead)

### Fixed

- Health URL bypass vulnerability: `ExcludeHealthAPI` config is now respected, path-only matching (merged from PR #5)

---

## [v1.0.12] - `2026-11-20`

- Fixed encryption bypass via "health" substring in request URL

## [v1.0.10] - `2026-09-24`

- Updated dependencies version

## [v1.0.9] - `2026-07-13`

- Updated dependencies version

## [v1.0.8] - `2026-05-20`

- Updated dependencies version

## [v1.0.7] - `2026-02-09`

- Updated dependencies version

## [v1.0.6] - `2025-09-17`

- Updated dependencies version

## [v1.0.5] - `2025-08-28`

- Updated dependencies version

## [v1.0.4] - `2025-08-07`

- Updated dependencies version

## [v1.0.3] - `2025-04-30`

- Updated dependencies version

## [v1.0.2] - `2025-02-17`

- Updated dependencies version

## [v1.0.1] - `2024-11-19`

- Updated dependencies version

## [v1.0.0] - `2024-09-13`

- Updated dependencies version
- Transfer project to `owlsome-official`

## v0 is Legacy version

[v2.0.0]: https://github.com/owlsome-official/cipherPayload/releases/tag/v2.0.0
[v1.0.12]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.12
[v1.0.10]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.10
[v1.0.9]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.9
[v1.0.8]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.8
[v1.0.7]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.7
[v1.0.6]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.6
[v1.0.5]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.5
[v1.0.4]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.4
[v1.0.3]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.3
[v1.0.2]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.2
[v1.0.1]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.1
[v1.0.0]: https://github.com/owlsome-official/cipherPayload/releases/tag/v1.0.0
