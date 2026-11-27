package cipherPayload

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"
)

var (
	serviceName = "[Middleware] cipherPayload"

	errUnsupportedContentEncoding = errors.New("unsupported Content-Encoding")
	errTooManyContentEncodings    = errors.New("too many Content-Encoding values")
	errBrotliWindowTooLarge       = errors.New("brotli window exceeds the body limit")
)

const maxContentEncodings = 3

// brotliWindowSize returns the sliding window a brotli stream declares in its
// WBITS header (RFC 7932, section 9.1). The large-window marker counts as the
// largest window that extension allows.
func brotliWindowSize(stream []byte) int {
	if len(stream) == 0 {
		return 0
	}
	b := stream[0]
	bits := 17
	switch {
	case b&1 == 0:
		bits = 16
	case (b>>1)&7 != 0:
		bits = 17 + int((b>>1)&7)
	case (b>>4)&7 == 1:
		bits = 30
	case (b>>4)&7 != 0:
		bits = 8 + int((b>>4)&7)
	}
	return 1<<bits - 16
}

// decodeRequestBody expands a Content-Encoding body in place with every decoder
// capped at the app's BodyLimit, then drops the header. Fiber's Body and
// BodyParser expand encoded bodies without any output limit, so they must only
// ever see the already decoded body.
func decodeRequestBody(c *fiber.Ctx) error {
	req := c.Request()

	var encodings []string
	for _, value := range req.Header.PeekAll(fiber.HeaderContentEncoding) {
		for _, token := range strings.Split(string(value), ",") {
			token = strings.ToLower(strings.TrimSpace(token))
			if token == "" || token == "identity" {
				continue
			}
			encodings = append(encodings, token)
		}
	}
	req.Header.Del(fiber.HeaderContentEncoding)

	if len(encodings) == 0 {
		return nil
	}
	if len(encodings) > maxContentEncodings {
		return errTooManyContentEncodings
	}

	limit := c.App().Config().BodyLimit
	if limit <= 0 {
		limit = fiber.DefaultBodyLimit
	}

	// Codings are listed in the order they were applied (RFC 9110, section 8.4).
	for _, encoding := range slices.Backward(encodings) {
		var (
			body []byte
			err  error
		)
		switch encoding {
		case fiber.StrGzip:
			body, err = req.BodyGunzipWithLimit(limit)
		case fiber.StrBr, fiber.StrBrotli:
			// The brotli decoder buffers up to the declared window before
			// yielding output, so the output cap alone does not bound it.
			if brotliWindowSize(req.Body()) > limit {
				return errBrotliWindowTooLarge
			}
			body, err = req.BodyUnbrotliWithLimit(limit)
		case fiber.StrDeflate:
			body, err = req.BodyInflateWithLimit(limit)
		default:
			return errUnsupportedContentEncoding
		}
		if err != nil {
			return err
		}
		req.SetBodyRaw(body)
	}
	return nil
}

func New(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	panicResponseHeader := serviceName + ": Some configuration is missing: "

	if len(cfg.KeyPairs.AESKeyForEncrypt) == 0 {
		panic(panicResponseHeader + "`AESKeyForEncrypt` is required.")
	}

	if len(cfg.KeyPairs.AESKeyForDecrypt) == 0 {
		panic(panicResponseHeader + "`AESKeyForDecrypt` is required.")
	}

	// IV fields are only required for CBC mode
	if cfg.Mode == ModeCBC {
		if len(cfg.KeyPairs.AESIVForEncrypt) == 0 {
			panic(panicResponseHeader + "`AESIVForEncrypt` is required for CBC mode.")
		}
		if len(cfg.KeyPairs.AESIVForDecrypt) == 0 {
			panic(panicResponseHeader + "`AESIVForDecrypt` is required for CBC mode.")
		}
	}

	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		if cfg.ExcludeHealthAPI && isHealthPath(c.Path()) {
			return c.Next()
		}

		if !isExist(cfg.AllowMethod, c.Method()) {
			return c.Next()
		}

		logger := newLogger(cfg.DebugMode)

		var reqBody PayloadBody
		err := decodeRequestBody(c)
		if err == nil {
			err = c.BodyParser(&reqBody)
		}
		if err != nil || reqBody.Payload == "" {
			errMsg := "BodyParser error or Empty Payload"
			if cfg.StrictMode {
				errMsg := "Invalid Payload"
				logger.printf("error", errMsg, string(c.Request().Body()))
				return cfg.FailResponse(c, errMsg)
			}
			logger.printf("info", errMsg, string(c.Request().Body()))
		}
		logger.printf("debug", "Request:", reqBody.Payload)

		encrypterDecrypter := NewCipher(cfg.Mode, cfg.KeyPairs, cfg.DebugMode)
		decryptedPayload, err := encrypterDecrypter.Decrypt(reqBody.Payload)
		logger.printf("debug", "Decrypted:", decryptedPayload)
		if err != nil || decryptedPayload == "" {
			errMsg := "Payload decrypt fail or Empty payload"
			if cfg.StrictMode {
				logger.printf("error", serviceName, err)
				return cfg.FailResponse(c, errMsg)
			}
			logger.printf("info", errMsg)
		}

		jsonRaw := json.RawMessage(decryptedPayload)
		jsonBytes, _ := json.Marshal(jsonRaw)

		logger.printf("debug", "jsonBytes:", string(jsonBytes))
		c.Request().SetBodyRaw(jsonBytes)

		c.Next()

		interceptBody := string(c.Response().Body())
		logger.printf("debug", "Intercept Body:", interceptBody)

		encryptedPayload, err := encrypterDecrypter.Encrypt(interceptBody)
		logger.printf("debug", "Encrypted:", encryptedPayload)

		if err != nil || encryptedPayload == "" {
			logger.printf("error", serviceName, err)
			errMsg := "InternalServerError: Cannot encrypt payload or invalid payload"
			return cfg.ErrorResponse(c, errMsg)
		}

		var resBody PayloadBody
		resBody.Payload = encryptedPayload
		return c.JSON(resBody)
	}
}
