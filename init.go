package cipherPayload

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"
)

var (
	serviceName = "[Middleware] cipherPayload"
)

const (
	invalidPayloadMsg = "Invalid Payload"
	decryptFailMsg    = "Payload decrypt fail or Empty payload"
)

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
		if err := c.BodyParser(&reqBody); err != nil || reqBody.Payload == "" {
			logger.printf("error", invalidPayloadMsg, string(c.Request().Body()))
			return cfg.FailResponse(c, invalidPayloadMsg)
		}
		logger.printf("debug", "Request:", reqBody.Payload)

		encrypterDecrypter := NewCipher(cfg.Mode, cfg.KeyPairs, cfg.DebugMode)
		decryptedPayload, err := encrypterDecrypter.Decrypt(reqBody.Payload)
		logger.printf("debug", "Decrypted:", decryptedPayload)
		if err != nil || decryptedPayload == "" {
			logger.printf("error", serviceName, decryptFailMsg, err)
			return cfg.FailResponse(c, decryptFailMsg)
		}

		jsonBytes, err := json.Marshal(json.RawMessage(decryptedPayload))
		if err != nil {
			logger.printf("error", serviceName, decryptFailMsg, err)
			return cfg.FailResponse(c, decryptFailMsg)
		}

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
