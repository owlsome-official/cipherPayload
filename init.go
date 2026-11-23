package cipherPayload

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"
)

var (
	serviceName = "[Middleware] cipherPayload"
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
		err := c.BodyParser(&reqBody)
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
