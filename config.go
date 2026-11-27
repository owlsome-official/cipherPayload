package cipherPayload

import (
	"github.com/gofiber/fiber/v2"
)

type Config struct {
	// Optional. Default: nil
	Next func(c *fiber.Ctx) bool

	// Optional. Default: ModeGCM
	// ModeGCM: AES-GCM with random 12-byte nonce per message (authenticated encryption).
	// ModeCBC: AES-CBC with PKCS#7 padding and fixed IV from KeyPairs (legacy).
	Mode CipherMode

	// Required. Default: KeyPairs{}
	// For ModeGCM: only AESKeyForEncrypt and AESKeyForDecrypt are required (IV fields are ignored).
	// For ModeCBC: all four fields (key + IV) are required.
	KeyPairs KeyPairs

	// Optional. Default: OPTIONS, POST, PUT, DELETE
	AllowMethod []string

	// Optional. Default: false
	DebugMode bool

	// Deprecated: has no effect. Requests on an allowed method whose payload is missing,
	// empty, cannot be decrypted, or does not decrypt to JSON are always rejected with
	// FailResponse before the next handler runs.
	StrictMode bool

	// Optional. Default: true in ConfigDefault, false when omitted from a passed Config.
	// When true, requests whose path (query string excluded) is /health or ends in /health skip encryption.
	ExcludeHealthAPI bool

	// Optional. Default: BadRequestResponse
	FailResponse func(c *fiber.Ctx, msg string) error

	// Optional. Default: InternalServerErrorResponse
	ErrorResponse func(c *fiber.Ctx, msg string) error
}

var ConfigDefault = Config{
	Next:     nil,
	Mode:     ModeGCM,
	KeyPairs: KeyPairs{},
	AllowMethod: []string{
		fiber.MethodOptions,
		fiber.MethodPost,
		fiber.MethodPut,
		fiber.MethodDelete,
	},
	DebugMode:        false,
	ExcludeHealthAPI: true,
	FailResponse:     BadRequestResponse,
	ErrorResponse:    InternalServerErrorResponse,
}

func configDefault(config ...Config) Config {
	// Return default config if nothing provided
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	// set default values
	if cfg.AllowMethod == nil {
		cfg.AllowMethod = ConfigDefault.AllowMethod
	}

	if cfg.Mode == "" {
		cfg.Mode = ConfigDefault.Mode
	}

	// Note: cfg.DebugMode: it's false by default.
	// Note: cfg.ExcludeHealthAPI: it's false unless set, because a bool zero value cannot be told apart from an explicit false.

	// set default values
	if cfg.FailResponse == nil {
		cfg.FailResponse = ConfigDefault.FailResponse
	}

	// set default values
	if cfg.ErrorResponse == nil {
		cfg.ErrorResponse = ConfigDefault.ErrorResponse
	}

	return cfg
}

type PayloadBody struct {
	Payload string `json:"payload"`
}

type KeyPairs struct {
	AESKeyForEncrypt []byte
	AESIVForEncrypt  []byte
	AESKeyForDecrypt []byte
	AESIVForDecrypt  []byte
}

func BadRequestResponse(c *fiber.Ctx, msg string) error { // 400
	if msg == "" {
		msg = "Bad Request"
	}
	res := fiber.Map{
		"status":  "bad_request",
		"message": msg,
	}
	return c.Status(fiber.StatusBadRequest).JSON(res)
}

func InternalServerErrorResponse(c *fiber.Ctx, msg string) error { // 500
	if msg == "" {
		msg = "Internal Server Error"
	}
	res := fiber.Map{
		"status":  "internal_server_error",
		"message": msg,
	}
	return c.Status(fiber.StatusInternalServerError).JSON(res)
}
