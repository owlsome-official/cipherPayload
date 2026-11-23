package main

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	cipherPayload "github.com/owlsome-official/cipherPayload/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	aesSecretKeyForEncrypt []byte
	aesSecretIVForEncrypt  []byte
	aesSecretKeyForDecrypt []byte
	aesSecretIVForDecrypt  []byte
)

func init() {
	aesSecretKeyForEncrypt = []byte("12345678901234567890123456789012")
	aesSecretIVForEncrypt = []byte("1234567890123456") // this would be ignore if mode is not CBC
	aesSecretKeyForDecrypt = []byte("67890123456789012345678901234567")
	aesSecretIVForDecrypt = []byte("6789012345678901") // this would be ignore if mode is not CBC

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
}

func main() {
	// === Plaintext API (no middleware) ===
	appPlaintext := fiber.New()
	apiPlaintextGroup := appPlaintext.Group("/api", nextHandlerAPI)
	apiPlaintextGroup.Post("/example", HandlerExample)

	// === AES-GCM API (v2 default, authenticated encryption) ===
	appGCM := fiber.New()
	appGCM.Use(cipherPayload.New(cipherPayload.Config{
		KeyPairs: cipherPayload.KeyPairs{
			AESKeyForEncrypt: aesSecretKeyForEncrypt,
			AESKeyForDecrypt: aesSecretKeyForDecrypt,
		},
		DebugMode: true,
	}))
	apiGCMGroup := appGCM.Group("/api", nextHandlerAPI)
	apiGCMGroup.Post("/example", HandlerExample)

	// === AES-GCM + StrictMode API (error showcase) ===
	appStrict := fiber.New()
	appStrict.Use(cipherPayload.New(cipherPayload.Config{
		KeyPairs: cipherPayload.KeyPairs{
			AESKeyForEncrypt: aesSecretKeyForEncrypt,
			AESKeyForDecrypt: aesSecretKeyForDecrypt,
		},
		StrictMode: true,
		DebugMode:  true,
	}))
	apiStrictGroup := appStrict.Group("/api", nextHandlerAPI)
	apiStrictGroup.Post("/example", HandlerExample)

	// === AES-CBC API (legacy, backward compatible) ===
	appCBC := fiber.New()
	appCBC.Use(cipherPayload.New(cipherPayload.Config{
		Mode: cipherPayload.ModeCBC,
		KeyPairs: cipherPayload.KeyPairs{
			AESKeyForEncrypt: aesSecretKeyForEncrypt,
			AESIVForEncrypt:  aesSecretIVForEncrypt,
			AESKeyForDecrypt: aesSecretKeyForDecrypt,
			AESIVForDecrypt:  aesSecretIVForDecrypt,
		},
		DebugMode: true,
	}))
	apiCBCGroup := appCBC.Group("/api", nextHandlerAPI)
	apiCBCGroup.Post("/example", HandlerExample)

	log.Info().Msg("Starting servers...")
	log.Info().Msg(":5000 - Plaintext (no encryption)")
	log.Info().Msg(":8000 - AES-GCM (v2 default, authenticated)")
	log.Info().Msg(":8001 - AES-GCM + StrictMode (error showcase)")
	log.Info().Msg(":9000 - AES-CBC (legacy, backward compatible)")

	go appPlaintext.Listen(":5000")
	go appGCM.Listen(":8000")
	go appStrict.Listen(":8001")
	appCBC.Listen(":9000")
}

var nextHandlerAPI = func(c *fiber.Ctx) error {
	c.Accepts(fiber.MIMEApplicationJSONCharsetUTF8)
	log.Info().Msg("Called API")
	return c.Next()
}

var HandlerExample = func(c *fiber.Ctx) error {
	log.Info().Msg("Called HandlerExample")

	var reqBody map[string]interface{}
	_ = c.BodyParser(&reqBody)
	for k, v := range reqBody {
		reqBody[k] = fmt.Sprintf("%v [Modified]", v)
	}

	return c.Status(fiber.StatusOK).JSON(reqBody)
}
