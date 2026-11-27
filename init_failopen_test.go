package cipherPayload

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

// Placeholder AES material for tests. These are not credentials.
const (
	placeholderEncryptKey = "placeholder-encrypt-key-32bytes!"
	placeholderDecryptKey = "placeholder-decrypt-key-32bytes!"
	placeholderOtherKey   = "placeholder-other-key-32-bytes!!"
	placeholderEncryptIV  = "placeholder-iv-e"
	placeholderDecryptIV  = "placeholder-iv-d"

	invalidPayloadMessage = "Invalid Payload"
	decryptFailMessage    = "Payload decrypt fail or Empty payload"
)

// commandEffect records work a route performs when the middleware lets it run.
// The call is counted before the body is parsed, and a missing action is treated
// as the default command "transfer".
type commandEffect struct {
	calls   int
	bodies  []string
	actions []string
}

func (e *commandEffect) handler(c *fiber.Ctx) error {
	e.calls++
	e.bodies = append(e.bodies, string(c.Body()))

	var cmd struct {
		Action string `json:"action"`
		Amount int    `json:"amount"`
	}
	_ = c.BodyParser(&cmd)
	if cmd.Action == "" {
		cmd.Action = "transfer"
	}
	e.actions = append(e.actions, cmd.Action)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"executed": cmd.Action,
		"amount":   cmd.Amount,
	})
}

func gcmQuickStart() Config {
	return Config{
		KeyPairs: KeyPairs{
			AESKeyForEncrypt: []byte(placeholderEncryptKey),
			AESKeyForDecrypt: []byte(placeholderDecryptKey),
		},
	}
}

func cbcQuickStart() Config {
	return Config{
		Mode: ModeCBC,
		KeyPairs: KeyPairs{
			AESKeyForEncrypt: []byte(placeholderEncryptKey),
			AESIVForEncrypt:  []byte(placeholderEncryptIV),
			AESKeyForDecrypt: []byte(placeholderDecryptKey),
			AESIVForDecrypt:  []byte(placeholderDecryptIV),
		},
	}
}

func payloadEnvelope(ciphertext string) string {
	body, err := json.Marshal(PayloadBody{Payload: ciphertext})
	if err != nil {
		panic(err)
	}
	return string(body)
}

func encryptForServer(mode CipherMode, server KeyPairs, plaintext string) string {
	keys := KeyPairs{
		AESKeyForEncrypt: server.AESKeyForDecrypt,
		AESIVForEncrypt:  server.AESIVForDecrypt,
		AESKeyForDecrypt: server.AESKeyForDecrypt,
		AESIVForDecrypt:  server.AESIVForDecrypt,
	}
	out, err := NewCipher(mode, keys).Encrypt(plaintext)
	if err != nil {
		panic(err)
	}
	return out
}

func tamperCiphertext(ciphertext string) string {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		panic(err)
	}
	raw[len(raw)-1] ^= 0xff
	return base64.StdEncoding.EncodeToString(raw)
}

// sealEmptyGCM builds an authenticated AES-GCM message whose plaintext is empty.
// The library's Encrypt returns immediately for an empty string, so this uses the
// same AES-GCM layout the middleware decrypts: base64(nonce || ciphertext || tag).
func sealEmptyGCM(key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := bytes.Repeat([]byte{0x11}, aead.NonceSize())
	sealed := aead.Seal(append([]byte{}, nonce...), nonce, nil, nil)
	return base64.StdEncoding.EncodeToString(sealed)
}

func assertRejected(t *testing.T, cfg Config, method, body, contentType, wantMessage string) {
	t.Helper()

	effect := &commandEffect{}
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(New(cfg))
	app.Add(method, "/api/command", effect.handler)

	req := httptest.NewRequest(method, "/api/command", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set(fiber.HeaderContentType, contentType)
	}
	res, err := app.Test(req, -1)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = res.Body.Close()
	})
	respBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	require.Zero(
		t,
		effect.calls,
		"state-changing handler ran; method=%s bodies=%q actions=%q status=%d resp=%s",
		method,
		effect.bodies,
		effect.actions,
		res.StatusCode,
		string(respBody),
	)
	require.Equal(t, http.StatusBadRequest, res.StatusCode, "resp=%s", string(respBody))

	var parsed struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Payload string `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(respBody, &parsed), "resp=%s", string(respBody))
	require.Equal(t, "bad_request", parsed.Status)
	require.Equal(t, wantMessage, parsed.Message)
	require.Empty(t, parsed.Payload)
}

func TestQuickStartRejectsUntrustedPayloadBeforeHandler(t *testing.T) {
	cfg := gcmQuickStart()
	valid := encryptForServer(ModeGCM, cfg.KeyPairs, `{"action":"transfer","amount":10}`)
	tampered := tamperCiphertext(valid)
	wrongKey := encryptForServer(ModeGCM, KeyPairs{
		AESKeyForDecrypt: []byte(placeholderOtherKey),
		AESIVForDecrypt:  []byte(placeholderDecryptIV),
	}, `{"action":"transfer","amount":10}`)
	rawValid, err := base64.StdEncoding.DecodeString(valid)
	require.NoError(t, err)
	truncated := base64.StdEncoding.EncodeToString(rawValid[:8])

	methods := []string{
		fiber.MethodPost,
		fiber.MethodPut,
		fiber.MethodDelete,
		fiber.MethodOptions,
	}
	shared := []struct {
		name        string
		body        string
		wantMessage string
	}{
		{name: "empty object", body: `{}`, wantMessage: invalidPayloadMessage},
		{name: "missing payload field", body: `{"action":"transfer","amount":10}`, wantMessage: invalidPayloadMessage},
		{name: "authentication failure", body: payloadEnvelope(tampered), wantMessage: decryptFailMessage},
	}

	for _, method := range methods {
		for _, tc := range shared {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				assertRejected(t, cfg, method, tc.body, fiber.MIMEApplicationJSON, tc.wantMessage)
			})
		}
	}

	extra := []struct {
		name        string
		body        string
		contentType string
		wantMessage string
	}{
		{name: "empty payload field", body: `{"payload":""}`, contentType: fiber.MIMEApplicationJSON, wantMessage: invalidPayloadMessage},
		{name: "null payload field", body: `{"payload":null}`, contentType: fiber.MIMEApplicationJSON, wantMessage: invalidPayloadMessage},
		{name: "empty body", body: ``, contentType: fiber.MIMEApplicationJSON, wantMessage: invalidPayloadMessage},
		{name: "invalid json", body: `{`, contentType: fiber.MIMEApplicationJSON, wantMessage: invalidPayloadMessage},
		{name: "missing content type", body: `{}`, contentType: ``, wantMessage: invalidPayloadMessage},
		{name: "bad base64", body: payloadEnvelope("****"), contentType: fiber.MIMEApplicationJSON, wantMessage: decryptFailMessage},
		{name: "truncated ciphertext", body: payloadEnvelope(truncated), contentType: fiber.MIMEApplicationJSON, wantMessage: decryptFailMessage},
		{name: "wrong key", body: payloadEnvelope(wrongKey), contentType: fiber.MIMEApplicationJSON, wantMessage: decryptFailMessage},
		{name: "authenticated empty plaintext", body: payloadEnvelope(sealEmptyGCM([]byte(placeholderDecryptKey))), contentType: fiber.MIMEApplicationJSON, wantMessage: decryptFailMessage},
	}
	for _, tc := range extra {
		t.Run(fiber.MethodPost+"/"+tc.name, func(t *testing.T) {
			assertRejected(t, cfg, fiber.MethodPost, tc.body, tc.contentType, tc.wantMessage)
		})
	}

	t.Run("debug quick start", func(t *testing.T) {
		debugCfg := gcmQuickStart()
		debugCfg.DebugMode = true
		assertRejected(t, debugCfg, fiber.MethodPost, `{}`, fiber.MIMEApplicationJSON, invalidPayloadMessage)
	})

	t.Run("PATCH when allowed", func(t *testing.T) {
		patchCfg := gcmQuickStart()
		patchCfg.AllowMethod = []string{fiber.MethodPatch}
		assertRejected(t, patchCfg, fiber.MethodPatch, `{}`, fiber.MIMEApplicationJSON, invalidPayloadMessage)
		assertRejected(t, patchCfg, fiber.MethodPatch, payloadEnvelope(tampered), fiber.MIMEApplicationJSON, decryptFailMessage)
	})
}

func TestLegacyCBCQuickStartRejectsUntrustedPayloadBeforeHandler(t *testing.T) {
	cfg := cbcQuickStart()
	methods := []string{fiber.MethodPost, fiber.MethodPut, fiber.MethodDelete, fiber.MethodOptions}
	shortCiphertext := base64.StdEncoding.EncodeToString([]byte("short"))

	cases := []struct {
		name        string
		body        string
		wantMessage string
	}{
		{name: "empty object", body: `{}`, wantMessage: invalidPayloadMessage},
		{name: "missing payload field", body: `{"action":"transfer","amount":10}`, wantMessage: invalidPayloadMessage},
		{name: "undecryptable ciphertext", body: payloadEnvelope(shortCiphertext), wantMessage: decryptFailMessage},
		{name: "empty payload field", body: `{"payload":""}`, wantMessage: invalidPayloadMessage},
		{name: "bad base64", body: payloadEnvelope("****"), wantMessage: decryptFailMessage},
	}

	for _, method := range methods {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				assertRejected(t, cfg, method, tc.body, fiber.MIMEApplicationJSON, tc.wantMessage)
			})
		}
	}
}

func TestValidEncryptedPayloadStillReachesHandler(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		mode CipherMode
	}{
		{name: "gcm", cfg: gcmQuickStart(), mode: ModeGCM},
		{name: "cbc", cfg: cbcQuickStart(), mode: ModeCBC},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			effect := &commandEffect{}
			app := fiber.New(fiber.Config{DisableStartupMessage: true})
			app.Use(New(tc.cfg))
			app.Post("/api/command", effect.handler)

			plain := `{"action":"audit","amount":1}`
			body := payloadEnvelope(encryptForServer(tc.mode, tc.cfg.KeyPairs, plain))
			req := httptest.NewRequest(fiber.MethodPost, "/api/command", strings.NewReader(body))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			res, err := app.Test(req, -1)
			require.NoError(t, err)
			t.Cleanup(func() { _ = res.Body.Close() })
			respBody, err := io.ReadAll(res.Body)
			require.NoError(t, err)

			require.Equal(t, 1, effect.calls)
			require.Equal(t, []string{"audit"}, effect.actions)
			require.Equal(t, http.StatusOK, res.StatusCode, "resp=%s", string(respBody))

			var envelope PayloadBody
			require.NoError(t, json.Unmarshal(respBody, &envelope), "resp=%s", string(respBody))
			reader := NewCipher(tc.mode, KeyPairs{
				AESKeyForEncrypt: tc.cfg.KeyPairs.AESKeyForEncrypt,
				AESIVForEncrypt:  tc.cfg.KeyPairs.AESIVForEncrypt,
				AESKeyForDecrypt: tc.cfg.KeyPairs.AESKeyForEncrypt,
				AESIVForDecrypt:  tc.cfg.KeyPairs.AESIVForEncrypt,
			})
			decrypted, err := reader.Decrypt(envelope.Payload)
			require.NoError(t, err)
			require.Contains(t, decrypted, `"executed":"audit"`)
		})
	}
}

func TestStrictModeRejectsBeforeHandler(t *testing.T) {
	cfg := gcmQuickStart()
	cfg.StrictMode = true
	valid := encryptForServer(ModeGCM, cfg.KeyPairs, `{"action":"transfer","amount":10}`)
	assertRejected(t, cfg, fiber.MethodPost, `{}`, fiber.MIMEApplicationJSON, invalidPayloadMessage)
	assertRejected(t, cfg, fiber.MethodPut, payloadEnvelope(tamperCiphertext(valid)), fiber.MIMEApplicationJSON, decryptFailMessage)
}
