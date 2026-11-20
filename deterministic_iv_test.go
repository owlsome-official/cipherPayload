package cipherPayload_test

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/owlsome-official/cipherPayload"
	"github.com/stretchr/testify/require"
)

// serverKeys is the middleware configuration. The values are obvious
// placeholders, not credentials. Encrypt and decrypt directions use different
// placeholders so each configured vector is on a real request or response path.
func serverKeys() cipherPayload.KeyPairs {
	return cipherPayload.KeyPairs{
		AESKeyForEncrypt: []byte("placeholder-encrypt-key-32-bytes"),
		AESIVForEncrypt:  []byte("placeholder-ive1"),
		AESKeyForDecrypt: []byte("placeholder-decrypt-key-32-bytes"),
		AESIVForDecrypt:  []byte("placeholder-ivd1"),
	}
}

// clientKeys swaps the server directions, which is how a caller builds a
// request the middleware can decrypt and reads a response the middleware built.
func clientKeys() cipherPayload.KeyPairs {
	server := serverKeys()
	return cipherPayload.KeyPairs{
		AESKeyForEncrypt: server.AESKeyForDecrypt,
		AESIVForEncrypt:  server.AESIVForDecrypt,
		AESKeyForDecrypt: server.AESKeyForEncrypt,
		AESIVForDecrypt:  server.AESIVForEncrypt,
	}
}

func customerJSON(taxID, name string) string {
	return `{"taxId":"` + taxID + `","name":"` + name + `"}`
}

func assertCiphertextsUnlinkable(t *testing.T, first, second string) {
	t.Helper()
	require.NotEmpty(t, first)
	require.NotEmpty(t, second)
	require.NotEqual(t, first, second, "an observer can link equal ciphertexts to equal plaintexts")

	rawFirst, err := base64.StdEncoding.DecodeString(first)
	require.NoError(t, err)
	rawSecond, err := base64.StdEncoding.DecodeString(second)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(rawFirst), aes.BlockSize)
	require.GreaterOrEqual(t, len(rawSecond), aes.BlockSize)
	require.NotEqual(t, rawFirst[:aes.BlockSize], rawSecond[:aes.BlockSize],
		"the first ciphertext block must not stay stable for a repeated plaintext prefix")
}

func TestSamePlaintextProducesDistinctCiphertexts(t *testing.T) {
	require.Len(t, serverKeys().AESKeyForEncrypt, 32)
	require.Len(t, serverKeys().AESIVForEncrypt, aes.BlockSize)

	plaintext := customerJSON("123-45-6789", "Ada Lovelace")
	server := cipherPayload.NewAESEncryption(serverKeys())
	client := cipherPayload.NewAESEncryption(clientKeys())

	first, err := server.Encrypt(plaintext)
	require.NoError(t, err)
	second, err := server.Encrypt(plaintext)
	require.NoError(t, err)

	openedFirst, err := client.Decrypt(first)
	require.NoError(t, err)
	openedSecond, err := client.Decrypt(second)
	require.NoError(t, err)
	require.Equal(t, plaintext, openedFirst)
	require.Equal(t, plaintext, openedSecond)

	assertCiphertextsUnlinkable(t, first, second)
}

func TestSharedPlaintextPrefixProducesDistinctFirstBlocks(t *testing.T) {
	ada := customerJSON("123-45-6789", "Ada")
	bob := customerJSON("123-45-6789", "Bob")
	require.Equal(t, ada[:aes.BlockSize], bob[:aes.BlockSize])
	require.NotEqual(t, ada, bob)

	server := cipherPayload.NewAESEncryption(serverKeys())
	client := cipherPayload.NewAESEncryption(clientKeys())

	adaCipher, err := server.Encrypt(ada)
	require.NoError(t, err)
	bobCipher, err := server.Encrypt(bob)
	require.NoError(t, err)

	openedAda, err := client.Decrypt(adaCipher)
	require.NoError(t, err)
	openedBob, err := client.Decrypt(bobCipher)
	require.NoError(t, err)
	require.Equal(t, ada, openedAda)
	require.Equal(t, bob, openedBob)

	assertCiphertextsUnlinkable(t, adaCipher, bobCipher)
}

func newCustomerApp(t *testing.T) *fiber.App {
	t.Helper()
	app := fiber.New()
	app.Use(cipherPayload.New(cipherPayload.Config{
		KeyPairs: serverKeys(),
	}))
	app.Post("/customers", func(c *fiber.Ctx) error {
		var body struct {
			TaxID string `json:"taxId"`
			Name  string `json:"name"`
		}
		if err := c.BodyParser(&body); err != nil {
			return err
		}
		if body.TaxID == "" || body.Name == "" {
			return c.SendStatus(fiber.StatusBadRequest)
		}
		return c.SendString(customerJSON(body.TaxID, body.Name))
	})
	return app
}

func postCustomer(t *testing.T, app *fiber.App, requestCipher string) (int, string) {
	t.Helper()
	raw, err := json.Marshal(cipherPayload.PayloadBody{Payload: requestCipher})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/customers", bytes.NewReader(raw))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var wrapped cipherPayload.PayloadBody
	require.NoError(t, json.Unmarshal(body, &wrapped))
	return resp.StatusCode, wrapped.Payload
}

func TestMiddlewareIdenticalCustomersAreNotLinkable(t *testing.T) {
	plaintext := customerJSON("123-45-6789", "Ada Lovelace")
	client := cipherPayload.NewAESEncryption(clientKeys())

	firstRequest, err := client.Encrypt(plaintext)
	require.NoError(t, err)
	secondRequest, err := client.Encrypt(plaintext)
	require.NoError(t, err)

	app := newCustomerApp(t)
	firstStatus, firstResponse := postCustomer(t, app, firstRequest)
	secondStatus, secondResponse := postCustomer(t, app, secondRequest)
	require.Equal(t, http.StatusOK, firstStatus)
	require.Equal(t, http.StatusOK, secondStatus)

	openedFirst, err := client.Decrypt(firstResponse)
	require.NoError(t, err)
	openedSecond, err := client.Decrypt(secondResponse)
	require.NoError(t, err)
	require.Equal(t, plaintext, openedFirst)
	require.Equal(t, plaintext, openedSecond)

	t.Run("request", func(t *testing.T) {
		assertCiphertextsUnlinkable(t, firstRequest, secondRequest)
	})
	t.Run("response", func(t *testing.T) {
		assertCiphertextsUnlinkable(t, firstResponse, secondResponse)
	})
}

func TestMiddlewareSharedFieldPrefixIsNotLinkable(t *testing.T) {
	ada := customerJSON("123-45-6789", "Ada")
	bob := customerJSON("123-45-6789", "Bob")
	require.Equal(t, ada[:aes.BlockSize], bob[:aes.BlockSize])
	require.NotEqual(t, ada, bob)

	client := cipherPayload.NewAESEncryption(clientKeys())
	adaRequest, err := client.Encrypt(ada)
	require.NoError(t, err)
	bobRequest, err := client.Encrypt(bob)
	require.NoError(t, err)

	app := newCustomerApp(t)
	adaStatus, adaResponse := postCustomer(t, app, adaRequest)
	bobStatus, bobResponse := postCustomer(t, app, bobRequest)
	require.Equal(t, http.StatusOK, adaStatus)
	require.Equal(t, http.StatusOK, bobStatus)

	openedAda, err := client.Decrypt(adaResponse)
	require.NoError(t, err)
	openedBob, err := client.Decrypt(bobResponse)
	require.NoError(t, err)
	require.Equal(t, ada, openedAda)
	require.Equal(t, bob, openedBob)

	t.Run("request", func(t *testing.T) {
		assertCiphertextsUnlinkable(t, adaRequest, bobRequest)
	})
	t.Run("response", func(t *testing.T) {
		assertCiphertextsUnlinkable(t, adaResponse, bobResponse)
	})
}
