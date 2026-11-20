package cipherPayload

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

// These tests are the spec for authenticated request and response bodies.
// They fail while AES-CBC ciphertext is decrypted and trusted with no authentication tag.

const (
	documentedTaxBody  = `{"key":"tax_id","value":"1234567890121"}`
	documentedNameBody = `{"firstname":"Chinnawat","lastname":"Chimdee"}`
)

// alignedNameTaxBody places the name across a full AES block and the tax id in the next block,
// which is the layout a padding-valid bit flip needs in order to leave JSON intact.
func alignedNameTaxBody() string {
	return `{"name":"` + "BBBBBBBBBBBBBBBBBBBBBBB" + `","tax_id":"11"}`
}

func placeholderKeyPairs() KeyPairs {
	// Obvious fixtures. Not a deployed credential.
	return KeyPairs{
		AESKeyForEncrypt: bytes.Repeat([]byte{0xA1}, 32),
		AESIVForEncrypt:  bytes.Repeat([]byte{0xA2}, aes.BlockSize),
		AESKeyForDecrypt: bytes.Repeat([]byte{0xB1}, 32),
		AESIVForDecrypt:  bytes.Repeat([]byte{0xB2}, aes.BlockSize),
	}
}

// swappedPairs is the peer view of keys: request encryption uses the server
// decrypt key, and response decryption uses the server encrypt key.
func swappedPairs(keys KeyPairs) KeyPairs {
	return KeyPairs{
		AESKeyForEncrypt: keys.AESKeyForDecrypt,
		AESIVForEncrypt:  keys.AESIVForDecrypt,
		AESKeyForDecrypt: keys.AESKeyForEncrypt,
		AESIVForDecrypt:  keys.AESIVForEncrypt,
	}
}

type handlerView struct {
	raw string
}

type gateway struct {
	app  *fiber.App
	view *handlerView
}

func newGateway(keys KeyPairs, strict bool) *gateway {
	view := &handlerView{}
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(New(Config{
		KeyPairs:   keys,
		StrictMode: strict,
	}))
	app.All("/api/example", func(c *fiber.Ctx) error {
		view.raw = string(bytes.Clone(c.Body()))
		note := bytes.Repeat([]byte{'n'}, 48)
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"body": string(note),
		})
	})
	return &gateway{app: app, view: view}
}

func (g *gateway) submit(t *testing.T, method string, payloadB64 string) (int, []byte) {
	t.Helper()
	g.view.raw = ""
	wrapped, err := json.Marshal(PayloadBody{Payload: payloadB64})
	require.NoError(t, err)
	req := httptest.NewRequest(method, "/api/example", bytes.NewReader(wrapped))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	resp, err := g.app.Test(req, -1)
	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, respBody
}

func mustEncrypt(t *testing.T, enc AES, plain string) (string, []byte) {
	t.Helper()
	encoded, err := enc.Encrypt(plain)
	require.NoError(t, err)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	require.Zero(t, len(raw)%aes.BlockSize)
	return encoded, raw
}

func flipByte(raw []byte, index int, delta byte) string {
	buf := bytes.Clone(raw)
	buf[index] ^= delta
	return base64.StdEncoding.EncodeToString(buf)
}

func parsedJSON(raw string) (any, bool) {
	if raw == "" {
		return nil, false
	}
	var got any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		return nil, false
	}
	return got, true
}

// taxDigitCipherIndex is the ciphertext byte that changes the first tax digit
// and leaves the final padding block untouched.
func taxDigitCipherIndex(t *testing.T, plain string) int {
	t.Helper()
	digit := bytes.Index([]byte(plain), []byte(`"11"`))
	require.GreaterOrEqual(t, digit, 0)
	digit++ // first digit inside the quotes
	require.GreaterOrEqual(t, digit, aes.BlockSize)
	index := digit - aes.BlockSize
	// Keep the last ciphertext block and the block that feeds it unchanged.
	require.Less(t, index, len(plain)-aes.BlockSize)
	return index
}

func TestDecryptRejectsPaddingValidTamper(t *testing.T) {
	keys := placeholderKeyPairs()
	client := NewAESEncryption(swappedPairs(keys))
	server := NewAESEncryption(keys)

	bodies := []struct {
		name  string
		plain string
	}{
		{name: "aligned-name-tax", plain: alignedNameTaxBody()},
		{name: "documented-tax-id", plain: documentedTaxBody},
		{name: "documented-name", plain: documentedNameBody},
	}
	for _, body := range bodies {
		t.Run(body.name, func(t *testing.T) {
			plain := body.plain
			_, raw := mustEncrypt(t, client, plain)
			// First byte of ciphertext block 1. On these bodies it changes a later
			// plaintext byte and leaves the PKCS#7 trailer valid.
			index := 0
			if len(raw) >= aes.BlockSize*3 {
				index = aes.BlockSize
			}
			tampered := flipByte(raw, index, 0x01)
			out, err := server.Decrypt(tampered)
			if err == nil {
				t.Fatalf("Decrypt accepted padding-valid tampered ciphertext and returned %q", out)
			}
		})
	}
}

func TestTamperedRequestDoesNotChangeTrustedFields(t *testing.T) {
	keys := placeholderKeyPairs()
	client := NewAESEncryption(swappedPairs(keys))
	plain := alignedNameTaxBody()
	require.Equal(t, 48, len(plain))
	encoded, raw := mustEncrypt(t, client, plain)
	var original any
	require.NoError(t, json.Unmarshal([]byte(plain), &original))
	index := taxDigitCipherIndex(t, plain)

	methods := []string{
		fiber.MethodPost,
		fiber.MethodPut,
		fiber.MethodDelete,
		fiber.MethodOptions,
	}
	for _, strict := range []bool{false, true} {
		for _, method := range methods {
			name := method
			if strict {
				name += "/strict"
			} else {
				name += "/default"
			}
			t.Run(name, func(t *testing.T) {
				g := newGateway(keys, strict)
				status, _ := g.submit(t, method, encoded)
				require.Equal(t, fiber.StatusOK, status)
				got, ok := parsedJSON(g.view.raw)
				require.True(t, ok, "legitimate ciphertext did not reach the handler as JSON: %q", g.view.raw)
				require.True(t, reflect.DeepEqual(original, got), "handler saw %q", g.view.raw)

				for delta := 1; delta < 256; delta++ {
					tampered := flipByte(raw, index, byte(delta))
					g.submit(t, method, tampered)
					altered, parsed := parsedJSON(g.view.raw)
					if parsed && !reflect.DeepEqual(original, altered) {
						t.Fatalf("handler trusted altered JSON after a padding-valid ciphertext change: %s", g.view.raw)
					}
				}
			})
		}
	}
}

func TestStrictModePaddingOracleCannotRecoverPlaintext(t *testing.T) {
	keys := placeholderKeyPairs()
	client := NewAESEncryption(swappedPairs(keys))
	plain := documentedTaxBody
	_, raw := mustEncrypt(t, client, plain)
	require.Equal(t, aes.BlockSize*3, len(raw))

	g := newGateway(keys, true)
	oracle := func(ct []byte) bool {
		status, _ := g.submit(t, fiber.MethodPost, base64.StdEncoding.EncodeToString(ct))
		return status == fiber.StatusOK
	}

	// Invalid padding and a padding-valid tamper of an earlier block must not be distinguishable.
	invalid := bytes.Clone(raw)
	invalid[len(invalid)-1] ^= 0x01
	validPad := bytes.Clone(raw)
	validPad[0] ^= 0x01
	if oracle(invalid) != oracle(validPad) {
		t.Errorf("strict mode revealed padding validity: invalid=%v validPad=%v", oracle(invalid), oracle(validPad))
	}

	// Block 1 holds `"value":"1234567` and block 2 holds the rest of the tax id.
	for block := 1; block <= 2; block++ {
		prev := raw[(block-1)*aes.BlockSize : block*aes.BlockSize]
		target := raw[block*aes.BlockSize : (block+1)*aes.BlockSize]
		got, ok := recoverBlock(oracle, prev, target)
		want := plaintextBlock(plain, block)
		if ok && bytes.Equal(got, want) {
			t.Errorf("padding oracle recovered plaintext block %d %q without the AES key", block, got)
		}
	}
}

func TestResponseCiphertextIsNotMalleable(t *testing.T) {
	keys := placeholderKeyPairs()
	client := NewAESEncryption(swappedPairs(keys))
	viewer := NewAESEncryption(swappedPairs(keys))
	plain := documentedNameBody
	encoded, _ := mustEncrypt(t, client, plain)

	g := newGateway(keys, false)
	status, respBody := g.submit(t, fiber.MethodPost, encoded)
	require.Equal(t, fiber.StatusOK, status)

	var wrapped PayloadBody
	require.NoError(t, json.Unmarshal(respBody, &wrapped))
	raw, err := base64.StdEncoding.DecodeString(wrapped.Payload)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(raw), aes.BlockSize*3)
	legit, err := viewer.Decrypt(wrapped.Payload)
	require.NoError(t, err)
	require.Contains(t, legit, "nnnn")

	tampered := flipByte(raw, 0, 0x01)
	out, err := viewer.Decrypt(tampered)
	if err == nil {
		t.Fatalf("response ciphertext tamper decrypted to %q", out)
	}
}

func plaintextBlock(plain string, block int) []byte {
	padded := []byte(plain)
	n := aes.BlockSize - (len(padded) % aes.BlockSize)
	padded = append(padded, bytes.Repeat([]byte{byte(n)}, n)...)
	start := block * aes.BlockSize
	return padded[start : start+aes.BlockSize]
}

func recoverBlock(oracle func([]byte) bool, prev, target []byte) ([]byte, bool) {
	inter := make([]byte, aes.BlockSize)
	dec := make([]byte, aes.BlockSize)
	for i := aes.BlockSize - 1; i >= 0; i-- {
		pad := byte(aes.BlockSize - i)
		for j := i + 1; j < aes.BlockSize; j++ {
			inter[j] = dec[j] ^ pad
		}
		found := false
		for guess := 0; guess < 256; guess++ {
			inter[i] = byte(guess)
			if !oracle(joinBlocks(inter, target)) {
				continue
			}
			if i > 0 {
				inter[i-1] ^= 0x55
				still := oracle(joinBlocks(inter, target))
				inter[i-1] ^= 0x55
				if !still {
					continue
				}
			}
			dec[i] = byte(guess) ^ pad
			found = true
			break
		}
		if !found {
			return nil, false
		}
	}
	plain := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		plain[i] = dec[i] ^ prev[i]
	}
	return plain, true
}

func joinBlocks(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}
