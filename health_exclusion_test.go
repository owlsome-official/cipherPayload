package cipherPayload

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

// Health-exclusion spec for the payload middleware.
//
// Encryption may be skipped only when ExcludeHealthAPI is true and the
// request path, with the query string removed and trailing slashes trimmed,
// is /health or ends in the path segment /health. The comparison is
// case-sensitive. A query key or value is never part of that decision.
//
// Every other request whose method is listed in AllowMethod must run
// decryption, strict mode, and response encryption. These tests fail while
// the middleware skips that work whenever the raw URL contains the lowercase
// substring "health".
//
// GET, HEAD, and PATCH are not in the default AllowMethod list, so the
// default configuration already skips them before encryption. They are
// covered below only when AllowMethod is set to that method. CONNECT and
// TRACE are left untested: this package does not register them, and the
// skip under test is the single URL check in New, which runs before the
// method allow-list.

const (
	customerName = "Ada"
	modifiedName = "Ada [Modified]"
)

func placeholderKeyPairs() KeyPairs {
	// Obvious placeholders. Encrypt and decrypt use the same material so a
	// request built with NewAESEncryption round-trips through the middleware.
	return KeyPairs{
		AESKeyForEncrypt: bytes.Repeat([]byte("k"), 32),
		AESIVForEncrypt:  bytes.Repeat([]byte("i"), 16),
		AESKeyForDecrypt: bytes.Repeat([]byte("k"), 32),
		AESIVForDecrypt:  bytes.Repeat([]byte("i"), 16),
	}
}

type customerStore struct {
	mu    sync.Mutex
	names []string
}

func (s *customerStore) save(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names = append(s.names, name)
}

func (s *customerStore) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.names))
	copy(out, s.names)
	return out
}

func customerHandler(store *customerStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var body map[string]any
		if err := c.BodyParser(&body); err != nil || body == nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "handler_rejected"})
		}
		name, _ := body["name"].(string)
		if name != "" {
			store.save(name)
			body["name"] = name + " [Modified]"
		}
		return c.Status(fiber.StatusOK).JSON(body)
	}
}

func newCipherApp(cfg Config, store *customerStore, routes []string) *fiber.App {
	if cfg.KeyPairs.AESKeyForEncrypt == nil {
		cfg.KeyPairs = placeholderKeyPairs()
	}
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(New(cfg))
	handler := customerHandler(store)
	methods := []string{
		fiber.MethodGet,
		fiber.MethodHead,
		fiber.MethodPost,
		fiber.MethodPut,
		fiber.MethodPatch,
		fiber.MethodDelete,
		fiber.MethodOptions,
	}
	for _, route := range routes {
		for _, method := range methods {
			app.Add(method, route, handler)
		}
	}
	return app
}

func perform(t *testing.T, app *fiber.App, method, target, rawBody string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewBufferString(rawBody))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	res, err := app.Test(req, -1)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, body
}

func encryptedRequestBody(t *testing.T, plain string) string {
	t.Helper()
	enc := NewAESEncryption(placeholderKeyPairs(), false)
	ciphertext, err := enc.Encrypt(plain)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	raw, err := json.Marshal(PayloadBody{Payload: ciphertext})
	require.NoError(t, err)
	return string(raw)
}

func decryptResponsePayload(t *testing.T, raw []byte) string {
	t.Helper()
	var envelope PayloadBody
	require.NoError(t, json.Unmarshal(raw, &envelope))
	require.NotEmpty(t, envelope.Payload)
	plain, err := NewAESEncryption(placeholderKeyPairs(), false).Decrypt(envelope.Payload)
	require.NoError(t, err)
	return plain
}

func requireStrictRejection(t *testing.T, status int, raw []byte, store *customerStore) {
	t.Helper()
	require.Equal(t, fiber.StatusBadRequest, status)
	var body map[string]string
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Equal(t, "bad_request", body["status"])
	require.Equal(t, "Invalid Payload", body["message"])
	require.NotContains(t, string(raw), customerName)
	require.Empty(t, store.snapshot())
}

func requireEncryptedCustomer(t *testing.T, status int, raw []byte, store *customerStore) {
	t.Helper()
	require.Equal(t, fiber.StatusOK, status)
	plain := decryptResponsePayload(t, raw)
	require.NotContains(t, string(raw), customerName)
	require.NotContains(t, string(raw), modifiedName)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(plain), &body))
	require.Equal(t, modifiedName, body["name"])
	require.Equal(t, []string{customerName}, store.snapshot())
}

func requirePlaintextPassThrough(t *testing.T, status int, raw []byte, store *customerStore) {
	t.Helper()
	require.Equal(t, fiber.StatusOK, status)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Equal(t, modifiedName, body["name"])
	require.Empty(t, body["payload"])
	require.Contains(t, string(raw), modifiedName)
	require.Equal(t, []string{customerName}, store.snapshot())
}

var protectedRoutes = []string{
	"/api/example",
	"/api/healthcare",
	"/api/healthcheck",
	"/api/unhealthy",
	"/healthiness",
	"/api/health/records",
	"/health",
	"/api/health",
	"/api/v1/health",
}

func TestHealthExclusion_QueryDoesNotSkipStrictMode(t *testing.T) {
	targets := []string{
		"/api/example?probe=health",
		"/api/example?health=1",
		"/api/example?a=1&note=prehealthpost&b=2",
		"/api/example?probe=healthcare",
		"/api/healthcare?ready=1",
		"/api/healthcheck",
		"/api/unhealthy",
		"/healthiness",
		"/api/health/records",
		"/api/health/records?probe=health",
		"/Health",
		"/api/example?probe=Health",
		"/api/example?probe=%68ealth",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			store := &customerStore{}
			app := newCipherApp(Config{
				KeyPairs:         placeholderKeyPairs(),
				StrictMode:       true,
				ExcludeHealthAPI: true,
			}, store, protectedRoutes)
			status, raw := perform(t, app, http.MethodPost, target, `{"name":"Ada"}`)
			requireStrictRejection(t, status, raw, store)
		})
	}
}

func TestHealthExclusion_SampleConfigQueryDoesNotReturnPlaintext(t *testing.T) {
	// example/main.go builds Config with keys and DebugMode only.
	// ExcludeHealthAPI is left false and StrictMode is left false.
	cfg := Config{
		KeyPairs:  placeholderKeyPairs(),
		DebugMode: true,
	}
	baselineStore := &customerStore{}
	baselineApp := newCipherApp(cfg, baselineStore, protectedRoutes)
	baseStatus, baseRaw := perform(t, baselineApp, http.MethodPost, "/api/example", `{"name":"Ada"}`)

	store := &customerStore{}
	app := newCipherApp(cfg, store, protectedRoutes)
	status, raw := perform(t, app, http.MethodPost, "/api/example?probe=health", `{"name":"Ada"}`)

	require.NotContains(t, string(raw), modifiedName)
	require.NotContains(t, store.snapshot(), customerName)
	require.Equal(t, baseStatus, status)
	require.Equal(t, baselineStore.snapshot(), store.snapshot())
	plain := decryptResponsePayload(t, raw)
	basePlain := decryptResponsePayload(t, baseRaw)
	require.NotContains(t, plain, customerName)
	require.NotContains(t, basePlain, customerName)
	require.JSONEq(t, basePlain, plain)
}

func TestHealthExclusion_PlaintextWithoutHealthQueryStaysStrict(t *testing.T) {
	store := &customerStore{}
	app := newCipherApp(Config{
		KeyPairs:         placeholderKeyPairs(),
		StrictMode:       true,
		ExcludeHealthAPI: true,
	}, store, protectedRoutes)
	status, raw := perform(t, app, http.MethodPost, "/api/example", `{"name":"Ada"}`)
	requireStrictRejection(t, status, raw, store)
}

func TestHealthExclusion_ValidCiphertextStaysEncryptedWithHealthQuery(t *testing.T) {
	body := encryptedRequestBody(t, `{"name":"Ada"}`)
	targets := []string{
		"/api/example",
		"/api/example?probe=health",
		"/api/healthcare",
		"/api/health/records?x=health",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			store := &customerStore{}
			app := newCipherApp(Config{
				KeyPairs:         placeholderKeyPairs(),
				StrictMode:       true,
				ExcludeHealthAPI: true,
			}, store, protectedRoutes)
			status, raw := perform(t, app, http.MethodPost, target, body)
			requireEncryptedCustomer(t, status, raw, store)
		})
	}
}

func TestHealthExclusion_AllowedMethodsShareTheQueryBypass(t *testing.T) {
	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			store := &customerStore{}
			app := newCipherApp(Config{
				KeyPairs:         placeholderKeyPairs(),
				StrictMode:       true,
				ExcludeHealthAPI: true,
			}, store, protectedRoutes)
			status, raw := perform(t, app, method, "/api/example?probe=health", `{"name":"Ada"}`)
			requireStrictRejection(t, status, raw, store)
		})
	}
}

func TestHealthExclusion_CustomAllowMethodStillRejectsHealthQuery(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPatch}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			store := &customerStore{}
			app := newCipherApp(Config{
				KeyPairs:         placeholderKeyPairs(),
				StrictMode:       true,
				ExcludeHealthAPI: true,
				AllowMethod:      []string{method},
			}, store, protectedRoutes)
			status, raw := perform(t, app, method, "/api/example?probe=health", `{"name":"Ada"}`)
			if method == http.MethodHead {
				require.Equal(t, fiber.StatusBadRequest, status)
				require.Empty(t, store.snapshot())
				return
			}
			requireStrictRejection(t, status, raw, store)
		})
	}
}

func TestHealthExclusion_FlagFalseProtectsDedicatedHealthPath(t *testing.T) {
	targets := []string{
		"/health",
		"/health/",
		"/health?ready=1",
		"/health?probe=health",
		"/api/health",
		"/api/health?ready=1",
		"/api/v1/health",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			store := &customerStore{}
			app := newCipherApp(Config{
				KeyPairs:         placeholderKeyPairs(),
				StrictMode:       true,
				ExcludeHealthAPI: false,
			}, store, protectedRoutes)
			status, raw := perform(t, app, http.MethodPost, target, `{"name":"Ada"}`)
			requireStrictRejection(t, status, raw, store)
		})
	}
}

func TestHealthExclusion_FlagTrueSkipsOnlyDedicatedHealthPath(t *testing.T) {
	targets := []string{
		"/health",
		"/health/",
		"/health?ready=1",
		"/health?probe=not-a-secret",
		"/api/health",
		"/api/v1/health?ready=1",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			store := &customerStore{}
			app := newCipherApp(Config{
				KeyPairs:         placeholderKeyPairs(),
				StrictMode:       true,
				ExcludeHealthAPI: true,
			}, store, protectedRoutes)
			status, raw := perform(t, app, http.MethodPost, target, `{"name":"Ada"}`)
			requirePlaintextPassThrough(t, status, raw, store)
		})
	}
}

func TestHealthExclusion_AbsoluteFormQueryDoesNotSkipStrictMode(t *testing.T) {
	store := &customerStore{}
	app := newCipherApp(Config{
		KeyPairs:         placeholderKeyPairs(),
		StrictMode:       true,
		ExcludeHealthAPI: true,
	}, store, protectedRoutes)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		_ = app.Listener(ln)
	}()
	defer func() {
		_ = app.Shutdown()
	}()

	body := `{"name":"Ada"}`
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	// app.Test dumps absolute-form targets without a Host header, and fasthttp
	// refuses that request before the middleware. Write the request the server
	// accepts: absolute-form request-target plus Host.
	rawReq := fmt.Sprintf(
		"POST http://example.test/api/example?probe=health HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body),
		body,
	)
	_, err = conn.Write([]byte(rawReq))
	require.NoError(t, err)
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	requireStrictRejection(t, res.StatusCode, raw, store)
}
