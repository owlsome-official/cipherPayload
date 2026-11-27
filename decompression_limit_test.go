package cipherPayload

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	brrr "github.com/molecule-man/go-brrr"
	"github.com/stretchr/testify/require"
)

// These tests are the spec for the request-body decompression limit.
// They fail while cipherPayload parses a compressed JSON or XML body through
// Fiber's unlimited gzip, brotli, and deflate readers. A fix passes them by
// rejecting Content-Encoding before that parse, or by capping every decoder's
// output at the same limit as the raw request body. Fully expanding the body
// and then rejecting it still fails: the heap delta below counts that expansion.

const decompressionTestKey = "12345678901234567890123456789012"

func TestUncompressedJSONRequestStillDecrypts(t *testing.T) {
	keys := decompressionTestKeys()
	app := newDecompressionApp(t, decompressionAppOptions{})

	plain := `{"hello":"world"}`
	encrypted, err := NewCipher(ModeGCM, keys).Encrypt(plain)
	require.NoError(t, err)

	body := []byte(`{"payload":"` + encrypted + `"}`)
	limit := app.Config().BodyLimit
	require.Less(t, len(body), limit)

	status, responseBody := postDecompressionRequest(t, app, decompressionRequest{
		method:      fiber.MethodPost,
		contentType: fiber.MIMEApplicationJSON,
		body:        body,
	})
	require.Equal(t, fiber.StatusOK, status)

	var wrapped PayloadBody
	require.NoError(t, json.Unmarshal(responseBody, &wrapped))
	decrypted, err := NewCipher(ModeGCM, keys).Decrypt(wrapped.Payload)
	require.NoError(t, err)
	require.JSONEq(t, plain, decrypted)
}

func TestRequestBodyDecompressionLimit(t *testing.T) {
	const smallLimit = 64 * 1024

	cases := []decompressionCase{
		{name: "default limit gzip", encoding: "gzip"},
		{name: "default limit deflate", encoding: "deflate"},
		{name: "default limit br", encoding: "br"},
		{name: "default limit brotli", encoding: "brotli"},
		{name: "put", encoding: "gzip", method: fiber.MethodPut, bodyLimit: smallLimit},
		{name: "delete", encoding: "gzip", method: fiber.MethodDelete, bodyLimit: smallLimit},
		{name: "options", encoding: "gzip", method: fiber.MethodOptions, bodyLimit: smallLimit},
		{name: "strict mode", encoding: "gzip", bodyLimit: smallLimit, strict: true},
		{name: "cbc mode", encoding: "deflate", bodyLimit: smallLimit, mode: ModeCBC},
		{name: "json charset", encoding: "gzip", bodyLimit: smallLimit, contentType: fiber.MIMEApplicationJSONCharsetUTF8},
		{name: "problem json", encoding: "br", bodyLimit: smallLimit, contentType: "application/problem+json"},
		{name: "application xml", encoding: "gzip", bodyLimit: smallLimit, contentType: fiber.MIMEApplicationXML},
		{name: "text xml", encoding: "deflate", bodyLimit: smallLimit, contentType: fiber.MIMETextXML},
		{name: "chunked gzip", encoding: "gzip", bodyLimit: smallLimit, chunked: true},
		{name: "allowed patch", encoding: "brotli", bodyLimit: smallLimit, method: fiber.MethodPatch, allow: []string{fiber.MethodPatch}},
		{name: "health exclusion does not cover other routes", encoding: "gzip", bodyLimit: smallLimit, excludeHealth: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GC()
			assertCompressedBodyStaysWithinRawLimit(t, tc)
		})
	}
}

type decompressionCase struct {
	name          string
	encoding      string
	method        string
	contentType   string
	bodyLimit     int
	strict        bool
	mode          CipherMode
	allow         []string
	chunked       bool
	excludeHealth bool
}

type decompressionAppOptions struct {
	bodyLimit     int
	strict        bool
	mode          CipherMode
	allow         []string
	excludeHealth bool
}

type decompressionRequest struct {
	method      string
	contentType string
	encoding    string
	body        []byte
	chunked     bool
}

func assertCompressedBodyStaysWithinRawLimit(t *testing.T, tc decompressionCase) {
	t.Helper()

	app := newDecompressionApp(t, decompressionAppOptions{
		bodyLimit:     tc.bodyLimit,
		strict:        tc.strict,
		mode:          tc.mode,
		allow:         tc.allow,
		excludeHealth: tc.excludeHealth,
	})
	limit := app.Config().BodyLimit
	require.Positive(t, limit)
	if tc.bodyLimit == 0 {
		require.Equal(t, 4*1024*1024, limit)
	}

	plain := expandableBody(tc.contentType, expandedSize(limit))
	require.Greater(t, len(plain), limit)
	compressed := compressBody(t, tc.encoding, plain)
	require.Less(t, len(compressed), limit, "compressed body must sit under the raw request limit")

	method := tc.method
	if method == "" {
		method = fiber.MethodPost
	}
	contentType := tc.contentType
	if contentType == "" {
		contentType = fiber.MIMEApplicationJSON
	}

	// A tiny request pays for one-time server setup outside the measurement.
	postDecompressionRequest(t, app, decompressionRequest{
		method:      method,
		contentType: contentType,
		body:        []byte(`{"payload":""}`),
	})

	runtime.GC()
	before := heapTotalAlloc()
	status, _ := postDecompressionRequest(t, app, decompressionRequest{
		method:      method,
		contentType: contentType,
		encoding:    tc.encoding,
		body:        compressed,
		chunked:     tc.chunked,
	})
	delta := heapTotalAlloc() - before

	// The raw limit applies only to the compressed bytes. Passing the test
	// requires the process not to allocate the expanded document. Rejecting
	// the encoding, or stopping the decoder at the raw limit, both stay under
	// this line. Materializing plain and then returning an error does not.
	require.Less(t, delta, uint64(len(plain)),
		"status %d: %s %s body of %d bytes expanded to %d bytes, past the %d byte raw limit; heap grew by %d",
		status, tc.encoding, contentType, len(compressed), len(plain), limit, delta)
}

func newDecompressionApp(t *testing.T, opts decompressionAppOptions) *fiber.App {
	t.Helper()

	fiberCfg := fiber.Config{DisableStartupMessage: true}
	if opts.bodyLimit > 0 {
		fiberCfg.BodyLimit = opts.bodyLimit
	}
	app := fiber.New(fiberCfg)

	cfg := Config{
		KeyPairs:         decompressionTestKeys(),
		StrictMode:       opts.strict,
		Mode:             opts.mode,
		AllowMethod:      opts.allow,
		ExcludeHealthAPI: opts.excludeHealth,
	}
	app.Use(New(cfg))
	app.All("/api/example", func(c *fiber.Ctx) error {
		return c.Send(c.Body())
	})
	return app
}

func decompressionTestKeys() KeyPairs {
	return KeyPairs{
		AESKeyForEncrypt: []byte(decompressionTestKey),
		AESIVForEncrypt:  []byte("1234567890123456"),
		AESKeyForDecrypt: []byte(decompressionTestKey),
		AESIVForDecrypt:  []byte("1234567890123456"),
	}
}

// expandedSize is larger than the allocations a decoder can make while
// stopping at limit. ByteBuffer.ReadFrom doubles up to the next power of two
// past the cap, and that series sums to about four times a power-of-two limit.
// The extra mebibyte covers the rest of the request.
func expandedSize(limit int) int {
	return limit*8 + 1<<20
}

func expandableBody(contentType string, size int) []byte {
	if strings.Contains(contentType, "xml") {
		open := []byte("<r>")
		closeTag := []byte("</r>")
		fill := size - len(open) - len(closeTag)
		if fill < 1 {
			fill = 1
		}
		body := make([]byte, 0, len(open)+fill+len(closeTag))
		body = append(body, open...)
		body = append(body, bytes.Repeat([]byte("A"), fill)...)
		body = append(body, closeTag...)
		return body
	}

	prefix := []byte(`{"payload":"`)
	suffix := []byte(`"}`)
	fill := size - len(prefix) - len(suffix)
	if fill < 1 {
		fill = 1
	}
	body := make([]byte, 0, len(prefix)+fill+len(suffix))
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("A"), fill)...)
	body = append(body, suffix...)
	return body
}

func compressBody(t *testing.T, encoding string, plain []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	var writer io.WriteCloser
	var err error
	switch encoding {
	case "gzip":
		writer, err = gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	case "deflate":
		writer, err = zlib.NewWriterLevel(&buf, zlib.BestSpeed)
	case "br", "brotli":
		writer, err = brrr.NewWriter(&buf, brrr.BestSpeed)
	default:
		t.Fatalf("unknown encoding %q", encoding)
	}
	require.NoError(t, err)
	_, err = writer.Write(plain)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

func postDecompressionRequest(t *testing.T, app *fiber.App, req decompressionRequest) (int, []byte) {
	t.Helper()

	if req.chunked {
		return postChunkedDecompressionRequest(t, app, req)
	}

	httpReq := httptest.NewRequest(req.method, "/api/example", bytes.NewReader(req.body))
	httpReq.Header.Set(fiber.HeaderContentType, req.contentType)
	if req.encoding != "" {
		httpReq.Header.Set(fiber.HeaderContentEncoding, req.encoding)
	}

	resp, err := app.Test(httpReq, 60_000)
	require.NoError(t, err)
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, responseBody
}

func postChunkedDecompressionRequest(t *testing.T, app *fiber.App, req decompressionRequest) (int, []byte) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- app.Listener(ln)
	}()
	t.Cleanup(func() {
		_ = app.Shutdown()
		<-done
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	var raw bytes.Buffer
	fmt.Fprintf(&raw, "%s /api/example HTTP/1.1\r\n", req.method)
	fmt.Fprintf(&raw, "Host: %s\r\n", ln.Addr().String())
	fmt.Fprintf(&raw, "Content-Type: %s\r\n", req.contentType)
	if req.encoding != "" {
		fmt.Fprintf(&raw, "Content-Encoding: %s\r\n", req.encoding)
	}
	raw.WriteString("Transfer-Encoding: chunked\r\n")
	raw.WriteString("Connection: close\r\n\r\n")
	fmt.Fprintf(&raw, "%x\r\n", len(req.body))
	raw.Write(req.body)
	raw.WriteString("\r\n0\r\n\r\n")

	_, err = conn.Write(raw.Bytes())
	require.NoError(t, err)

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	require.NoError(t, err)
	var status int
	_, err = fmt.Sscanf(statusLine, "HTTP/1.1 %d", &status)
	require.NoError(t, err)

	responseBody, err := io.ReadAll(reader)
	require.NoError(t, err)
	return status, responseBody
}

func heapTotalAlloc() uint64 {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.TotalAlloc
}
