package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewHTTPErrorLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l := NewHTTPErrorLogger(logger, "acme-tls-alpn-01", ":443")

	// The classic case: client sent plaintext HTTP to the TLS port. Routine
	// scanner noise -> INFO, tagged with service and addr.
	l.Printf("http: TLS handshake error from [2001:410:3:5::]:22730: client sent an HTTP request to an HTTPS server")
	out := buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("handshake error should log at INFO, got: %s", out)
	}
	if !strings.Contains(out, "service=acme-tls-alpn-01") || !strings.Contains(out, "addr=:443") {
		t.Errorf("log line missing service/addr attribution: %s", out)
	}
	if !strings.Contains(out, "client sent an HTTP request to an HTTPS server") {
		t.Errorf("original message lost: %s", out)
	}

	// Another client-caused case: legacy semicolon-separated query string.
	buf.Reset()
	l.Printf("http: URL query contains semicolon, which is no longer a supported separator; parts of the query may be stripped when parsed; see golang.org/issue/25192")
	out = buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("semicolon query notice should log at INFO, got: %s", out)
	}

	// Anything else is a real error.
	buf.Reset()
	l.Printf("http: Accept error: some failure; retrying in 5ms")
	out = buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("accept error should log at ERROR, got: %s", out)
	}
	if !strings.Contains(out, "service=acme-tls-alpn-01") {
		t.Errorf("log line missing service attribution: %s", out)
	}
}
