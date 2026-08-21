package logging

import (
	"log"
	"log/slog"
	"strings"
)

// httpServerErrorWriter adapts a slog.Logger for use as a net/http
// Server.ErrorLog. The stdlib http.Server emits connection-scoped diagnostics
// through ErrorLog (e.g. "http: TLS handshake error from 1.2.3.4:5: client sent
// an HTTP request to an HTTPS server") with no indication of which listener
// produced them, because the format only carries the *client's* address. The
// adapter tags every line with the service name and bind address of the
// listener it belongs to.
type httpServerErrorWriter struct {
	logger  *slog.Logger
	service string
	addr    string
}

// benignErrorSubstrings identifies client-caused diagnostics that are routine
// internet noise on public ports rather than server faults. Matched as
// substrings (not exact prefixes) so minor stdlib rewordings don't silently
// escalate them to ERROR. The classic case is a scanner probing :443 with
// plaintext HTTP ("http: TLS handshake error from ..."); a client sending a
// legacy semicolon-separated query is another.
var benignErrorSubstrings = []string{
	"TLS handshake error",
	"URL query contains semicolon",
}

func (w *httpServerErrorWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimRight(string(p), "\n")
	// Client-caused noise stays at INFO; anything else (accept errors, handler
	// panics already recovered per-request, aborts) is a real ERROR.
	for _, s := range benignErrorSubstrings {
		if strings.Contains(msg, s) {
			w.logger.Info("HTTP server error", "service", w.service, "addr", w.addr, "message", msg)
			return len(p), nil
		}
	}
	w.logger.Error("HTTP server error", "service", w.service, "addr", w.addr, "message", msg)
	return len(p), nil
}

// NewHTTPErrorLogger returns a *log.Logger suitable for http.Server.ErrorLog
// that routes the server's diagnostics into the given slog logger, tagged with
// the service name (e.g. "acme-tls-alpn-01") and bind address (e.g. ":443") so
// they can be attributed to the listener that emitted them.
func NewHTTPErrorLogger(logger *slog.Logger, service, addr string) *log.Logger {
	return log.New(&httpServerErrorWriter{logger: logger, service: service, addr: addr}, "", 0)
}
