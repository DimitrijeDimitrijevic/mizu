package smtp

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/logging"

	gosmtp "github.com/emersion/go-smtp"
)

// TestE2E_PauseBeforeEHLOBoundedByReadTimeout pins down which layer owns the
// "how long may the client stay quiet" budget.
//
// go-smtp re-arms the read deadline from Server.ReadTimeout (config
// timeout_seconds) before every command read, so it — not the session-level
// IdleTimeout constant — decides how long a client may pause, including the
// pause between the banner and the first EHLO. A client that overruns it gets
// "421 4.4.2 Idle timeout" and a closed socket; from the MUA's side that looks
// like an unexplained broken connection right after the TLS handshake, which is
// exactly how a too-short timeout_seconds shows up in the wild (desktop MUAs
// that resolve their own LAN address before EHLO can stall for 10+ seconds).
//
// RFC 5321 §4.5.3.2.7 puts the floor for this budget at 5 minutes; the
// production default lives in config.DefaultConfig and is asserted in
// pkg/config.
func TestE2E_PauseBeforeEHLOBoundedByReadTimeout(t *testing.T) {
	const readTimeout = 700 * time.Millisecond

	tests := []struct {
		name     string
		pause    time.Duration
		wantCode string
	}{
		{"pause within budget", readTimeout / 4, "250"},
		{"pause beyond budget", readTimeout * 2, "421"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, stop := startIdleTimeoutServer(t, readTimeout)
			defer stop()

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))

			r := bufio.NewReader(conn)
			greeting, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("read greeting: %v", err)
			}
			if !strings.HasPrefix(greeting, "220") {
				t.Fatalf("greeting = %q; want 220", greeting)
			}

			// Stall the way a MUA does while it looks up its own hostname.
			time.Sleep(tt.pause)

			if _, err := conn.Write([]byte("EHLO [10.67.99.121]\r\n")); err != nil {
				t.Fatalf("write EHLO: %v", err)
			}
			resp, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("read EHLO response: %v", err)
			}
			if !strings.HasPrefix(resp, tt.wantCode) {
				t.Errorf("response = %q; want %s", resp, tt.wantCode)
			}
		})
	}
}

// startIdleTimeoutServer runs a minimal relay backend whose only interesting
// property is its command read timeout.
func startIdleTimeoutServer(t *testing.T, readTimeout time.Duration) (addr string, stop func()) {
	t.Helper()

	backend := &Backend{
		ServerConfig: &config.ServerConfig{
			Name:     "test-idle-timeout",
			Type:     "relay",
			Hostname: "localhost",
		},
		GlobalConfig:     &config.Config{Local: true},
		ConnTracker:      NewConnectionTracker(100, 10, 0, nil),
		ActiveSessionsWg: &sync.WaitGroup{},
		Logger:           logging.NewTestLogger(),
	}

	s := gosmtp.NewServer(backend)
	s.Domain = "localhost"
	s.ReadTimeout = readTimeout
	s.WriteTimeout = readTimeout
	s.AllowInsecureAuth = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go s.Serve(ln)

	return ln.Addr().String(), func() {
		s.Close()
		ln.Close()
	}
}
