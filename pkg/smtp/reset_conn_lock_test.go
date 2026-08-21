package smtp

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// Session.Reset must not reach the connection through smtp.Conn: go-smtp's
// accessors (Conn, Session, TLSConnectionState, Context) take the per-connection
// lock, and Reset runs as a callback from Conn.reset. Re-entering that lock
// wedges the connection goroutine permanently — every RSET and every completed
// message stops answering, and the socket, session and connection-tracker slot
// are never released. Deadlines go through the net.Conn captured in NewSession
// instead; this test pins that by giving the session a live net.Conn and a nil
// smtp.Conn, so a regression panics here instead of hanging in production.
func TestSessionResetDoesNotUseSMTPConnAccessors(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	recorder := &deadlineRecorder{Conn: server}

	ctx, cancel := context.WithTimeout(context.Background(), SessionDeadline)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	session := &Session{
		conn:       nil, // Reset must not dereference this
		netConn:    recorder,
		ctx:        ctx,
		baseLogger: logger,
		Logger:     logger,
		remoteAddr: "192.0.2.1",
		from:       "sender@example.com",
		to:         []string{"recipient@example.com"},
	}
	traceIDBefore := session.traceID

	done := make(chan struct{})
	go func() {
		defer close(done)
		session.Reset()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Session.Reset did not return: it must not block, go-smtp calls it from Conn.reset")
	}

	if session.traceID == traceIDBefore {
		t.Error("Reset did not rotate the trace ID")
	}
	if session.from != "" || len(session.to) != 0 {
		t.Errorf("Reset did not clear the envelope: from=%q to=%v", session.from, session.to)
	}

	// The idle deadline must have been applied to the captured connection.
	if recorder.deadline.IsZero() {
		t.Error("Reset did not set the idle deadline on the captured connection")
	} else if remaining := time.Until(recorder.deadline); remaining > IdleTimeout || remaining < IdleTimeout-time.Minute {
		t.Errorf("Reset set an unexpected deadline: %v from now, want ~%v", remaining, IdleTimeout)
	}
}

// deadlineRecorder records the last deadline set on a connection.
type deadlineRecorder struct {
	net.Conn
	deadline time.Time
}

func (d *deadlineRecorder) SetDeadline(t time.Time) error {
	d.deadline = t
	return d.Conn.SetDeadline(t)
}
