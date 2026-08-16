package smtp

import (
	"io"
	"net"
	"time"
)

// rollingDeadlineReader re-arms the connection's read deadline before every
// read, so the deadline bounds how long the peer may stall rather than how long
// the whole transfer may take.
//
// A net.Conn deadline is an absolute point in time: set once around a large
// read it becomes a budget for the entire transfer, which turns a size limit
// into a bandwidth floor and truncates slow-but-healthy senders. Re-arming per
// read keeps the stall protection while letting a transfer take as long as it
// needs, matching RFC 5321 §4.5.3.2.6, which specifies the DATA timeout per
// block rather than per message.
//
// hardLimit, when set, is the point past which the deadline is never pushed —
// otherwise a peer dripping one byte per interval could hold the phase open
// forever. The session deadline is the natural value: it is what bounds the
// rest of the transaction.
//
// Only the read deadline is touched; the write deadline stays where the caller
// (or go-smtp's response writer) put it.
type rollingDeadlineReader struct {
	r         io.Reader
	conn      net.Conn
	timeout   time.Duration
	hardLimit time.Time
}

// newRollingDeadlineReader wraps r so each read re-arms conn's read deadline.
// It returns r unchanged when there is nothing to arm — a nil conn (bare test
// sessions) or a non-positive timeout.
func newRollingDeadlineReader(r io.Reader, conn net.Conn, timeout time.Duration, hardLimit time.Time) io.Reader {
	if conn == nil || timeout <= 0 {
		return r
	}
	return &rollingDeadlineReader{r: r, conn: conn, timeout: timeout, hardLimit: hardLimit}
}

func (rr *rollingDeadlineReader) Read(p []byte) (int, error) {
	deadline := time.Now().Add(rr.timeout)
	if !rr.hardLimit.IsZero() && rr.hardLimit.Before(deadline) {
		deadline = rr.hardLimit
	}
	if err := rr.conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	return rr.r.Read(p)
}
