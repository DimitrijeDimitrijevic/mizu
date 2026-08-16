package smtp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestRollingDeadlineReader_SlowTransferSurvives is the regression this reader
// exists for: a transfer that takes far longer than the timeout, but never
// stalls for that long, must complete. A single absolute deadline over the
// whole read would have failed it — and with a 25MB size limit that arithmetic
// silently demanded ~1.7 Mbit/s of every sender.
func TestRollingDeadlineReader_SlowTransferSurvives(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	const (
		timeout = 200 * time.Millisecond
		chunks  = 8
		gap     = timeout / 2 // progress before each deadline would fire
	)

	go func() {
		for i := 0; i < chunks; i++ {
			time.Sleep(gap)
			if _, err := client.Write([]byte("chunk")); err != nil {
				return
			}
		}
		client.Close()
	}()

	r := newRollingDeadlineReader(server, server, timeout, time.Time{})
	start := time.Now()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read failed after %v: %v", time.Since(start), err)
	}

	if want := bytes.Repeat([]byte("chunk"), chunks); !bytes.Equal(got, want) {
		t.Errorf("read %q; want %q", got, want)
	}
	// The point of the test: total time exceeded the timeout comfortably.
	if elapsed := time.Since(start); elapsed <= timeout {
		t.Errorf("transfer took %v, not longer than the %v timeout — test proves nothing", elapsed, timeout)
	}
}

// TestRollingDeadlineReader_StallIsCutOff verifies the protection is still
// there: no progress for longer than the timeout ends the read.
func TestRollingDeadlineReader_StallIsCutOff(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	const timeout = 150 * time.Millisecond

	go func() {
		client.Write([]byte("start"))
		// Then go silent, holding the connection open.
		time.Sleep(5 * time.Second)
	}()

	r := newRollingDeadlineReader(server, server, timeout, time.Time{})
	start := time.Now()
	_, err := io.ReadAll(r)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v; want %v", err, os.ErrDeadlineExceeded)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("stall took %v to detect; want ~%v", elapsed, timeout)
	}
}

// TestRollingDeadlineReader_HardLimitCaps closes the hole the rolling deadline
// would otherwise open: a peer that keeps dripping bytes must not be able to
// extend the phase past the session deadline forever.
func TestRollingDeadlineReader_HardLimitCaps(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	const (
		timeout   = 2 * time.Second // generous per-block budget...
		hardAfter = 300 * time.Millisecond
	)

	go func() {
		for {
			if _, err := client.Write([]byte("drip")); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// ...which the hard limit must override.
	r := newRollingDeadlineReader(server, server, timeout, time.Now().Add(hardAfter))
	start := time.Now()
	_, err := io.ReadAll(r)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v; want %v", err, os.ErrDeadlineExceeded)
	}
	if elapsed := time.Since(start); elapsed >= timeout {
		t.Errorf("drip lasted %v; hard limit of %v was not enforced", elapsed, hardAfter)
	}
}

// TestRollingDeadlineReader_NoConn covers bare test sessions, which have no
// connection to arm.
func TestRollingDeadlineReader_NoConn(t *testing.T) {
	src := bytes.NewReader([]byte("body"))
	if r := newRollingDeadlineReader(src, nil, time.Minute, time.Time{}); r != io.Reader(src) {
		t.Error("nil conn should return the reader unwrapped")
	}
	if r := newRollingDeadlineReader(src, &net.TCPConn{}, 0, time.Time{}); r != io.Reader(src) {
		t.Error("non-positive timeout should return the reader unwrapped")
	}
}
