package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSend_PostsJSONPayload(t *testing.T) {
	var got Payload
	var contentType, auth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	want := Payload{
		TraceID:         "trace-1",
		MailFrom:        "alias@example.com",
		AuthUser:        "sender@example.com",
		Recipients:      []string{"a@example.com", "b@example.com"},
		Subject:         "Grüße",
		MessageID:       "abc@example.com",
		SpamAction:      "no action",
		SpamScore:       1.25,
		ClientIP:        "203.0.113.7",
		ClientUserAgent: "Thunderbird",
	}

	c := NewClient(server.URL, "tok", 5*time.Second, 3, testLogger())
	if err := c.Send(context.Background(), want); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	if auth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", auth)
	}
	if got.TraceID != want.TraceID || got.Subject != want.Subject || got.SpamScore != want.SpamScore {
		t.Errorf("payload round-trip mismatch: got %+v want %+v", got, want)
	}
	if got.MailFrom != want.MailFrom || got.AuthUser != want.AuthUser {
		t.Errorf("sender identity = %q/%q, want %q/%q", got.MailFrom, got.AuthUser, want.MailFrom, want.AuthUser)
	}
	if len(got.Recipients) != 2 {
		t.Errorf("recipients = %v, want both envelope recipients", got.Recipients)
	}
}

// A transient failure at the receiver must not lose the notification.
func TestSend_RetriesServerErrors(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := NewClient(server.URL, "", 5*time.Second, 3, testLogger())
	if err := c.Send(context.Background(), Payload{TraceID: "t"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", calls.Load())
	}
}

// A rejected payload fails identically on every attempt, so retrying only
// delays the failure and multiplies load on the receiver.
func TestSend_DoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := NewClient(server.URL, "", 5*time.Second, 3, testLogger())
	if err := c.Send(context.Background(), Payload{TraceID: "t"}); err == nil {
		t.Fatal("expected an error for 401")
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (no retry on 4xx)", calls.Load())
	}
}

func TestSend_ExhaustsAttemptsThenFails(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	c := NewClient(server.URL, "", 5*time.Second, 2, testLogger())
	if err := c.Send(context.Background(), Payload{TraceID: "t"}); err == nil {
		t.Fatal("expected an error after exhausting attempts")
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", calls.Load())
	}
}

// A webhook endpoint has no legitimate redirect use, and following one would
// forward the payload to an unvetted host.
func TestSend_DoesNotFollowRedirects(t *testing.T) {
	var elsewhereHit atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhereHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	c := NewClient(server.URL, "", 5*time.Second, 1, testLogger())
	if err := c.Send(context.Background(), Payload{TraceID: "t"}); err == nil {
		t.Fatal("expected an error rather than a followed redirect")
	}
	if elsewhereHit.Load() {
		t.Error("payload was forwarded to the redirect target")
	}
}

// Operators need to correlate a notification with the SMTP session that caused
// it and with what the receiver answered, so the URL, the response status and
// the trace ID must all reach the log.
func TestSend_LogsURLStatusAndTraceID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	var buf bytes.Buffer
	c := NewClient(server.URL, "", 5*time.Second, 1,
		slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err := c.Send(context.Background(), Payload{TraceID: "trace-xyz", Direction: "outgoing"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	logged := buf.String()
	for _, want := range []string{"url=" + server.URL, "status=202", "trace_id=trace-xyz"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log is missing %q:\n%s", want, logged)
		}
	}
}

func TestSend_LogsStatusOnRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	var buf bytes.Buffer
	c := NewClient(server.URL, "", 5*time.Second, 1,
		slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err := c.Send(context.Background(), Payload{TraceID: "trace-401"}); err == nil {
		t.Fatal("expected an error for 401")
	}

	logged := buf.String()
	for _, want := range []string{"url=" + server.URL, "status=401", "trace_id=trace-401", "retryable=false"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log is missing %q:\n%s", want, logged)
		}
	}
}

// A request that never reaches the receiver has no status; the log must still
// carry the URL and trace ID so the failure is attributable.
func TestSend_LogsTransportFailureWithoutStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close() // nothing is listening now

	var buf bytes.Buffer
	c := NewClient(url, "", 2*time.Second, 1,
		slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err := c.Send(context.Background(), Payload{TraceID: "trace-down"}); err == nil {
		t.Fatal("expected an error when the receiver is unreachable")
	}

	logged := buf.String()
	for _, want := range []string{"url=" + url, "status=0", "trace_id=trace-down"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log is missing %q:\n%s", want, logged)
		}
	}
}
