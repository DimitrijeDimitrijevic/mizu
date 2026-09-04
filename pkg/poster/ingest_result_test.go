package poster

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A delivery backend answers 200 for both a fresh enqueue and one it recognised
// as already queued, distinguishing them only by X-Ingest. Mizu fires its
// outgoing webhook on "queued" alone, so the value has to survive the poster's
// retry and circuit-breaker layers rather than being dropped with the response.
func TestPostEmailToDestination_SurfacesIngestResult(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"queued", IngestResultQueued, IngestResultQueued},
		{"duplicate", IngestResultDuplicate, IngestResultDuplicate},
		{"absent", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.header != "" {
					w.Header().Set(IngestResultHeader, tt.header)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))
			defer server.Close()

			got, err := PostEmailToDestinationWithContext(
				context.Background(), "test email", server.URL, "api-key", 3, false,
				"sender@example.com", "recipient@example.com", "trace-1", "",
				nil, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ingest result = %q, want %q", got, tt.want)
			}
		})
	}
}

// The circuit breaker's Call only carries an error, so the ingest result is
// captured from the enclosing scope. Guard against it being lost on that path.
func TestPostEmailToDestination_IngestResultThroughCircuitBreaker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(IngestResultHeader, IngestResultQueued)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		Enabled: true, FailureThreshold: 5, SuccessThreshold: 1,
		Timeout: time.Second, HalfOpenMaxCalls: 1, ResetTimeout: time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	got, err := PostEmailToDestinationWithContext(
		context.Background(), "test email", server.URL, "api-key", 3, false,
		"s@example.com", "r@example.com", "trace-2", "",
		cb, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != IngestResultQueued {
		t.Errorf("ingest result = %q, want %q", got, IngestResultQueued)
	}
}

// A failed delivery must not report an ingest verdict: the message was not
// accepted, so nothing should be treated as queued.
func TestPostEmailToDestination_NoIngestResultOnFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(IngestResultHeader, IngestResultQueued)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	got, err := PostEmailToDestinationWithContext(
		context.Background(), "test email", server.URL, "api-key", 1, false,
		"s@example.com", "r@example.com", "trace-3", "",
		nil, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err == nil {
		t.Fatal("expected an error for a 503 response")
	}
	if got != "" {
		t.Errorf("ingest result = %q, want empty on failure", got)
	}
}
