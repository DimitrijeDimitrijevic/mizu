package smtp

import (
	"io"
	"log/slog"
	"regexp"
	"testing"
)

func TestGenerateTraceID(t *testing.T) {
	// Test basic generation
	traceID := generateTraceID()

	// Should be 16 hex characters
	matched, err := regexp.MatchString("^[0-9a-f]{16}$", traceID)
	if err != nil {
		t.Fatalf("Regex error: %v", err)
	}
	if !matched {
		t.Errorf("Invalid trace ID format: %s (expected 16 hex chars)", traceID)
	}

	t.Logf("Generated trace ID: %s", traceID)
}

// TestResetRotatesTraceID ensures a second message on the same connection gets
// its own trace ID (one trace ID = one message), so trace views and the
// mailqueuer ingest dedup key never conflate distinct messages.
func TestResetRotatesTraceID(t *testing.T) {
	session := &Session{
		traceID: generateTraceID(),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	first := session.traceID
	session.Reset()

	if session.traceID == first {
		t.Errorf("Reset did not rotate trace ID: still %s", first)
	}
	matched, err := regexp.MatchString("^[0-9a-f]{16}$", session.traceID)
	if err != nil {
		t.Fatalf("Regex error: %v", err)
	}
	if !matched {
		t.Errorf("Invalid rotated trace ID format: %s", session.traceID)
	}
}

func TestGenerateTraceIDUniqueness(t *testing.T) {
	// Generate 1000 trace IDs and ensure they're all unique
	ids := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := generateTraceID()
		if ids[id] {
			t.Errorf("Duplicate trace ID generated: %s", id)
		}
		ids[id] = true
	}
	t.Logf("Generated 1000 unique trace IDs")
}
