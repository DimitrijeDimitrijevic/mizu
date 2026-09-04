package smtp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/webhook"
)

type fakeNotifier struct {
	mu   sync.Mutex
	sent []webhook.Payload
	done chan struct{}
}

func newFakeNotifier() *fakeNotifier {
	return &fakeNotifier{done: make(chan struct{}, 8)}
}

func (f *fakeNotifier) Send(_ context.Context, p webhook.Payload) error {
	f.mu.Lock()
	f.sent = append(f.sent, p)
	f.mu.Unlock()
	f.done <- struct{}{}
	return nil
}

func (f *fakeNotifier) payloads() []webhook.Payload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]webhook.Payload(nil), f.sent...)
}

// ingestStub answers each per-recipient POST with a scripted X-Ingest verdict,
// keyed by the X-Mail-To envelope address. A recipient mapped to "fail" answers
// 503, which is how a partial failure reaches mizu.
func ingestStub(t *testing.T, verdicts map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := verdicts[r.Header.Get("X-Mail-To")]
		if v == "fail" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if v != "" {
			w.Header().Set("X-Ingest", v)
		}
		w.WriteHeader(http.StatusOK)
	}))
}

var fiveRecipients = []string{"r1@example.com", "r2@example.com", "r3@example.com", "r4@example.com", "r5@example.com"}

func webhookSession(t *testing.T, n WebhookNotifier, serverType string, deliveryURL string, client *http.Client) *Session {
	t.Helper()
	return &Session{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		ctx:               context.Background(),
		serverConfig:      &config.ServerConfig{Name: "mizu-out", Type: serverType, Delivery: config.DeliveryConfig{URL: deliveryURL, MaxRetryAttempts: 1}},
		webhookClient:     n,
		traceID:           "trace-1",
		from:              "alias@example.com",
		isAuthenticated:   true,
		authenticatedUser: "sender@example.com",
		to:                append([]string(nil), fiveRecipients...),
		subject:           "Quarterly report",
		messageID:         "abc@example.com",
		remoteAddr:        "203.0.113.7",
		clientUserAgent:   "Thunderbird",
		spamResult:        &SpamCheckResult{Action: "no action", Score: 1.25},
		sessionsWg:        &sync.WaitGroup{},
		httpClient:        client,
	}
}

// runTransaction mirrors what Data() does: deliver, then dispatch on BOTH the
// success and the failure path.
func runTransaction(s *Session) error {
	err := s.deliverSynchronous(context.Background(), "raw email")
	s.dispatchWebhook()
	s.sessionsWg.Wait()
	return err
}

// The scenario table from the design: exactly one notification per message,
// fired on the first transaction that queues anything.
func TestDispatchWebhook_ExactlyOncePerMessage(t *testing.T) {
	tests := []struct {
		name      string
		verdicts  map[string]string
		wantFire  bool
		wantError bool
	}{
		{
			name: "first attempt, partial failure at recipient 4",
			verdicts: map[string]string{
				"r1@example.com": "queued", "r2@example.com": "queued",
				"r3@example.com": "queued", "r4@example.com": "fail",
			},
			wantFire: true, wantError: true,
		},
		{
			name: "sender retries: earlier recipients are duplicates",
			verdicts: map[string]string{
				"r1@example.com": "duplicate", "r2@example.com": "duplicate",
				"r3@example.com": "duplicate", "r4@example.com": "queued",
				"r5@example.com": "queued",
			},
			wantFire: false,
		},
		{
			name: "all queued on a clean first attempt",
			verdicts: map[string]string{
				"r1@example.com": "queued", "r2@example.com": "queued", "r3@example.com": "queued",
				"r4@example.com": "queued", "r5@example.com": "queued",
			},
			wantFire: true,
		},
		{
			name: "250 lost, sender replays the whole transaction",
			verdicts: map[string]string{
				"r1@example.com": "duplicate", "r2@example.com": "duplicate", "r3@example.com": "duplicate",
				"r4@example.com": "duplicate", "r5@example.com": "duplicate",
			},
			wantFire: false,
		},
		{
			name:      "attempt fails on the very first recipient",
			verdicts:  map[string]string{"r1@example.com": "fail"},
			wantFire:  false,
			wantError: true,
		},
		{
			name: "recipient 4 still failing on a later retry",
			verdicts: map[string]string{
				"r1@example.com": "duplicate", "r2@example.com": "duplicate",
				"r3@example.com": "duplicate", "r4@example.com": "fail",
			},
			wantFire: false, wantError: true,
		},
		{
			name: "backend reports no verdict at all",
			verdicts: map[string]string{
				"r1@example.com": "", "r2@example.com": "", "r3@example.com": "",
				"r4@example.com": "", "r5@example.com": "",
			},
			wantFire: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := ingestStub(t, tt.verdicts)
			defer server.Close()

			n := newFakeNotifier()
			s := webhookSession(t, n, "submission", server.URL, server.Client())

			err := runTransaction(s)
			if tt.wantError && err == nil {
				t.Error("expected a delivery error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected delivery error: %v", err)
			}

			got := n.payloads()
			if tt.wantFire && len(got) != 1 {
				t.Fatalf("dispatched %d webhooks, want exactly 1", len(got))
			}
			if !tt.wantFire && len(got) != 0 {
				t.Fatalf("dispatched %d webhooks, want none: %+v", len(got), got)
			}

			// Even a partial failure reports the whole envelope: every
			// recipient passed RCPT TO, so the message is fully described.
			if tt.wantFire && len(got[0].Recipients) != len(fiveRecipients) {
				t.Errorf("recipients = %v, want all %d envelope recipients", got[0].Recipients, len(fiveRecipients))
			}
		})
	}
}

// Across the two attempts of a partial failure the app must be told exactly
// once, so a per-message counter lands on 1.
func TestDispatchWebhook_PartialFailureCountsOnce(t *testing.T) {
	n := newFakeNotifier()

	first := ingestStub(t, map[string]string{
		"r1@example.com": "queued", "r2@example.com": "queued",
		"r3@example.com": "queued", "r4@example.com": "fail",
	})
	defer first.Close()
	if err := runTransaction(webhookSession(t, n, "submission", first.URL, first.Client())); err == nil {
		t.Fatal("expected the first attempt to fail")
	}

	retry := ingestStub(t, map[string]string{
		"r1@example.com": "duplicate", "r2@example.com": "duplicate", "r3@example.com": "duplicate",
		"r4@example.com": "queued", "r5@example.com": "queued",
	})
	defer retry.Close()
	if err := runTransaction(webhookSession(t, n, "submission", retry.URL, retry.Client())); err != nil {
		t.Fatalf("expected the retry to succeed: %v", err)
	}

	if got := n.payloads(); len(got) != 1 {
		t.Fatalf("dispatched %d webhooks across both attempts, want exactly 1", len(got))
	}
}

func TestDispatchWebhook_Direction(t *testing.T) {
	for _, tt := range []struct{ serverType, want string }{
		{"submission", "outgoing"},
		{"relay", "incoming"},
	} {
		t.Run(tt.serverType, func(t *testing.T) {
			server := ingestStub(t, map[string]string{
				"r1@example.com": "queued", "r2@example.com": "queued", "r3@example.com": "queued",
				"r4@example.com": "queued", "r5@example.com": "queued",
			})
			defer server.Close()

			n := newFakeNotifier()
			s := webhookSession(t, n, tt.serverType, server.URL, server.Client())
			if err := runTransaction(s); err != nil {
				t.Fatalf("delivery: %v", err)
			}

			got := n.payloads()
			if len(got) != 1 {
				t.Fatalf("dispatched %d webhooks, want 1", len(got))
			}
			if got[0].Direction != tt.want {
				t.Errorf("direction = %q, want %q", got[0].Direction, tt.want)
			}
			if got[0].Server != "mizu-out" {
				t.Errorf("server = %q, want the [[server]] name", got[0].Server)
			}
		})
	}
}

func TestDispatchWebhook_NilSpamResult(t *testing.T) {
	server := ingestStub(t, map[string]string{
		"r1@example.com": "queued", "r2@example.com": "queued", "r3@example.com": "queued",
		"r4@example.com": "queued", "r5@example.com": "queued",
	})
	defer server.Close()

	n := newFakeNotifier()
	s := webhookSession(t, n, "submission", server.URL, server.Client())
	s.spamResult = nil
	if err := runTransaction(s); err != nil {
		t.Fatalf("delivery: %v", err)
	}

	got := n.payloads()
	if len(got) != 1 {
		t.Fatalf("dispatched %d webhooks, want 1", len(got))
	}
	if got[0].SpamAction != "" || got[0].SpamScore != 0 {
		t.Errorf("spam fields = %q/%v, want zero values", got[0].SpamAction, got[0].SpamScore)
	}
}

// Captures the exact JSON an app receives, end to end through the real client.
func TestWebhookPayload_OnTheWire(t *testing.T) {
	received := make(chan []byte, 1)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer app.Close()

	ingest := ingestStub(t, map[string]string{
		"r1@example.com": "queued", "r2@example.com": "queued", "r3@example.com": "queued",
		"r4@example.com": "queued", "r5@example.com": "queued",
	})
	defer ingest.Close()

	s := webhookSession(t, webhook.NewClient(app.URL, "secret", 5*time.Second, 1,
		slog.New(slog.NewTextHandler(io.Discard, nil))), "submission", ingest.URL, ingest.Client())
	if err := runTransaction(s); err != nil {
		t.Fatalf("delivery: %v", err)
	}

	select {
	case body := <-received:
		var pretty map[string]any
		if err := json.Unmarshal(body, &pretty); err != nil {
			t.Fatalf("payload is not valid JSON: %v", err)
		}
		out, _ := json.MarshalIndent(pretty, "", "  ")
		t.Logf("payload delivered to the app:\n%s", out)
	case <-time.After(3 * time.Second):
		t.Fatal("app received no webhook")
	}
}
