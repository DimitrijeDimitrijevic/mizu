// Package webhook posts a JSON notification for each outgoing message that a
// delivery backend has just enqueued.
//
// The notification is deliberately fired only for messages the backend reports
// as newly queued (poster.IngestResultQueued). A backend that recognises a
// message as already queued answers with the same 200 OK, and suppressing the
// notification there is what lets a receiver record one row per message without
// having to deduplicate: an MTA that retries a whole transaction produces no
// second notification.
//
// Dispatch is advisory. The message is already durably queued by the time a
// webhook is attempted, so a failure here is logged and counted but never
// propagated back into the SMTP transaction, which would only provoke a
// redundant retry of mail that was accepted.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Payload is the JSON body posted for one accepted outgoing message.
//
// It describes the message, not a single delivery: Recipients holds every
// envelope recipient of the SMTP transaction, even though the message is
// handed to the delivery backend one recipient at a time.
//
// MailFrom and AuthUser are reported separately and routinely differ. A
// submission user may send as any address its allowed_from grants - an alias,
// a *@domain wildcard, or a /regex/ match - so the envelope sender identifies
// the message while the authenticated user identifies the account responsible
// for it. AuthUser is empty for unauthenticated relay and inbound mail.
type Payload struct {
	TraceID string `json:"trace_id"`
	// Direction is "outgoing" for a submission server and "incoming" for a
	// relay one. Server names the [[server]] the message arrived on, which
	// separates the inbound-MX and relay tiers - both are type = "relay".
	Direction       string   `json:"direction"`
	Server          string   `json:"server"`
	MailFrom        string   `json:"mail_from"`
	AuthUser        string   `json:"auth_user"`
	Recipients      []string `json:"recipients"`
	Subject         string   `json:"subject"`
	MessageID       string   `json:"message_id"`
	SpamAction      string   `json:"spam_action"`
	SpamScore       float64  `json:"spam_score"`
	ClientIP        string   `json:"client_ip"`
	ClientUserAgent string   `json:"client_user_agent"`
}

// Client posts Payloads to a configured endpoint.
type Client struct {
	url         string
	authToken   string
	maxAttempts int
	httpClient  *http.Client
	logger      *slog.Logger
}

// NewClient builds a webhook client. timeout bounds a single POST attempt, not
// the whole retry sequence. maxAttempts below 1 is treated as 1.
//
// The default is a single attempt. The payload carries no idempotency key, so a
// receiver counting one event per message cannot tell a genuine retry from a
// first delivery whose response was merely lost - retrying would over-count.
// Losing a notification to a transient blip is the safer failure.
func NewClient(url, authToken string, timeout time.Duration, maxAttempts int, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	return &Client{
		url:         url,
		authToken:   authToken,
		maxAttempts: maxAttempts,
		httpClient: &http.Client{
			Timeout: timeout,
			// A webhook endpoint has no legitimate redirect use, and following
			// one would forward the payload (including recipients and the
			// bearer token's effects) to an unvetted host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger: logger,
	}
}

// Send posts the payload, retrying transient failures with exponential backoff.
// It blocks; callers are expected to dispatch it on their own goroutine.
//
// Every attempt is logged with the destination URL, the response status the
// receiver returned, and the trace ID of the message being reported, so a
// notification can be followed from the SMTP session to the receiver's answer.
func (c *Client) Send(ctx context.Context, p Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < c.maxAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return fmt.Errorf("webhook cancelled during backoff: %w", ctx.Err())
			}
		}

		start := time.Now()
		status, retryable, err := c.post(ctx, body)
		duration := time.Since(start)

		if err == nil {
			c.logger.Info("Webhook delivered",
				"url", c.url,
				"status", status,
				"trace_id", p.TraceID,
				"direction", p.Direction,
				"recipients", len(p.Recipients),
				"attempt", attempt+1,
				"duration_ms", duration.Milliseconds())
			return nil
		}

		// status is 0 when the request never produced a response (DNS failure,
		// connection refused, timeout), which is worth distinguishing in logs
		// from a receiver that answered and rejected.
		lastErr = err
		c.logger.Warn("Webhook attempt failed",
			"url", c.url,
			"status", status,
			"trace_id", p.TraceID,
			"attempt", attempt+1,
			"max_attempts", c.maxAttempts,
			"retryable", retryable,
			"duration_ms", duration.Milliseconds(),
			"error", err)

		if !retryable {
			return err
		}
	}

	return fmt.Errorf("webhook failed after %d attempts: %w", c.maxAttempts, lastErr)
}

// post performs one attempt, returning the response status (0 if the request
// never got one) and whether the failure is worth retrying. Transport errors
// and 429/5xx are retryable; any other non-2xx is not, since a malformed or
// unauthorized payload will fail identically next time.
func (c *Client) post(ctx context.Context, body []byte) (status int, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return 0, false, fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, true, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	// Drain the response so the keep-alive connection can be reused; a
	// receiver's body is not otherwise interesting to us.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, false, nil
	}
	retryable = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return resp.StatusCode, retryable, fmt.Errorf("webhook returned status %d", resp.StatusCode)
}
