package poster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"log/slog"

	"migadu/mizu/pkg/metrics"
)

// Delivery backends answer 200 OK both for a message they enqueued on this
// request and for one they recognised as already queued from an earlier
// attempt. IngestResultHeader carries that distinction, which is otherwise
// invisible: same status, same body. It is a response header on the delivery
// POST, so it never becomes part of the message and never reaches a recipient.
//
// An empty value means the backend does not report the distinction; callers
// must treat that as unknown rather than assuming either verdict.
const (
	IngestResultHeader    = "X-Ingest"
	IngestResultQueued    = "queued"
	IngestResultDuplicate = "duplicate"
)

// statusCodeBucket maps an HTTP status code to a bucket label (e.g. "2xx", "4xx", "5xx")
// to avoid unbounded label cardinality in Prometheus metrics.
func statusCodeBucket(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	default:
		return "other"
	}
}

// NewHTTPClient creates a new HTTP client with the specified timeout and connection pool settings.
// The timeout controls the maximum time for the entire request/response cycle.
// maxIdleConnsPerHost controls how many idle connections to keep per backend host (0 = use default 100).
// maxConnsPerHost limits total connections per host (0 = unlimited).
// idleConnTimeout controls how long idle connections stay in the pool (0 = use default 90s).
// These settings are critical for high-throughput relay scenarios — Go's default of 2 idle
// connections per host is insufficient when posting many emails to a single backend.
func NewHTTPClient(timeout time.Duration, maxIdleConnsPerHost, maxConnsPerHost int, idleConnTimeout time.Duration) *http.Client {
	// Apply sensible defaults if not configured
	if maxIdleConnsPerHost <= 0 {
		maxIdleConnsPerHost = 100
	}
	if idleConnTimeout <= 0 {
		idleConnTimeout = 90 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = maxIdleConnsPerHost * 2 // Total idle connections across all hosts
	transport.MaxIdleConnsPerHost = maxIdleConnsPerHost
	transport.MaxConnsPerHost = maxConnsPerHost // 0 = unlimited
	transport.IdleConnTimeout = idleConnTimeout

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// A delivery endpoint has no legitimate redirect use. Stop at the first
		// response instead of following 3xx, which could re-route the message
		// body (Go only strips the Authorization header on cross-host redirects,
		// so the message itself would still be forwarded wherever pointed).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// PostEmailToDestinationWithContext sends the raw email content to the destination with retry logic and context support.
// It implements exponential backoff between retries and respects context cancellation.
// The isJunk parameter adds an X-Junk header to help the destination system handle spam appropriately.
// The mailFrom and mailTo parameters are added as X-Mail-From and X-Mail-To headers with envelope addresses.
// The traceID parameter is added as X-Trace-ID header for distributed tracing and log correlation.
// The authenticatedUser parameter is added as X-Auth-User header when the message was sent via authenticated submission.
// The circuitBreaker parameter is optional - if provided, each retry attempt will be protected by the circuit breaker.
// The httpClient parameter specifies the HTTP client to use for requests (with configured timeout).
//
// On success it returns the destination's X-Ingest value, which distinguishes a
// message the backend enqueued just now ("queued") from one it recognised as
// already queued ("duplicate"). Both are 200 OK. The string is empty when the
// backend sends no such header, so callers must treat "" as "unknown" rather
// than as either verdict.
func PostEmailToDestinationWithContext(ctx context.Context, rawEmail string, destinationURL, apiKey string, maxRetryAttempts int, isJunk bool, mailFrom string, mailTo string, traceID string, authenticatedUser string, circuitBreaker *CircuitBreaker, httpClient *http.Client, logger *slog.Logger, m *metrics.Metrics) (string, error) {
	return postEmailWithRetries(ctx, rawEmail, destinationURL, apiKey, maxRetryAttempts, isJunk, mailFrom, mailTo, traceID, authenticatedUser, circuitBreaker, httpClient, logger, m)
}

// postEmailWithRetries contains the actual retry logic with circuit breaker protection per attempt
func postEmailWithRetries(ctx context.Context, rawEmail string, destinationURL, apiKey string, maxRetryAttempts int, isJunk bool, mailFrom string, mailTo string, traceID string, authenticatedUser string, circuitBreaker *CircuitBreaker, httpClient *http.Client, logger *slog.Logger, m *metrics.Metrics) (string, error) {
	var lastErr error

	// Ensure at least one attempt even if configured incorrectly
	if maxRetryAttempts < 1 {
		maxRetryAttempts = 1
	}

	// Retry loop with exponential backoff
	for attempt := 0; attempt < maxRetryAttempts; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("context cancelled: %w", ctx.Err())
		default:
		}

		// Implement exponential backoff between retries to avoid overwhelming the destination
		// Backoff sequence: 0s (first attempt), 1s, 2s, 4s, 8s, etc.
		if attempt > 0 {
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			logger.Info(fmt.Sprintf("Retrying HTTP post to URL (attempt %d/%d) after %v delay", attempt+1, maxRetryAttempts, backoff))

			// Sleep with context awareness - allows early cancellation
			select {
			case <-time.After(backoff):
				// Continue after backoff
			case <-ctx.Done():
				return "", fmt.Errorf("context cancelled during backoff: %w", ctx.Err())
			}
		}

		// Execute this attempt with circuit breaker protection.
		// CircuitBreaker.Call only carries an error, so the ingest result is
		// captured from the enclosing scope rather than returned through it.
		var ingestResult string
		var err error
		if circuitBreaker != nil {
			// Circuit breaker protects each individual attempt
			err = circuitBreaker.Call(func() error {
				var attemptErr error
				ingestResult, attemptErr = postEmailAttemptWithContext(ctx, rawEmail, destinationURL, apiKey, isJunk, mailFrom, mailTo, traceID, authenticatedUser, httpClient, logger, m)
				return attemptErr
			})
		} else {
			// No circuit breaker - call directly
			ingestResult, err = postEmailAttemptWithContext(ctx, rawEmail, destinationURL, apiKey, isJunk, mailFrom, mailTo, traceID, authenticatedUser, httpClient, logger, m)
		}

		if err == nil {
			// Success
			return ingestResult, nil
		}

		lastErr = err

		// Determine if the error warrants a retry
		// Non-retryable errors (like 4xx HTTP codes) fail immediately
		if !IsRetryableError(err) {
			logger.Warn(fmt.Sprintf("Non-retryable error posting to URL: %v", err))
			return "", err
		}

		if attempt < maxRetryAttempts-1 {
			logger.Warn(fmt.Sprintf("Retryable error posting to URL (attempt %d/%d): %v", attempt+1, maxRetryAttempts, err))
		}
	}

	// All retries exhausted
	logger.Error(fmt.Sprintf("All retry attempts exhausted (%d/%d) posting to URL: %v", maxRetryAttempts, maxRetryAttempts, lastErr))
	return "", fmt.Errorf("failed after %d attempts: %w", maxRetryAttempts, lastErr)
}

// postEmailAttemptWithContext performs a single attempt to post the email with context support.
// It sends the raw email as message/rfc822 content type with API key authentication.
func postEmailAttemptWithContext(ctx context.Context, rawEmail string, destinationURL, apiKey string, isJunk bool, mailFrom string, mailTo string, traceID string, authenticatedUser string, httpClient *http.Client, logger *slog.Logger, m *metrics.Metrics) (string, error) {
	if httpClient == nil {
		return "", fmt.Errorf("httpClient cannot be nil")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", destinationURL, strings.NewReader(rawEmail))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set standard headers for email relay
	req.Header.Set("Content-Type", "message/rfc822") // RFC 2822 compliant email format

	// Only set API key if provided (custom endpoints may use URL-based auth)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey) // Bearer token authentication
	}

	// Add envelope addresses as headers
	if mailFrom != "" {
		req.Header.Set("X-Mail-From", mailFrom)
	}
	if mailTo != "" {
		req.Header.Set("X-Mail-To", mailTo)
	}

	// Add trace ID for distributed tracing and log correlation
	if traceID != "" {
		req.Header.Set("X-Trace-ID", traceID)
	}

	// Add authenticated user if message was sent via authenticated submission
	if authenticatedUser != "" {
		req.Header.Set("X-Auth-User", authenticatedUser)
	}

	// Signal to destination that this message was classified as junk/spam
	if isJunk {
		req.Header.Set("X-Junk", "yes")
	}

	start := time.Now()
	resp, err := httpClient.Do(req)
	duration := time.Since(start).Seconds()
	if err != nil {
		if m != nil {
			m.HTTPRequestsTotal.WithLabelValues("error").Inc()
			m.HTTPRequestDuration.Observe(duration)
			m.HTTPRequestSize.Observe(float64(len(rawEmail)))
		}
		return "", fmt.Errorf("failed to send HTTP request to URL: %w", err)
	}
	defer resp.Body.Close()

	statusBucket := statusCodeBucket(resp.StatusCode)
	if m != nil {
		m.HTTPRequestsTotal.WithLabelValues(statusBucket).Inc()
		m.HTTPRequestDuration.Observe(duration)
		m.HTTPRequestSize.Observe(float64(len(rawEmail)))
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if m != nil {
			m.HTTPResponseSize.Observe(float64(len(bodyBytes)))
		}
		return "", NewHTTPStatusError(resp.StatusCode, string(bodyBytes))
	}

	ingestResult := resp.Header.Get(IngestResultHeader)

	// Drain the (tiny) success body before Close so the keep-alive connection
	// is returned to the pool. Delivery deliberately raises MaxIdleConnsPerHost
	// well above Go's default of 2, which only pays off if sockets are reused.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	logger.Info(fmt.Sprintf("Successfully sent email to destination URL, status: %d, ingest: %q", resp.StatusCode, ingestResult))
	return ingestResult, nil
}

// IsRetryableError determines if an error should trigger a retry.
// Returns false for permanent failures (4xx HTTP codes, context cancellation).
// Returns true for temporary failures (5xx codes, network errors, timeouts).
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Circuit breaker being open is a temporary, retryable state.
	if errors.Is(err, ErrCircuitOpen) {
		return true
	}

	// Check if it's an HTTP status error with specific retry logic
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return httpErr.IsRetryable() // 5xx errors are retryable, 4xx are not
	}

	// Context errors indicate intentional cancellation - don't retry
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for specific network errors that are generally retryable.
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Timeouts are always retryable
		if netErr.Timeout() {
			return true
		}

		// DNS lookup errors can be temporary
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return true
		}

		// Connection refused is retryable (server may come back up)
		if strings.Contains(err.Error(), "connection refused") {
			return true
		}

		// Connection reset / broken pipe are retryable
		if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "broken pipe") {
			return true
		}

		return false
	}

	// Default to non-retryable for unknown errors to avoid infinite retry loops on unexpected issues.
	return false
}
