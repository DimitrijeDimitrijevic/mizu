// Package smtp implements a production-ready SMTP relay server with comprehensive
// security and anti-spam features.
//
// # Overview
//
// The smtp package provides the core SMTP protocol implementation for Mizu, a high-performance
// email relay server that accepts emails via SMTP and synchronously forwards them to an
// HTTP backend. The package implements RFC 5321 (SMTP) with STARTTLS support (RFC 3207).
//
// # Architecture
//
// The package uses a two-tier architecture:
//
//	Backend: Creates and manages SMTP sessions, handles connection limits and rate limiting
//	Session: Handles individual SMTP conversations, performs validation and delivery
//
// Each incoming SMTP connection creates a new Session that processes the full email
// lifecycle: HELO → MAIL FROM → RCPT TO → DATA → delivery.
//
// # Message Flow
//
//  1. Connection Acceptance
//     - Check connection limits (global and per-IP)
//     - Check rate limits (multi-dimensional)
//     - Perform reverse DNS lookup
//     - Check DNS blacklists (DNSBL)
//
//  2. SMTP Protocol Handling
//     - HELO/EHLO: Validate hostname
//     - MAIL FROM: Validate sender domain (MX records)
//     - RCPT TO: Accept recipients
//     - DATA: Receive message content
//
//  3. Pre-Delivery Validation
//     - Header validation (From, Date, Message-ID required)
//     - SPF validation (sender IP authorization)
//     - DKIM validation (message signatures)
//     - DMARC validation (alignment checking)
//     - ARC validation (forwarding chain verification)
//
//  4. Synchronous Delivery
//     - Optionally sign with ARC headers
//     - POST email to HTTP backend
//     - Wait for 200/202 response
//     - Send SMTP 250 OK only after successful delivery
//
//  5. Stats and Metrics
//     - Update reputation scores (IP and domain)
//     - Record metrics (Prometheus)
//     - Sync stats across cluster (optional)
//
// # Zero Message Loss
//
// The package guarantees zero message loss by design: the SMTP "250 OK" response
// is sent ONLY after receiving a successful HTTP response from the backend.
// There is no internal queue - delivery is synchronous. If the backend is down,
// the SMTP session returns a temporary failure (4xx), and the sending server
// will retry later.
//
// # DoS Protection
//
// Multiple layers of protection against denial-of-service attacks:
//
//	Connection Limits: Global and per-IP concurrent connection limits
//	Rate Limiting: Sliding window algorithm with multi-dimensional keys
//	Distributed Tracking: Cluster-wide limits via gossip protocol
//	Circuit Breaker: Protects backend from being overwhelmed
//
// # Anti-Spam Features
//
//	Reverse DNS (rDNS): Reject IPs without valid PTR records
//	DNS Blacklists: Check against RBL/DNSBL services (Spamhaus, etc.)
//	SPF Validation: Verify sender IP authorization (RFC 7208)
//	DKIM Validation: Verify cryptographic signatures (RFC 6376)
//	DMARC Validation: Enforce sender policies (RFC 7489)
//	ARC Validation: Verify forwarding chains (RFC 8617)
//	Sender MX Validation: Require valid MX records for sender domains
//	Header Validation: Enforce required headers (From, Date, Message-ID)
//
// # Distributed Mode
//
// When cluster mode is enabled, the package can coordinate with peer nodes:
//
//	Connection Tracking: Share connection state via gossip + S3
//	Rate Limiting: Cluster-wide rate limit enforcement
//	Recipient Caching: Cache backend responses (404/403) across cluster
//	Stats Sync: Share reputation data via S3
//
// # Graceful Shutdown
//
// The package supports graceful shutdown with configurable timeout:
//
//  1. Stop accepting new connections (close ShutdownChan)
//  2. Wait for active sessions to complete (ActiveSessionsWg)
//  3. Close listeners
//
// Active sessions have a bounded lifetime (SessionDeadline, restarted on each
// completed transaction) to prevent indefinite hangs during shutdown. A session
// that stops making progress is dropped much sooner: the wait for the next
// command is bounded by timeout_seconds and a stall inside the message body by
// DataBlockTimeout.
//
// # Thread Safety
//
// All types in this package are designed for concurrent use. The Backend
// can handle multiple sessions simultaneously, and each Session runs in
// its own goroutine with proper synchronization.
//
// # Example Usage
//
//	// Create backend
//	backend := &smtp.Backend{
//	    Config:         cfg,
//	    Logger:         logger,
//	    HTTPClient:     httpClient,
//	    DNSResolver:    dnsResolver,
//	    // ... other fields
//	}
//
//	// Create SMTP server
//	server := gosmtp.NewServer(backend)
//	server.Addr = ":25"
//	server.Domain = "mail.example.com"
//	server.MaxMessageBytes = 10 * 1024 * 1024
//
//	// Start server
//	if err := server.ListenAndServe(); err != nil {
//	    log.Fatal(err)
//	}
//
// # Error Handling
//
// The package uses SMTP error codes per RFC 5321:
//
//	421: Service not available (temporary failure, retry later)
//	450: Mailbox unavailable (temporary failure)
//	451: Local error in processing (temporary failure)
//	452: Insufficient system storage (temporary failure)
//	501: Syntax error in parameters
//	502: Command not implemented
//	503: Bad sequence of commands
//	550: Requested action not taken (permanent failure)
//	551: User not local
//	552: Exceeded storage allocation
//	553: Mailbox name not allowed
//	554: Transaction failed
//
// Temporary failures (4xx) cause the sending server to retry.
// Permanent failures (5xx) cause the sending server to bounce the message.
//
// # Panic Recovery
//
// All goroutines use panic recovery to prevent crashes. The concurrency.SafeGo
// helper ensures WaitGroups are properly cleaned up even if a goroutine panics.
package smtp
