package smtp

import (
	"errors"

	"github.com/emersion/go-smtp"
)

// Common SMTP server errors
var (
	// Session errors
	ErrSessionTimeout      = errors.New("session timeout")
	ErrInternalServerError = errors.New("internal server error")
	ErrServerUnavailable   = errors.New("server temporarily unavailable")
	ErrNoReverseDNS        = errors.New("no reverse DNS record")

	// TLS errors. These are structured SMTPErrors so clients receive the
	// RFC 3207 §4 mandated "530 5.7.0 Must issue a STARTTLS command first"
	// response rather than go-smtp's generic default reply.
	ErrTLSRequired = &smtp.SMTPError{
		Code:         530,
		EnhancedCode: smtp.EnhancedCode{5, 7, 0},
		Message:      "Must issue a STARTTLS command first",
	}
	ErrTLSRequiredStartTLS = &smtp.SMTPError{
		Code:         530,
		EnhancedCode: smtp.EnhancedCode{5, 7, 0},
		Message:      "Must issue a STARTTLS command first",
	}

	// Authentication errors. Structured SMTPErrors so the auth-failure code is
	// correct per RFC 4954 §6, which Outlook's setup wizard relies on: a
	// permanent 535 is a password prompt, a temporary 454 is read as "server
	// down" and aborts account creation.
	//
	// ErrAuthCredentialsInvalid: the credential was judged and rejected —
	// PERMANENT. Deliberately says nothing about which half was wrong so
	// neither the server nor an attacker can enumerate mailboxes.
	ErrAuthCredentialsInvalid = &smtp.SMTPError{
		Code:         535,
		EnhancedCode: smtp.EnhancedCode{5, 7, 8},
		Message:      "Authentication credentials invalid",
	}
	// ErrAuthTemporaryFailure: the credential was never judged (backend
	// unreachable/5xx/misconfigured) — TEMPORARY, so a stored password
	// survives our outage instead of being discarded by the client.
	ErrAuthTemporaryFailure = &smtp.SMTPError{
		Code:         454,
		EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message:      "temporary authentication failure: please try again later",
	}

	// Message errors
	ErrMessageTooBig = errors.New("message too big")

	// Context errors
	ErrContextCancelled = errors.New("context cancelled")
	ErrContextTimeout   = errors.New("context deadline exceeded")
)

// Common error messages for logging (not returned to clients)
const (
	LogMsgFailedSetDeadline       = "Failed to set connection deadline"
	LogMsgDomainListNotReady      = "domain list not ready"
	LogMsgSessionDeadlineExceeded = "Session deadline exceeded"
)
