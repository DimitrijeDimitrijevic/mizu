package smtp

import (
	"context"
	"errors"
	"testing"

	"github.com/emersion/go-smtp"
)

// RFC 5321 §2.3.5: a domain in an SMTP transaction must be fully qualified.
// go-smtp's parser is grammar-only (§4.1.2 allows a single label), so the
// session refuses a dotless recipient domain itself: 553 5.1.3 at RCPT TO.
// Before this, `RCPT TO:<user@gmail>` (2026-10-24) was accepted and failed
// only at delivery, where mailqueuer's 422 became a 451 the client retried.

func assertNotFQDNRefused(t *testing.T, err error) {
	t.Helper()
	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("want *smtp.SMTPError, got %T: %v", err, err)
	}
	if smtpErr.Code != 553 || smtpErr.EnhancedCode != (smtp.EnhancedCode{5, 1, 3}) {
		t.Fatalf("want 553 5.1.3, got %d %v %q", smtpErr.Code, smtpErr.EnhancedCode, smtpErr.Message)
	}
}

func TestRcpt_NonFQDNRecipientRefused(t *testing.T) {
	for _, to := range []string{
		"user@example",
		"user@test",
		"user@email",
		"user@somedomain",
		"user@gmail",
	} {
		t.Run(to, func(t *testing.T) {
			s := nonASCIISession()
			s.commandState = stateMail
			s.from = "sender@example.com"
			err := s.Rcpt(context.Background(), to, nil)
			assertNotFQDNRefused(t, err)
			if len(s.to) != 0 {
				t.Fatalf("refused recipient must not be recorded, got %v", s.to)
			}
		})
	}
}

func TestRcpt_FQDNRecipientAccepted(t *testing.T) {
	for _, to := range []string{
		"user@example.com",
		"user@sub.example.com",
	} {
		t.Run(to, func(t *testing.T) {
			s := nonASCIISession()
			s.commandState = stateMail
			s.from = "sender@example.com"
			if err := s.Rcpt(context.Background(), to, nil); err != nil {
				t.Fatalf("fully qualified recipient refused: %v", err)
			}
			if len(s.to) != 1 || s.to[0] != to {
				t.Fatalf("accepted recipient must be recorded, got %v", s.to)
			}
		})
	}
}
