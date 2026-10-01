package smtp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"migadu/mizu/pkg/config"

	"github.com/emersion/go-smtp"
)

// SMTPUTF8 is not offered, but go-smtp's parser accepts raw UTF-8 in an
// envelope address with or without the parameter, so the session has to
// refuse it itself: 553 5.6.7 (RFC 6531 §3.7.1) at MAIL FROM and RCPT TO.

func nonASCIISession() *Session {
	return &Session{
		helo:         "client.example",
		serverConfig: &config.ServerConfig{Name: "test", Type: "relay"},
		globalConfig: &config.Config{Local: true},
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteAddr:   "192.0.2.1:12345",
		ctx:          context.Background(),
		commandState: stateHelo,
	}
}

func assertNonASCIIRefused(t *testing.T, err error) {
	t.Helper()
	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("want *smtp.SMTPError, got %T: %v", err, err)
	}
	if smtpErr.Code != 553 || smtpErr.EnhancedCode != (smtp.EnhancedCode{5, 6, 7}) {
		t.Fatalf("want 553 5.6.7, got %d %v %q", smtpErr.Code, smtpErr.EnhancedCode, smtpErr.Message)
	}
}

func TestMail_NonASCIIAddressRefused(t *testing.T) {
	for _, from := range []string{"ü@example.com", "user@exämple.com", "用户@例子.广告"} {
		t.Run(from, func(t *testing.T) {
			s := nonASCIISession()
			err := s.Mail(context.Background(), from, &smtp.MailOptions{})
			assertNonASCIIRefused(t, err)
			if s.commandState != stateHelo {
				t.Fatalf("refused MAIL FROM must not advance the session, state %v", s.commandState)
			}
		})
	}
}

func TestRcpt_NonASCIIAddressRefused(t *testing.T) {
	for _, to := range []string{"jörg@example.org", "user@exämple.org"} {
		t.Run(to, func(t *testing.T) {
			s := nonASCIISession()
			s.commandState = stateMail
			s.from = "sender@example.com"
			err := s.Rcpt(context.Background(), to, nil)
			assertNonASCIIRefused(t, err)
			if len(s.to) != 0 {
				t.Fatalf("refused recipient must not be recorded, got %v", s.to)
			}
		})
	}
}

// Control: an ASCII recipient on the same minimal session is accepted, so the
// refusal above is the non-ASCII check and not some other gate.
func TestRcpt_ASCIIAddressAccepted(t *testing.T) {
	s := nonASCIISession()
	s.commandState = stateMail
	s.from = "sender@example.com"
	if err := s.Rcpt(context.Background(), "user@example.org", nil); err != nil {
		t.Fatalf("ASCII recipient refused: %v", err)
	}
	if len(s.to) != 1 {
		t.Fatalf("want 1 recipient recorded, got %v", s.to)
	}
}
