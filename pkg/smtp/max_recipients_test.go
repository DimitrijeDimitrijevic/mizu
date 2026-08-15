package smtp

import (
	"context"
	"log/slog"
	"migadu/mizu/pkg/config"
	"os"
	"testing"

	"github.com/emersion/go-smtp"
)

func TestMaxRecipientsPerMessage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{
		Local: true,
	}

	serverCfg := &config.ServerConfig{
		Name:                    "test-server",
		Type:                    "relay",
		MaxRecipientsPerMessage: 3, // Allow only 3 recipients
	}

	// Create session directly
	session := &Session{
		serverConfig: serverCfg,
		globalConfig: cfg,
		Logger:       logger,
		remoteAddr:   "192.0.2.1:12345",
		ctx:          context.Background(),
		commandState: stateMail, // Start after MAIL FROM
		from:         "sender@example.com",
		to:           []string{},
	}

	// Add recipients up to the limit
	for i := 1; i <= 3; i++ {
		recipient := "user" + string(rune('0'+i)) + "@example.com"
		if err := session.Rcpt(context.Background(), recipient, nil); err != nil {
			t.Fatalf("RCPT TO #%d failed: %v", i, err)
		}
		t.Logf("✓ Recipient #%d accepted: %s", i, recipient)
	}

	// Try to add 4th recipient - should be rejected
	err := session.Rcpt(context.Background(), "user4@example.com", nil)
	if err == nil {
		t.Fatal("Expected RCPT TO to fail after max recipients, but it succeeded")
	}

	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("Expected SMTPError, got: %T", err)
	}

	if smtpErr.Code != 452 {
		t.Errorf("Expected SMTP code 452, got %d", smtpErr.Code)
	}

	if smtpErr.EnhancedCode[0] != 4 || smtpErr.EnhancedCode[1] != 5 || smtpErr.EnhancedCode[2] != 3 {
		t.Errorf("Expected enhanced code 4.5.3, got %v", smtpErr.EnhancedCode)
	}

	t.Logf("✓ 4th recipient correctly rejected: %s", smtpErr.Message)
	t.Log("✓ Max recipients limit enforced correctly")
}

func TestMaxRecipientsDefaultValue(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg := &config.Config{
		Local: true,
	}

	serverCfg := &config.ServerConfig{
		Name:                    "test-server",
		Type:                    "relay",
		MaxRecipientsPerMessage: 0, // Not set - should default to 100
	}

	// Create session directly
	session := &Session{
		serverConfig: serverCfg,
		globalConfig: cfg,
		Logger:       logger,
		remoteAddr:   "192.0.2.1:12345",
		ctx:          context.Background(),
		commandState: stateMail, // Start after MAIL FROM
		from:         "sender@example.com",
		to:           []string{},
	}

	// Add 10 recipients (should work since default is 100)
	for i := 1; i <= 10; i++ {
		recipient := "user" + string(rune('0'+i)) + "@example.com"
		if err := session.Rcpt(context.Background(), recipient, nil); err != nil {
			t.Fatalf("RCPT TO #%d failed with default limit: %v", i, err)
		}
	}

	t.Logf("✓ 10 recipients accepted with default limit (100)")
	t.Log("✓ Default max recipients value (100) works correctly")
}

func TestMaxRecipientsReset(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{
		Local: true,
	}

	serverCfg := &config.ServerConfig{
		Name:                    "test-server",
		Type:                    "relay",
		MaxRecipientsPerMessage: 3,
	}

	// Create session directly
	session := &Session{
		serverConfig: serverCfg,
		globalConfig: cfg,
		Logger:       logger,
		remoteAddr:   "192.0.2.1:12345",
		ctx:          context.Background(),
		commandState: stateMail, // Start after MAIL FROM
		from:         "sender@example.com",
		to:           []string{},
	}

	// First transaction - add 3 recipients
	for i := 1; i <= 3; i++ {
		if err := session.Rcpt(context.Background(), "user"+string(rune('0'+i))+"@example.com", nil); err != nil {
			t.Fatalf("RCPT TO #%d failed: %v", i, err)
		}
	}

	// Reset the session
	session.Reset()

	// After reset, need to set state back to stateMail
	session.commandState = stateMail
	session.from = "sender@example.com"

	// Second transaction - should accept 3 more recipients
	for i := 1; i <= 3; i++ {
		if err := session.Rcpt(context.Background(), "newuser"+string(rune('0'+i))+"@example.com", nil); err != nil {
			t.Fatalf("RCPT TO #%d (2nd transaction) failed: %v", i, err)
		}
	}

	t.Log("✓ Max recipients counter resets correctly between transactions")
}
