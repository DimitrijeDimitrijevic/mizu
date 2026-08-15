package smtp

import (
	"io"
	"log/slog"
	"testing"

	"migadu/mizu/pkg/config"
)

// --- HELO validation gate: type-aware defaults ---
//
// The validation rules only run when the gate is open. The gate must default
// OFF on submission servers: authenticated desktop clients (Windows Outlook
// et al.) send their bare machine name — e.g. "ChiaraThinkpad" — as the EHLO
// argument, and rejecting it locks every such client out (the August 2026
// Outlook incident). Relay keeps the check for spam screening.

func newHeloGateSession(t *testing.T, serverType string, heloValidation *bool) *Session {
	t.Helper()
	cfg := config.DefaultConfig()
	sc := config.ServerConfig{Hostname: "mx.example.com", Type: serverType, HELOValidation: heloValidation}
	return &Session{
		serverConfig: &sc,
		globalConfig: &cfg,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestHeloValidationGateDefaultsOffOnSubmission(t *testing.T) {
	s := newHeloGateSession(t, "submission", nil)
	if s.heloValidationEnabled() {
		t.Fatal("HELO validation must default OFF on submission servers")
	}
}

func TestHeloValidationGateDefaultsOnForRelay(t *testing.T) {
	s := newHeloGateSession(t, "relay", nil)
	if !s.heloValidationEnabled() {
		t.Fatal("HELO validation must default ON for relay servers")
	}
}

func TestHeloValidationGateExplicitWinsOnSubmission(t *testing.T) {
	trueVal := true
	s := newHeloGateSession(t, "submission", &trueVal)
	if !s.heloValidationEnabled() {
		t.Fatal("explicit helo_validation=true must win on submission")
	}
}

func TestHeloValidationGateExplicitWinsOnRelay(t *testing.T) {
	falseVal := false
	s := newHeloGateSession(t, "relay", &falseVal)
	if s.heloValidationEnabled() {
		t.Fatal("explicit helo_validation=false must win on relay")
	}
}

// The incident case, end to end through ApplyDefaults: a submission server
// with no explicit setting must not reject a bare Windows machine name.
func TestSubmissionAcceptsBareWindowsMachineName(t *testing.T) {
	sc := config.ServerConfig{Hostname: "smtp.example.com", Type: "submission"}
	sc.ApplyDefaults(config.DefaultsConfig{})

	cfg := config.DefaultConfig()
	s := &Session{
		serverConfig: &sc,
		globalConfig: &cfg,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if s.heloValidationEnabled() {
		t.Fatal("submission server rejects bare machine names (gate open after ApplyDefaults)")
	}
	// Sanity: the rule itself would reject it — proving the gate is what
	// protects the client.
	if err := s.validateHeloHostname("ChiaraThinkpad"); err == nil {
		t.Fatal("expected the validation rule to reject a bare machine name (test premise)")
	}
}
