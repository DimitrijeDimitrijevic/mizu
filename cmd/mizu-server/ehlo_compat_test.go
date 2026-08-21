package main

import (
	"testing"

	gosmtp "github.com/emersion/go-smtp"

	"migadu/mizu/pkg/config"
)

// applyEhloCompat is the config-to-server mapping for the EHLO compatibility
// knobs; the go-smtp fork's own tests cover how the flags shape the actual
// EHLO response bytes.

func submissionCfg() *config.ServerConfig {
	s := &config.ServerConfig{Type: "submission", Name: "test-submission"}
	s.ApplyDefaults(config.DefaultsConfig{})
	return s
}

// Defaults on a submission server: legacy AUTH= line on, LIMITS suppressed —
// the Outlook-compatible surface (August 2026 incident).
func TestApplyEhloCompatSubmissionDefaults(t *testing.T) {
	server := gosmtp.NewServer(nil)
	applyEhloCompat(server, submissionCfg())

	if !server.EnableLegacyAuthCap {
		t.Fatal("submission server must advertise legacy AUTH= by default")
	}
	if !server.DisableLimitsCap {
		t.Fatal("LIMITS must be suppressed by default")
	}
}

func TestApplyEhloCompatLegacyAuthDisabled(t *testing.T) {
	cfg := submissionCfg()
	falseVal := false
	cfg.LegacyAuthCap = &falseVal

	server := gosmtp.NewServer(nil)
	applyEhloCompat(server, cfg)

	if server.EnableLegacyAuthCap {
		t.Fatal("legacy_auth_cap=false must disable the legacy AUTH= line")
	}
}

func TestApplyEhloCompatAdvertiseLimits(t *testing.T) {
	cfg := submissionCfg()
	cfg.AdvertiseLimits = true

	server := gosmtp.NewServer(nil)
	applyEhloCompat(server, cfg)

	if server.DisableLimitsCap {
		t.Fatal("advertise_limits=true must re-enable the LIMITS capability")
	}
}

// Relay (MX) servers advertise no AUTH, so the legacy line stays off there
// regardless of the default.
func TestApplyEhloCompatRelayNoLegacyAuth(t *testing.T) {
	cfg := &config.ServerConfig{Type: "relay", Name: "test-mx"}
	cfg.ApplyDefaults(config.DefaultsConfig{})

	server := gosmtp.NewServer(nil)
	applyEhloCompat(server, cfg)

	if server.EnableLegacyAuthCap {
		t.Fatal("relay server must not enable the legacy AUTH= line")
	}
	if !server.DisableLimitsCap {
		t.Fatal("LIMITS must be suppressed by default on relay servers too")
	}
}
