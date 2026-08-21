package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The legacy "AUTH=" EHLO line must default to ON (Microsoft Outlook
// compatibility — the August 2026 new-Outlook incident) and be disablable.
func TestLegacyAuthCapDefaultsTrue(t *testing.T) {
	s := &ServerConfig{Type: "submission"}
	s.ApplyDefaults(DefaultsConfig{})

	if s.LegacyAuthCap == nil {
		t.Fatal("ApplyDefaults must materialize LegacyAuthCap")
	}
	if !s.LegacyAuthCapEnabled() {
		t.Fatal("LegacyAuthCap must default to true")
	}
}

func TestLegacyAuthCapExplicitFalsePreserved(t *testing.T) {
	falseVal := false
	s := &ServerConfig{Type: "submission", LegacyAuthCap: &falseVal}
	s.ApplyDefaults(DefaultsConfig{})

	if s.LegacyAuthCapEnabled() {
		t.Fatal("explicit legacy_auth_cap=false must survive ApplyDefaults")
	}
}

func TestLegacyAuthCapEnabledNilReceiverField(t *testing.T) {
	// Accessor must be safe (and true) before ApplyDefaults runs.
	s := &ServerConfig{}
	if !s.LegacyAuthCapEnabled() {
		t.Fatal("LegacyAuthCapEnabled must be true when unset")
	}
}

// LIMITS advertisement must default to OFF and be re-enablable.
func TestAdvertiseLimitsDefaultsFalse(t *testing.T) {
	s := &ServerConfig{Type: "submission"}
	s.ApplyDefaults(DefaultsConfig{})

	if s.AdvertiseLimits {
		t.Fatal("AdvertiseLimits must default to false")
	}
}

// TOML parsing of both knobs.
func TestEhloCompatTOMLParsing(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`
[[server]]
name = "submission-test"
type = "submission"
listen_addr = ":465"
legacy_auth_cap = false
advertise_limits = true
`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("Expected 1 server, got %d", len(cfg.Servers))
	}
	s := cfg.Servers[0]
	if s.LegacyAuthCapEnabled() {
		t.Fatal("legacy_auth_cap = false not parsed")
	}
	if !s.AdvertiseLimits {
		t.Fatal("advertise_limits = true not parsed")
	}
}

// The default TOML surface (knobs omitted) must land on the compatible
// defaults after ApplyDefaults: legacy AUTH= on, LIMITS off.
func TestEhloCompatTOMLDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`
[[server]]
name = "submission-test"
type = "submission"
listen_addr = ":465"
`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	s := cfg.Servers[0]
	s.ApplyDefaults(cfg.Defaults)
	if !s.LegacyAuthCapEnabled() {
		t.Fatal("legacy_auth_cap must default to true")
	}
	if s.AdvertiseLimits {
		t.Fatal("advertise_limits must default to false")
	}
}

// --- helo_validation type-aware defaults (August 2026 Outlook incident) ---

func TestHeloValidationDefaultOffForSubmission(t *testing.T) {
	s := &ServerConfig{Type: "submission"}
	s.ApplyDefaults(DefaultsConfig{})
	if s.HELOValidation == nil {
		t.Fatal("ApplyDefaults must materialize HELOValidation")
	}
	if *s.HELOValidation {
		t.Fatal("helo_validation must default to false on submission servers")
	}
}

func TestHeloValidationDefaultOnForRelay(t *testing.T) {
	s := &ServerConfig{Type: "relay"}
	s.ApplyDefaults(DefaultsConfig{})
	if s.HELOValidation == nil || !*s.HELOValidation {
		t.Fatal("helo_validation must default to true on relay servers")
	}
}

func TestHeloValidationExplicitSettingSurvivesDefaults(t *testing.T) {
	trueVal := true
	s := &ServerConfig{Type: "submission", HELOValidation: &trueVal}
	s.ApplyDefaults(DefaultsConfig{})
	if !*s.HELOValidation {
		t.Fatal("explicit helo_validation=true must survive ApplyDefaults on submission")
	}

	falseVal := false
	r := &ServerConfig{Type: "relay", HELOValidation: &falseVal}
	r.ApplyDefaults(DefaultsConfig{})
	if *r.HELOValidation {
		t.Fatal("explicit helo_validation=false must survive ApplyDefaults on relay")
	}
}
