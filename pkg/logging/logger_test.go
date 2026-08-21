package logging

import (
	"os"
	"path/filepath"
	"testing"

	"migadu/mizu/pkg/config"
)

func TestSetup_JSON(t *testing.T) {
	logger, err := Setup("json", false)
	if err != nil {
		t.Fatalf("Failed to setup JSON logger: %v", err)
	}
	if logger == nil {
		t.Fatal("Logger is nil")
	}

	logger.Info("test message")
	t.Log("✓ JSON logger created successfully")
}

func TestSetup_Console(t *testing.T) {
	logger, err := Setup("console", false)
	if err != nil {
		t.Fatalf("Failed to setup console logger: %v", err)
	}
	if logger == nil {
		t.Fatal("Logger is nil")
	}

	logger.Info("test message")
	t.Log("✓ Console logger created successfully")
}

func TestSetup_Verbose(t *testing.T) {
	logger, err := Setup("console", true)
	if err != nil {
		t.Fatalf("Failed to setup verbose logger: %v", err)
	}
	if logger == nil {
		t.Fatal("Logger is nil")
	}

	logger.Debug("debug message")
	t.Log("✓ Verbose logger created successfully")
}

func TestSetup_NonVerbose(t *testing.T) {
	logger, err := Setup("json", false)
	if err != nil {
		t.Fatalf("Failed to setup non-verbose logger: %v", err)
	}
	if logger == nil {
		t.Fatal("Logger is nil")
	}

	logger.Debug("debug message") // Should not appear
	logger.Info("info message")   // Should appear
	t.Log("✓ Non-verbose logger created successfully")
}

func TestNewLogger_LogFilePermissions(t *testing.T) {
	// Log files carry PII (envelope addresses, sender IPs, usernames) and must
	// not be group/world readable, even when the rotation tool pre-created the
	// file with looser modes.
	dir := t.TempDir()
	path := filepath.Join(dir, "mizu.log")

	// Simulate a rotation tool pre-creating the file with permissive modes.
	if err := os.WriteFile(path, []byte("rotated\n"), 0o644); err != nil {
		t.Fatalf("failed to pre-create log file: %v", err)
	}

	_, w, err := NewLogger(config.LoggingConfig{Level: "info", Format: "console", Output: path})
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer w.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("log file mode = %o, want 0600 (pre-existing loose mode must be tightened)", perm)
	}

	// Reopen (SIGHUP path) must also produce 0600 on a fresh file.
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("failed to reset modes: %v", err)
	}
	if err := w.Reopen(); err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("log file mode after Reopen = %o, want 0600", perm)
	}
}
