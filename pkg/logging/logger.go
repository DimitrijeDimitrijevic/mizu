package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"migadu/mizu/pkg/config"
)

// LogWriter wraps a log output destination and supports reopening for log rotation.
// When the output is a file, Reopen closes the old handle and opens a new one so
// that newsyslog (or similar) rotation works correctly after SIGHUP.
type LogWriter struct {
	mu   sync.Mutex
	path string   // empty for stdout/stderr
	file *os.File // current output file (or os.Stdout/os.Stderr)
}

func (w *LogWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Write(p)
}

// Reopen closes and reopens the log file. No-op for stdout/stderr.
func (w *LogWriter) Reopen() error {
	if w.path == "" {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	newFile, err := openLogFile(w.path)
	if err != nil {
		return fmt.Errorf("reopen log file %s: %w", w.path, err)
	}
	w.file.Close()
	w.file = newFile
	return nil
}

func (w *LogWriter) Close() error {
	if w.path == "" {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

// NewLogger creates a configured slog.Logger based on the LoggingConfig.
func NewLogger(cfg config.LoggingConfig) (*slog.Logger, *LogWriter, error) {
	level, err := parseLogLevel(cfg.Level)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid log level: %w", err)
	}

	writer, err := newLogWriter(cfg.Output)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create log writer: %w", err)
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch strings.ToLower(cfg.Format) {
	case "json":
		handler = slog.NewJSONHandler(writer, opts)
	case "console", "":
		handler = slog.NewTextHandler(writer, opts)
	default:
		writer.Close()
		return nil, nil, fmt.Errorf("invalid log format: %s (must be 'console' or 'json')", cfg.Format)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger, writer, nil
}

// parseLogLevel converts a string log level to slog.Level.
func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown level: %s (must be debug, info, warn, or error)", level)
	}
}

// logFileMode is the permission for log files. Logs carry envelope addresses,
// sender IPs, usernames and hostnames (PII), so they are private to the
// service user.
const logFileMode = 0o600

// openLogFile opens (creating if needed) a log file with restrictive
// permissions. The mode argument of OpenFile only applies at creation, so the
// explicit Chmod also tightens files pre-created with looser modes by the
// rotation tool (newsyslog creates the new file before sending SIGHUP).
// Best effort: a Chmod failure (unusual filesystems) is not fatal.
func openLogFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFileMode)
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(logFileMode)
	return f, nil
}

func newLogWriter(output string) (*LogWriter, error) {
	switch strings.ToLower(output) {
	case "stderr":
		return &LogWriter{file: os.Stderr}, nil
	case "stdout":
		return &LogWriter{file: os.Stdout}, nil
	case "syslog", "":
		return &LogWriter{file: os.Stderr}, nil
	default:
		file, err := openLogFile(output)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", output, err)
		}
		return &LogWriter{path: output, file: file}, nil
	}
}

// Setup initializes a slog logger based on the provided format and verbosity.
// Deprecated: Use NewLogger with config.LoggingConfig instead.
func Setup(format string, verbose bool) (*slog.Logger, error) {
	var level slog.Level
	if verbose {
		level = slog.LevelDebug
	} else {
		level = slog.LevelInfo
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger, nil
}

// NewTestLogger creates a logger for testing that discards output
func NewTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}
