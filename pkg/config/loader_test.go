package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Test loading with no config file in local mode
	cfg, err := LoadConfig([]string{"--local"})
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg == nil {
		t.Fatal("LoadConfig returned nil config")
	}

	// Verify defaults are set (servers array can be empty if no config file)
	if cfg.Logging.Format != "console" {
		t.Errorf("Logging.Format = %s; want console", cfg.Logging.Format)
	}

	if !cfg.Local {
		t.Error("Local should be true when --local flag is used")
	}
}

func TestLoadConfig_LocalMode(t *testing.T) {
	cfg, err := LoadConfig([]string{"--local"})
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if !cfg.Local {
		t.Error("Local should be true")
	}
}

func TestLoadConfig_ConfigFile(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	configContent := `
[[server]]
name = "test-relay"
type = "relay"
listen_addr = ":2525"
hostname = "mail.test.com"

[server.tls]
enabled = true
mode = "starttls"

[server.delivery]
url = "https://destination.example.com/email"
api_key = "test-api-key"

[storage]
backend = "filesystem"
filesystem_path = "/tmp/mizu-test"

log_format = "json"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig([]string{"--config", configPath, "--local"})
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(cfg.Servers) != 1 {
		t.Fatalf("Expected 1 server, got %d", len(cfg.Servers))
	}

	srv := cfg.Servers[0]
	if srv.ListenAddr != ":2525" {
		t.Errorf("Server.ListenAddr = %s; want :2525", srv.ListenAddr)
	}

	if srv.Hostname != "mail.test.com" {
		t.Errorf("Server.Hostname = %s; want mail.test.com", srv.Hostname)
	}

	if cfg.Storage.Backend != "filesystem" {
		t.Errorf("Storage.Backend = %s; want filesystem", cfg.Storage.Backend)
	}

	if srv.Delivery.URL != "https://destination.example.com/email" {
		t.Errorf("Server.Delivery.URL = %s; want https://destination.example.com/email", srv.Delivery.URL)
	}
}

func TestLoadEnvVars(t *testing.T) {
	// Set environment variables
	os.Setenv("S3_ACCESS_KEY", "test-access-key")
	os.Setenv("S3_SECRET_KEY", "test-secret-key")
	os.Setenv("DELIVERY_AUTH_TOKEN", "test-dest-token")
	os.Setenv("AUTH_TOKEN", "test-auth-token")

	defer func() {
		os.Unsetenv("S3_ACCESS_KEY")
		os.Unsetenv("S3_SECRET_KEY")
		os.Unsetenv("DELIVERY_AUTH_TOKEN")
		os.Unsetenv("AUTH_TOKEN")
	}()

	defaultCfg := DefaultConfig()

	// Add a test server to verify delivery token is applied
	defaultCfg.Servers = []ServerConfig{
		{
			Name: "test-relay",
			Type: "relay",
			Delivery: DeliveryConfig{
				AuthToken: "", // Empty to test env var override
			},
		},
		{
			Name: "test-submission",
			Type: "submission",
			Auth: ServerAuthConfig{
				AuthToken: "", // Empty to test env var override
			},
			Delivery: DeliveryConfig{
				AuthToken: "",
			},
		},
	}

	cfg := &defaultCfg
	applyEnvironmentVariables(cfg)

	if cfg.Storage.S3AccessKey != "test-access-key" {
		t.Errorf("Storage.S3AccessKey = %s; want test-access-key", cfg.Storage.S3AccessKey)
	}

	if cfg.Storage.S3SecretKey != "test-secret-key" {
		t.Errorf("Storage.S3SecretKey = %s; want test-secret-key", cfg.Storage.S3SecretKey)
	}

	if cfg.Servers[0].Delivery.AuthToken != "test-dest-token" {
		t.Errorf("Server.Delivery.AuthToken = %s; want test-dest-token", cfg.Servers[0].Delivery.AuthToken)
	}

	// Check that AUTH_TOKEN is applied to submission servers
	for i := range cfg.Servers {
		if cfg.Servers[i].IsSubmission() && cfg.Servers[i].Auth.AuthToken == "" {
			t.Errorf("Submission server %s should have auth token set", cfg.Servers[i].Name)
		}
	}
}

func TestValidateConfig_PortConflict(t *testing.T) {
	cfg := DefaultConfig()

	// Add two servers on the same port
	cfg.Servers = []ServerConfig{
		{
			Name:       "server1",
			Type:       "relay",
			ListenAddr: ":25",
			Hostname:   "test1.com",
			TLS: ServerTLSConfig{
				Enabled: true,
				Mode:    "starttls",
			},
		},
		{
			Name:       "server2",
			Type:       "submission",
			ListenAddr: ":25", // Same port!
			Hostname:   "test2.com",
			TLS: ServerTLSConfig{
				Enabled: true,
				Mode:    "implicit",
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected port conflict error, got nil")
	}
}

func TestValidateConfig_ValidMultiServer(t *testing.T) {
	cfg := DefaultConfig()

	// Add multiple servers on different ports
	cfg.Servers = []ServerConfig{
		{
			Name:       "relay",
			Type:       "relay",
			ListenAddr: ":25",
			Hostname:   "mail.example.com",
			TLS: ServerTLSConfig{
				Enabled: true,
				Mode:    "starttls",
			},
		},
		{
			Name:       "submission",
			Type:       "submission",
			ListenAddr: ":465",
			Hostname:   "mail.example.com",
			TLS: ServerTLSConfig{
				Enabled:  true,
				Mode:     "implicit",
				Required: true,
			},
			Auth: ServerAuthConfig{
				Required:  true,
				URL:       "https://auth.example.com",
				AuthToken: "test-auth-token",
			},
		},
	}

	// Set required fields for production mode
	cfg.Local = true // Use local mode to skip some validations
	cfg.Storage.Backend = "filesystem"
	cfg.Storage.FilesystemPath = "/tmp/mizu"

	// Set delivery config for all servers
	for i := range cfg.Servers {
		cfg.Servers[i].Delivery.URL = "https://test.com"
		cfg.Servers[i].Delivery.AuthToken = "test-token"
		cfg.Servers[i].Delivery.MaxRetryAttempts = 3
		cfg.Servers[i].Delivery.HTTPTimeoutSeconds = 30
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Unexpected validation error: %v", err)
	}
}

func TestValidateServer_TLSVersionBounds(t *testing.T) {
	// Minimal relay server with TLS enabled, reaching the version checks.
	baseServer := func() ServerConfig {
		return ServerConfig{
			Name:       "relay",
			Type:       "relay",
			ListenAddr: ":25",
			TLS: ServerTLSConfig{
				Enabled: true,
				Mode:    "starttls",
			},
		}
	}

	tests := []struct {
		name    string
		min     string
		max     string
		wantErr string // substring; empty = expect success
	}{
		{name: "both empty", min: "", max: ""},
		{name: "max 1.2 only (Exchange compat)", min: "", max: "1.2"},
		{name: "max 1.3 only", min: "", max: "1.3"},
		{name: "min 1.2 max 1.2", min: "1.2", max: "1.2"},
		{name: "min 1.2 max 1.3", min: "1.2", max: "1.3"},
		{name: "min 1.3 max 1.3", min: "1.3", max: "1.3"},
		{name: "invalid max", min: "", max: "1.1", wantErr: "max_tls_version"},
		{name: "min above max", min: "1.3", max: "1.2", wantErr: "cannot be lower"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := baseServer()
			s.TLS.MinTLSVersion = tt.min
			s.TLS.MaxTLSVersion = tt.max
			err := s.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil || !contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Verify defaults (servers can be empty until config file is loaded)
	if cfg.Logging.Format != "console" {
		t.Errorf("Logging.Format = %s; want console", cfg.Logging.Format)
	}

	if cfg.Local {
		t.Error("Local should be false by default")
	}

	if !cfg.Stats.Enabled {
		t.Error("Stats.Enabled should be true by default")
	}

	if cfg.Storage.Backend != "s3" {
		t.Errorf("Storage.Backend = %s; want s3", cfg.Storage.Backend)
	}

	// Verify S3 defaults are set
	if cfg.Storage.S3Endpoint != "s3.amazonaws.com" {
		t.Errorf("Storage.S3Endpoint = %s; want s3.amazonaws.com", cfg.Storage.S3Endpoint)
	}

	if cfg.Storage.S3Region != "us-east-1" {
		t.Errorf("Storage.S3Region = %s; want us-east-1", cfg.Storage.S3Region)
	}

	// The command timeout becomes go-smtp's ReadTimeout, which is re-armed
	// before every command read — it is the real "how long may a client pause"
	// budget, including the pause before the first EHLO. RFC 5321 §4.5.3.2.7
	// puts the floor at 5 minutes; below that, MUAs that stall between commands
	// (e.g. a slow reverse-DNS lookup of their own LAN address) get a
	// "421 4.4.2 Idle timeout" and report a broken connection.
	if cfg.Defaults.TimeoutSeconds < 300 {
		t.Errorf("Defaults.TimeoutSeconds = %d; want >= 300 (RFC 5321 §4.5.3.2.7)", cfg.Defaults.TimeoutSeconds)
	}
}

func TestExpandEnvRefs(t *testing.T) {
	t.Setenv("MIZU_TEST_TOKEN", "s3cr3t-value")

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"braced ref expands", "${MIZU_TEST_TOKEN}", "s3cr3t-value"},
		{"ref embedded in text", "Bearer ${MIZU_TEST_TOKEN}!", "Bearer s3cr3t-value!"},
		{"unset ref expands to empty", "${MIZU_TEST_UNSET}", ""},
		// Regression: a literal secret containing '$' must NOT be mangled the way
		// os.ExpandEnv would ("pa$word" -> "pa"). Only ${...} is expanded.
		{"literal dollar preserved", "pa$$w0rd$x", "pa$$w0rd$x"},
		{"bare dollar-var not expanded", "$MIZU_TEST_TOKEN", "$MIZU_TEST_TOKEN"},
		{"no refs unchanged", "plain-token-123", "plain-token-123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expandEnvRefs(tt.in); got != tt.want {
				t.Errorf("expandEnvRefs(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSaveExample(t *testing.T) {
	tmpDir := t.TempDir()
	examplePath := filepath.Join(tmpDir, "config.toml.example")

	err := SaveExample(examplePath)
	if err != nil {
		t.Fatalf("SaveExample failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Error("example config file was not created")
	}

	// Verify file can be loaded
	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("failed to read example file: %v", err)
	}

	if len(data) == 0 {
		t.Error("example file is empty")
	}
}

func TestValidateConfig_ClusterBindAddr(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		port      int
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid IP address",
			addr:      "10.0.1.5",
			port:      7946,
			wantError: false,
		},
		{
			name:      "valid IP with port",
			addr:      "10.0.1.5:7946",
			port:      0,
			wantError: false,
		},
		{
			name:      "empty addr",
			addr:      "",
			port:      7946,
			wantError: true,
			errorMsg:  "cluster.addr must be set",
		},
		{
			name:      "0.0.0.0 not allowed",
			addr:      "0.0.0.0",
			port:      7946,
			wantError: true,
			errorMsg:  "cluster.addr cannot be 0.0.0.0",
		},
		{
			name:      ":: not allowed",
			addr:      "::",
			port:      7946,
			wantError: true,
			errorMsg:  "cluster.addr cannot be 0.0.0.0 or ::",
		},
		{
			name:      "localhost not allowed",
			addr:      "localhost",
			port:      7946,
			wantError: true,
			errorMsg:  "cluster.addr cannot be localhost",
		},
		{
			name:      "127.0.0.1 not allowed",
			addr:      "127.0.0.1",
			port:      7946,
			wantError: true,
			errorMsg:  "cluster.addr cannot be localhost/127.0.0.1",
		},
		{
			name:      "::1 not allowed",
			addr:      "::1",
			port:      7946,
			wantError: true,
			errorMsg:  "cluster.addr cannot be localhost",
		},
		{
			name:      "invalid port too high",
			addr:      "10.0.1.5",
			port:      70000,
			wantError: true,
			errorMsg:  "cluster bind port must be between 1 and 65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Local = false // Use production mode to trigger cluster validation
			cfg.Storage.Backend = "filesystem"
			cfg.Storage.FilesystemPath = "/tmp/mizu"
			cfg.TLS.Enabled = true
			cfg.TLS.Provider = "letsencrypt"
			cfg.TLS.LetsEncrypt.Email = "test@example.com"
			cfg.TLS.LetsEncrypt.Domains = []string{"test.example.com"}
			cfg.TLS.LetsEncrypt.StorageProvider = "s3"
			cfg.TLS.LetsEncrypt.S3.Bucket = "test-bucket"

			// Add a test server (DefaultConfig no longer includes servers)
			cfg.Servers = []ServerConfig{
				{
					Name:       "test-server",
					Type:       "relay",
					ListenAddr: ":25",
					Hostname:   "test.example.com",
					Delivery: DeliveryConfig{
						URL:                "https://test.com",
						AuthToken:          "test-token",
						MaxRetryAttempts:   3,
						HTTPTimeoutSeconds: 30,
					},
				},
			}

			// Enable cluster (a valid 32-byte base64 secret key is now required)
			cfg.Cluster.Enabled = true
			cfg.Cluster.SecretKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
			cfg.Cluster.Addr = tt.addr
			cfg.Cluster.Port = tt.port

			err := cfg.Validate()

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected validation error containing '%s', got nil", tt.errorMsg)
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

func TestValidateConfig_TLSProvider(t *testing.T) {
	// Helper to create a minimal valid config with TLS enabled.
	baseCfg := func() Config {
		cfg := DefaultConfig()
		cfg.Local = false
		cfg.Storage.Backend = "filesystem"
		cfg.Storage.FilesystemPath = "/tmp/mizu"
		cfg.TLS.Enabled = true
		cfg.Servers = []ServerConfig{
			{
				Name:       "test-server",
				Type:       "relay",
				ListenAddr: ":25",
				Hostname:   "test.example.com",
				Delivery: DeliveryConfig{
					URL:                "https://test.com",
					AuthToken:          "test-token",
					MaxRetryAttempts:   3,
					HTTPTimeoutSeconds: 30,
				},
			},
		}
		return cfg
	}

	t.Run("file provider valid", func(t *testing.T) {
		cfg := baseCfg()
		cfg.TLS.Provider = "file"
		cfg.TLS.File.CertFile = "/etc/ssl/cert.pem"
		cfg.TLS.File.KeyFile = "/etc/ssl/key.pem"
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("file provider missing cert_file", func(t *testing.T) {
		cfg := baseCfg()
		cfg.TLS.Provider = "file"
		cfg.TLS.File.CertFile = ""
		cfg.TLS.File.KeyFile = "/etc/ssl/key.pem"
		err := cfg.Validate()
		if err == nil || !contains(err.Error(), "cert_file") {
			t.Errorf("expected error about cert_file, got: %v", err)
		}
	})

	t.Run("file provider missing key_file", func(t *testing.T) {
		cfg := baseCfg()
		cfg.TLS.Provider = "file"
		cfg.TLS.File.CertFile = "/etc/ssl/cert.pem"
		cfg.TLS.File.KeyFile = ""
		err := cfg.Validate()
		if err == nil || !contains(err.Error(), "key_file") {
			t.Errorf("expected error about key_file, got: %v", err)
		}
	})

	t.Run("letsencrypt provider valid", func(t *testing.T) {
		cfg := baseCfg()
		cfg.TLS.Provider = "letsencrypt"
		cfg.TLS.LetsEncrypt.Email = "test@example.com"
		cfg.TLS.LetsEncrypt.Domains = []string{"test.example.com"}
		cfg.TLS.LetsEncrypt.StorageProvider = "s3"
		cfg.TLS.LetsEncrypt.S3.Bucket = "test-bucket"
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("letsencrypt provider missing email", func(t *testing.T) {
		cfg := baseCfg()
		cfg.TLS.Provider = "letsencrypt"
		cfg.TLS.LetsEncrypt.Email = ""
		cfg.TLS.LetsEncrypt.Domains = []string{"test.example.com"}
		cfg.TLS.LetsEncrypt.StorageProvider = "s3"
		cfg.TLS.LetsEncrypt.S3.Bucket = "test-bucket"
		err := cfg.Validate()
		if err == nil || !contains(err.Error(), "email") {
			t.Errorf("expected error about email, got: %v", err)
		}
	})

	t.Run("empty provider", func(t *testing.T) {
		cfg := baseCfg()
		cfg.TLS.Provider = ""
		err := cfg.Validate()
		if err == nil || !contains(err.Error(), "tls.provider must be set") {
			t.Errorf("expected error about provider, got: %v", err)
		}
	})

	t.Run("invalid provider", func(t *testing.T) {
		cfg := baseCfg()
		cfg.TLS.Provider = "magic"
		err := cfg.Validate()
		if err == nil || !contains(err.Error(), "invalid tls.provider") {
			t.Errorf("expected error about invalid provider, got: %v", err)
		}
	})
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestValidateConfig_MaxMessageSize(t *testing.T) {
	baseCfg := func(size int) Config {
		cfg := DefaultConfig()
		cfg.Local = true
		cfg.Storage.Backend = "filesystem"
		cfg.Storage.FilesystemPath = "/tmp/mizu"
		cfg.Servers = []ServerConfig{
			{
				Name:       "relay",
				Type:       "relay",
				ListenAddr: ":25",
				Hostname:   "test.example.com",
				Delivery: DeliveryConfig{
					URL:                "https://test.com",
					AuthToken:          "test-token",
					MaxRetryAttempts:   3,
					HTTPTimeoutSeconds: 30,
				},
			},
		}
		if size > 0 {
			cfg.Servers[0].MaxMessageSize = size
		}
		return cfg
	}

	t.Run("default applies and passes", func(t *testing.T) {
		cfg := baseCfg(0)
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error with default size, got: %v", err)
		}
	})

	t.Run("unset per-server inherits safe default", func(t *testing.T) {
		// A per-server 0 (or unset) means "inherit from defaults"; with the
		// standard 25 MiB default this is safe and must pass.
		cfg := baseCfg(1)
		cfg.Servers[0].MaxMessageSize = 0
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected inherited default to pass, got: %v", err)
		}
	})

	t.Run("unlimited defaults inherited rejected", func(t *testing.T) {
		cfg := baseCfg(1)
		cfg.Servers[0].MaxMessageSize = 0 // inherit from defaults
		cfg.Defaults.MaxMessageSize = 0   // explicitly unlimited defaults
		err := cfg.Validate()
		if err == nil || !contains(err.Error(), "max_message_size") {
			t.Errorf("expected max_message_size error, got: %v", err)
		}
	})

	t.Run("oversized limit rejected", func(t *testing.T) {
		cfg := baseCfg(MaxMessageSizeLimit + 1)
		err := cfg.Validate()
		if err == nil || !contains(err.Error(), "max_message_size") {
			t.Errorf("expected max_message_size error, got: %v", err)
		}
	})

	t.Run("ceiling accepted", func(t *testing.T) {
		cfg := baseCfg(MaxMessageSizeLimit)
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error at ceiling, got: %v", err)
		}
	})
}
