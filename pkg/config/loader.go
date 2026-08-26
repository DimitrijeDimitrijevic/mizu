package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/BurntSushi/toml"
	"github.com/spf13/pflag"
)

// envRefPattern matches an explicit ${VAR} reference. We deliberately only
// expand this braced form (not bare $VAR) so that a literal secret containing a
// '$' (common in passwords/tokens) is never mangled — os.ExpandEnv would treat
// "pa$word" as "pa" + $word and silently truncate the credential.
var envRefPattern = regexp.MustCompile(`\$\{(\w+)\}`)

// expandEnvRefs replaces ${VAR} references with the corresponding environment
// variable value, leaving all other text (including lone '$') untouched. A
// reference to an unset variable expands to "".
func expandEnvRefs(s string) string {
	return envRefPattern.ReplaceAllStringFunc(s, func(ref string) string {
		return os.Getenv(ref[2 : len(ref)-1]) // strip "${" and "}"
	})
}

func defaultConfigPath() string {
	for _, p := range []string{
		"/etc/mizu/config.toml",
		"/usr/local/etc/mizu/config.toml",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "config.toml"
}

// LoadConfig loads configuration from file and command line flags
func LoadConfig(args []string) (*Config, error) {
	// Start with default configuration
	defaultCfg := DefaultConfig()
	cfg := &defaultCfg

	// Define command line flags
	fs := pflag.NewFlagSet("mizu-server", pflag.ContinueOnError)

	// Config file flag
	configFile := fs.StringP("config", "c", defaultConfigPath(), "Path to configuration file")

	// Local development mode flag
	fs.BoolVar(&cfg.Local, "local", false, "Run in local development mode (no TLS, dump emails to terminal)")

	// Log format flag
	fs.StringVar(&cfg.Logging.Format, "log-format", "console", "Log format: console or json")

	// Parse command line flags
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %w", err)
	}

	// Load configuration from file if it exists
	if *configFile != "" {
		if _, err := os.Stat(*configFile); err == nil {
			md, err := toml.DecodeFile(*configFile, cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
			warnUndecodedKeys(*configFile, md)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat config file: %w", err)
		}
		// If file doesn't exist, just use defaults (no error)
	}

	// Expand ${VAR} references in secret fields, then apply env-var fallbacks
	expandSecretEnvVars(cfg)
	applyEnvironmentVariables(cfg)

	return cfg, nil
}

// expandSecretEnvVars expands ${VAR} references in secret-bearing string fields
// so configs can reference environment variables (e.g.
// auth_token = "${AUTH_TOKEN}") as documented, instead of embedding secrets in
// the file. Only the braced ${VAR} form is expanded so literal secrets
// containing '$' are preserved. A reference to an unset variable expands to ""
// so the dedicated applyEnvironmentVariables fallbacks can still populate it.
func expandSecretEnvVars(cfg *Config) {
	cfg.Storage.S3AccessKey = expandEnvRefs(cfg.Storage.S3AccessKey)
	cfg.Storage.S3SecretKey = expandEnvRefs(cfg.Storage.S3SecretKey)
	cfg.Cluster.SecretKey = expandEnvRefs(cfg.Cluster.SecretKey)
	cfg.Health.Password = expandEnvRefs(cfg.Health.Password)
	for i := range cfg.Servers {
		s := &cfg.Servers[i]
		s.Delivery.AuthToken = expandEnvRefs(s.Delivery.AuthToken)
		s.Auth.AuthToken = expandEnvRefs(s.Auth.AuthToken)
		s.SenderValidation.AuthToken = expandEnvRefs(s.SenderValidation.AuthToken)
		s.RecipientValidation.AuthToken = expandEnvRefs(s.RecipientValidation.AuthToken)
		s.SpamCheck.Password = expandEnvRefs(s.SpamCheck.Password)
	}
}

// applyEnvironmentVariables overrides configuration with environment variables
func applyEnvironmentVariables(cfg *Config) {
	// Storage credentials
	if val := os.Getenv("S3_ACCESS_KEY"); val != "" {
		cfg.Storage.S3AccessKey = val
	}
	if val := os.Getenv("S3_SECRET_KEY"); val != "" {
		cfg.Storage.S3SecretKey = val
	}

	// Delivery credentials (apply to all servers)
	if val := os.Getenv("DESTINATION_AUTH_TOKEN"); val != "" {
		for i := range cfg.Servers {
			if cfg.Servers[i].Delivery.AuthToken == "" || cfg.Servers[i].Delivery.AuthToken == "your-auth-token-here" {
				cfg.Servers[i].Delivery.AuthToken = val
			}
		}
	}
	if val := os.Getenv("DELIVERY_AUTH_TOKEN"); val != "" {
		for i := range cfg.Servers {
			if cfg.Servers[i].Delivery.AuthToken == "" || cfg.Servers[i].Delivery.AuthToken == "your-auth-token-here" {
				cfg.Servers[i].Delivery.AuthToken = val
			}
		}
	}

	// Health check credentials
	if val := os.Getenv("HEALTH_PASSWORD"); val != "" {
		cfg.Health.Password = val
	}

	// Cluster encryption key
	if val := os.Getenv("CLUSTER_SECRET_KEY"); val != "" {
		cfg.Cluster.SecretKey = val
	}

	// Apply auth token to all submission servers
	if val := os.Getenv("AUTH_TOKEN"); val != "" {
		for i := range cfg.Servers {
			if cfg.Servers[i].IsSubmission() && cfg.Servers[i].Auth.AuthToken == "" {
				cfg.Servers[i].Auth.AuthToken = val
			}
		}
	}
}

// SaveExample saves an example configuration file
func SaveExample(filename string) error {
	exampleConfig := DefaultConfig()

	// Create example config with comments
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := toml.NewEncoder(f)
	encoder.Indent = ""

	// Write example configuration
	if err := encoder.Encode(exampleConfig); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// LoadFromFile loads configuration from a specific file path
func LoadFromFile(filename string) (*Config, error) {
	cfg := DefaultConfig()

	md, err := toml.DecodeFile(filename, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file '%s': %w", filename, err)
	}
	warnUndecodedKeys(filename, md)

	// Expand ${VAR} references in secret fields, then apply env-var fallbacks
	expandSecretEnvVars(&cfg)
	applyEnvironmentVariables(&cfg)

	return &cfg, nil
}

// warnUndecodedKeys prints a stderr warning for config keys that matched no
// known field, so a stale key (e.g. one removed in a migration) fails loudly
// instead of being silently ignored. Runs before logging is configured, hence
// stderr rather than the logger.
func warnUndecodedKeys(filename string, md toml.MetaData) {
	for _, key := range md.Undecoded() {
		fmt.Fprintf(os.Stderr, "WARNING: unknown config key %q in %s (ignored)\n", key, filename)
	}
}

// GetConfigPath returns the configuration file path, checking common locations
func GetConfigPath() (string, error) {
	// Check in order: /usr/local/etc/mizu, current directory, /etc/mizu, ~/.config/mizu
	locations := []string{
		"/usr/local/etc/mizu/config.toml",
		"config.toml",
		"/etc/mizu/config.toml",
		filepath.Join(os.Getenv("HOME"), ".config", "mizu", "config.toml"),
	}

	for _, path := range locations {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("config file not found in standard locations")
}
