package smtp

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"migadu/mizu/pkg/config"
)

func TestIPInNets(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		entries  []string
		expected bool
	}{
		{
			name:     "empty whitelist",
			ip:       "1.2.3.4",
			entries:  nil,
			expected: false,
		},
		{
			name:     "exact IP in list",
			ip:       "1.2.3.4",
			entries:  []string{"5.6.7.8", "1.2.3.4"},
			expected: true,
		},
		{
			name:     "CIDR in list",
			ip:       "10.0.1.50",
			entries:  []string{"192.168.0.0/16", "10.0.0.0/8"},
			expected: true,
		},
		{
			name:     "no match",
			ip:       "1.2.3.4",
			entries:  []string{"5.6.7.8", "10.0.0.0/8"},
			expected: false,
		},
		{
			name:     "exact IPv6 in list",
			ip:       "2001:db8::1",
			entries:  []string{"2001:db8::1"},
			expected: true,
		},
		{
			name:     "IPv6 CIDR in list",
			ip:       "2001:db8::1234",
			entries:  []string{"2001:db8::/32"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, err := config.ParseIPList(tt.entries)
			if err != nil {
				t.Fatalf("ParseIPList(%v) failed: %v", tt.entries, err)
			}
			result := ipInNets(net.ParseIP(tt.ip), nets)
			if result != tt.expected {
				t.Errorf("ipInNets(%q, %v) = %v, want %v", tt.ip, tt.entries, result, tt.expected)
			}
		})
	}
}

func TestMatchHostWhitelist(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &Backend{
		ServerConfig: &config.ServerConfig{Name: "test"},
		Logger:       logger,
	}

	tests := []struct {
		name          string
		ptrHost       string
		whitelistHost string
		expected      bool
	}{
		// Exact matches
		{
			name:          "exact match",
			ptrHost:       "hetrixtools.com",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "exact match with trailing dot",
			ptrHost:       "hetrixtools.com.",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},

		// Suffix matches
		{
			name:          "subdomain suffix match",
			ptrHost:       "wk9-4.hetrixtools.com",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "subdomain suffix match with trailing dot",
			ptrHost:       "wk9-4.hetrixtools.com.",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "multi-level subdomain suffix match",
			ptrHost:       "server.monitoring.hetrixtools.com",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "no match different domain",
			ptrHost:       "mail.example.com",
			whitelistHost: "hetrixtools.com",
			expected:      false,
		},
		{
			name:          "no match partial suffix",
			ptrHost:       "fakehetrixtools.com",
			whitelistHost: "hetrixtools.com",
			expected:      false,
		},

		// Case insensitivity
		{
			name:          "case insensitive match",
			ptrHost:       "WK9-4.HetrixTools.COM",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},

		// Real-world examples
		{
			name:          "Hetrix Tools actual hostname",
			ptrHost:       "wk9-4.hetrixtools.com.",
			whitelistHost: "hetrixtools.com",
			expected:      true,
		},
		{
			name:          "Pingdom hostname",
			ptrHost:       "probe-123.pingdom.com",
			whitelistHost: "pingdom.com",
			expected:      true,
		},
		{
			name:          "UptimeRobot hostname",
			ptrHost:       "static.456.78.90.clients.your-server.de",
			whitelistHost: "your-server.de",
			expected:      true,
		},

		// Edge cases
		{
			name:          "empty PTR",
			ptrHost:       "",
			whitelistHost: "hetrixtools.com",
			expected:      false,
		},
		{
			name:          "empty whitelist",
			ptrHost:       "wk9-4.hetrixtools.com",
			whitelistHost: "",
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := backend.matchHostWhitelist(tt.ptrHost, tt.whitelistHost)
			if result != tt.expected {
				t.Errorf("matchHostWhitelist(%q, %q) = %v, want %v", tt.ptrHost, tt.whitelistHost, result, tt.expected)
			}
		})
	}
}
