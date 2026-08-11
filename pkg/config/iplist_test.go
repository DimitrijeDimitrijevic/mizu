package config

import (
	"testing"
)

func TestParseIPList(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		wantErr bool
	}{
		{
			name:    "empty list",
			entries: nil,
			wantErr: false,
		},
		{
			name:    "valid IPs and CIDRs",
			entries: []string{"1.2.3.4", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32"},
			wantErr: false,
		},
		{
			name:    "invalid IP",
			entries: []string{"not-an-ip"},
			wantErr: true,
		},
		{
			name:    "invalid CIDR mask",
			entries: []string{"10.0.0.1/33"},
			wantErr: true,
		},
		{
			name:    "valid entry followed by invalid",
			entries: []string{"1.2.3.4", "1.2.3,4"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, err := ParseIPList(tt.entries)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseIPList(%v) error = %v, wantErr %v", tt.entries, err, tt.wantErr)
			}
			if !tt.wantErr && len(nets) != len(tt.entries) {
				t.Errorf("ParseIPList(%v) returned %d networks, want %d", tt.entries, len(nets), len(tt.entries))
			}
		})
	}
}

func TestServerConfigValidate_ParsesIPLists(t *testing.T) {
	server := ServerConfig{
		Name:       "test",
		ListenAddr: ":25",
		Type:       "relay",
	}
	server.DNSChecks.RDNSWhitelistIPs = []string{"10.0.0.1/33"}

	if err := server.Validate(); err == nil {
		t.Error("Validate() accepted invalid rdns_whitelist_ips entry, want error")
	}

	server.DNSChecks.RDNSWhitelistIPs = []string{"1.2.3.4", "10.0.0.0/8"}
	server.Reputation.WhitelistIPs = []string{"192.168.0.0/16"}
	server.ProxyProtocol = true
	server.ProxyProtocolTrusted = []string{"10.1.0.0/16", "2001:db8::1"}
	if err := server.Validate(); err != nil {
		t.Fatalf("Validate() rejected valid IP lists: %v", err)
	}

	if got := len(server.DNSChecks.RDNSWhitelistNets()); got != 2 {
		t.Errorf("RDNSWhitelistNets() returned %d networks, want 2", got)
	}
	if got := len(server.Reputation.WhitelistNets()); got != 1 {
		t.Errorf("Reputation.WhitelistNets() returned %d networks, want 1", got)
	}
	if got := len(server.ProxyTrustedNets()); got != 2 {
		t.Errorf("ProxyTrustedNets() returned %d networks, want 2", got)
	}

	server.Reputation.WhitelistIPs = []string{"not-an-ip"}
	if err := server.Validate(); err == nil {
		t.Error("Validate() accepted invalid reputation.whitelist_ips entry, want error")
	}

	server.Reputation.WhitelistIPs = nil
	server.ProxyProtocolTrusted = []string{"10.0.0.1/33"}
	if err := server.Validate(); err == nil {
		t.Error("Validate() accepted invalid proxy_protocol_trusted entry, want error")
	}
}
