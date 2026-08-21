package config

import "testing"

func TestNeedsReverseDNS(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*ServerConfig)
		want bool
	}{
		{
			name: "bare submission server needs no PTR",
			mut:  func(*ServerConfig) {},
			want: false,
		},
		{
			name: "require_rdns forces the lookup",
			mut:  func(s *ServerConfig) { s.DNSChecks.RequireRDNS = true },
			want: true,
		},
		{
			name: "reputation enabled without host whitelist does not need PTR",
			mut:  func(s *ServerConfig) { s.Reputation.Enabled = true },
			want: false,
		},
		{
			name: "reputation host whitelist needs PTR",
			mut: func(s *ServerConfig) {
				s.Reputation.Enabled = true
				s.Reputation.WhitelistHosts = []string{"pingdom.com"}
			},
			want: true,
		},
		{
			name: "host whitelist without reputation enabled is inert",
			mut:  func(s *ServerConfig) { s.Reputation.WhitelistHosts = []string{"pingdom.com"} },
			want: false,
		},
		{
			name: "sender validation using $ptr needs the lookup",
			mut: func(s *ServerConfig) {
				s.SenderValidation.Enabled = true
				s.SenderValidation.URL = "https://api.example.com/sender?ip=$ip&ptr=$ptr"
			},
			want: true,
		},
		{
			name: "sender validation without $ptr does not need the lookup",
			mut: func(s *ServerConfig) {
				s.SenderValidation.Enabled = true
				s.SenderValidation.URL = "https://api.example.com/sender?ip=$ip"
			},
			want: false,
		},
		{
			name: "sender validation with $ptr but disabled is inert",
			mut: func(s *ServerConfig) {
				s.SenderValidation.URL = "https://api.example.com/sender?ptr=$ptr"
			},
			want: false,
		},
		{
			name: "recipient validation using $ptr needs the lookup",
			mut: func(s *ServerConfig) {
				s.RecipientValidation.Enabled = true
				s.RecipientValidation.URL = "https://api.example.com/rcpt?ptr=$ptr&email=$email"
			},
			want: true,
		},
		{
			name: "recipient validation without $ptr does not need the lookup",
			mut: func(s *ServerConfig) {
				s.RecipientValidation.Enabled = true
				s.RecipientValidation.URL = "https://api.example.com/rcpt?email=$email"
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ServerConfig{}
			tt.mut(s)
			if got := s.NeedsReverseDNS(); got != tt.want {
				t.Errorf("NeedsReverseDNS() = %v, want %v", got, tt.want)
			}
		})
	}
}
