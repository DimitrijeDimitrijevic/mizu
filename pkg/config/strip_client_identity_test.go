package config

import "testing"

func TestStripClientIdentity_Defaults(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name       string
		typ        string
		configured *bool
		want       bool
	}{
		// Submission clients are end users; their machine name and network must not
		// reach recipients unless the operator explicitly opts back in.
		{name: "submission defaults to stripped", typ: "submission", want: true},
		// Relays keep the full trace: downstream receivers use it for SPF/DMARC
		// forensics and loop detection.
		{name: "relay defaults to kept", typ: "relay", want: false},
		{name: "submission override off", typ: "submission", configured: boolPtr(false), want: false},
		{name: "relay override on", typ: "relay", configured: boolPtr(true), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ServerConfig{
				Name:                "srv",
				Type:                tt.typ,
				ListenAddr:          ":25",
				StripClientIdentity: tt.configured,
			}

			// The accessor must report the right answer before ApplyDefaults runs...
			if got := s.StripsClientIdentity(); got != tt.want {
				t.Errorf("StripsClientIdentity() before defaults = %v, want %v", got, tt.want)
			}

			// ...and ApplyDefaults must resolve the pointer to the same value.
			s.ApplyDefaults(DefaultsConfig{})
			if s.StripClientIdentity == nil {
				t.Fatal("ApplyDefaults left strip_client_identity unset")
			}
			if got := *s.StripClientIdentity; got != tt.want {
				t.Errorf("strip_client_identity after defaults = %v, want %v", got, tt.want)
			}
			if got := s.StripsClientIdentity(); got != tt.want {
				t.Errorf("StripsClientIdentity() after defaults = %v, want %v", got, tt.want)
			}
		})
	}
}
