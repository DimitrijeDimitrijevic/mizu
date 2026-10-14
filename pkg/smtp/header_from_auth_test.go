package smtp

import (
	"strings"
	"testing"
)

func headerMsg(extra ...string) string {
	lines := append([]string{
		"Date: Mon, 12 Oct 2026 10:00:00 +0000",
		"Message-ID: <1@example.com>",
		"To: rcpt@example.net",
		"Subject: hi",
	}, extra...)
	return strings.Join(lines, "\r\n") + "\r\n\r\nbody\r\n"
}

func TestValidateHeaders_AuthenticatedFromAuthorization(t *testing.T) {
	const login = "helios@example.com"
	auth := &masterAuthenticator{login: login, identity: login,
		allowed: []string{login, "alias@example.com"}}

	cases := []struct {
		name    string
		headers []string
		wantErr bool
	}{
		{"own address", []string{"From: " + login}, false},
		{"own address with display name", []string{"From: Helios <" + login + ">"}, false},
		{"allowed alias", []string{"From: alias@example.com"}, false},
		{"other mailbox, same domain", []string{"From: economato@example.com"}, true},
		{"other mailbox with display name", []string{"From: \"Helios\" <economato@example.com>"}, true},
		{"other domain", []string{"From: helios@evil.example"}, true},
		{"one allowed one not", []string{"From: " + login + ", economato@example.com"}, true},
		{"two From headers", []string{"From: " + login, "From: economato@example.com"}, true},
		{"unparseable From", []string{"From: not an address"}, true},
		{"Sender not allowed", []string{"From: " + login, "Sender: economato@example.com"}, true},
		{"Sender allowed", []string{"From: " + login, "Sender: alias@example.com"}, false},
		{"display name in windows-1252", []string{"From: =?windows-1252?Q?Jos=E9?= <" + login + ">"}, false},
		{"display name in iso-8859-2", []string{"From: =?iso-8859-2?Q?Bo=BEo?= <" + login + ">"}, false},
		{"unknown charset hiding other mailbox", []string{"From: =?koi8-r?B?8NLJ18XU?= <economato@example.com>"}, true},
		{"folded From", []string{"From: Helios\r\n <" + login + ">"}, false},
		{"empty group", []string{"From: undisclosed:;"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := masterSession(t, auth, login)
			err := s.validateHeaders(headerMsg(tc.headers...))
			if tc.wantErr && err == nil {
				t.Fatal("message was accepted, want rejection")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("message rejected: %v", err)
			}
		})
	}
}

// Relay sessions have no allowed_from; the header is not constrained.
func TestValidateHeaders_UnauthenticatedFromNotEnforced(t *testing.T) {
	auth := &masterAuthenticator{login: "helios@example.com", identity: "helios@example.com"}
	s := masterSession(t, auth, "")
	s.isAuthenticated = false
	if err := s.validateHeaders(headerMsg("From: anyone@elsewhere.example")); err != nil {
		t.Fatalf("unauthenticated message rejected: %v", err)
	}
}
