package smtp

import (
	"errors"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"
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

// Reply codes for the header check. An unauthorized address is 5.7.1. A header
// that is invalid RFC 5322 only because its display name was left unquoted
// ("Alfred @ Wear Zoor <a@b>", "Zoor, Alfred <a@b>") is accepted: receivers
// take the angle-addr, and such mail was never refused before the check
// existed. What does not parse even then is a client bug and gets 5.6.0 with a
// message naming the header, never the 5.7.1 "not allowed" that would send the
// user looking for a missing permission.
func TestValidateHeaders_AuthenticatedFromReplyCodes(t *testing.T) {
	const login = "helios@example.com"
	auth := &masterAuthenticator{login: login, identity: login,
		allowed: []string{login, "alias@example.com"}}

	var accepted smtp.EnhancedCode
	malformed := smtp.EnhancedCode{5, 6, 0}
	notAllowed := smtp.EnhancedCode{5, 7, 1}
	cases := []struct {
		name    string
		headers []string
		want    smtp.EnhancedCode
	}{
		{"quoted comma", []string{`From: "Wearzoor, Helios" <` + login + ">"}, accepted},
		// Unquoted specials in the display name: the angle-addr is the sender.
		{"lone at sign", []string{"From: Helios @ Wearzoor <" + login + ">"}, accepted},
		{"unquoted comma, last name first", []string{"From: Wearzoor, Helios <" + login + ">"}, accepted},
		{"unquoted comma, company suffix", []string{"From: Helios, Wearzoor Ltd <" + login + ">"}, accepted},
		{"square brackets", []string{"From: Helios [Wearzoor] <" + login + ">"}, accepted},
		{"semicolon", []string{"From: Helios; Wearzoor <" + login + ">"}, accepted},
		{"raw 8-bit name", []string{"From: Jos\xe9 Zoor <" + login + ">"}, accepted},
		{"unquoted Sender", []string{"From: " + login, "Sender: Wearzoor, Helios <" + login + ">"}, accepted},
		// The lenient parse authorizes what it finds, like the strict one.
		{"unquoted name, other mailbox", []string{"From: Wearzoor, Helios <economato@example.com>"}, notAllowed},
		{"unquoted Sender, other mailbox", []string{"From: " + login, "Sender: Wearzoor, Helios <economato@example.com>"}, notAllowed},
		{"unquoted name, second address not allowed", []string{"From: Wearzoor, Helios <" + login + ">, economato@example.com"}, notAllowed},
		// A name a lenient receiver could read as an address is not guessed at.
		{"address as unquoted name", []string{"From: economato@example.com <" + login + ">"}, malformed},
		{"own address as unquoted name", []string{"From: " + login + " <" + login + ">"}, malformed},
		{"address before unquoted name", []string{"From: economato@example.com, Wearzoor, Helios <" + login + ">"}, malformed},
		// Nothing to fall back to.
		{"no angle-addr", []string{"From: helios"}, malformed},
		{"two angle-addrs", []string{"From: Helios <boss> <" + login + ">"}, malformed},
		{"text after angle-addr", []string{"From: Wearzoor, Helios <" + login + "> Ltd"}, malformed},
		{"empty group", []string{"From: undisclosed:;"}, malformed},
		{"two From headers", []string{"From: " + login, "From: alias@example.com"}, malformed},
		{"malformed Sender", []string{"From: " + login, "Sender: helios"}, malformed},
		{"other mailbox", []string{"From: economato@example.com"}, notAllowed},
		{"other mailbox, Sender", []string{"From: " + login, "Sender: economato@example.com"}, notAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := masterSession(t, auth, login)
			err := s.validateHeaders(headerMsg(tc.headers...))
			if tc.want == accepted {
				if err != nil {
					t.Fatalf("message rejected: %v", err)
				}
				return
			}
			var smtpErr *smtp.SMTPError
			if !errors.As(err, &smtpErr) {
				t.Fatalf("want *smtp.SMTPError, got %T: %v", err, err)
			}
			if smtpErr.Code != 550 || smtpErr.EnhancedCode != tc.want {
				t.Fatalf("want 550 %v, got %d %v %q", tc.want, smtpErr.Code, smtpErr.EnhancedCode, smtpErr.Message)
			}
			if tc.want == malformed && !strings.Contains(smtpErr.Message, "malformed") {
				t.Fatalf("reply does not say the header is malformed: %q", smtpErr.Message)
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
