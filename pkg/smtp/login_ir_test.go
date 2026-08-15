package smtp

import (
	"errors"
	"testing"

	"github.com/emersion/go-smtp"
)

// LoginServer must support BOTH shapes of the LOGIN exchange. The initial-
// response form (`AUTH LOGIN <base64-username>`) is what Outlook and every
// go-sasl LOGIN client send; discarding the username there desyncs the
// exchange (the client answers "Username:" with its password) and auth can
// never succeed.

func TestLoginServer_InitialResponse_Username(t *testing.T) {
	var gotUser, gotPass string
	srv := NewLoginServer(func(u, p string) error { gotUser, gotPass = u, p; return nil })

	// Step 0: username supplied as the initial response -> must ask Password:
	challenge, done, err := srv.Next([]byte("user@example.com"))
	if err != nil || done {
		t.Fatalf("step0 IR: done=%v err=%v", done, err)
	}
	if string(challenge) != "Password:" {
		t.Fatalf("with initial response, expected 'Password:' challenge, got %q", challenge)
	}

	// Next line is the password -> exchange completes and authenticates.
	if _, done, err := srv.Next([]byte("secret")); !done || err != nil {
		t.Fatalf("password step: done=%v err=%v", done, err)
	}
	if gotUser != "user@example.com" || gotPass != "secret" {
		t.Fatalf("authenticator got (%q,%q), want (user@example.com, secret)", gotUser, gotPass)
	}
}

func TestLoginServer_InitialResponse_ZeroLength(t *testing.T) {
	// RFC 4954 "=" zero-length initial response decodes to a non-nil empty
	// slice: still an initial response (empty username), not the prompt form.
	srv := NewLoginServer(func(u, p string) error { return nil })
	challenge, _, err := srv.Next([]byte{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(challenge) != "Password:" {
		t.Fatalf("empty IR must still skip to 'Password:', got %q", challenge)
	}
}

func TestLoginServer_ThreeStep_NoInitialResponse(t *testing.T) {
	// The classic form must be unchanged: nil initial response -> ask Username:.
	var gotUser, gotPass string
	srv := NewLoginServer(func(u, p string) error { gotUser, gotPass = u, p; return nil })

	challenge, done, err := srv.Next(nil)
	if err != nil || done {
		t.Fatalf("step0: done=%v err=%v", done, err)
	}
	if string(challenge) != "Username:" {
		t.Fatalf("no initial response, expected 'Username:', got %q", challenge)
	}
	if challenge, _, _ := srv.Next([]byte("user@example.com")); string(challenge) != "Password:" {
		t.Fatalf("step1 expected 'Password:', got %q", challenge)
	}
	if _, done, err := srv.Next([]byte("secret")); !done || err != nil {
		t.Fatalf("step2: done=%v err=%v", done, err)
	}
	if gotUser != "user@example.com" || gotPass != "secret" {
		t.Fatalf("authenticator got (%q,%q)", gotUser, gotPass)
	}
}

func TestLoginServer_AuthenticatorErrorPropagates(t *testing.T) {
	want := errors.New("bad creds")
	srv := NewLoginServer(func(u, p string) error { return want })
	srv.Next([]byte("user@example.com")) // IR username -> Password:
	_, done, err := srv.Next([]byte("wrong"))
	if !done || !errors.Is(err, want) {
		t.Fatalf("expected authenticator error propagated, done=%v err=%v", done, err)
	}
}

// The auth-failure typed errors must carry the RFC 4954 §6 codes: a genuine
// rejection is a PERMANENT 535 (Outlook prompts for the password); a backend
// blip is a TEMPORARY 454 (Outlook's setup wizard reads 4xx as "server down"
// and aborts).
func TestAuthErrorCodes(t *testing.T) {
	var permanent *smtp.SMTPError
	if !errors.As(error(ErrAuthCredentialsInvalid), &permanent) {
		t.Fatal("ErrAuthCredentialsInvalid must be an *smtp.SMTPError")
	}
	if permanent.Code != 535 || permanent.EnhancedCode != (smtp.EnhancedCode{5, 7, 8}) {
		t.Fatalf("credentials-invalid must be 535 5.7.8, got %d %v", permanent.Code, permanent.EnhancedCode)
	}
	var temp *smtp.SMTPError
	if !errors.As(error(ErrAuthTemporaryFailure), &temp) {
		t.Fatal("ErrAuthTemporaryFailure must be an *smtp.SMTPError")
	}
	if temp.Code != 454 || temp.EnhancedCode != (smtp.EnhancedCode{4, 7, 0}) {
		t.Fatalf("temporary failure must be 454 4.7.0, got %d %v", temp.Code, temp.EnhancedCode)
	}
}
