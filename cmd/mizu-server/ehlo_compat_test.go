package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"

	"migadu/mizu/pkg/config"
)

// applyEhloCompat is the config-to-server mapping for the EHLO compatibility
// knobs; the go-smtp fork's own tests cover how the flags shape the actual
// EHLO response bytes.

func submissionCfg() *config.ServerConfig {
	s := &config.ServerConfig{Type: "submission", Name: "test-submission"}
	s.ApplyDefaults(config.DefaultsConfig{})
	return s
}

// Defaults on a submission server: legacy AUTH= line on, LIMITS suppressed —
// the Outlook-compatible surface (August 2026 incident).
func TestApplyEhloCompatSubmissionDefaults(t *testing.T) {
	server := gosmtp.NewServer(nil)
	applyEhloCompat(server, submissionCfg())

	if !server.EnableLegacyAuthCap {
		t.Fatal("submission server must advertise legacy AUTH= by default")
	}
	if !server.DisableLimitsCap {
		t.Fatal("LIMITS must be suppressed by default")
	}
}

func TestApplyEhloCompatLegacyAuthDisabled(t *testing.T) {
	cfg := submissionCfg()
	falseVal := false
	cfg.LegacyAuthCap = &falseVal

	server := gosmtp.NewServer(nil)
	applyEhloCompat(server, cfg)

	if server.EnableLegacyAuthCap {
		t.Fatal("legacy_auth_cap=false must disable the legacy AUTH= line")
	}
}

func TestApplyEhloCompatAdvertiseLimits(t *testing.T) {
	cfg := submissionCfg()
	cfg.AdvertiseLimits = true

	server := gosmtp.NewServer(nil)
	applyEhloCompat(server, cfg)

	if server.DisableLimitsCap {
		t.Fatal("advertise_limits=true must re-enable the LIMITS capability")
	}
}

// Relay (MX) servers advertise no AUTH, so the legacy line stays off there
// regardless of the default.
func TestApplyEhloCompatRelayNoLegacyAuth(t *testing.T) {
	cfg := &config.ServerConfig{Type: "relay", Name: "test-mx"}
	cfg.ApplyDefaults(config.DefaultsConfig{})

	server := gosmtp.NewServer(nil)
	applyEhloCompat(server, cfg)

	if server.EnableLegacyAuthCap {
		t.Fatal("relay server must not enable the legacy AUTH= line")
	}
	if !server.DisableLimitsCap {
		t.Fatal("LIMITS must be suppressed by default on relay servers too")
	}
}

// SMTPUTF8 is off unless enabled in config, on both server types.
func TestApplyEhloCompatSMTPUTF8DefaultOff(t *testing.T) {
	for _, typ := range []string{"submission", "relay"} {
		cfg := &config.ServerConfig{Type: typ, Name: "test-" + typ}
		cfg.ApplyDefaults(config.DefaultsConfig{})

		server := gosmtp.NewServer(nil)
		applyEhloCompat(server, cfg)

		if server.EnableSMTPUTF8 {
			t.Fatalf("%s server must not enable SMTPUTF8 by default", typ)
		}
	}
}

func TestApplyEhloCompatSMTPUTF8Enabled(t *testing.T) {
	for _, typ := range []string{"submission", "relay"} {
		cfg := &config.ServerConfig{Type: typ, Name: "test-" + typ}
		cfg.ApplyDefaults(config.DefaultsConfig{})
		cfg.SMTPUTF8 = true

		server := gosmtp.NewServer(nil)
		applyEhloCompat(server, cfg)

		if !server.EnableSMTPUTF8 {
			t.Fatalf("smtputf8=true must enable SMTPUTF8 on %s servers", typ)
		}
	}
}

// --- Wire-level check: what a client actually sees on port 25 ---

type nopSession struct{}

func (nopSession) Reset()        {}
func (nopSession) Logout() error { return nil }
func (nopSession) Mail(context.Context, string, *gosmtp.MailOptions) error {
	return nil
}
func (nopSession) Rcpt(context.Context, string, *gosmtp.RcptOptions) error {
	return nil
}
func (nopSession) Data(_ context.Context, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

// ehloAndMailUTF8 starts a relay server configured through applyEhloCompat,
// and returns the EHLO capability lines plus the reply to
// "MAIL FROM:<a@example.com> SMTPUTF8".
func ehloAndMailUTF8(t *testing.T, smtputf8 bool) (caps []string, mailReply string) {
	t.Helper()

	cfg := &config.ServerConfig{Type: "relay", Name: "test-mx"}
	cfg.ApplyDefaults(config.DefaultsConfig{})
	cfg.SMTPUTF8 = smtputf8

	server := gosmtp.NewServer(gosmtp.BackendFunc(func(*gosmtp.Conn) (gosmtp.Session, error) {
		return nopSession{}, nil
	}))
	server.Domain = "mx.test"
	applyEhloCompat(server, cfg)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(l)
	t.Cleanup(func() { server.Close() })

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	tp := textproto.NewConn(conn)

	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if err := tp.PrintfLine("EHLO client.test"); err != nil {
		t.Fatal(err)
	}
	_, msg, err := tp.ReadResponse(250)
	if err != nil {
		t.Fatalf("EHLO: %v", err)
	}
	caps = strings.Split(msg, "\n")

	if err := tp.PrintfLine("MAIL FROM:<a@example.com> SMTPUTF8"); err != nil {
		t.Fatal(err)
	}
	code, msg, err := tp.ReadResponse(0)
	if err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	return caps, fmt.Sprintf("%d %s", code, msg)
}

func hasCap(caps []string, name string) bool {
	for _, c := range caps {
		if c == name {
			return true
		}
	}
	return false
}

func TestEhloSMTPUTF8NotAdvertisedByDefault(t *testing.T) {
	caps, mailReply := ehloAndMailUTF8(t, false)

	if hasCap(caps, "SMTPUTF8") {
		t.Fatalf("SMTPUTF8 must not be advertised when disabled; EHLO: %q", caps)
	}
	if !strings.HasPrefix(mailReply, "504 5.5.4") {
		t.Fatalf("MAIL FROM ... SMTPUTF8 must be refused with 504 5.5.4, got %q", mailReply)
	}
}

func TestEhloSMTPUTF8AdvertisedWhenEnabled(t *testing.T) {
	caps, mailReply := ehloAndMailUTF8(t, true)

	if !hasCap(caps, "SMTPUTF8") {
		t.Fatalf("SMTPUTF8 must be advertised when enabled; EHLO: %q", caps)
	}
	if !strings.HasPrefix(mailReply, "250") {
		t.Fatalf("MAIL FROM ... SMTPUTF8 must be accepted, got %q", mailReply)
	}
}
