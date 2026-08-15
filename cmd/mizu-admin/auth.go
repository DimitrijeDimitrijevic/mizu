package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/smtp"

	"github.com/migadu/passwd"
)

// Auth exit codes. Operational failures (flag parse, config load, transport,
// unexpected HTTP status) exit 1, so the auth-result codes below deliberately
// avoid 1 to stay distinguishable from an error.
const (
	exitAuthOK       = 0 // password matched, or (no password) user found
	exitAuthNoMatch  = 2 // user found but password did not match
	exitAuthNotFound = 3 // user unknown (404 from the auth backend)
	exitAuthDenied   = 4 // user denied submission (403 from the auth backend)
)

// cmdAuth implements `mizu-admin auth [flags] <email> [password]`.
//
// It resolves the SMTP AUTH backend URL (rcptd's /auth) from the Mizu config —
// the exact endpoint Mizu queries during SMTP AUTH — fetches the user's password
// hashes and allowed_from list, and, if a password is supplied, verifies it
// locally via shared/passwd (the same implementation Mizu uses at auth time,
// covering bcrypt/BLF-CRYPT/SSHA512/SHA512). The plaintext password is never
// sent to the backend.
func cmdAuth() {
	// ContinueOnError: the stdlib's ExitOnError exits 2 on parse errors, which
	// would collide with exitAuthNoMatch. Flags go before positionals; use "--"
	// to pass a password that begins with "-".
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Output as JSON")
	urlOverride := fs.String("url", "", "Auth endpoint URL template (overrides config; must contain $email)")
	tokenOverride := fs.String("token", "", "Bearer token for the auth endpoint (required with --url if the endpoint needs one)")
	ip := fs.String("ip", "127.0.0.1", "Client IP substituted for the $ip placeholder")
	if err := fs.Parse(flag.Args()[1:]); err != nil {
		os.Exit(1)
	}

	args := fs.Args()
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(os.Stderr, "Usage: mizu-admin auth [--url <template>] [--token <token>] [--ip <ip>] [--json] [--] <email> [password]")
		os.Exit(1)
	}
	email := args[0]
	password := ""
	if len(args) > 1 {
		password = args[1]
	}
	// An explicitly-supplied empty password is treated the same as no password:
	// report the served hashes instead of verifying "" against them.
	havePassword := password != ""

	urlTemplate := *urlOverride
	token := *tokenOverride

	// The config is consulted only when --url is not given. In particular the
	// config's auth token belongs to the config's endpoint: it is never sent to
	// an operator-supplied --url (pass --token explicitly for that).
	if urlTemplate == "" {
		cfg, err := config.LoadFromFile(configFile)
		if err != nil {
			fatal("auth URL not given and failed to load config %s: %v", configFile, err)
		}
		srv := findAuthServer(cfg)
		if srv == nil {
			fatal("no submission server with auth.url found in %s; pass --url", configFile)
		}
		urlTemplate = srv.Auth.URL
		if token == "" {
			token = srv.Auth.AuthToken
		}
	}
	if !strings.Contains(urlTemplate, "$email") {
		fatal("auth URL template %q must contain $email", urlTemplate)
	}

	// Build the request URL and perform the GET exactly as Mizu's authenticator
	// does. Name the endpoint queried on stderr — a config may hold several
	// submission servers with different auth backends, and findAuthServer picks
	// the first.
	requestURL := smtp.BuildAuthURL(urlTemplate, email, *ip)
	fmt.Fprintf(os.Stderr, "auth endpoint: %s\n", requestURL)

	client := &http.Client{Timeout: timeout}
	status, resp, body, err := smtp.FetchAuthCredentials(context.Background(), client, requestURL, token)
	if err != nil {
		fatal("auth request failed: %v", err)
	}

	if status == http.StatusNotFound {
		if *jsonOut {
			var extra map[string]any
			if havePassword {
				extra = map[string]any{"password_match": false}
			}
			emitAuthJSON(email, nil, nil, "not_found", status, extra)
		} else {
			fmt.Printf("NOT FOUND %s\n", email)
		}
		os.Exit(exitAuthNotFound)
	}
	if status == http.StatusForbidden {
		// The backend denies submission for this user (rcptd deny_smtp); Mizu
		// rejects the AUTH exactly as it does for an unknown user.
		if *jsonOut {
			var extra map[string]any
			if havePassword {
				extra = map[string]any{"password_match": false}
			}
			emitAuthJSON(email, nil, nil, "denied", status, extra)
		} else {
			fmt.Printf("DENIED    %s\n", email)
		}
		os.Exit(exitAuthDenied)
	}
	if status != http.StatusOK {
		fatal("auth backend returned HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}

	// Mizu treats a 200 with no hashes as "no such user" and rejects the AUTH.
	if len(resp.PasswordHashes) == 0 {
		fmt.Fprintln(os.Stderr, "warning: backend served no password hashes; mizu-server rejects AUTH for this user")
	}

	// No password supplied: just report what the backend serves for this user.
	if !havePassword {
		if *jsonOut {
			emitAuthJSON(email, resp.PasswordHashes, resp.AllowedFrom, "found", status, nil)
		} else {
			fmt.Printf("FOUND     %s  (%d hash(es))\n", email, len(resp.PasswordHashes))
			for _, h := range resp.PasswordHashes {
				fmt.Printf("  hash: %s\n", h)
			}
			if len(resp.AllowedFrom) > 0 {
				fmt.Printf("  allowed_from: %s\n", strings.Join(resp.AllowedFrom, ", "))
			}
		}
		os.Exit(exitAuthOK)
	}

	// Verify the supplied password against the served hashes, exactly as Mizu
	// does. VerifyAny scans the full list so a corrupt or unsupported stored
	// hash is reported even when another hash matches.
	res := passwd.VerifyAny(resp.PasswordHashes, password)

	if *jsonOut {
		extra := map[string]any{"password_match": res.Matched}
		if res.Unsupported > 0 {
			extra["unsupported_hashes"] = res.Unsupported
		}
		if len(res.Malformed) > 0 {
			extra["malformed_hashes"] = res.Malformed
		}
		emitAuthJSON(email, resp.PasswordHashes, resp.AllowedFrom, "found", status, extra)
	} else {
		if res.Matched {
			fmt.Printf("MATCH     %s\n", email)
		} else {
			fmt.Printf("NO MATCH  %s\n", email)
		}
		if res.Unsupported > 0 {
			fmt.Fprintf(os.Stderr, "Note: %d hash(es) use a scheme Mizu does not support; these cannot authenticate and need to be regenerated.\n", res.Unsupported)
		}
		if len(res.Malformed) > 0 {
			fmt.Fprintf(os.Stderr, "Note: %d stored hash(es) could not be parsed (corrupt?): %s\n", len(res.Malformed), strings.Join(res.Malformed, "; "))
		}
	}

	if res.Matched {
		os.Exit(exitAuthOK)
	}
	os.Exit(exitAuthNoMatch)
}

// findAuthServer returns the first submission server that has an auth URL
// configured, or nil if none do.
func findAuthServer(cfg *config.Config) *config.ServerConfig {
	for i := range cfg.Servers {
		srv := &cfg.Servers[i]
		if srv.IsSubmission() && srv.Auth.URL != "" {
			return srv
		}
	}
	return nil
}

// emitAuthJSON prints a machine-readable summary of the auth lookup.
func emitAuthJSON(email string, hashes, allowedFrom []string, result string, status int, extra map[string]any) {
	out := map[string]any{
		"email":           email,
		"result":          result,
		"status_code":     status,
		"password_hashes": hashes,
		"allowed_from":    allowedFrom,
	}
	for k, v := range extra {
		out[k] = v
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}
