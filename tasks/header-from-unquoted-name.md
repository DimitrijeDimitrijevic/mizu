# Authenticated mail refused for an unquoted `@` in the From display name (2026-10-15)

## Symptom

Reported by a customer the day the header From check (69ff9ef) went live:

```
AUTH alfred@wearzoor.com (accepted)
MAIL FROM:<alfred@wearzoor.com>
DATA -> 550 5.7.1 sender address rejected: not allowed
```

Same login, envelope and BCC had been accepted at 06:43 UTC that morning. The
message carried `From: Alfred @ Wear Zoor <alfred@wearzoor.com>`.

## Diagnosis

The check parses `From` with net/mail, which is strict RFC 5322: `@` is a
special, so an unquoted display name holding one fails with "missing '@' or
angle-addr". An unquoted comma, semicolon or bracket fails the same way, and
so does a raw 8-bit name. Nothing in mizu looked at the header before 69ff9ef
and receivers take the angle-addr, so a flow that had worked for years broke
on deploy.

The sender is a script: the successful Message-ID has Python's `make_msgid`
shape, and `From` is built by hand (`formataddr` would have quoted it). A
script does not retry a 5xx at DATA, so this was mail lost, not delayed.

PR 24 (Dimitrije) relabels the refusal `550 5.6.0 malformed From header` and
logs the raw header as `value`; it still rejects.

## Plan

- [x] Keep PR 24's two commits (log `value`, 5.6.0 for malformed)
- [x] `parseHeaderAddresses`: strict parse, then retry from the first `<` with
      the display name dropped
- [x] Refuse the retry when the name holds a token with text on both sides of
      an `@` — a lenient receiver could read it as a second sender, which the
      strict path refuses as "one allowed one not"
- [x] Reply-code test table rewritten: 22 cases over accepted / 5.6.0 / 5.7.1
- [x] CLAUDE.md bullet

## Review

Files: `pkg/smtp/server.go`, `pkg/smtp/header_from_auth_test.go`, `CLAUDE.md`.

Verified against the parser rather than assumed: `Alfred @ Wear Zoor <a@b>`
fails strict; `"Alfred @ Wear Zoor" <a@b>` and a bare `<a@b>` parse;
`alice@x <a@b>` fails strict with "expected comma", which is why the `@`-token
rule is needed to keep it out of the fallback.

Judgment call to revisit if it bites: `me@mine <me@mine>` (some scripts emit
the address as its own display name) stays 5.6.0 under the `@`-token rule.

`go build ./...`, `go vet ./pkg/smtp`, `go test ./pkg/smtp` clean.

Customer workaround meanwhile: quote the name,
`"Alfred @ Wear Zoor" <alfred@wearzoor.com>`.
