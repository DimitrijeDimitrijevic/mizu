# STARTTLS failures from a pre-ECDHE appliance (2026-09-18)

## Symptom

Repeated on submission-587, same IP, every 10-60s:

```
STARTTLS error from 104.2.72.110: handshake failed: tls: no cipher suite
supported by both client and server; client offered:
[6b 6a 3d 67 40 3c 39 38 35 33 32 2f 16 13 a 5 4 15 12 9 ff]
```

`104-2-72-110.lightspeed.sbndin.sbcglobal.net` — residential AT&T. A UPS
network management card, so the client cannot be changed.

## Diagnosis

The offer is 12 DHE/DSS suites (Go has never implemented DHE), `0x3d`/`0x09`/
`0x04` (never implemented), `0x2f`/`0x35`/`0x3c` (RSA key exchange, off by
default since Go 1.22), `0x0a` (3DES, off since Go 1.23), `0x05` (RC4, needs an
explicit list) and the renegotiation SCSV. Intersection with Go's defaults is
empty. No ECDHE, no GCM, no ChaCha20 anywhere in the offer.

Two things that shaped the fix:

- The client *does* negotiate TLS 1.2 (the `_CBC_SHA256` suites are TLS 1.2-only,
  and it fails at `pickCipherSuite`, not version negotiation). **Lowering
  `min_tls_version` would be wrong and would not help.**
- Only `TLS_RSA_WITH_AES_128_CBC_SHA` is needed. Go's preference order picks it
  first among the three RSA-kex CBC suites, so 3DES/RC4/DES stay off.

## Plan

- [x] `extra_cipher_suites` on `[server.tls]`, resolved in `ServerConfig.Validate`
- [x] Additive union with Go's secure defaults, never a substitution
- [x] Unknown names fail startup; enabled ones log a `Warn` at listener setup
- [x] Real-handshake tests: fails on defaults, succeeds when named, modern
      clients still get ECDHE
- [x] CLAUDE.md rationale

## Review

Files: `pkg/config/cipher_suites.go` (new), `pkg/config/cipher_suites_test.go`
(new), `pkg/config/types.go`, `pkg/config/config.go`,
`cmd/mizu-server/main.go`, `CLAUDE.md`.

Three facts verified in the source rather than assumed:

1. **Assigning `CipherSuites` is itself the mechanism.** `defaults.go` filters
   GODEBUG-disabled suites only on the nil path (`defaultCipherSuites`); an
   explicit list is filtered from `supportedCipherSuites` instead. So no
   process-wide `GODEBUG=tlsrsakex=1`.
2. **No downgrade risk.** `cipherSuitesPreferenceOrder` puts all ECDHE above all
   RSA-kex, and the server walks its own preference picking the first the client
   offers. Asserted by test, not just read.
3. **The RSA cert path works.** RSA-kex needs an RSA cert; the leader maintains
   both key types, and a hello with no ECDSA suite is how autocert selects
   `+rsa`. The SNI-less fallback in `manager.go` copies the hello and overrides
   only `ServerName`, so the cipher list survives into that decision.

`go build ./...` and `go test -race ./...` clean.

To deploy: `extra_cipher_suites = ["TLS_RSA_WITH_AES_128_CBC_SHA"]` on the
submission-587 `[server.tls]` block. Result for the appliance: TLS 1.2 +
AES-128-CBC-SHA + RSA cert.

Residual risk: no forward secrecy on that session, so its AUTH credentials
become decryptable if the RSA key later leaks. The appliance should have its own
credential, not a shared human one.

## Not done

Uncommitted — the working tree also carries in-progress
`fix/letsencrypt-renewal-leader-gate` edits to `cmd/mizu-server/main.go`,
`pkg/metrics/metrics.go` and `pkg/tls/manager.go`. These two changes need
separating before either is committed.
