# Authenticated mail refused for an unquoted `@` in the From display name

**Date:** 2026-10-15
**Affected:** authenticated submission (465/587), messages whose `From` display
name holds an unquoted RFC 5322 special (`@ , ; : [ ] ( ) . "`)
**Introduced by:** 69ff9ef, "smtp: authorize the header From of authenticated
mail, not only the envelope"
**Fixed by:** 6a3ddb5, a88e0b9, 872502b (branch `fix/header-from-unquoted-name`)

---

## The failing case

A customer's script sent mail that had been delivered for years. On
2026-10-15 the message was refused at DATA:

```
=== REJECTED (2026-10-15 17:04:38 UTC) ===
From: Alfred @ Wear Zoor <alfred@wearzoor.com>
To: <recipient redacted>
Subject: <redacted>
Date: Thu, 15 Oct 2026 10:04:38 -0700
In-Reply-To: <...@...PROD.OUTLOOK.COM>
MIME-Version: 1.0
Content-Type: multipart/alternative

SMTP: smtp.migadu.com:465 (implicit TLS)
AUTH alfred@wearzoor.com (accepted)
MAIL FROM:<alfred@wearzoor.com>
RCPT TO:<recipient redacted>
RCPT TO:<BCC to own domain>
DATA -> 550 5.7.1 sender address rejected: not allowed
```

The same login, envelope sender, BCC and `From` header had been accepted that
morning:

```
=== LAST SUCCESSFUL (2026-10-15 06:43:23 UTC) ===
Message-ID: <179204660351.2856796.8451648530421897736@wearzoor.com>
From: Alfred @ Wear Zoor <alfred@wearzoor.com>
Same AUTH, MAIL FROM and BCC -> 250 accepted
```

Nothing in the customer's setup changed between the two messages. 69ff9ef was
deployed in between.

A 5xx at DATA is permanent and a script does not retry it, so the message was
lost, not delayed. No bounce and no stored copy exist.

## Why it failed

69ff9ef started checking the header `From` (and `Sender`) of authenticated
mail: every address in it must be one the login may send as
(`allowed_from`, via `ResolveSender`). Before that commit Mizu checked only
MAIL FROM and never looked at the header.

To find the addresses, the check parsed the header with Go's `net/mail`, which
follows RFC 5322 strictly. In RFC 5322 a display name is a `phrase`: atoms and
quoted strings. `@` is one of the `specials` (§3.2.3), so it cannot appear in
an atom:

```
Alfred @ Wear Zoor <alfred@wearzoor.com>     invalid: "@" unquoted in the name
"Alfred @ Wear Zoor" <alfred@wearzoor.com>   valid
```

`net/mail` fails the first form with `missing '@' or angle-addr`. The check
treated any parse failure as a refusal and answered with the same reply it
gives an unauthorized address, `550 5.7.1 sender address rejected: not
allowed`. That sent the customer looking for a permission problem they did not
have: `alfred@wearzoor.com` was their own address and also the envelope sender.

Unquoted commas (`Zoor, Alfred <a@b>`), semicolons, square brackets and raw
8-bit names fail the same way. These headers are hand-built: the successful
message's Message-ID has Python's `email.utils.make_msgid` shape, and
`email.utils.formataddr` would have quoted the name. Receivers have always
taken the address in angle brackets, which is why the flow worked until the
check existed.

## How it was fixed

**6a3ddb5: log the raw header.** The reject log carried only `from`, which is
the envelope sender, so a rejected `From` header was invisible in the logs. The
header is now logged as `value`, cut to 256 bytes.

**a88e0b9: a malformed header is 5.6.0, not 5.7.1.** A header that does not
parse now gets `550 5.6.0 malformed From header: not a valid address; a display
name holding specials or an @ must be quoted`. An unauthorized address keeps
`550 5.7.1 sender address rejected: not allowed`. A second `From` header is
5.6.0 as well.

**872502b: accept an unquoted display name.** `parseHeaderAddresses`
(`pkg/smtp/server.go`) tries the strict parse first. If that fails, it parses
the header again from the first `<`, dropping the display name, and authorizes
the address it finds. Only the address is authorized, so the name's syntax is
not a security question, with one exception: a name that could itself be read
as an address. If the dropped name holds a word with text on both sides of an
`@` (`ceo@big.example <me@mine.example>`), the header stays malformed. A
lenient receiver could take that word as a second sender that Mizu never
authorized.

Result for the failing case:

```
From: Alfred @ Wear Zoor <alfred@wearzoor.com>
  strict parse   -> fails ("missing '@' or angle-addr")
  dropped name   -> "Alfred @ Wear Zoor ": no word has text on both sides of '@'
  retry parse    -> <alfred@wearzoor.com>
  ResolveSender  -> allowed (own address)
  verdict        -> accepted
```

On production submission (465 and 587, `inventory/group_vars/mizu_out/vars.yml`)
`missing_headers_action` is `fix`, so a message that also lacks a `Message-ID`
gets one added rather than being refused by the next check.

### Behaviour after the fix

| Header `From:` | Reply |
|---|---|
| `Alfred @ Wear Zoor <own@address>` | accepted |
| `Zoor, Alfred <own@address>` | accepted |
| `Alfred [Wear Zoor] <own@address>` | accepted |
| `Jos\xe9 Zoor <own@address>` (raw 8-bit) | accepted |
| `"Alfred @ Wear Zoor" <own@address>` | accepted (strict parse, unchanged) |
| `Zoor, Alfred <other@address>` | 550 5.7.1 not allowed |
| `ceo@big.example <own@address>` | 550 5.6.0 malformed |
| `own@address <own@address>` | 550 5.6.0 malformed (see Open items) |
| `Zoor, Alfred <own@address> Ltd` | 550 5.6.0 malformed |
| `alfred` (no address at all) | 550 5.6.0 malformed |
| two `From` headers | 550 5.6.0 malformed |

These are the cases in `TestValidateHeaders_AuthenticatedFromReplyCodes`
(`pkg/smtp/header_from_auth_test.go`). The failing case is `lone at sign`.

## Workaround

Until the fix is deployed, quote the display name:

```
From: "Alfred @ Wear Zoor" <alfred@wearzoor.com>
```

In Python, build the header with `email.utils.formataddr(("Alfred @ Wear Zoor",
"alfred@wearzoor.com"))`, which quotes the name when it has to.

## Open items

- **The `@`-word guard can be bypassed.** RFC 5322 allows whitespace and
  comments around the `@` of an address (§3.2.3, §3.4.1, §4.4), so
  `ceo @ big.example, Bob <me@mine.example>` is a *valid* header with two
  authors. `net/mail` rejects whitespace before an `@`, the fallback drops
  everything before `<`, and only `me@mine.example` is authorized.
  `ceo@ big.example <me@mine.example>` and a non-breaking space before the `@`
  get through the same way. The proposed fix removes whitespace from the
  dropped name and refuses it when any `@` is followed by a dotted domain or a
  domain literal. That still accepts the failing case above, whose `@` is
  followed by the single label `Wear`.
- **`own@address <own@address>` is still refused.** Some scripts use the
  address as its own display name. A receiver that picks either reading gets
  the same, authorized address, so it could be exempted.
- **The header is not required to match MAIL FROM.** By design (see CLAUDE.md),
  envelope and header must each be authorized, not equal, to allow VERP and
  aliases.

## Finding these in the logs

Rejections log `Rejecting message - unparseable From header` (5.6.0) or
`Rejecting message - From header address not allowed` (5.7.1), with the login
as `user`, the envelope sender as `from` and the raw header as `value`.
