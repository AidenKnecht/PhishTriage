# Decisions

Choices that weren't spelled out in `CLAUDE.md`, and why. Newest at the bottom.

## Tooling

- **`pyyaml` added as a dependency.** `rules/scoring.yaml` and the requirement that "rules are data, not code" need a YAML reader; the stdlib has none. `pyyaml` is the boring, ubiquitous choice and is loaded with `safe_load` only.
- **`dnspython` is an optional extra (`uv sync --extra dns`) and a dev dependency.** It is only used under `--live-dns`. Keeping it optional means the default install has no DNS resolver dependency, and the tool still runs when it is absent (`--live-dns` then reports "dnspython not installed"). It is in the dev group so the DNS code paths can be unit-tested with a mocked resolver.
- **No `filetype` library.** Magic-byte detection is hand-rolled for the dozen types an analyst actually cares about (PE, ELF, Mach-O, PDF, ZIP/OOXML, OLE2, RTF, ISO, LNK, gzip, 7z, RAR, PNG/JPEG/GIF, HTML). Fewer deps, and the list of what we sniff is readable in one screen.
- **ruff config is strict-ish**: `E, F, I, UP, B, SIM, ANN, RUF` with `ANN` disabled for tests and scripts. Type hints are mandatory in `src/` and enforced by lint, not just convention.
- **Python 3.12 is the pinned dev interpreter** (`uv sync --python 3.12`); `requires-python` stays `>=3.11` and CI runs both. `StrEnum` (3.11+) is used for enums so JSON export is trivial.

## Parsing

- **Two parses per message.** The email is parsed once with `email.policy.default` (decoded, RFC 2047-aware header values) and once with `compat32` (raw, folded values preserving duplicates). The strict parse can raise on pathological headers when a value is *accessed*, so every access goes through a getter that falls back to the raw value and records a warning. This is what makes "never crash on a bad email" true in practice.
- **`received_headers` are kept in message order** (index 0 = most recent hop). `hops.py` reverses them into origin-first order; the parser doesn't guess.
- **Attachment classification:** a part is an attachment if `Content-Disposition: attachment`, or if it has a filename and is not `text/*`. Inline images therefore count as attachments (they get hashed), which is what you want when someone embeds an `.html` "image". Text parts with a filename are treated as body text, not attachments, because plenty of legitimate mailers name their text parts.
- **Attachment bytes stay in memory** on `Attachment.data` so `indicators.py` can sniff magic bytes and inspect ZIP headers without re-parsing. `to_jsonable` drops bytes fields so JSON export stays small.
- **Address normalisation:** all addresses are lowercased. Display names have surrounding quotes stripped. When `parseaddr` can't cope (e.g. two angle-addresses in one `From:`), we take the first angle-address and record a warning; the auth stage treats that warning as a spoofing signal.
- **Date parsing** tries `parsedate_to_datetime`, then strips `(comments)` and trailing junk and retries. Genuinely unparseable dates yield `date=None` plus a warning; the raw string is kept on `date_raw` for the report.

## Authentication and alignment

- **Organisational domain is hand-rolled.** Relaxed alignment needs "same org" matching (`bounce.mail.example.net` aligns with `example.net`). Shipping the full Public Suffix List is overkill for a triage tool, so `rulesdata.organizational_domain` takes the last two labels unless the suffix is in a short list of two-label public suffixes (`co.uk`, `com.au`, ...). Wrong answers are possible for exotic TLDs; they would show up as a false "misaligned" flag, which is the safe direction.
- **Result precedence:** `Authentication-Results` first, then `ARC-Authentication-Results` (forwarded mail), then `Received-SPF` for SPF only. When several DKIM results exist, a `pass` wins because multi-signature mail is common and a failing second signature is noise.
- **"missing" vs "none":** if *no* results headers exist at all, every mechanism is `missing` and `no_auth_headers` is set (this is the internal-mail calibration case). If a results header exists but is silent about a mechanism, that mechanism is `none`. A `DKIM-Signature` with no verification result is also `none` but its `d=` domain is still used for alignment.
- **SPF alignment uses `Return-Path`** when present, falling back to `smtp.mailfrom` from the results header. DKIM alignment passes if *any* signature domain aligns with `From`.
- **Display-name spoofing** fires on three things: the display name contains an email address at a different org than the sender; the display name contains a brand from `rules/brands.txt` and the sender's domain isn't one of that brand's legitimate domains; or the raw `From:` header contains more than one address (the stdlib parser silently keeps only the first, so this is checked on the raw header). Brand matching is bounded by non-alphanumerics so "ups" does not fire on "Groups".
- **`rules/brands.txt` format** is `brand: domain1 domain2 ...` with the domain list optional. A brand with no domains is legitimate when the brand name appears in the sender's org domain. The domain list is what stops "Microsoft" from `@office.com` being flagged.
- **`--live-dns` SPF evaluation is deliberately minimal**: `ip4/ip6/a/mx/include/redirect/all` with a recursion cap of 10. `exists` and `ptr` never match. It is an analyst aid, not a replacement for the receiving MX's verdict, and it is fully mockable through an injected resolver callable.

## Hop analysis

- **RFC 5737 documentation ranges are treated as public.** Python's `ipaddress` marks `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` as private, which would make every synthetic sample look like it came from a private origin. `hops.is_private_ip` uses an explicit list (RFC 1918, loopback, link-local, CGNAT, multicast, class E, IPv6 ULA/link-local) instead.
- **The "boundary hop" is what gets scored.** Sender-side internal relays with `10.x` addresses are normal (Gmail does it); recipient-side internal relays are too. The private-IP rule fires only on the first hop received *by* the recipient's own infrastructure (matched against the `To:` domain, or the `for <...>` clause when `To:` is missing), i.e. the point where the sender's claims stop being under the sender's control. Other private IPs get an informational hop flag only.
- **Timestamp anomalies** tolerate 5 minutes of backwards skew (real servers drift) and flag forward jumps over 24 hours. Hops without a parseable date are skipped, not flagged.
- **Comments are blanked before matching** `from`/`by`/`with`, so `(qmail 123 invoked from network)` does not produce a hop from host `network`.
- **Origin country is filled in by the enrichment stage** (RDAP), not by `hops.py`, so the hop parser stays offline-pure.

## Indicators and attachments

- **Flags are stable identifiers, not prose.** Every URL/domain/attachment flag is a short token (`shortener`, `raw_ip_url`, `lookalike_domain`, `double_extension`, `macro_enabled`, ...) with the human explanation stored alongside in `details`. `rules/scoring.yaml` references flags by token, which is what lets a rule be "data, not code".
- **Lookalike detection has three tiers**, checked in order against `rules/brands.txt`: (1) the brand name appears as or inside a hostname token (`paypal-secure.example`, `login.microsoft.example`); (2) the same after folding common homoglyphs (`0→o`, `1→l`, `rn→m`, `vv→w`), which catches `micr0soft-login.example`; (3) Levenshtein distance ≤ 1 (≤ 2 for brands longer than six characters) between the registrable label and the brand or any of its legitimate domains, which catches `micosoft.com`. Brands shorter than four characters (`ups`) only match as a whole token, so `groups.example` is fine. Any host the brand file lists as legitimate is skipped before all three tiers.
- **Link-text mismatch** fires when the visible anchor text is itself URL/domain-shaped and its org domain differs from the `href`, or when the text names a brand and the `href` is not one of that brand's domains. "Click here" pointing anywhere is not a mismatch; that is what the lookalike and enrichment rules are for.
- **Defanging replaces every dot**, not just the host's (`hxxps://evil[.]example/login[.]php`). It is a little noisier but guarantees nothing in a pasted report is clickable.
- **Domain indicators include the sender and Reply-To domains**, so a lookalike in `From:` is caught even when the body has no links.
- **File-hosting domains are a weak signal** (`rules/filehosts.txt`). Real Dropbox/OneDrive links are everywhere in legitimate mail, so the scoring weight is small; the flag mostly exists so an analyst sees it in the indicators table.
- **Attachment magic sniffing is hand-rolled** for PE, ELF, Mach-O, PDF, ZIP (and OOXML/JAR by extension), OLE2, RTF, gzip, 7z, RAR, PNG/JPEG/GIF, ISO 9660, Windows `.lnk`, and HTML/XML. `mime_mismatch` fires only when the extension implies a type *and* the bytes say something else; declared `Content-Type` disagreements are recorded in `details` but not scored, because mail clients get `Content-Type` wrong constantly.
- **Double extension** fires when a dangerous extension follows any other (`invoice.pdf.exe`), when a document extension is followed by a non-document one, or when the real extension is padded away with runs of spaces. `archive.tar.gz` is not a double extension.
- **ZIP inspection is metadata only**: the central directory is read to detect the encryption bit (password-protected archive), `vbaProject.bin` (macros inside an OOXML file with a harmless extension), and executable inner filenames. Nothing is extracted. RAR/7z encryption is not detected; they just get the `archive` flag.
- **Keyword matching is per category** (`rules/keywords.txt` uses `[section]` headers). One hit in a category is as good as ten, so a long invoice email doesn't rack up points for saying "invoice" repeatedly.
