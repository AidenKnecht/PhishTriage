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
