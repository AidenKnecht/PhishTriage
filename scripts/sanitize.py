"""Sanitise real .eml exports so they can be committed to ``samples/``.

What it does, byte-preserving everywhere else:

- Replaces the real recipient address(es) with ``analyst@example.com`` in every
  header and in the body text/HTML.
- Replaces the recipient's display name, if given, with ``Analyst``.
- Rewrites tracking tokens: long opaque query-string values and path segments
  (hex, base64-ish, UUIDs of 16+ characters) become ``REDACTED``.
- Strips headers that leak the mailbox owner or infrastructure secrets
  (``X-Original-To``, ``Delivered-To``, ``X-Received``, ``X-Google-*`` bodies
  are kept, but ``Received: ... for <real address>`` is rewritten).

It does NOT touch sender addresses, URLs' hosts, or attachments: those are the
evidence. Review every file by hand before committing anyway.

Usage:
    uv run python scripts/sanitize.py --recipient you@real.example [--name "Your Name"] \
        --out samples/phish path/to/*.eml
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PLACEHOLDER = "analyst@example.com"
PLACEHOLDER_NAME = "Analyst"

# Opaque tokens in query strings and path segments (hex / base64url / uuid-ish).
_QUERY_TOKEN = re.compile(rb"([?&](?:[A-Za-z0-9_\-\.]+)=)([A-Za-z0-9_\-%\.~+/]{16,})")
_PATH_TOKEN = re.compile(rb"(/)([A-Za-z0-9_\-]{24,})(?=[/?\s\"'<>)]|$)")
_URL_SPAN = re.compile(rb"https?://[^\s\"'<>]+", re.IGNORECASE)
_DROP_HEADERS = (b"x-original-to", b"delivered-to", b"x-envelope-to", b"x-rcpt-to")


def sanitize(raw: bytes, recipient: str, name: str | None = None) -> bytes:
    recipient_b = recipient.encode()
    out = raw

    # Address in any encoding variant that shows up in headers and bodies.
    variants = {recipient_b, recipient_b.lower(), recipient_b.upper()}
    variants.add(recipient_b.replace(b"@", b"%40"))
    variants.add(recipient_b.replace(b"@", b"=40"))
    for v in sorted(variants, key=len, reverse=True):
        out = re.sub(re.escape(v), PLACEHOLDER.encode(), out, flags=re.IGNORECASE)
    if name:
        out = re.sub(re.escape(name.encode()), PLACEHOLDER_NAME.encode(), out, flags=re.IGNORECASE)

    # Drop headers that only exist to name the real mailbox.
    head, sep, body = out.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = out.partition(b"\n\n")
    if sep:
        lines = re.split(rb"\r?\n", head)
        kept: list[bytes] = []
        skipping = False
        for line in lines:
            if line[:1] in (b" ", b"\t") and skipping:
                continue
            skipping = any(line.lower().startswith(h + b":") for h in _DROP_HEADERS)
            if not skipping:
                kept.append(line)
        head = b"\n".join(kept)
        out = head + sep + body

    # Only rewrite tokens inside URLs; header encoded-words and base64 bodies
    # look token-like but must stay byte-exact.
    def _redact_url(m: re.Match[bytes]) -> bytes:
        url = _QUERY_TOKEN.sub(rb"\1REDACTED", m.group(0))
        return _PATH_TOKEN.sub(rb"\1REDACTED", url)

    return _URL_SPAN.sub(_redact_url, out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--recipient", required=True, help="Your real address to replace.")
    ap.add_argument("--name", help="Your display name to replace, if it appears.")
    ap.add_argument(
        "--out", required=True, type=Path, help="Directory to write sanitised files into."
    )
    ap.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    for path in args.files:
        raw = path.read_bytes()
        cleaned = sanitize(raw, args.recipient, args.name)
        target = args.out / path.name
        target.write_bytes(cleaned)
        leftover = args.recipient.lower().encode() in cleaned.lower()
        status = "STILL CONTAINS RECIPIENT" if leftover else "ok"
        print(f"{path} -> {target} [{status}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
