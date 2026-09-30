"""Sanitise real .eml exports so they can be committed to ``samples/``.

What it does, byte-preserving everywhere else:

- Replaces the real recipient address(es) with ``analyst@example.com`` in every
  header and in the body text/HTML.
- Replaces the recipient's display name, if given, with ``Analyst``.
- Applies any ``--replace OLD=NEW`` pairs (case-insensitive) everywhere, e.g.
  to pseudonymise a third party whose account sent the mail.
- Rewrites tracking tokens: long opaque query-string values and path segments
  (hex, base64-ish, UUIDs of 16+ characters) become ``REDACTED``.
- Strips headers that leak the mailbox owner or infrastructure secrets
  (``X-Original-To``, ``Delivered-To``, ``X-Received``, ``X-Google-*`` bodies
  are kept, but ``Received: ... for <real address>`` is rewritten).

Quoted-printable and base64 text parts are decoded before redaction and
re-encoded afterwards; otherwise a soft line break (``=`` at end of line) or
``=3D`` inside a URL hides the token from every pattern.

It does NOT touch sender addresses, URLs' hosts, or attachments: those are the
evidence. Review every file by hand before committing anyway.

Usage:
    uv run python scripts/sanitize.py --recipient you@real.example [--name "Your Name"] \
        [--replace "Real Sender=Pseudonym" ...] --out samples/phish path/to/*.eml
"""

from __future__ import annotations

import argparse
import base64
import email
import quopri
import re
import sys
from email import policy
from pathlib import Path

PLACEHOLDER = "analyst@example.com"
PLACEHOLDER_NAME = "Analyst"

# Opaque tokens in query strings and path segments (hex / base64url / uuid-ish).
# ``;`` as a separator catches ``&amp;tok=`` inside HTML attributes; the name is
# optional for bare ``open.aspx?TOKEN.123`` open-tracking pixels.
_QUERY_TOKEN = re.compile(rb"([?&;](?:[A-Za-z0-9_\-\.]+=)?)([A-Za-z0-9_\-%\.~+/]{16,})")
_PATH_TOKEN = re.compile(rb"(/)([A-Za-z0-9_\-]{24,})(?=[/?\s\"'<>)]|$)")
_URL_SPAN = re.compile(rb"https?://[^\s\"'<>]+", re.IGNORECASE)
_DROP_HEADERS = (b"x-original-to", b"delivered-to", b"x-envelope-to", b"x-rcpt-to")


def _replacements(
    recipient: str, name: str | None, replace: dict[str, str] | None
) -> list[tuple[bytes, bytes]]:
    recipient_b = recipient.encode()
    variants = {recipient_b, recipient_b.replace(b"@", b"%40"), recipient_b.replace(b"@", b"=40")}
    pairs = [(v, PLACEHOLDER.encode()) for v in variants]
    if name:
        pairs.append((name.encode(), PLACEHOLDER_NAME.encode()))
    for old, new in (replace or {}).items():
        pairs.append((old.encode(), new.encode()))
    # Longest first so "Doe, Jane (jdoe)" wins over "jdoe".
    return sorted(pairs, key=lambda p: len(p[0]), reverse=True)


def _redact(data: bytes, pairs: list[tuple[bytes, bytes]]) -> bytes:
    for old, new in pairs:
        data = re.sub(re.escape(old), new.replace(b"\\", b"\\\\"), data, flags=re.IGNORECASE)

    # Only rewrite tokens inside URLs; header encoded-words and base64 bodies
    # look token-like but must stay byte-exact.
    def _redact_url(m: re.Match[bytes]) -> bytes:
        url = _QUERY_TOKEN.sub(rb"\1REDACTED", m.group(0))
        return _PATH_TOKEN.sub(rb"\1REDACTED", url)

    return _URL_SPAN.sub(_redact_url, data)


def _encoded_parts(raw: bytes, pairs: list[tuple[bytes, bytes]]) -> bytes:
    """Decode each QP/base64 text part, redact it, and splice it back in place."""
    msg = email.message_from_bytes(raw, policy=policy.compat32)
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    for part in msg.walk():
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()
        if cte not in ("quoted-printable", "base64"):
            continue
        payload = part.get_payload(decode=False)
        if not isinstance(payload, str):
            continue
        original = payload.encode("ascii", "surrogateescape")
        original = re.sub(rb"\r?\n", newline, original)
        decoded = part.get_payload(decode=True) or b""
        cleaned = _redact(decoded, pairs)
        if cleaned == decoded or original not in raw:
            continue
        encode = base64.encodebytes if cte == "base64" else quopri.encodestring
        encoded = re.sub(rb"\r?\n", newline, encode(cleaned))
        if original.endswith(newline) and not encoded.endswith(newline):
            encoded += newline
        raw = raw.replace(original, encoded, 1)
    return raw


def sanitize(
    raw: bytes,
    recipient: str,
    name: str | None = None,
    replace: dict[str, str] | None = None,
) -> bytes:
    pairs = _replacements(recipient, name, replace)
    out = _encoded_parts(raw, pairs)

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

    # Headers and unencoded (7bit/8bit) bodies.
    return _redact(out, pairs)


def _pair(value: str) -> tuple[str, str]:
    old, sep, new = value.partition("=")
    if not sep or not old:
        raise argparse.ArgumentTypeError(f"expected OLD=NEW, got {value!r}")
    return old, new


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--recipient", required=True, help="Your real address to replace.")
    ap.add_argument("--name", help="Your display name to replace, if it appears.")
    ap.add_argument(
        "--replace",
        type=_pair,
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="Extra case-insensitive replacement; repeatable.",
    )
    ap.add_argument(
        "--out", required=True, type=Path, help="Directory to write sanitised files into."
    )
    ap.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args(argv)

    replace = dict(args.replace)
    args.out.mkdir(parents=True, exist_ok=True)
    for path in args.files:
        raw = path.read_bytes()
        cleaned = sanitize(raw, args.recipient, args.name, replace)
        target = args.out / path.name
        target.write_bytes(cleaned)
        lowered = cleaned.lower()
        leftovers = [s for s in (args.recipient, *replace) if s.lower().encode() in lowered]
        status = f"STILL CONTAINS {', '.join(leftovers)}" if leftovers else "ok"
        print(f"{path} -> {target} [{status}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
