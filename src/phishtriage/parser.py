"""Turn a raw ``.eml`` file into an :class:`~phishtriage.models.EmailRecord`.

Design rule: never crash on a bad email. Every header access is wrapped so a
malformed value degrades to a raw string (or empty) and appends a warning to
the record instead of raising.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from collections.abc import Iterable
from datetime import datetime
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path

from phishtriage.models import Attachment, EmailRecord

_ANGLE_ADDR = re.compile(r"<([^<>]+)>")
_BARE_ADDR = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+", re.IGNORECASE)


def parse_file(path: str | Path) -> EmailRecord:
    """Parse an ``.eml`` on disk."""
    path = Path(path)
    raw = path.read_bytes()
    record = parse_bytes(raw)
    record.source = str(path)
    return record


def parse_bytes(raw: bytes) -> EmailRecord:
    """Parse raw RFC 5322 bytes."""
    record = EmailRecord()

    # Strict-ish policy for decoded values; compat32 for the raw header dump.
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:  # pragma: no cover - the stdlib parser is very forgiving
        record.warnings.append(f"parser: could not parse message with default policy ({exc})")
        msg = None
    try:
        raw_msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as exc:  # pragma: no cover
        record.warnings.append(f"parser: could not parse message with compat32 policy ({exc})")
        raw_msg = None

    if raw_msg is not None:
        record.raw_headers = _raw_headers(raw_msg)
    if msg is None and raw_msg is None:
        record.warnings.append("parser: message is unparseable; record is empty")
        return record

    getter = _HeaderGetter(msg, raw_msg, record)

    record.message_id = getter.get("Message-ID").strip()
    record.subject = getter.get("Subject").strip()
    record.date_raw = getter.get("Date").strip()
    record.date = _parse_date(record.date_raw, record)

    from_raw = getter.get("From")
    record.from_display, record.from_addr = _split_address(from_raw, record, "From")
    record.from_domain = _domain_of(record.from_addr)

    reply_raw = getter.get("Reply-To")
    _, record.reply_to_addr = _split_address(reply_raw, record, "Reply-To")
    record.reply_to_domain = _domain_of(record.reply_to_addr)

    return_raw = getter.get("Return-Path")
    record.return_path = _extract_addr(return_raw)
    record.return_path_domain = _domain_of(record.return_path)

    record.to = _address_list(getter.get_all("To") + getter.get_all("Cc"))

    record.received_headers = [_unfold(v) for v in getter.get_all("Received")]
    record.authentication_results = [_unfold(v) for v in getter.get_all("Authentication-Results")]

    if not record.message_id:
        record.warnings.append("parser: missing Message-ID")
    if not record.from_addr:
        record.warnings.append("parser: missing or unparseable From address")
    if not record.date_raw:
        record.warnings.append("parser: missing Date header")

    body_msg: Message | None = msg if msg is not None else raw_msg
    if body_msg is not None:
        _walk_body(body_msg, record)
    return record


class _HeaderGetter:
    """Read a header from the strict message, falling back to the raw one."""

    def __init__(
        self, msg: EmailMessage | None, raw_msg: Message | None, record: EmailRecord
    ) -> None:
        self.msg = msg
        self.raw_msg = raw_msg
        self.record = record

    def get(self, name: str) -> str:
        values = self.get_all(name)
        return values[0] if values else ""

    def get_all(self, name: str) -> list[str]:
        if self.msg is not None:
            try:
                values = self.msg.get_all(name) or []
                return [str(v) for v in values]
            except Exception as exc:
                self.record.warnings.append(f"parser: header {name} malformed ({exc}); using raw")
        if self.raw_msg is not None:
            values = self.raw_msg.get_all(name) or []
            return [_decode_rfc2047(str(v)) for v in values]
        return []


def _raw_headers(raw_msg: Message) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key, value in raw_msg.items():
        out.setdefault(key, []).append(_unfold(str(value)))
    return out


def _unfold(value: str) -> str:
    return re.sub(r"\r?\n[ \t]+", " ", value).strip()


def _decode_rfc2047(value: str) -> str:
    """Decode ``=?utf-8?b?...?=`` words, tolerating junk."""
    if "=?" not in value:
        return value
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _parse_date(value: str, record: EmailRecord) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except Exception:
        pass
    # Common malformations: missing weekday/comma, extra text, "(UTC)" comments.
    cleaned = re.sub(r"\([^)]*\)", "", value).strip()
    for candidate in (cleaned, cleaned.rsplit(" ", 1)[0]):
        try:
            return parsedate_to_datetime(candidate)
        except Exception:
            continue
    record.warnings.append(f"parser: unparseable Date header: {value!r}")
    return None


def _split_address(value: str, record: EmailRecord, header: str) -> tuple[str, str]:
    """Return ``(display_name, addr)`` from a From/Reply-To style header."""
    if not value:
        return "", ""
    value = _decode_rfc2047(value)
    display, addr = parseaddr(value)
    if not addr or "@" not in addr:
        # parseaddr gives up on things like 'Name <a@b> <c@d>' or spaces in the addr.
        addr = _extract_addr(value)
        if addr:
            display = value.split("<", 1)[0].strip().strip('"')
            record.warnings.append(f"parser: {header} header is non-standard: {value!r}")
        else:
            record.warnings.append(f"parser: no address found in {header}: {value!r}")
            return value.strip(), ""
    return display.strip().strip('"'), addr.strip().lower()


def _extract_addr(value: str) -> str:
    if not value:
        return ""
    m = _ANGLE_ADDR.search(value)
    if m:
        inner = m.group(1).strip()
        return inner.lower() if "@" in inner else ""
    m = _BARE_ADDR.search(value)
    return m.group(0).lower() if m else ""


def _address_list(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    try:
        pairs = getaddresses([_decode_rfc2047(v) for v in values])
    except Exception:
        pairs = []
    for _, addr in pairs:
        addr = addr.strip().lower()
        if addr and "@" in addr and addr not in out:
            out.append(addr)
    return out


def _domain_of(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().lower().rstrip(".")


def _walk_body(msg: Message, record: EmailRecord) -> None:
    texts: list[str] = []
    htmls: list[str] = []
    for part in msg.walk():
        try:
            if part.is_multipart():
                continue
            disposition = (part.get_content_disposition() or "").lower()
            filename = _part_filename(part)
            ctype = (part.get_content_type() or "application/octet-stream").lower()
            payload = _decoded_payload(part, record)

            is_attachment = disposition == "attachment" or bool(
                filename and not ctype.startswith("text/")
            )
            if is_attachment:
                record.attachments.append(_make_attachment(filename, ctype, payload))
                continue

            if ctype == "text/plain":
                texts.append(_decode_text(part, payload))
            elif ctype == "text/html":
                htmls.append(_decode_text(part, payload))
            elif filename:
                record.attachments.append(_make_attachment(filename, ctype, payload))
        except Exception as exc:
            record.warnings.append(f"parser: failed to process MIME part ({exc})")
    record.body_text = "\n".join(t for t in texts if t)
    record.body_html = "\n".join(h for h in htmls if h)


def _part_filename(part: Message) -> str:
    try:
        name = part.get_filename()
    except Exception:
        name = None
    if not name:
        # Some senders put the name only in Content-Type name=...
        try:
            name = part.get_param("name")
        except Exception:
            name = None
    if isinstance(name, tuple):  # RFC 2231 encoded triple
        name = name[2]
    return _decode_rfc2047(str(name)).strip() if name else ""


def _decoded_payload(part: Message, record: EmailRecord) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception as exc:
        record.warnings.append(f"parser: could not decode part payload ({exc})")
        payload = None
    if payload is None:
        raw = part.get_payload()
        payload = raw.encode("utf-8", "replace") if isinstance(raw, str) else b""
    return payload


def _decode_text(part: Message, payload: bytes) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _make_attachment(filename: str, ctype: str, payload: bytes) -> Attachment:
    return Attachment(
        filename=filename or "(unnamed)",
        content_type=ctype,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        md5=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        data=payload,
    )
