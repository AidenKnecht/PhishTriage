"""Dataclasses shared across every phishtriage module.

Everything the tool learns about an email lives in one of these. They are plain
dataclasses so the JSON export is just ``dataclasses.asdict`` plus a little
cleanup (see :func:`to_jsonable`).
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


@dataclass(slots=True)
class Attachment:
    """One attachment as found in the MIME tree.

    ``data`` is kept in memory so the indicator stage can sniff magic bytes and
    inspect archives, but it is excluded from JSON output.
    """

    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    data: bytes = field(default=b"", repr=False, compare=False)


@dataclass(slots=True)
class EmailRecord:
    """The parsed email. Produced by :mod:`phishtriage.parser`.

    Header order matters for ``received_headers``: they are kept in the order
    they appear in the message, so index 0 is the *most recent* hop (the
    receiving server) and the last element is the origin.
    """

    source: str = ""
    message_id: str = ""
    date: datetime | None = None
    date_raw: str = ""
    from_display: str = ""
    from_addr: str = ""
    from_domain: str = ""
    reply_to_addr: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    to: list[str] = field(default_factory=list)
    subject: str = ""
    received_headers: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    raw_headers: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        """First raw value of a header, case-insensitive, or ``None``."""
        values = self.headers(name)
        return values[0] if values else None

    def headers(self, name: str) -> list[str]:
        """All raw values of a header, case-insensitive."""
        wanted = name.lower()
        for key, values in self.raw_headers.items():
            if key.lower() == wanted:
                return list(values)
        return []


class AuthStatus(StrEnum):
    """Normalised result of an authentication mechanism."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    POLICY = "policy"
    MISSING = "missing"


@dataclass(slots=True)
class AuthResult:
    """Result for one mechanism (spf / dkim / dmarc)."""

    mechanism: str
    status: AuthStatus = AuthStatus.MISSING
    domain: str = ""
    detail: str = ""
    source_header: str = ""


@dataclass(slots=True)
class AuthAnalysis:
    """Authentication results plus the alignment checks that matter more than they do."""

    spf: AuthResult = field(default_factory=lambda: AuthResult("spf"))
    dkim: AuthResult = field(default_factory=lambda: AuthResult("dkim"))
    dmarc: AuthResult = field(default_factory=lambda: AuthResult("dmarc"))
    dkim_signature_domains: list[str] = field(default_factory=list)
    spf_aligned: bool | None = None
    dkim_aligned: bool | None = None
    reply_to_mismatch: bool = False
    display_name_spoof: bool = False
    display_name_spoof_reason: str = ""
    no_auth_headers: bool = False
    live_dns_spf_authorized: bool | None = None
    live_dns_detail: str = ""
    flags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Hop:
    """One parsed ``Received:`` header."""

    from_host: str = ""
    from_ip: str = ""
    by_host: str = ""
    with_protocol: str = ""
    timestamp: datetime | None = None
    raw: str = ""
    flags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HopAnalysis:
    """Received chain, reversed so index 0 is the origin."""

    hops: list[Hop] = field(default_factory=list)
    first_external_ip: str = ""
    first_external_host: str = ""
    origin_country: str = ""
    timestamp_anomaly: bool = False
    private_ip_origin: bool = False
    reverse_dns_mismatch: bool = False
    flags: list[str] = field(default_factory=list)


class EnrichStatus(StrEnum):
    """What an enrichment source concluded about an indicator."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    NOT_CHECKED = "not checked"


@dataclass(slots=True)
class EnrichmentResult:
    """One lookup against one source."""

    source: str
    indicator: str
    status: EnrichStatus = EnrichStatus.NOT_CHECKED
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    cached: bool = False

    @property
    def summary(self) -> str:
        return f"{self.source}: {self.status}" + (f" ({self.detail})" if self.detail else "")


class IndicatorType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"


@dataclass(slots=True)
class Indicator:
    """A URL, domain, IP, or file hash pulled from the email."""

    type: IndicatorType
    value: str
    context: str = ""
    flags: list[str] = field(default_factory=list)
    details: dict[str, str] = field(default_factory=dict)
    enrichment: list[EnrichmentResult] = field(default_factory=list)


@dataclass(slots=True)
class AttachmentAnalysis:
    """Static (never detonated) findings for one attachment."""

    filename: str
    extension: str
    declared_mime: str
    magic_mime: str
    size: int
    sha256: str
    md5: str
    flags: list[str] = field(default_factory=list)
    details: dict[str, str] = field(default_factory=dict)
    enrichment: list[EnrichmentResult] = field(default_factory=list)


@dataclass(slots=True)
class LinkMismatch:
    """Visible link text that looks like one place but points at another."""

    text: str
    href: str
    reason: str


@dataclass(slots=True)
class IndicatorAnalysis:
    urls: list[Indicator] = field(default_factory=list)
    domains: list[Indicator] = field(default_factory=list)
    ips: list[Indicator] = field(default_factory=list)
    attachments: list[AttachmentAnalysis] = field(default_factory=list)
    link_mismatches: list[LinkMismatch] = field(default_factory=list)
    keyword_categories: dict[str, list[str]] = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)


class Verdict(StrEnum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_PHISH = "LIKELY PHISH"
    MALICIOUS = "MALICIOUS"


@dataclass(slots=True)
class FiredRule:
    id: str
    description: str
    weight: int
    category: str
    rationale: str
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScoreResult:
    score: int = 0
    raw_score: int = 0
    verdict: Verdict = Verdict.CLEAN
    fired: list[FiredRule] = field(default_factory=list)


@dataclass(slots=True)
class EnrichmentStats:
    lookups: int = 0
    cached: int = 0
    skipped: int = 0


@dataclass(slots=True)
class TriageResult:
    """Everything the report needs, in one place."""

    record: EmailRecord
    auth: AuthAnalysis
    hops: HopAnalysis
    indicators: IndicatorAnalysis
    score: ScoreResult
    enrichment_stats: EnrichmentStats = field(default_factory=EnrichmentStats)
    elapsed_seconds: float = 0.0
    offline: bool = False


def to_jsonable(obj: Any) -> Any:
    """Convert dataclasses (recursively) into JSON-serialisable primitives.

    Bytes fields are dropped, datetimes become ISO 8601 strings, enums become
    their values.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            value = getattr(obj, f.name)
            if isinstance(value, bytes | bytearray):
                continue
            out[f.name] = to_jsonable(value)
        return out
    if isinstance(obj, StrEnum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple | set):
        return [to_jsonable(v) for v in obj]
    return obj
