"""Parse the ``Received:`` chain and look for things that don't add up.

Headers are prepended as mail moves, so the top ``Received:`` is the last hop.
We reverse them so the chain reads origin -> destination, the way an analyst
walks it. The interesting hop is the *boundary*: the first one received by
the recipient's own infrastructure, because that is where the sender's claims
stop being under the sender's control.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime

from phishtriage.models import EmailRecord, Hop, HopAnalysis
from phishtriage.rulesdata import organizational_domain, same_org

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:.])(?:IPv6:)?([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:])")
_FROM = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_TRAILING_COMMENTS = re.compile(r"^(?:\s*\([^()]*\))*")
_BY = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_WITH = re.compile(r"\bwith\s+(\S+)", re.IGNORECASE)
_FOR = re.compile(r"\bfor\s+<?([\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+)>?", re.IGNORECASE)
_COMMENT = re.compile(r"\([^()]*\)")

BACKWARDS_TOLERANCE = timedelta(minutes=5)
"""Clock skew between real servers is common; only flag bigger reversals."""
FORWARD_JUMP = timedelta(hours=24)

# RFC 5737 documentation ranges are *not* treated as private, because the
# sample corpus uses them as stand-ins for public addresses. See DECISIONS.md.
_PRIVATE_V4 = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
]
_PRIVATE_V6 = [
    ipaddress.ip_network(n) for n in ("::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")
]

PtrResolver = Callable[[str], list[str]]
"""``resolver(ip) -> [hostnames]``; injectable for tests."""


def is_private_ip(ip: str) -> bool:
    """True for RFC 1918, loopback, link-local, CGNAT, multicast and reserved space."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 4:
        return any(addr in net for net in _PRIVATE_V4)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return is_private_ip(str(addr.ipv4_mapped))
    return any(addr in net for net in _PRIVATE_V6)


def parse_received(header: str) -> Hop:
    """Parse a single unfolded ``Received:`` value. Never raises."""
    hop = Hop(raw=header.strip())
    head, _, tail = header.rpartition(";")
    if tail.strip():
        hop.timestamp = _parse_date(tail.strip())
    if hop.timestamp is None:
        head = header  # no usable date part; scan the whole thing

    # Blank out comments (keeping offsets) so "(invoked from network)" can't match.
    blanked = _COMMENT.sub(lambda c: " " * len(c.group(0)), head)
    m = _FROM.search(blanked)
    if m:
        host = m.group(1)
        trailing = _TRAILING_COMMENTS.match(head[m.end() :])
        comments = trailing.group(0) if trailing else ""
        host = host.strip("(),;")
        if host.startswith("[") and host.endswith("]"):
            hop.from_ip = _first_ip(host)
            hop.from_host = ""
        else:
            hop.from_host = host.lower()
        if not hop.from_ip:
            hop.from_ip = _first_ip(comments) or _first_ip(host)
        if not hop.from_host and comments:
            # "from [1.2.3.4] (host.example [1.2.3.4])" -> host.example
            inner = _COMMENT.search(comments)
            if inner:
                candidate = (
                    inner.group(0).strip("()").split()[0] if inner.group(0).strip("()") else ""
                )
                if candidate and not candidate.startswith("[") and "." in candidate:
                    hop.from_host = candidate.lower()

    m = _BY.search(_COMMENT.sub(" ", head))
    if m:
        hop.by_host = m.group(1).strip("(),;").lower()
    m = _WITH.search(_COMMENT.sub(" ", head))
    if m:
        hop.with_protocol = m.group(1).strip("(),;")
    return hop


def analyze_hops(
    record: EmailRecord,
    *,
    live_dns: bool = False,
    ptr_resolver: PtrResolver | None = None,
) -> HopAnalysis:
    """Build the origin-first chain and flag anomalies."""
    analysis = HopAnalysis()
    hops = [parse_received(h) for h in record.received_headers]
    hops.reverse()
    analysis.hops = hops
    if not hops:
        analysis.flags.append("No Received headers")
        return analysis

    families = _recipient_families(record, hops)
    boundary = _boundary_hop(hops, families)
    if boundary is not None:
        analysis.first_external_ip = boundary.from_ip
        analysis.first_external_host = boundary.from_host
        if boundary.from_ip and is_private_ip(boundary.from_ip):
            analysis.private_ip_origin = True
            boundary.flags.append("private/reserved IP presented to recipient MX")
            analysis.flags.append(
                f"External origin {boundary.from_ip} is a private/reserved address"
            )
        elif not boundary.from_ip:
            analysis.flags.append("Boundary hop has no source IP")
    else:
        # Every hop stayed inside the recipient's infrastructure family (intra-tenant
        # mail, or provider-to-provider handoffs). Fall back to the sender IP the
        # gateway recorded in Authentication-Results / Received-SPF, if any.
        fallback = _ip_from_auth_headers(record)
        if fallback:
            analysis.first_external_ip = fallback
            analysis.flags.append(
                "No boundary hop identified; origin IP taken from Authentication-Results"
            )
        else:
            analysis.flags.append(
                "No external origin: message never left the recipient's mail infrastructure"
            )

    for hop in hops:
        if hop.from_ip and is_private_ip(hop.from_ip) and hop is not boundary:
            hop.flags.append("private IP (internal relay)")

    _check_timestamps(hops, analysis)

    if live_dns:
        _check_reverse_dns(hops, analysis, ptr_resolver)
    return analysis


# --------------------------------------------------------------------------- helpers


def _parse_date(value: str) -> datetime | None:
    cleaned = _COMMENT.sub("", value).strip()
    for candidate in (value, cleaned, cleaned.rsplit(" ", 1)[0]):
        try:
            return parsedate_to_datetime(candidate)
        except Exception:
            continue
    return None


def _first_ip(text: str) -> str:
    for m in _IPV4.finditer(text):
        try:
            ipaddress.IPv4Address(m.group(0))
            return m.group(0)
        except ValueError:
            continue
    for m in _IPV6.finditer(text):
        try:
            return str(ipaddress.IPv6Address(m.group(1)))
        except ValueError:
            continue
    return ""


# Hosting providers whose relays never carry the recipient's own domain name.
# Any host in one of these groups is treated as the same infrastructure.
_INFRA_FAMILIES: dict[str, str] = {}
for _family, _orgs in {
    "google": ("google.com", "gmail.com", "googlemail.com"),
    "microsoft": (
        "outlook.com",
        "office365.com",
        "exchangelabs.com",
        "hotmail.com",
        "live.com",
        "microsoft.com",
        "onmicrosoft.com",
    ),
}.items():
    for _org in _orgs:
        _INFRA_FAMILIES[_org] = _family

_SENDER_IP = re.compile(
    r"(?:sender IP is|client-ip=|smtp\.remote-ip=)\s*\[?([0-9a-fA-F.:]+)", re.IGNORECASE
)


def infra_family(host: str) -> str:
    """Organisational domain of ``host``, collapsed to a provider family where known."""
    if not host or _first_ip(host) == host.strip("[]"):
        return ""
    org = organizational_domain(host)
    return _INFRA_FAMILIES.get(org, org)


def _recipient_families(record: EmailRecord, hops: list[Hop]) -> set[str]:
    """Infrastructure families that belong to the recipient side of the chain."""
    families: set[str] = set()
    if record.to:
        families.add(infra_family(record.to[0].rsplit("@", 1)[1]))
    for hop in hops:
        m = _FOR.search(hop.raw)
        if m:
            families.add(infra_family(m.group(1).rsplit("@", 1)[1]))
    # The final delivering server is recipient infrastructure by definition.
    for hop in reversed(hops):
        fam = infra_family(hop.by_host)
        if fam:
            families.add(fam)
            break
    families.discard("")
    return families


def _boundary_hop(hops: list[Hop], families: set[str]) -> Hop | None:
    """First hop (origin-first) where recipient infrastructure accepted outside mail.

    A recipient-family server receiving from another recipient-family host, or
    from a private address with no hostname, is internal relaying, not a
    boundary. If every hop is internal there is no boundary at all.
    """
    if not families:
        return hops[-1] if hops else None  # unknown infrastructure: best guess
    for hop in hops:
        if infra_family(hop.by_host) not in families:
            continue
        source_family = infra_family(hop.from_host)
        private_source = not hop.from_ip or is_private_ip(hop.from_ip)
        internal = (source_family and source_family in families) or (
            private_source and not hop.from_host
        )
        if not internal:
            return hop
    return None


def _ip_from_auth_headers(record: EmailRecord) -> str:
    for name in ("Authentication-Results", "Received-SPF", "ARC-Authentication-Results"):
        for value in record.headers(name):
            m = _SENDER_IP.search(value)
            if m:
                ip = _first_ip(m.group(1))
                if ip:
                    return ip
    return ""


def _check_timestamps(hops: list[Hop], analysis: HopAnalysis) -> None:
    prev: Hop | None = None
    for hop in hops:
        if hop.timestamp is None:
            prev = prev or None
            continue
        if prev is not None and prev.timestamp is not None:
            delta = hop.timestamp - prev.timestamp
            if delta < -BACKWARDS_TOLERANCE:
                hop.flags.append(f"timestamp goes backwards by {_fmt(-delta)}")
                analysis.timestamp_anomaly = True
            elif delta > FORWARD_JUMP:
                hop.flags.append(f"timestamp jumps forward by {_fmt(delta)}")
                analysis.timestamp_anomaly = True
        prev = hop
    if analysis.timestamp_anomaly:
        analysis.flags.append("Received timestamps are out of order or have large gaps")


def _fmt(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds >= 86400:
        return f"{seconds / 86400:.1f}d"
    if seconds >= 3600:
        return f"{seconds / 3600:.1f}h"
    if seconds >= 60:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _default_ptr_resolver() -> PtrResolver | None:
    try:
        import dns.resolver  # type: ignore[import-not-found]
        import dns.reversename  # type: ignore[import-not-found]
    except ImportError:
        return None

    def resolve(ip: str) -> list[str]:
        try:
            name = dns.reversename.from_address(ip)
            return [
                str(r).rstrip(".").lower() for r in dns.resolver.resolve(name, "PTR", lifetime=5.0)
            ]
        except Exception:
            return []

    return resolve


def _check_reverse_dns(
    hops: list[Hop], analysis: HopAnalysis, ptr_resolver: PtrResolver | None
) -> None:
    ptr_resolver = ptr_resolver or _default_ptr_resolver()
    if ptr_resolver is None:
        analysis.flags.append("Live DNS: dnspython not installed; reverse lookups skipped")
        return
    for hop in hops:
        if not hop.from_ip or not hop.from_host or is_private_ip(hop.from_ip):
            continue
        names = ptr_resolver(hop.from_ip)
        if not names:
            hop.flags.append(f"no PTR record for {hop.from_ip}")
            continue
        if not any(n == hop.from_host or same_org(n, hop.from_host) for n in names):
            hop.flags.append(f"{hop.from_ip} reverse-resolves to {names[0]}, not {hop.from_host}")
            analysis.reverse_dns_mismatch = True
    if analysis.reverse_dns_mismatch:
        analysis.flags.append("A relay's claimed hostname does not match its reverse DNS")
