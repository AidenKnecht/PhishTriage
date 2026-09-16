"""SPF / DKIM / DMARC results and, more importantly, alignment.

An email can carry a perfectly valid DKIM signature for ``attacker.example``
and still claim to be from ``bank.example`` in the ``From:`` header. Mail
servers report "dkim=pass"; analysts care whether the *authenticated* domain is
the *displayed* domain. That is alignment, and it is computed here separately
from the raw results.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from phishtriage.models import AuthAnalysis, AuthResult, AuthStatus, EmailRecord
from phishtriage.rulesdata import Brand, load_brands, same_org

_COMMENT = re.compile(r"\([^()]*\)")
_CLAUSE = re.compile(r"^\s*([\w-]+)\s*=\s*([\w-]+)(.*)$", re.DOTALL)
_PROP = re.compile(r"([\w-]+)\.([\w-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)")
_EMAIL_IN_TEXT = re.compile(r"[\w.+\-]+@([\w\-]+(?:\.[\w\-]+)+)", re.IGNORECASE)
_DKIM_TAG = re.compile(r"(?:^|;)\s*([a-z])\s*=\s*([^;]*)", re.IGNORECASE)
_SPF_DOMAIN_OF = re.compile(r"domain of\s+(?:[\w.+\-]+@)?([\w\-]+(?:\.[\w\-]+)+)", re.IGNORECASE)

_STATUS_MAP = {
    "pass": AuthStatus.PASS,
    "fail": AuthStatus.FAIL,
    "hardfail": AuthStatus.FAIL,
    "softfail": AuthStatus.SOFTFAIL,
    "neutral": AuthStatus.NEUTRAL,
    "none": AuthStatus.NONE,
    "temperror": AuthStatus.TEMPERROR,
    "permerror": AuthStatus.PERMERROR,
    "policy": AuthStatus.POLICY,
    "bestguesspass": AuthStatus.NEUTRAL,
}

Resolver = Callable[[str, str], list[str]]
"""``resolver(name, rtype) -> list[str]``; injectable so tests never touch DNS."""


def analyze_auth(
    record: EmailRecord,
    *,
    live_dns: bool = False,
    origin_ip: str = "",
    resolver: Resolver | None = None,
    brands: tuple[Brand, ...] | None = None,
) -> AuthAnalysis:
    """Run every authentication and alignment check on a parsed record."""
    analysis = AuthAnalysis()
    brands = load_brands() if brands is None else brands

    ar_headers = record.headers("Authentication-Results")
    arc_headers = record.headers("ARC-Authentication-Results")
    received_spf = record.headers("Received-SPF")
    dkim_sigs = record.headers("DKIM-Signature")

    analysis.dkim_signature_domains = _dkim_signature_domains(dkim_sigs)

    results = _collect_results(ar_headers, "Authentication-Results")
    arc_results = _collect_results(arc_headers, "ARC-Authentication-Results")
    for mech in ("spf", "dkim", "dmarc"):
        chosen = _pick(results.get(mech, [])) or _pick(arc_results.get(mech, []))
        if chosen is not None:
            setattr(analysis, mech, chosen)

    if analysis.spf.status is AuthStatus.MISSING and received_spf:
        analysis.spf = _parse_received_spf(received_spf[0])

    analysis.no_auth_headers = not (ar_headers or arc_headers or received_spf)

    if ar_headers or arc_headers:
        # A results header exists but is silent on a mechanism: that's "none".
        for mech in ("spf", "dkim", "dmarc"):
            result: AuthResult = getattr(analysis, mech)
            if result.status is AuthStatus.MISSING:
                result.status = AuthStatus.NONE
                result.detail = "not reported by receiving server"

    if analysis.dkim.status in (AuthStatus.MISSING, AuthStatus.NONE) and dkim_sigs:
        analysis.dkim.detail = (
            f"signature present (d={', '.join(analysis.dkim_signature_domains)}) but not verified"
        )
        analysis.dkim.status = AuthStatus.NONE
    if not analysis.dkim.domain and analysis.dkim_signature_domains:
        analysis.dkim.domain = analysis.dkim_signature_domains[0]

    _alignment(record, analysis)
    _reply_to(record, analysis)
    _display_name(record, analysis, brands)

    if live_dns:
        _live_spf(record, analysis, origin_ip, resolver)

    _summarise_flags(analysis)
    return analysis


# --------------------------------------------------------------------------- parsing


def _strip_comments(value: str) -> str:
    prev = None
    while prev != value:
        prev, value = value, _COMMENT.sub(" ", value)
    return value


def _collect_results(headers: list[str], source: str) -> dict[str, list[AuthResult]]:
    """Parse RFC 8601 headers into ``{mechanism: [results in order]}``."""
    out: dict[str, list[AuthResult]] = {}
    for header in headers:
        for result in parse_authentication_results(header):
            result.source_header = source
            out.setdefault(result.mechanism, []).append(result)
    return out


def parse_authentication_results(header: str) -> list[AuthResult]:
    """Parse one ``Authentication-Results`` value into per-mechanism results."""
    cleaned = _strip_comments(header)
    segments = [s.strip() for s in cleaned.split(";") if s.strip()]
    results: list[AuthResult] = []
    for i, segment in enumerate(segments):
        if i == 0 and "=" not in segment:
            continue  # authserv-id
        if re.fullmatch(r"i\s*=\s*\d+", segment):
            continue  # ARC instance tag
        m = _CLAUSE.match(segment)
        if not m:
            continue
        mech, raw_status, rest = m.group(1).lower(), m.group(2).lower(), m.group(3)
        if mech not in ("spf", "dkim", "dmarc"):
            continue
        props = {f"{p}.{n}": v.strip('"') for p, n, v in _PROP.findall(rest)}
        result = AuthResult(mechanism=mech, status=_STATUS_MAP.get(raw_status, AuthStatus.NONE))
        if raw_status not in _STATUS_MAP:
            result.detail = f"unrecognised result {raw_status!r}"
        result.domain = _domain_for(mech, props)
        results.append(result)
    return results


def _domain_for(mech: str, props: dict[str, str]) -> str:
    if mech == "spf":
        cand = props.get("smtp.mailfrom") or props.get("smtp.helo") or ""
    elif mech == "dkim":
        cand = props.get("header.d") or props.get("header.i") or ""
    else:
        cand = props.get("header.from") or ""
    if "@" in cand:
        cand = cand.rsplit("@", 1)[1]
    return cand.strip().lower().rstrip(".")


def _pick(results: list[AuthResult]) -> AuthResult | None:
    """Prefer a pass (multiple DKIM signatures are common), else the first."""
    if not results:
        return None
    for r in results:
        if r.status is AuthStatus.PASS:
            return r
    return results[0]


def _parse_received_spf(header: str) -> AuthResult:
    result = AuthResult(mechanism="spf", source_header="Received-SPF")
    first = header.strip().split(None, 1)[0].lower() if header.strip() else ""
    result.status = _STATUS_MAP.get(first, AuthStatus.NONE)
    m = re.search(r"envelope-from=\"?([^\s;\"]+)", header, re.IGNORECASE)
    domain = m.group(1) if m else ""
    if not domain:
        m = _SPF_DOMAIN_OF.search(header)
        domain = m.group(1) if m else ""
    result.domain = _domain_for("spf", {"smtp.mailfrom": domain})
    return result


def _dkim_signature_domains(sigs: list[str]) -> list[str]:
    domains: list[str] = []
    for sig in sigs:
        tags = {k.lower(): v.strip() for k, v in _DKIM_TAG.findall(sig)}
        d = tags.get("d", "").lower().rstrip(".")
        if d and d not in domains:
            domains.append(d)
    return domains


# --------------------------------------------------------------------------- alignment


def _alignment(record: EmailRecord, analysis: AuthAnalysis) -> None:
    from_domain = record.from_domain
    if not from_domain:
        return

    spf_domain = record.return_path_domain or analysis.spf.domain
    if spf_domain:
        analysis.spf_aligned = same_org(spf_domain, from_domain)
        if not analysis.spf_aligned:
            analysis.flags.append(
                f"SPF/Return-Path domain {spf_domain} does not align with From {from_domain}"
            )

    dkim_domains = list(analysis.dkim_signature_domains)
    if analysis.dkim.domain and analysis.dkim.domain not in dkim_domains:
        dkim_domains.append(analysis.dkim.domain)
    if dkim_domains:
        analysis.dkim_aligned = any(same_org(d, from_domain) for d in dkim_domains)
        if not analysis.dkim_aligned:
            analysis.flags.append(
                f"DKIM domain {', '.join(dkim_domains)} does not align with From {from_domain}"
            )


def _reply_to(record: EmailRecord, analysis: AuthAnalysis) -> None:
    if (
        record.reply_to_domain
        and record.from_domain
        and not same_org(record.reply_to_domain, record.from_domain)
    ):
        analysis.reply_to_mismatch = True
        analysis.flags.append(
            f"Reply-To {record.reply_to_addr} points to a different domain than From"
        )


def _display_name(record: EmailRecord, analysis: AuthAnalysis, brands: tuple[Brand, ...]) -> None:
    display = record.from_display.strip()
    reasons: list[str] = []

    if any("From header is non-standard" in w for w in record.warnings):
        reasons.append("From header contains more than one address")

    for m in _EMAIL_IN_TEXT.finditer(display):
        embedded_domain = m.group(1).lower()
        if not same_org(embedded_domain, record.from_domain):
            reasons.append(
                f"display name contains address @{embedded_domain} "
                f"but sender is @{record.from_domain}"
            )
            break

    lowered = display.lower()
    for brand in brands:
        if re.search(rf"(?<![a-z0-9]){re.escape(brand.name)}(?![a-z0-9])", lowered) and not (
            record.from_domain and brand.is_legitimate_domain(record.from_domain)
        ):
            reasons.append(
                f"display name impersonates {brand.name!r} "
                f"but sender is @{record.from_domain or '?'}"
            )
            break

    if reasons:
        analysis.display_name_spoof = True
        analysis.display_name_spoof_reason = "; ".join(reasons)
        analysis.flags.append(f"Display-name spoofing: {analysis.display_name_spoof_reason}")


def _summarise_flags(analysis: AuthAnalysis) -> None:
    if analysis.no_auth_headers:
        analysis.flags.insert(0, "No Authentication-Results / Received-SPF headers present")
    for result in (analysis.spf, analysis.dkim, analysis.dmarc):
        if result.status in (AuthStatus.FAIL, AuthStatus.SOFTFAIL, AuthStatus.PERMERROR):
            analysis.flags.append(f"{result.mechanism.upper()} {result.status}")


# --------------------------------------------------------------------------- live DNS


def _default_resolver() -> Resolver | None:
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ImportError:
        return None

    def resolve(name: str, rtype: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, rtype, lifetime=5.0)
        except Exception:
            return []
        out: list[str] = []
        for rdata in answers:
            if rtype == "TXT":
                out.append(
                    "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                )
            elif rtype == "MX":
                out.append(str(rdata.exchange).rstrip("."))
            else:
                out.append(str(rdata))
        return out

    return resolve


def _live_spf(
    record: EmailRecord, analysis: AuthAnalysis, origin_ip: str, resolver: Resolver | None
) -> None:
    resolver = resolver or _default_resolver()
    if resolver is None:
        analysis.live_dns_detail = "dnspython not installed; run `uv sync --extra dns`"
        return
    domain = record.return_path_domain or analysis.spf.domain or record.from_domain
    if not domain or not origin_ip:
        analysis.live_dns_detail = "no sending domain or origin IP to check"
        return
    verdict = spf_check(domain, origin_ip, resolver)
    analysis.live_dns_detail = f"live SPF for {domain} from {origin_ip}: {verdict}"
    if verdict == "pass":
        analysis.live_dns_spf_authorized = True
    elif verdict in ("fail", "softfail"):
        analysis.live_dns_spf_authorized = False
        analysis.flags.append(f"Live DNS: {origin_ip} is not an authorised sender for {domain}")


def spf_check(domain: str, ip: str, resolver: Resolver, depth: int = 0) -> str:
    """Minimal SPF evaluator: ip4/ip6/a/mx/include/redirect/all.

    Returns ``pass``, ``fail``, ``softfail``, ``neutral``, ``none`` or ``error``.
    ``exists`` and ``ptr`` mechanisms are treated as non-matching.
    """
    if depth > 10:
        return "error"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "error"
    records = [r for r in resolver(domain, "TXT") if r.lower().startswith("v=spf1")]
    if not records:
        return "none"
    terms = records[0].split()[1:]
    redirect = ""
    for term in terms:
        qualifier = "+"
        if term[0] in "+-~?":
            qualifier, term = term[0], term[1:]
        name, _, arg = term.partition(":")
        name = name.lower()
        if name.startswith("redirect="):
            redirect = term.split("=", 1)[1]
            continue
        if name.startswith("exp=") or name in ("exists", "ptr"):
            continue
        if _spf_term_matches(name, arg, term, domain, addr, resolver, depth):
            return {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
    if redirect:
        return spf_check(redirect, ip, resolver, depth + 1)
    return "neutral"


def _spf_term_matches(
    name: str,
    arg: str,
    term: str,
    domain: str,
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    resolver: Resolver,
    depth: int,
) -> bool:
    if name == "all":
        return True
    if name in ("ip4", "ip6"):
        try:
            return addr in ipaddress.ip_network(arg, strict=False)
        except ValueError:
            return False
    if name == "include":
        return spf_check(arg, str(addr), resolver, depth + 1) == "pass"
    if name in ("a", "mx"):
        target, _, cidr = (arg or domain).partition("/")
        target = target or domain
        hosts = resolver(target, "MX") if name == "mx" else [target]
        rtype = "AAAA" if addr.version == 6 else "A"
        for host in hosts:
            for value in resolver(host, rtype):
                try:
                    if cidr:
                        if addr in ipaddress.ip_network(f"{value}/{cidr}", strict=False):
                            return True
                    elif ipaddress.ip_address(value) == addr:
                        return True
                except ValueError:
                    continue
    return False
