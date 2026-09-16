"""RDAP: domain registration age and IP country. No key needed.

Uses the rdap.org bootstrap service, which redirects to the authoritative
registry/RIR server. Age is computed from the ``registration`` event.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from phishtriage.enrich.http import ApiError, not_checked, request_json
from phishtriage.models import EnrichmentResult, EnrichStatus, IndicatorType
from phishtriage.rulesdata import organizational_domain

BASE = "https://rdap.org"
NEW_DOMAIN_DAYS = 30


class RdapEnricher:
    name = "rdap"
    supports = frozenset({IndicatorType.DOMAIN, IndicatorType.IP})

    def __init__(self, client: httpx.Client, now: datetime | None = None) -> None:
        self.client = client
        self._now = now

    def lookup(self, indicator: str, kind: IndicatorType) -> EnrichmentResult:
        try:
            if kind is IndicatorType.IP:
                return self._ip(indicator)
            return self._domain(indicator)
        except ApiError as exc:
            return not_checked(self.name, indicator, f"API error: {exc.reason}")

    def _domain(self, domain: str) -> EnrichmentResult:
        org = organizational_domain(domain)
        result = EnrichmentResult(self.name, domain)
        payload = request_json(self.client, "GET", f"{BASE}/domain/{org}")
        if not payload:
            result.status = EnrichStatus.UNKNOWN
            result.detail = "no RDAP record"
            return result
        registered = _event_date(payload, ("registration",))
        expires = _event_date(payload, ("expiration",))
        registrar = _registrar(payload)
        result.data = {
            "domain": org,
            "registered": registered.isoformat() if registered else None,
            "expires": expires.isoformat() if expires else None,
            "registrar": registrar,
        }
        if registered is None:
            result.status = EnrichStatus.UNKNOWN
            result.detail = "no registration date"
            return result
        now = self._now or datetime.now(UTC)
        age = max(0, (now - registered).days)
        result.data["age_days"] = age
        result.status = EnrichStatus.SUSPICIOUS if age < NEW_DOMAIN_DAYS else EnrichStatus.CLEAN
        result.detail = f"registered {registered.date()} ({age} days ago)"
        if registrar:
            result.detail += f" via {registrar}"
        return result

    def _ip(self, ip: str) -> EnrichmentResult:
        result = EnrichmentResult(self.name, ip)
        payload = request_json(self.client, "GET", f"{BASE}/ip/{ip}")
        if not payload:
            result.status = EnrichStatus.UNKNOWN
            result.detail = "no RDAP record"
            return result
        country = (payload.get("country") or "").upper() or _entity_country(payload)
        name = payload.get("name") or ""
        result.data = {"country": country, "network": name, "handle": payload.get("handle")}
        result.status = EnrichStatus.CLEAN
        result.detail = " ".join(p for p in (country, name) if p) or "record found"
        return result


def _event_date(payload: dict[str, Any], actions: tuple[str, ...]) -> datetime | None:
    for event in payload.get("events") or []:
        if event.get("eventAction") in actions and event.get("eventDate"):
            raw = str(event["eventDate"]).replace("Z", "+00:00")
            try:
                parsed = datetime.fromisoformat(raw)
            except ValueError:
                continue
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _registrar(payload: dict[str, Any]) -> str:
    for entity in payload.get("entities") or []:
        if "registrar" in (entity.get("roles") or []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if isinstance(item, list) and item and item[0] == "fn" and len(item) >= 4:
                    return str(item[3])
            return str(entity.get("handle") or "")
    return ""


def _entity_country(payload: dict[str, Any]) -> str:
    for entity in payload.get("entities") or []:
        for item in (entity.get("vcardArray") or [None, []])[1]:
            if isinstance(item, list) and item and item[0] == "adr" and len(item) >= 4:
                adr = item[3]
                if isinstance(adr, list) and adr and adr[-1]:
                    return str(adr[-1]).upper()[:2]
    return ""
