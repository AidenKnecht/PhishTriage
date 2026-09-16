"""VirusTotal v3 lookups for URLs, domains and file hashes.

Free tier: 4 requests/minute, 500/day. A :class:`TokenBucket` enforces the
per-minute limit locally so the tool never spams the API, and a per-run
budget (``VT_MAX_LOOKUPS``) keeps one big email from eating the daily quota.
"""

from __future__ import annotations

import base64

import httpx

from phishtriage.enrich.base import TokenBucket
from phishtriage.enrich.http import ApiError, not_checked, request_json
from phishtriage.models import EnrichmentResult, EnrichStatus, IndicatorType

BASE = "https://www.virustotal.com/api/v3"
MALICIOUS_VENDORS = 3
"""Vendors flagging malicious at which we call it malicious rather than suspicious."""


class VirusTotalEnricher:
    name = "virustotal"
    supports = frozenset({IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.HASH})

    def __init__(
        self,
        client: httpx.Client,
        api_key: str,
        bucket: TokenBucket | None = None,
    ) -> None:
        self.client = client
        self.api_key = api_key
        self.bucket = bucket or TokenBucket(rate=4, per=60.0)

    def lookup(self, indicator: str, kind: IndicatorType) -> EnrichmentResult:
        if not self.api_key:
            return not_checked(self.name, indicator, "no key")
        if kind is IndicatorType.URL:
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            endpoint = f"{BASE}/urls/{url_id}"
        elif kind is IndicatorType.DOMAIN:
            endpoint = f"{BASE}/domains/{indicator}"
        elif kind is IndicatorType.HASH:
            endpoint = f"{BASE}/files/{indicator}"
        else:
            return not_checked(self.name, indicator, "unsupported indicator type")

        self.bucket.acquire()
        try:
            payload = request_json(self.client, "GET", endpoint, headers={"x-apikey": self.api_key})
        except ApiError as exc:
            reason = "rate limited" if "429" in exc.reason else f"API error: {exc.reason}"
            return not_checked(self.name, indicator, reason)

        result = EnrichmentResult(self.name, indicator)
        if payload is None:
            result.status = EnrichStatus.UNKNOWN
            result.detail = "never seen"
            return result
        attrs = (payload.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total = sum(int(v or 0) for v in stats.values())
        result.data = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
            "total": total,
            "reputation": attrs.get("reputation"),
            "categories": list((attrs.get("categories") or {}).values())[:3],
            "meaningful_name": attrs.get("meaningful_name"),
        }
        if malicious >= MALICIOUS_VENDORS:
            result.status = EnrichStatus.MALICIOUS
        elif malicious or suspicious:
            result.status = EnrichStatus.SUSPICIOUS
        elif total:
            result.status = EnrichStatus.CLEAN
        else:
            result.status = EnrichStatus.UNKNOWN
        result.detail = f"{malicious} malicious, {suspicious} suspicious of {total}"
        return result
