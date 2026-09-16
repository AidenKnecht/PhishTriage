"""URLhaus (abuse.ch) URL and host lookups.

API: https://urlhaus-api.abuse.ch/v1/  (POST form fields ``url`` / ``host``).
An ``Auth-Key`` header is sent when ``URLHAUS_AUTH_KEY`` is set; without one
the public endpoint may answer 401, which is reported as "not checked".
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from phishtriage.enrich.http import ApiError, not_checked, request_json
from phishtriage.models import EnrichmentResult, EnrichStatus, IndicatorType

BASE = "https://urlhaus-api.abuse.ch/v1"


class UrlhausEnricher:
    name = "urlhaus"
    supports = frozenset({IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.IP})

    def __init__(self, client: httpx.Client, auth_key: str = "") -> None:
        self.client = client
        self.auth_key = auth_key

    def _headers(self) -> dict[str, str]:
        return {"Auth-Key": self.auth_key} if self.auth_key else {}

    def lookup(self, indicator: str, kind: IndicatorType) -> EnrichmentResult:
        try:
            if kind is IndicatorType.URL:
                return self._url(indicator)
            return self._host(indicator)
        except ApiError as exc:
            reason = "auth key required" if "auth" in exc.reason else f"API error: {exc.reason}"
            return not_checked(self.name, indicator, reason)

    def _url(self, url: str) -> EnrichmentResult:
        payload = request_json(
            self.client, "POST", f"{BASE}/url/", data={"url": url}, headers=self._headers()
        )
        result = EnrichmentResult(self.name, url)
        if not payload or payload.get("query_status") != "ok":
            result.status = EnrichStatus.UNKNOWN
            result.detail = "not listed"
            return result
        result.status = EnrichStatus.MALICIOUS
        parts = [payload.get("threat") or "listed", payload.get("url_status") or ""]
        tags = payload.get("tags") or []
        if tags:
            parts.append(",".join(tags[:4]))
        result.detail = " ".join(p for p in parts if p)
        result.data = {
            "threat": payload.get("threat"),
            "url_status": payload.get("url_status"),
            "tags": tags,
            "date_added": payload.get("date_added"),
            "reference": payload.get("urlhaus_reference"),
        }
        return result

    def _host(self, host: str) -> EnrichmentResult:
        host = urlsplit(f"//{host}").hostname or host
        payload = request_json(
            self.client, "POST", f"{BASE}/host/", data={"host": host}, headers=self._headers()
        )
        result = EnrichmentResult(self.name, host)
        if not payload or payload.get("query_status") != "ok":
            result.status = EnrichStatus.UNKNOWN
            result.detail = "not listed"
            return result
        count = int(payload.get("url_count") or 0)
        blacklists = payload.get("blacklists") or {}
        listed = [k for k, v in blacklists.items() if v and v != "not listed"]
        result.data = {"url_count": count, "blacklists": blacklists}
        if count > 0 or listed:
            result.status = EnrichStatus.MALICIOUS
            result.detail = f"{count} malware URL(s) on host"
            if listed:
                result.detail += f"; blacklisted: {', '.join(listed)}"
        else:
            result.status = EnrichStatus.UNKNOWN
            result.detail = "known host, no active URLs"
        return result
