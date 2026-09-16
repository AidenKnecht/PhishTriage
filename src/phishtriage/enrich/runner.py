"""Run every enricher over an :class:`IndicatorAnalysis`, through the cache."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Sequence
from dataclasses import dataclass, field

from phishtriage.enrich.base import Cache, Enricher
from phishtriage.enrich.http import make_client
from phishtriage.enrich.rdap import RdapEnricher
from phishtriage.enrich.urlhaus import UrlhausEnricher
from phishtriage.enrich.virustotal import VirusTotalEnricher
from phishtriage.models import (
    AttachmentAnalysis,
    EnrichmentResult,
    EnrichmentStats,
    EnrichStatus,
    Indicator,
    IndicatorAnalysis,
    IndicatorType,
)

DEFAULT_BUDGET = {"virustotal": 8, "urlhaus": 20, "rdap": 20}
"""Max live lookups per source per email; flagged indicators go first."""


@dataclass
class Runner:
    enrichers: Sequence[Enricher]
    cache: Cache
    budget: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_BUDGET))

    def run(self, indicators: IndicatorAnalysis, *, origin_ip: str = "") -> EnrichmentStats:
        stats = EnrichmentStats()
        spent: dict[str, int] = {}
        for item, kind, value in self._targets(indicators):
            for enricher in self.enrichers:
                if kind not in enricher.supports:
                    continue
                result = self._lookup(enricher, value, kind, spent, stats)
                item.enrichment.append(result)
        return stats

    def origin_country(self, ip: str) -> str:
        for enricher in self.enrichers:
            if enricher.name == "rdap" and IndicatorType.IP in enricher.supports:
                result = self.cache.get("rdap", ip) or enricher.lookup(ip, IndicatorType.IP)
                self.cache.put(result)
                return str(result.data.get("country") or "")
        return ""

    def _lookup(
        self,
        enricher: Enricher,
        value: str,
        kind: IndicatorType,
        spent: dict[str, int],
        stats: EnrichmentStats,
    ) -> EnrichmentResult:
        cached = self.cache.get(enricher.name, value)
        if cached is not None:
            stats.lookups += 1
            stats.cached += 1
            return cached
        limit = self.budget.get(enricher.name)
        if limit is not None and spent.get(enricher.name, 0) >= limit:
            stats.skipped += 1
            return EnrichmentResult(
                enricher.name, value, EnrichStatus.NOT_CHECKED, "lookup budget exhausted"
            )
        spent[enricher.name] = spent.get(enricher.name, 0) + 1
        stats.lookups += 1
        try:
            result = enricher.lookup(value, kind)
        except Exception as exc:  # an enricher bug must never kill the report
            result = EnrichmentResult(
                enricher.name, value, EnrichStatus.NOT_CHECKED, f"API error: {exc}"
            )
        self.cache.put(result)
        return result

    @staticmethod
    def _targets(
        ind: IndicatorAnalysis,
    ) -> list[tuple[Indicator | AttachmentAnalysis, IndicatorType, str]]:
        """Flagged indicators first so a tight budget lands on the interesting ones."""
        out: list[tuple[Indicator | AttachmentAnalysis, IndicatorType, str]] = []
        for group, kind in ((ind.urls, IndicatorType.URL), (ind.domains, IndicatorType.DOMAIN)):
            for item in group:
                out.append((item, kind, item.value))
        for item in ind.ips:
            out.append((item, IndicatorType.IP, item.value))
        for att in ind.attachments:
            out.append((att, IndicatorType.HASH, att.sha256))
        out.sort(key=lambda t: 0 if t[0].flags else 1)
        return out


def build_runner(cache: Cache | None = None) -> Runner:
    """Wire up the real enrichers from environment variables."""
    client = make_client()
    enrichers: list[Enricher] = [
        UrlhausEnricher(client, auth_key=os.environ.get("URLHAUS_AUTH_KEY", "")),
        VirusTotalEnricher(client, api_key=os.environ.get("VT_API_KEY", "")),
        RdapEnricher(client),
    ]
    budget = dict(DEFAULT_BUDGET)
    if os.environ.get("VT_MAX_LOOKUPS"):
        with contextlib.suppress(ValueError):
            budget["virustotal"] = int(os.environ["VT_MAX_LOOKUPS"])
    return Runner(enrichers=enrichers, cache=cache or Cache.default(), budget=budget)
