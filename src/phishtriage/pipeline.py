"""Run every stage on one email and return a :class:`TriageResult`.

This is the one place that knows the order of operations. The CLI, the batch
command, and the regression tests all go through :func:`triage`.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from phishtriage.auth import analyze_auth
from phishtriage.hops import analyze_hops
from phishtriage.indicators import analyze_indicators
from phishtriage.models import EnrichmentStats, IndicatorAnalysis, TriageResult
from phishtriage.parser import parse_file
from phishtriage.scoring import RuleSet, score


class EnrichmentRunner(Protocol):
    """Anything that can enrich an IndicatorAnalysis in place (see ``enrich/``)."""

    def run(self, indicators: IndicatorAnalysis, *, origin_ip: str) -> EnrichmentStats: ...

    def origin_country(self, ip: str) -> str: ...


def triage(
    path: str | Path,
    *,
    offline: bool = True,
    live_dns: bool = False,
    enricher: EnrichmentRunner | None = None,
    ruleset: RuleSet | None = None,
) -> TriageResult:
    """Parse, analyse, optionally enrich, and score one ``.eml`` file."""
    started = time.perf_counter()
    record = parse_file(path)

    hops = analyze_hops(record, live_dns=live_dns)
    auth = analyze_auth(record, live_dns=live_dns, origin_ip=hops.first_external_ip)
    indicators = analyze_indicators(record, origin_ip=hops.first_external_ip)

    stats = EnrichmentStats()
    if not offline and enricher is not None:
        stats = enricher.run(indicators, origin_ip=hops.first_external_ip)
        if hops.first_external_ip:
            hops.origin_country = enricher.origin_country(hops.first_external_ip)

    result = score(record, auth, hops, indicators, ruleset=ruleset)
    return TriageResult(
        record=record,
        auth=auth,
        hops=hops,
        indicators=indicators,
        score=result,
        enrichment_stats=stats,
        elapsed_seconds=time.perf_counter() - started,
        offline=offline or enricher is None,
    )


def eml_files(directory: str | Path) -> list[Path]:
    """All ``.eml`` files under ``directory``, recursively, sorted."""
    return sorted(p for p in Path(directory).rglob("*.eml") if p.is_file())


def triage_many(paths: Sequence[str | Path], **kwargs: object) -> list[TriageResult]:
    return [triage(p, **kwargs) for p in paths]  # type: ignore[arg-type]
