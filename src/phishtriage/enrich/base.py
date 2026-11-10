"""Enricher protocol, on-disk cache, and a token bucket for rate-limited APIs."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from phishtriage.models import EnrichmentResult, EnrichStatus, IndicatorType

DEFAULT_TTL_SECONDS = 24 * 60 * 60


@runtime_checkable
class Enricher(Protocol):
    """One threat-intel source."""

    name: str
    supports: frozenset[IndicatorType]

    def lookup(self, indicator: str, kind: IndicatorType) -> EnrichmentResult: ...


_RESERVED_TLDS = ("example", "test", "invalid", "localhost", "local")
_RESERVED_DOMAINS = ("example.com", "example.net", "example.org")


def unroutable_reason(value: str, kind: IndicatorType) -> str:
    """Why an indicator can't mean anything to a public threat-intel API, or ``""``.

    RFC 2606/6761 reserved names and non-global IPs (RFC 1918, RFC 5737
    documentation ranges, loopback...) never resolve on the internet, so
    sending them to VirusTotal or RDAP only produces confusing API errors.
    """
    if kind is IndicatorType.HASH:
        return ""
    host = value
    if kind is IndicatorType.URL:
        try:
            host = urlsplit(value).hostname or ""
        except ValueError:
            return ""
    host = host.lower().rstrip(".")
    if not host:
        return ""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return "" if addr.is_global else "non-routable IP"
    labels = host.split(".")
    if labels[-1] in _RESERVED_TLDS or ".".join(labels[-2:]) in _RESERVED_DOMAINS:
        return "reserved name"
    return ""


def cache_dir() -> Path:
    override = os.environ.get("PHISHTRIAGE_CACHE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "phishtriage"


@dataclass
class Cache:
    """JSON-file cache keyed by (source, indicator) with a TTL."""

    root: Path
    ttl_seconds: int = DEFAULT_TTL_SECONDS

    @classmethod
    def default(cls) -> Cache:
        return cls(cache_dir())

    def _path(self, source: str, indicator: str) -> Path:
        digest = hashlib.sha1(
            indicator.encode("utf-8", "replace"), usedforsecurity=False
        ).hexdigest()
        return self.root / source / f"{digest}.json"

    def get(self, source: str, indicator: str) -> EnrichmentResult | None:
        path = self._path(source, indicator)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if time.time() - float(payload.get("ts", 0)) > self.ttl_seconds:
            return None
        data = payload.get("result") or {}
        try:
            result = EnrichmentResult(
                source=data["source"],
                indicator=data["indicator"],
                status=EnrichStatus(data["status"]),
                detail=data.get("detail", ""),
                data=dict(data.get("data") or {}),
                cached=True,
            )
        except (KeyError, ValueError):
            return None
        return result

    def put(self, result: EnrichmentResult, key: str | None = None) -> None:
        """Store ``result``; ``key`` overrides the indicator as the cache key."""
        if result.status is EnrichStatus.NOT_CHECKED:
            return  # never cache "no key" / "API error"
        path = self._path(result.source, key or result.indicator)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "ts": time.time(),
            "result": {
                "source": result.source,
                "indicator": result.indicator,
                "status": result.status.value,
                "detail": result.detail,
                "data": result.data,
            },
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    def clear(self) -> int:
        removed = 0
        if not self.root.exists():
            return 0
        for path in self.root.rglob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
        return removed

    def count(self) -> int:
        return sum(1 for _ in self.root.rglob("*.json")) if self.root.exists() else 0


class TokenBucket:
    """Blocking rate limiter: at most ``rate`` calls per ``per`` seconds."""

    def __init__(self, rate: int, per: float, sleep: object = None) -> None:
        self.rate = rate
        self.per = per
        self._stamps: list[float] = []
        self._lock = threading.Lock()
        self._sleep = sleep or time.sleep
        self._clock = time.monotonic

    def acquire(self) -> float:
        """Wait until a call is allowed; returns seconds slept."""
        slept = 0.0
        with self._lock:
            while True:
                now = self._clock()
                self._stamps = [s for s in self._stamps if now - s < self.per]
                if len(self._stamps) < self.rate:
                    self._stamps.append(now)
                    return slept
                wait = self.per - (now - self._stamps[0]) + 0.01
                self._sleep(wait)  # type: ignore[operator]
                slept += wait
