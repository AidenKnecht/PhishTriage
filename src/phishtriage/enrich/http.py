"""Tiny httpx wrapper so every enricher fails the same way."""

from __future__ import annotations

from typing import Any

import httpx

from phishtriage.models import EnrichmentResult, EnrichStatus

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "phishtriage/0.1 (+https://github.com/aidenknecht/phishtriage)"


class ApiError(Exception):
    """Non-success from an enrichment API, with a short reason for the report."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def make_client(timeout: float = DEFAULT_TIMEOUT, **kwargs: Any) -> httpx.Client:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    headers.update(kwargs.pop("headers", {}) or {})
    return httpx.Client(timeout=timeout, headers=headers, follow_redirects=True, **kwargs)


def request_json(client: httpx.Client, method: str, url: str, **kwargs: Any) -> Any:
    """Perform a request and return parsed JSON; raise :class:`ApiError` otherwise."""
    try:
        response = client.request(method, url, **kwargs)
    except httpx.TimeoutException as exc:
        raise ApiError("timeout") from exc
    except httpx.HTTPError as exc:
        raise ApiError(f"network error: {exc.__class__.__name__}") from exc
    if response.status_code == 404:
        return None
    if response.status_code in (401, 403):
        raise ApiError(f"HTTP {response.status_code} (auth)")
    if response.status_code == 429:
        raise ApiError("HTTP 429 (rate limited)")
    if response.status_code >= 400:
        raise ApiError(f"HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise ApiError("invalid JSON") from exc


def not_checked(source: str, indicator: str, reason: str) -> EnrichmentResult:
    return EnrichmentResult(source, indicator, EnrichStatus.NOT_CHECKED, reason)
