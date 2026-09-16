import json
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from phishtriage.enrich.base import Cache, TokenBucket
from phishtriage.enrich.rdap import RdapEnricher
from phishtriage.enrich.runner import Runner, build_runner
from phishtriage.enrich.urlhaus import UrlhausEnricher
from phishtriage.enrich.virustotal import VirusTotalEnricher
from phishtriage.models import (
    AttachmentAnalysis,
    EnrichmentResult,
    EnrichStatus,
    Indicator,
    IndicatorAnalysis,
    IndicatorType,
)
from phishtriage.pipeline import triage

ROOT = Path(__file__).resolve().parents[1]


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _json(data, status=200):
    return httpx.Response(status, json=data)


# --------------------------------------------------------------------------- cache


def test_cache_roundtrip_and_ttl(tmp_path):
    cache = Cache(tmp_path, ttl_seconds=60)
    assert cache.get("urlhaus", "http://x/") is None

    cache.put(EnrichmentResult("urlhaus", "http://x/", EnrichStatus.MALICIOUS, "bad", {"a": 1}))
    got = cache.get("urlhaus", "http://x/")
    assert got is not None
    assert got.cached is True
    assert got.status is EnrichStatus.MALICIOUS
    assert got.data == {"a": 1}
    assert cache.count() == 1

    # expire it
    path = next(tmp_path.rglob("*.json"))
    payload = json.loads(path.read_text())
    payload["ts"] = time.time() - 120
    path.write_text(json.dumps(payload))
    assert cache.get("urlhaus", "http://x/") is None

    # corrupt file
    path.write_text("not json")
    assert cache.get("urlhaus", "http://x/") is None
    path.write_text(json.dumps({"ts": time.time(), "result": {"nope": 1}}))
    assert cache.get("urlhaus", "http://x/") is None

    assert cache.clear() == 1
    assert cache.count() == 0
    assert Cache(tmp_path / "missing").clear() == 0


def test_cache_never_stores_not_checked(tmp_path):
    cache = Cache(tmp_path)
    cache.put(EnrichmentResult("virustotal", "x", EnrichStatus.NOT_CHECKED, "no key"))
    assert cache.count() == 0


def test_cache_dir_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHTRIAGE_CACHE_DIR", str(tmp_path / "c"))
    assert Cache.default().root == tmp_path / "c"
    monkeypatch.delenv("PHISHTRIAGE_CACHE_DIR")
    assert Cache.default().root.name == "phishtriage"


def test_token_bucket_sleeps_when_exhausted():
    slept = []
    bucket = TokenBucket(rate=2, per=60.0, sleep=slept.append)
    clock = [1000.0]
    bucket._clock = lambda: clock[0]

    assert bucket.acquire() == 0
    assert bucket.acquire() == 0
    # third call must wait; simulate time passing when we "sleep"
    original = bucket._sleep

    def fake_sleep(s):
        original(s)
        clock[0] += s

    bucket._sleep = fake_sleep
    waited = bucket.acquire()
    assert waited > 59
    assert len(slept) == 1


# --------------------------------------------------------------------------- urlhaus


def test_urlhaus_url_hit_and_miss():
    def handler(request):
        assert request.method == "POST"
        body = request.content.decode()
        if "evil" in body:
            return _json(
                {
                    "query_status": "ok",
                    "threat": "malware_download",
                    "url_status": "online",
                    "tags": ["exe", "Loader"],
                    "date_added": "2024-09-01",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
                }
            )
        return _json({"query_status": "no_results"})

    e = UrlhausEnricher(_client(handler))
    hit = e.lookup("http://evil.example/a.exe", IndicatorType.URL)
    assert hit.status is EnrichStatus.MALICIOUS
    assert hit.detail == "malware_download online exe,Loader"
    assert hit.data["tags"] == ["exe", "Loader"]

    miss = e.lookup("http://fine.example/", IndicatorType.URL)
    assert miss.status is EnrichStatus.UNKNOWN
    assert miss.detail == "not listed"


def test_urlhaus_host_lookup_and_auth_key():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("Auth-Key")
        host = request.content.decode().split("=", 1)[1]
        if host == "bad.example":
            return _json(
                {"query_status": "ok", "url_count": "3", "blacklists": {"spamhaus_dbl": "listed"}}
            )
        if host == "quiet.example":
            return _json({"query_status": "ok", "url_count": 0, "blacklists": {}})
        return _json({"query_status": "no_results"})

    e = UrlhausEnricher(_client(handler), auth_key="k123")
    r = e.lookup("bad.example", IndicatorType.DOMAIN)
    assert seen["auth"] == "k123"
    assert r.status is EnrichStatus.MALICIOUS
    assert "3 malware URL(s)" in r.detail and "spamhaus_dbl" in r.detail

    assert e.lookup("quiet.example", IndicatorType.DOMAIN).status is EnrichStatus.UNKNOWN
    assert e.lookup("203.0.113.5", IndicatorType.IP).status is EnrichStatus.UNKNOWN


def test_urlhaus_errors_degrade():
    e = UrlhausEnricher(_client(lambda r: httpx.Response(401)))
    r = e.lookup("http://x/", IndicatorType.URL)
    assert r.status is EnrichStatus.NOT_CHECKED
    assert r.detail == "auth key required"

    e = UrlhausEnricher(_client(lambda r: httpx.Response(500)))
    assert e.lookup("http://x/", IndicatorType.URL).detail == "API error: HTTP 500"

    def boom(r):
        raise httpx.ConnectTimeout("slow")

    e = UrlhausEnricher(_client(boom))
    assert e.lookup("http://x/", IndicatorType.URL).detail == "API error: timeout"

    e = UrlhausEnricher(_client(lambda r: httpx.Response(200, content=b"<html>")))
    assert e.lookup("http://x/", IndicatorType.URL).detail == "API error: invalid JSON"


# --------------------------------------------------------------------------- virustotal


def _vt_payload(malicious, suspicious=0, harmless=60, undetected=10):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "reputation": -5,
                "categories": {"a": "phishing"},
            }
        }
    }


def test_virustotal_status_mapping_and_endpoints():
    seen = []

    def handler(request):
        seen.append((request.url.path, request.headers.get("x-apikey")))
        if "/urls/" in request.url.path:
            return _json(_vt_payload(5))
        if "/domains/" in request.url.path:
            return _json(_vt_payload(1, 1))
        if "/files/" in request.url.path:
            return _json(_vt_payload(0))
        return httpx.Response(404)

    e = VirusTotalEnricher(_client(handler), api_key="vt-key", bucket=TokenBucket(100, 1))
    url = e.lookup("http://evil.example/", IndicatorType.URL)
    assert url.status is EnrichStatus.MALICIOUS
    assert url.data["malicious"] == 5
    assert url.detail == "5 malicious, 0 suspicious of 75"
    assert seen[0][0].startswith("/api/v3/urls/") and seen[0][1] == "vt-key"

    dom = e.lookup("evil.example", IndicatorType.DOMAIN)
    assert dom.status is EnrichStatus.SUSPICIOUS
    assert seen[1][0] == "/api/v3/domains/evil.example"

    fh = e.lookup("a" * 64, IndicatorType.HASH)
    assert fh.status is EnrichStatus.CLEAN
    assert seen[2][0] == f"/api/v3/files/{'a' * 64}"

    assert e.lookup("x", IndicatorType.IP).status is EnrichStatus.NOT_CHECKED


def test_virustotal_no_key_never_calls_api():
    calls = []
    e = VirusTotalEnricher(_client(lambda r: calls.append(r)), api_key="")
    r = e.lookup("http://x/", IndicatorType.URL)
    assert r.status is EnrichStatus.NOT_CHECKED
    assert r.detail == "no key"
    assert calls == []


def test_virustotal_404_429_and_empty_stats():
    e = VirusTotalEnricher(_client(lambda r: httpx.Response(404)), "k", TokenBucket(100, 1))
    r = e.lookup("http://x/", IndicatorType.URL)
    assert r.status is EnrichStatus.UNKNOWN and r.detail == "never seen"

    e = VirusTotalEnricher(_client(lambda r: httpx.Response(429)), "k", TokenBucket(100, 1))
    r = e.lookup("http://x/", IndicatorType.URL)
    assert r.status is EnrichStatus.NOT_CHECKED and r.detail == "rate limited"

    e = VirusTotalEnricher(_client(lambda r: _json({"data": {}})), "k", TokenBucket(100, 1))
    assert e.lookup("http://x/", IndicatorType.URL).status is EnrichStatus.UNKNOWN


# --------------------------------------------------------------------------- rdap


def _rdap_domain(registered):
    return {
        "events": [
            {"eventAction": "registration", "eventDate": registered},
            {"eventAction": "expiration", "eventDate": "2026-01-01T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Cheap Registrar LLC"]]],
            }
        ],
    }


def test_rdap_domain_age():
    now = datetime(2024, 9, 13, tzinfo=UTC)

    def handler(request):
        if request.url.path == "/domain/fresh.example":
            return _json(_rdap_domain("2024-09-10T00:00:00Z"))
        if request.url.path == "/domain/old.example":
            return _json(_rdap_domain("2010-01-01T00:00:00+00:00"))
        if request.url.path == "/domain/nodate.example":
            return _json({"events": []})
        return httpx.Response(404)

    e = RdapEnricher(_client(handler), now=now)
    fresh = e.lookup("mail.fresh.example", IndicatorType.DOMAIN)  # org-domain lookup
    assert fresh.status is EnrichStatus.SUSPICIOUS
    assert fresh.data["age_days"] == 3
    assert fresh.data["registrar"] == "Cheap Registrar LLC"
    assert "3 days ago" in fresh.detail and "Cheap Registrar" in fresh.detail

    old = e.lookup("old.example", IndicatorType.DOMAIN)
    assert old.status is EnrichStatus.CLEAN
    assert old.data["age_days"] > 5000

    assert e.lookup("nodate.example", IndicatorType.DOMAIN).status is EnrichStatus.UNKNOWN
    assert e.lookup("missing.example", IndicatorType.DOMAIN).detail == "no RDAP record"


def test_rdap_ip_country():
    def handler(request):
        if request.url.path == "/ip/203.0.113.5":
            return _json(
                {"country": "nl", "name": "EXAMPLE-NET", "handle": "203.0.113.0 - 203.0.113.255"}
            )
        if request.url.path == "/ip/198.51.100.7":
            return _json(
                {
                    "name": "X",
                    "entities": [
                        {
                            "vcardArray": [
                                "vcard",
                                [["adr", {}, "text", ["", "", "", "", "", "", "DE"]]],
                            ]
                        }
                    ],
                }
            )
        return httpx.Response(500)

    e = RdapEnricher(_client(handler))
    r = e.lookup("203.0.113.5", IndicatorType.IP)
    assert r.data["country"] == "NL"
    assert r.detail == "NL EXAMPLE-NET"

    assert e.lookup("198.51.100.7", IndicatorType.IP).data["country"] == "DE"
    assert e.lookup("192.0.2.1", IndicatorType.IP).status is EnrichStatus.NOT_CHECKED


# --------------------------------------------------------------------------- runner


class FakeEnricher:
    def __init__(self, name, supports, status=EnrichStatus.CLEAN, fail=False):
        self.name = name
        self.supports = frozenset(supports)
        self.status = status
        self.fail = fail
        self.calls = []

    def lookup(self, indicator, kind):
        self.calls.append((indicator, kind))
        if self.fail:
            raise RuntimeError("kaboom")
        data = {"country": "US"} if kind is IndicatorType.IP else {}
        return EnrichmentResult(self.name, indicator, self.status, "ok", data)


def _indicators():
    ind = IndicatorAnalysis()
    ind.urls = [
        Indicator(IndicatorType.URL, "http://plain.example/"),
        Indicator(IndicatorType.URL, "http://evil.example/", flags=["lookalike_domain"]),
    ]
    ind.domains = [Indicator(IndicatorType.DOMAIN, "evil.example", flags=["lookalike_domain"])]
    ind.ips = [Indicator(IndicatorType.IP, "203.0.113.5")]
    ind.attachments = [AttachmentAnalysis("a.exe", "exe", "x", "y", 1, "f" * 64, "m")]
    return ind


def test_runner_orders_flagged_first_and_respects_budget(tmp_path):
    vt = FakeEnricher("virustotal", {IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.HASH})
    runner = Runner([vt], Cache(tmp_path), budget={"virustotal": 2})
    ind = _indicators()

    stats = runner.run(ind)

    assert [c[0] for c in vt.calls] == ["http://evil.example/", "evil.example"]
    assert stats.lookups == 2 and stats.skipped == 2 and stats.cached == 0
    plain = next(u for u in ind.urls if "plain" in u.value)
    assert plain.enrichment[0].status is EnrichStatus.NOT_CHECKED
    assert plain.enrichment[0].detail == "lookup budget exhausted"
    assert ind.attachments[0].enrichment[0].detail == "lookup budget exhausted"


def test_runner_uses_cache_on_second_run(tmp_path):
    e = FakeEnricher("urlhaus", {IndicatorType.URL})
    runner = Runner([e], Cache(tmp_path))
    ind = _indicators()
    first = runner.run(ind)
    assert first.lookups == 2 and first.cached == 0

    second = runner.run(_indicators())
    assert second.lookups == 2 and second.cached == 2
    assert len(e.calls) == 2


def test_runner_survives_enricher_exception_and_country(tmp_path):
    bad = FakeEnricher("urlhaus", {IndicatorType.URL}, fail=True)
    rdap = FakeEnricher("rdap", {IndicatorType.IP, IndicatorType.DOMAIN})
    runner = Runner([bad, rdap], Cache(tmp_path))
    ind = _indicators()
    runner.run(ind)

    assert ind.urls[0].enrichment[0].status is EnrichStatus.NOT_CHECKED
    assert "kaboom" in ind.urls[0].enrichment[0].detail
    assert runner.origin_country("203.0.113.5") == "US"
    assert Runner([bad], Cache(tmp_path)).origin_country("203.0.113.5") == ""


def test_build_runner_reads_env(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "k")
    monkeypatch.setenv("VT_MAX_LOOKUPS", "3")
    runner = build_runner(Cache(tmp_path))
    assert [e.name for e in runner.enrichers] == ["urlhaus", "virustotal", "rdap"]
    assert runner.budget["virustotal"] == 3
    monkeypatch.setenv("VT_MAX_LOOKUPS", "bogus")
    assert build_runner(Cache(tmp_path)).budget["virustotal"] == 8


def test_pipeline_online_with_fake_enrichers_changes_verdict(tmp_path):
    """Enrichment results feed the scorer: a URLhaus hit adds 40 and RDAP fills the country."""
    uh = FakeEnricher("urlhaus", {IndicatorType.URL}, status=EnrichStatus.MALICIOUS)
    rdap = FakeEnricher("rdap", {IndicatorType.IP})
    runner = Runner([uh, rdap], Cache(tmp_path))

    result = triage(
        ROOT / "samples" / "phish" / "12-html-attachment.eml", offline=False, enricher=runner
    )
    assert result.offline is False
    assert result.hops.origin_country == "US"
    assert result.enrichment_stats.lookups >= 1
    assert result.score.score == 50  # no URL in that sample: nothing for urlhaus to hit

    result = triage(
        ROOT / "samples" / "phish" / "02-display-name-spoof.eml", offline=False, enricher=runner
    )
    assert "urlhaus_hit" in {r.id for r in result.score.fired}
    assert result.score.score == 95


@pytest.mark.parametrize("offline", [True])
def test_offline_flag_skips_runner(tmp_path, offline):
    uh = FakeEnricher("urlhaus", {IndicatorType.URL}, status=EnrichStatus.MALICIOUS)
    result = triage(
        ROOT / "samples" / "benign" / "01-newsletter.eml",
        offline=offline,
        enricher=Runner([uh], Cache(tmp_path)),
    )
    assert uh.calls == []
    assert result.offline is True
