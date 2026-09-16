from pathlib import Path

import pytest

from phishtriage.models import (
    AttachmentAnalysis,
    AuthAnalysis,
    AuthStatus,
    EmailRecord,
    EnrichmentResult,
    EnrichStatus,
    HopAnalysis,
    Indicator,
    IndicatorAnalysis,
    IndicatorType,
    LinkMismatch,
    Verdict,
)
from phishtriage.pipeline import eml_files, triage
from phishtriage.scoring import RuleError, load_rules, score

ROOT = Path(__file__).resolve().parents[1]


def _empty():
    return (
        EmailRecord(from_addr="a@example.net", from_domain="example.net"),
        AuthAnalysis(),
        HopAnalysis(),
        IndicatorAnalysis(),
    )


def _rules(tmp_path: Path, body: str):
    p = tmp_path / "scoring.yaml"
    p.write_text(body, encoding="utf-8")
    load_rules.cache_clear()
    return load_rules(p)


# --------------------------------------------------------------------------- loading


def test_real_rules_load_and_are_well_formed():
    rs = load_rules()

    assert rs.source.name == "scoring.yaml"
    assert len(rs.rules) >= 25
    ids = [r.id for r in rs.rules]
    assert len(ids) == len(set(ids))
    for r in rs.rules:
        assert r.description and r.rationale and r.category
        assert 0 < r.weight <= 50
        for target in r.supersedes:
            assert target in ids, f"{r.id} supersedes unknown rule {target}"
    assert rs.verdict_for(0) is Verdict.CLEAN
    assert rs.verdict_for(19) is Verdict.CLEAN
    assert rs.verdict_for(20) is Verdict.SUSPICIOUS
    assert rs.verdict_for(49) is Verdict.SUSPICIOUS
    assert rs.verdict_for(50) is Verdict.LIKELY_PHISH
    assert rs.verdict_for(79) is Verdict.LIKELY_PHISH
    assert rs.verdict_for(80) is Verdict.MALICIOUS
    assert rs.verdict_for(100) is Verdict.MALICIOUS


def test_every_rule_condition_is_evaluable():
    """Every condition in the real file must evaluate without raising on an empty result."""
    rs = load_rules()
    rec, auth, hops, ind = _empty()
    result = score(rec, auth, hops, ind, ruleset=rs)
    # An empty record has dkim missing, no auth headers, so a couple of rules fire.
    assert {r.id for r in result.fired} <= {"dkim_fail_or_none", "no_auth_headers"}


RULES_HEADER = "verdicts: {CLEAN: 0, SUSPICIOUS: 20, LIKELY PHISH: 50, MALICIOUS: 80}\nrules:\n"


def _rule(id_: str, weight: int, when: str, extra: str = "") -> str:
    head = f"id: {id_}, description: {id_}, weight: {weight}, category: t, rationale: r"
    return f"  - {{{head}, when: {when}{extra}}}\n"


def test_malformed_rules_rejected(tmp_path):
    with pytest.raises(RuleError, match="expected a mapping"):
        _rules(tmp_path, "- just a list\n")
    with pytest.raises(RuleError, match="invalid"):
        _rules(tmp_path, "rules:\n  - id: x\n    weight: 5\n")
    with pytest.raises(RuleError, match="duplicate"):
        _rules(tmp_path, "rules:\n" + _rule("x", 5, "{keywords: true}") * 2)
    with pytest.raises(RuleError, match="unknown verdict"):
        _rules(tmp_path, "verdicts: {BOGUS: 1}\nrules:\n" + _rule("x", 5, "{keywords: true}"))
    with pytest.raises(RuleError, match="not found"):
        load_rules(tmp_path / "nope.yaml")


def test_unknown_condition_raises(tmp_path):
    rs = _rules(tmp_path, "rules:\n" + _rule("x", 5, "{bogus: 1}"))
    with pytest.raises(RuleError, match="unknown condition"):
        score(*_empty(), ruleset=rs)

    rs = _rules(tmp_path, "rules:\n" + _rule("x", 5, "{field: auth.spf}"))
    with pytest.raises(RuleError, match="no comparison"):
        score(*_empty(), ruleset=rs)


# --------------------------------------------------------------------------- conditions


def test_field_conditions(tmp_path):
    rs = _rules(
        tmp_path,
        RULES_HEADER
        + _rule("dmarc", 25, "{field: auth.dmarc.status, in: [fail]}")
        + _rule("aligned", 15, "{field: auth.spf_aligned, is_false: true}")
        + _rule("nohdr", 10, "{field: auth.no_auth_headers, is_true: true}")
        + _rule("mm", 20, "{field: indicators.link_mismatches, not_empty: true}")
        + _rule("eq", 1, "{field: record.from_domain, equals: example.net}")
        + _rule("ni", 1, "{field: record.from_domain, not_in: [example.net]}")
        + _rule("none", 1, "{field: hops.origin_country, is_none: true}")
        + _rule("gte", 1, "{field: record.subject, gte: 'b'}")
        + _rule("lte", 1, "{field: record.subject, lte: 'b'}")
        + _rule("contains", 1, "{field: record.subject, contains: 'ell'}"),
    )
    rec, auth, hops, ind = _empty()
    rec.subject = "hello"
    auth.dmarc.status = AuthStatus.FAIL
    auth.dmarc.domain = "example.net"
    auth.spf_aligned = False
    auth.flags.append("SPF/Return-Path domain x does not align with From example.net")
    ind.link_mismatches.append(LinkMismatch("t", "h", "text says a but link goes to b"))

    result = score(rec, auth, hops, ind, ruleset=rs)
    fired = {r.id: r for r in result.fired}

    assert set(fired) == {"dmarc", "aligned", "mm", "eq", "gte", "contains"}
    assert fired["dmarc"].evidence == ["DMARC fail (example.net)"]
    assert fired["aligned"].evidence == [
        "SPF/Return-Path domain x does not align with From example.net"
    ]
    assert fired["mm"].evidence == ["link_mismatches = text says a but link goes to b"]
    assert result.score == 25 + 15 + 20 + 3
    assert result.verdict is Verdict.LIKELY_PHISH
    assert [r.id for r in result.fired][:3] == ["dmarc", "mm", "aligned"]  # sorted by weight


def test_flag_conditions_and_evidence(tmp_path):
    rs = _rules(
        tmp_path,
        RULES_HEADER
        + _rule("look", 25, "{flag: lookalike_domain}")
        + _rule("ip", 15, "{flag: raw_ip_url, scope: urls}")
        + _rule("att", 30, "{flag: double_extension, scope: attachments}")
        + _rule("miss", 30, "{flag: double_extension, scope: urls}"),
    )
    rec, auth, hops, ind = _empty()
    ind.domains.append(
        Indicator(
            IndicatorType.DOMAIN,
            "paypa1.com",
            flags=["lookalike_domain"],
            details={"lookalike_domain": "homoglyph"},
        )
    )
    ind.urls.append(Indicator(IndicatorType.URL, "http://203.0.113.5/", flags=["raw_ip_url"]))
    ind.attachments.append(
        AttachmentAnalysis("a.pdf.exe", "exe", "x", "y", 1, "s", "m", flags=["double_extension"])
    )

    result = score(rec, auth, hops, ind, ruleset=rs)
    fired = {r.id: r for r in result.fired}

    assert set(fired) == {"look", "ip", "att"}
    assert fired["look"].evidence == ["paypa1.com: homoglyph"]
    assert fired["ip"].evidence == ["http://203.0.113.5/"]
    assert fired["att"].evidence == ["a.pdf.exe"]
    assert result.score == 70


def test_enrichment_conditions_and_supersedes(tmp_path):
    rs = _rules(
        tmp_path,
        RULES_HEADER
        + _rule(
            "vt_mal",
            40,
            "{enrichment: {source: virustotal, data_gte: {malicious: 3}}}",
            ", supersedes: [vt_sus]",
        )
        + _rule("vt_sus", 15, "{enrichment: {source: virustotal, status: [malicious, suspicious]}}")
        + _rule(
            "age7",
            30,
            "{enrichment: {source: rdap, data_lt: {age_days: 7}}}",
            ", supersedes: [age30]",
        )
        + _rule("age30", 20, "{enrichment: {source: rdap, data_lt: {age_days: 30}}}")
        + _rule("uh", 40, "{enrichment: {source: urlhaus, status: malicious}}"),
    )
    rec, auth, hops, ind = _empty()
    url = Indicator(IndicatorType.URL, "https://evil.example/")
    url.enrichment.append(
        EnrichmentResult("virustotal", url.value, EnrichStatus.MALICIOUS, "5/90", {"malicious": 5})
    )
    url.enrichment.append(EnrichmentResult("urlhaus", url.value, EnrichStatus.CLEAN))
    dom = Indicator(IndicatorType.DOMAIN, "evil.example")
    dom.enrichment.append(
        EnrichmentResult(
            "rdap", "evil.example", EnrichStatus.SUSPICIOUS, "3 days old", {"age_days": 3}
        )
    )
    ind.urls.append(url)
    ind.domains.append(dom)

    result = score(rec, auth, hops, ind, ruleset=rs)
    ids = [r.id for r in result.fired]

    assert ids == ["vt_mal", "age7"]
    assert result.raw_score == 70
    assert "evil.example: rdap: suspicious (3 days old)" in result.fired[1].evidence

    # Only 2 detections: the suspicious rule fires instead; old domain: nothing.
    url.enrichment[0].data["malicious"] = 2
    dom.enrichment[0].data["age_days"] = 400
    result = score(rec, auth, hops, ind, ruleset=rs)
    assert [r.id for r in result.fired] == ["vt_sus"]

    # not checked: nothing fires
    url.enrichment[0] = EnrichmentResult(
        "virustotal", url.value, EnrichStatus.NOT_CHECKED, "no key"
    )
    result = score(rec, auth, hops, ind, ruleset=rs)
    assert result.fired == []


def test_keyword_rule_scales_per_category_with_cap(tmp_path):
    rs = _rules(
        tmp_path,
        RULES_HEADER
        + _rule("kw", 5, "{keywords: true}", ", weight_per: keyword_category, max_weight: 15"),
    )
    rec, auth, hops, ind = _empty()
    assert score(rec, auth, hops, ind, ruleset=rs).fired == []

    ind.keyword_categories = {"urgency": ["urgent"]}
    assert score(rec, auth, hops, ind, ruleset=rs).score == 5

    ind.keyword_categories = {"urgency": ["urgent"], "credential": ["verify your account"]}
    r = score(rec, auth, hops, ind, ruleset=rs)
    assert r.score == 10
    assert r.fired[0].evidence == ["urgency: urgent", "credential: verify your account"]

    ind.keyword_categories = {"a": ["x"], "b": ["y"], "c": ["z"], "d": ["w"]}
    assert score(rec, auth, hops, ind, ruleset=rs).score == 15


def test_composition_and_cap(tmp_path):
    rs = _rules(
        tmp_path,
        RULES_HEADER
        + _rule(
            "both",
            60,
            "{all: [{field: auth.spf.status, in: [fail]}, {field: auth.dmarc.status, in: [fail]}]}",
        )
        + _rule("either", 60, "{any: [{field: auth.spf.status, in: [fail]}, {flag: nope}]}")
        + _rule("neg", 10, "{not: {flag: nope}}"),
    )
    rec, auth, hops, ind = _empty()
    auth.spf.status = AuthStatus.FAIL
    r = score(rec, auth, hops, ind, ruleset=rs)
    assert [x.id for x in r.fired] == ["either", "neg"]

    auth.dmarc.status = AuthStatus.FAIL
    r = score(rec, auth, hops, ind, ruleset=rs)
    assert [x.id for x in r.fired] == ["both", "either", "neg"]
    assert r.raw_score == 130
    assert r.score == 100
    assert r.verdict is Verdict.MALICIOUS


# --------------------------------------------------------------------------- corpus regression


def _corpus(kind: str) -> list[Path]:
    files = eml_files(ROOT / "samples" / kind)
    assert files, f"no samples under samples/{kind}"
    return files


def _known_misses() -> dict[str, str]:
    """``samples/known-misses.txt``: phish files the offline rules are known to under-score."""
    path = ROOT / "samples" / "known-misses.txt"
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, _, reason = line.partition("#")
        out[name.strip().replace("\\", "/")] = reason.strip()
    return out


def test_known_misses_file_points_at_real_files():
    for name in _known_misses():
        assert (ROOT / "samples" / name).is_file(), f"stale known-misses entry: {name}"


@pytest.mark.parametrize("path", _corpus("phish"), ids=lambda p: p.name)
def test_every_phish_sample_scores_at_least_50(path):
    result = triage(path, offline=True)
    fired = ", ".join(f"{r.id}({r.weight})" for r in result.score.fired)
    rel = path.relative_to(ROOT / "samples").as_posix()
    misses = _known_misses()
    if rel in misses:
        # Documented miss: must still be at least SUSPICIOUS, and if it ever
        # reaches 50 the entry should be removed so the list stays honest.
        assert 20 <= result.score.score < 50, (
            f"{rel} is listed as a known miss ({misses[rel]}) but scored "
            f"{result.score.score}: {fired}"
        )
        return
    assert result.score.score >= 50, f"{path.name} scored {result.score.score}: {fired}"
    assert result.score.verdict in (Verdict.LIKELY_PHISH, Verdict.MALICIOUS)


@pytest.mark.parametrize("path", _corpus("benign"), ids=lambda p: p.name)
def test_every_benign_sample_scores_under_50(path):
    result = triage(path, offline=True)
    fired = ", ".join(f"{r.id}({r.weight})" for r in result.score.fired)
    assert result.score.score < 50, f"{path.name} scored {result.score.score}: {fired}"
    assert result.score.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS)


def test_corpus_size():
    assert len(_corpus("phish")) >= 10
    assert len(_corpus("benign")) >= 5


def test_internal_no_auth_sample_is_suspicious_not_malicious():
    result = triage(ROOT / "samples" / "benign" / "04-internal-no-auth.eml", offline=True)
    assert result.score.verdict is Verdict.SUSPICIOUS
    assert {r.id for r in result.score.fired} == {"no_auth_headers", "dkim_fail_or_none"}


def test_aligned_vs_authenticated_sample():
    result = triage(ROOT / "samples" / "phish" / "10-dmarc-fail-dkim-unrelated.eml", offline=True)
    ids = {r.id for r in result.score.fired}
    assert result.auth.spf.status is AuthStatus.PASS
    assert result.auth.dkim.status is AuthStatus.PASS
    assert {"dmarc_fail", "spf_misaligned", "dkim_misaligned"} <= ids
