"""Apply ``rules/scoring.yaml`` to an analysed email.

The engine knows nothing about phishing. It knows how to evaluate a small
condition language (field comparisons, indicator flags, enrichment results,
keyword categories, and/or/not) against the analysis objects. Everything that
makes a verdict a verdict lives in the YAML file.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from phishtriage.models import (
    AuthAnalysis,
    EmailRecord,
    EnrichmentResult,
    FiredRule,
    HopAnalysis,
    IndicatorAnalysis,
    ScoreResult,
    Verdict,
)
from phishtriage.rulesdata import rules_dir

_INDICATOR_GROUPS = ("urls", "domains", "ips", "attachments")


class RuleError(ValueError):
    """A rule in scoring.yaml is malformed."""


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    weight: int
    category: str
    rationale: str
    when: dict[str, Any]
    supersedes: tuple[str, ...] = ()
    weight_per: str = ""
    max_weight: int | None = None


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[Rule, ...]
    verdicts: tuple[tuple[Verdict, int], ...]
    source: Path

    def verdict_for(self, score: int) -> Verdict:
        verdict = self.verdicts[0][0]
        for name, floor in self.verdicts:
            if score >= floor:
                verdict = name
        return verdict


@dataclass
class _Context:
    record: EmailRecord
    auth: AuthAnalysis
    hops: HopAnalysis
    indicators: IndicatorAnalysis
    extra: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- loading


@lru_cache(maxsize=4)
def load_rules(path: Path | None = None) -> RuleSet:
    path = path or rules_dir() / "scoring.yaml"
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise RuleError(f"scoring rules not found at {path}") from exc
    if not isinstance(raw, dict) or "rules" not in raw:
        raise RuleError(f"{path}: expected a mapping with a 'rules' list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw["rules"] or []):
        if not isinstance(entry, dict):
            raise RuleError(f"{path}: rule #{i} is not a mapping")
        try:
            rule = Rule(
                id=str(entry["id"]),
                description=str(entry["description"]),
                weight=int(entry["weight"]),
                category=str(entry["category"]),
                rationale=str(entry["rationale"]),
                when=dict(entry["when"]),
                supersedes=tuple(entry.get("supersedes", []) or []),
                weight_per=str(entry.get("weight_per", "") or ""),
                max_weight=int(entry["max_weight"]) if "max_weight" in entry else None,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuleError(
                f"{path}: rule #{i} ({entry.get('id', '?')}) is invalid: {exc}"
            ) from exc
        if rule.id in seen:
            raise RuleError(f"{path}: duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        rules.append(rule)

    verdict_map = raw.get("verdicts") or {}
    verdicts: list[tuple[Verdict, int]] = []
    for name, floor in verdict_map.items():
        try:
            verdicts.append((Verdict(str(name)), int(floor)))
        except ValueError as exc:
            raise RuleError(f"{path}: unknown verdict {name!r}") from exc
    if not verdicts:
        verdicts = [
            (Verdict.CLEAN, 0),
            (Verdict.SUSPICIOUS, 20),
            (Verdict.LIKELY_PHISH, 50),
            (Verdict.MALICIOUS, 80),
        ]
    verdicts.sort(key=lambda v: v[1])
    return RuleSet(rules=tuple(rules), verdicts=tuple(verdicts), source=path)


# --------------------------------------------------------------------------- scoring


def score(
    record: EmailRecord,
    auth: AuthAnalysis,
    hops: HopAnalysis,
    indicators: IndicatorAnalysis,
    ruleset: RuleSet | None = None,
) -> ScoreResult:
    """Evaluate every rule and produce a capped score, verdict and evidence."""
    ruleset = ruleset or load_rules()
    ctx = _Context(record=record, auth=auth, hops=hops, indicators=indicators)

    fired: dict[str, FiredRule] = {}
    for rule in ruleset.rules:
        matched, evidence = evaluate(rule.when, ctx)
        if not matched:
            continue
        weight = rule.weight
        if rule.weight_per == "keyword_category":
            weight = rule.weight * max(1, len(indicators.keyword_categories))
        if rule.max_weight is not None:
            weight = min(weight, rule.max_weight)
        fired[rule.id] = FiredRule(
            id=rule.id,
            description=rule.description,
            weight=weight,
            category=rule.category,
            rationale=rule.rationale,
            evidence=evidence,
        )

    for rule in ruleset.rules:
        if rule.id in fired:
            for loser in rule.supersedes:
                fired.pop(loser, None)

    ordered = sorted(fired.values(), key=lambda r: (-r.weight, r.id))
    raw = sum(r.weight for r in ordered)
    total = max(0, min(100, raw))
    return ScoreResult(
        score=total, raw_score=raw, verdict=ruleset.verdict_for(total), fired=ordered
    )


# --------------------------------------------------------------------------- conditions


def evaluate(cond: dict[str, Any], ctx: _Context) -> tuple[bool, list[str]]:
    """Evaluate one condition. Returns ``(matched, evidence_lines)``."""
    if not isinstance(cond, dict) or not cond:
        raise RuleError(f"condition must be a non-empty mapping, got {cond!r}")

    if "all" in cond:
        evidence: list[str] = []
        for sub in cond["all"]:
            ok, ev = evaluate(sub, ctx)
            if not ok:
                return False, []
            evidence.extend(ev)
        return True, evidence
    if "any" in cond:
        for sub in cond["any"]:
            ok, ev = evaluate(sub, ctx)
            if ok:
                return True, ev
        return False, []
    if "not" in cond:
        ok, _ = evaluate(cond["not"], ctx)
        return (not ok), []
    if "field" in cond:
        return _eval_field(cond, ctx)
    if "flag" in cond:
        return _eval_flag(cond, ctx)
    if "enrichment" in cond:
        return _eval_enrichment(cond["enrichment"], ctx)
    if "keywords" in cond:
        cats = ctx.indicators.keyword_categories
        if not cats:
            return False, []
        return True, [f"{cat}: {', '.join(words)}" for cat, words in cats.items()]
    raise RuleError(f"unknown condition {cond!r}")


def _resolve(path: str, ctx: _Context) -> Any:
    node: Any = ctx
    for part in path.split("."):
        node = node.get(part) if isinstance(node, dict) else getattr(node, part, None)
        if node is None:
            return None
    return node


def _describe(value: Any) -> str:
    if isinstance(value, list):
        parts = []
        for item in value:
            if dataclasses.is_dataclass(item) and hasattr(item, "reason"):
                parts.append(str(item.reason))
            else:
                parts.append(str(item))
        return "; ".join(parts) if parts else "(empty)"
    if hasattr(value, "value") and not isinstance(value, str | int | float):
        return str(value.value)
    return str(value)


def _eval_field(cond: dict[str, Any], ctx: _Context) -> tuple[bool, list[str]]:
    path = cond["field"]
    value = _resolve(path, ctx)
    label = path.split(".")[-1]
    comparable = value.value if hasattr(value, "value") and not isinstance(value, int) else value

    if "equals" in cond:
        ok = comparable == cond["equals"]
    elif "in" in cond:
        ok = comparable in cond["in"]
    elif "not_in" in cond:
        ok = comparable not in cond["not_in"]
    elif "is_true" in cond:
        ok = (value is True) == bool(cond["is_true"])
    elif "is_false" in cond:
        ok = (value is False) == bool(cond["is_false"])
    elif "is_none" in cond:
        ok = (value is None) == bool(cond["is_none"])
    elif "not_empty" in cond:
        ok = bool(value) == bool(cond["not_empty"])
    elif "gte" in cond:
        ok = value is not None and value >= cond["gte"]
    elif "lte" in cond:
        ok = value is not None and value <= cond["lte"]
    elif "contains" in cond:
        ok = value is not None and cond["contains"] in value
    else:
        raise RuleError(f"field condition on {path!r} has no comparison")

    if not ok:
        return False, []
    evidence = [f"{label} = {_describe(value)}"]
    # Attach the human-readable flags the analysis modules produced, where relevant.
    owner = _resolve(path.rsplit(".", 1)[0], ctx) if "." in path else None
    for f in getattr(owner, "flags", []) or []:
        related = label.replace("_", " ").split()[0] in f.lower()
        if related and f not in evidence:
            evidence.append(f)
    detail = getattr(value, "detail", "") if not isinstance(value, str | bool) else ""
    if detail:
        evidence.append(detail)
    if label == "display_name_spoof" and ctx.auth.display_name_spoof_reason:
        evidence = [ctx.auth.display_name_spoof_reason]
    if label == "reply_to_mismatch":
        evidence = [f"Reply-To {ctx.record.reply_to_addr} vs From {ctx.record.from_addr}"]
    if label in ("spf_aligned", "dkim_aligned"):
        evidence = [f for f in ctx.auth.flags if "align" in f] or evidence
    if label == "status":
        mech = _resolve(path.rsplit(".", 1)[0], ctx)
        domain = getattr(mech, "domain", "")
        evidence = [f"{mech.mechanism.upper()} {comparable}" + (f" ({domain})" if domain else "")]
        if getattr(mech, "detail", ""):
            evidence.append(mech.detail)
    return True, evidence


def _eval_flag(cond: dict[str, Any], ctx: _Context) -> tuple[bool, list[str]]:
    flag = cond["flag"]
    scope = cond.get("scope", "any")
    if scope != "any" and scope not in _INDICATOR_GROUPS:
        raise RuleError(f"flag scope must be one of {_INDICATOR_GROUPS} or 'any', got {scope!r}")
    groups = _INDICATOR_GROUPS if scope == "any" else (scope,)
    evidence: list[str] = []
    for group in groups:
        for item in getattr(ctx.indicators, group, []):
            if flag in item.flags:
                value = getattr(item, "value", None) or getattr(item, "filename", "?")
                detail = item.details.get(flag, "")
                evidence.append(f"{value}" + (f": {detail}" if detail else ""))
    return bool(evidence), evidence


def _all_enrichment(ctx: _Context) -> list[tuple[str, EnrichmentResult]]:
    out: list[tuple[str, EnrichmentResult]] = []
    for group in _INDICATOR_GROUPS:
        for item in getattr(ctx.indicators, group, []):
            label = getattr(item, "value", None) or getattr(item, "filename", "?")
            for res in item.enrichment:
                out.append((label, res))
    return out


def _eval_enrichment(spec: dict[str, Any], ctx: _Context) -> tuple[bool, list[str]]:
    source = spec.get("source")
    statuses = spec.get("status")
    if isinstance(statuses, str):
        statuses = [statuses]
    data_gte: dict[str, Any] = spec.get("data_gte") or {}
    data_lt: dict[str, Any] = spec.get("data_lt") or {}
    evidence: list[str] = []
    for label, res in _all_enrichment(ctx):
        if source and res.source != source:
            continue
        if statuses and res.status.value not in statuses:
            continue
        if any(
            not isinstance(res.data.get(k), int | float) or res.data[k] < v
            for k, v in data_gte.items()
        ):
            continue
        if any(
            not isinstance(res.data.get(k), int | float) or res.data[k] >= v
            for k, v in data_lt.items()
        ):
            continue
        evidence.append(f"{label}: {res.summary}")
    return bool(evidence), evidence
