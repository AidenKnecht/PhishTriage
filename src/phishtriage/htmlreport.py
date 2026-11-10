"""Render a :class:`TriageResult` as one self-contained HTML file.

Built for sharing and for a projector: no JavaScript, no external fonts,
images or stylesheets, and a Content-Security-Policy that forbids loading
anything at all. Every value taken from the email is HTML-escaped and
defanged, and no indicator is ever rendered as a link. The only links in the
file point at attack.mitre.org technique pages.

Colour follows the reference data-viz palette: rule categories take fixed
categorical slots (so "links" is always the same colour, in every report),
and the verdict uses the reserved status colours, always next to an icon and
a text label so colour never carries meaning alone.
"""

from __future__ import annotations

from collections import defaultdict
from html import escape
from pathlib import Path

from phishtriage import __version__
from phishtriage.indicators import defang as _defang
from phishtriage.models import (
    AuthResult,
    AuthStatus,
    EnrichmentResult,
    EnrichStatus,
    FiredRule,
    TriageResult,
    Verdict,
)
from phishtriage.scoring import RuleError, load_rules

CATEGORY_ORDER = (
    "authentication",
    "alignment",
    "sender",
    "links",
    "attachments",
    "content",
    "hops",
    "enrichment",
)
"""Fixed categorical slot per rule category; the stack is drawn in this order."""

_VERDICT_STYLE = {
    Verdict.CLEAN: ("good", "&#10003;"),
    Verdict.SUSPICIOUS: ("warning", "!"),
    Verdict.LIKELY_PHISH: ("serious", "!!"),
    Verdict.MALICIOUS: ("critical", "&#10005;"),
}

_AUTH_STYLE = {
    AuthStatus.PASS: "good",
    AuthStatus.FAIL: "critical",
    AuthStatus.PERMERROR: "critical",
    AuthStatus.SOFTFAIL: "serious",
}

_ENRICH_STYLE = {
    EnrichStatus.MALICIOUS: "critical",
    EnrichStatus.SUSPICIOUS: "serious",
    EnrichStatus.CLEAN: "good",
}

_CSS = """
.pt {
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --ring: rgba(11,11,11,0.10);
  --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; --s4: #eda100;
  --s5: #e87ba4; --s6: #008300; --s7: #6250d6; --s8: #e34948;
  --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
  --code-bg: #f0efec; --on-s4: #0b0b0b;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) .pt {
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
    --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s4: #c98500;
    --s5: #d55181; --s6: #008300; --s7: #9085e9; --s8: #e66767;
    --code-bg: #262624; --on-s4: #ffffff;
  }
}
:root[data-theme="dark"] .pt {
  color-scheme: dark;
  --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
  --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s4: #c98500;
  --s5: #d55181; --s6: #008300; --s7: #9085e9; --s8: #e66767;
  --code-bg: #262624; --on-s4: #ffffff;
}
* { box-sizing: border-box; }
body { margin: 0; }
.pt {
  background: var(--page); color: var(--ink); min-height: 100vh;
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; padding: 32px 16px 48px;
}
.wrap { max-width: 1100px; margin: 0 auto; display: grid; gap: 20px; }
.card {
  background: var(--surface); border: 1px solid var(--ring); border-radius: 12px;
  padding: 20px 24px;
}
h1 { font-size: 15px; font-weight: 600; color: var(--ink-2); margin: 0 0 12px; }
h2 { font-size: 18px; margin: 0 0 14px; }
.subject { font-size: 26px; font-weight: 650; line-height: 1.25; margin: 0 0 12px;
  overflow-wrap: anywhere; }
.meta { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; color: var(--ink-2); }
.meta dt { color: var(--muted); }
.meta dd { margin: 0; overflow-wrap: anywhere; }
.hero { display: grid; grid-template-columns: max-content 1fr; gap: 28px; align-items: center;
  margin-top: 20px; }
.score { font-size: 64px; font-weight: 700; line-height: 1; }
.score small { font-size: 22px; color: var(--muted); font-weight: 500; }
.pill { display: inline-flex; align-items: center; gap: 8px; border-radius: 999px;
  padding: 4px 14px; font-weight: 700; letter-spacing: .02em; color: #fff; }
.pill.lg { font-size: 20px; padding: 6px 18px; margin-top: 10px; }
.pill.sm { font-size: 13px; padding: 1px 10px; font-weight: 600; }
.good { background: var(--good); } .warning { background: var(--warning); color: #0b0b0b; }
.serious { background: var(--serious); } .critical { background: var(--critical); }
.neutral { background: var(--grid); color: var(--ink); }
.meter { position: relative; height: 14px; background: var(--grid); border-radius: 7px; }
.meter .fill { position: absolute; inset: 0 auto 0 0; border-radius: 7px; }
.meter .tick { position: absolute; top: -4px; bottom: -4px; width: 2px;
  background: var(--surface); }
.bands { position: relative; height: 22px; margin-top: 6px; font-size: 12px; color: var(--muted); }
.bands span { position: absolute; white-space: nowrap; }
.stack { display: flex; gap: 2px; height: 40px; margin-top: 4px; }
.seg { border-radius: 4px; min-width: 6px; display: flex; align-items: center;
  justify-content: center; color: #fff; font-size: 13px; font-weight: 700; overflow: hidden; }
.seg.dark-ink { color: var(--on-s4); }
.cap { font-size: 12px; color: var(--muted); margin-top: 6px; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; margin-top: 12px; font-size: 14px;
  color: var(--ink-2); }
.legend i { display: inline-block; width: 12px; height: 12px; border-radius: 3px;
  margin-right: 6px; vertical-align: -1px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; color: var(--muted); font-weight: 600; font-size: 12px;
  text-transform: uppercase; letter-spacing: .04em; padding: 6px 10px 6px 0;
  border-bottom: 1px solid var(--axis); }
td { padding: 9px 10px 9px 0; border-bottom: 1px solid var(--grid); vertical-align: top;
  overflow-wrap: anywhere; }
tr:last-child td { border-bottom: 0; }
td.num { text-align: right; font-variant-numeric: tabular-nums; font-weight: 700;
  white-space: nowrap; }
code { font: 13px/1.4 ui-monospace, "Cascadia Mono", Consolas, monospace;
  background: var(--code-bg); border-radius: 4px; padding: 1px 5px; overflow-wrap: anywhere; }
.muted { color: var(--muted); } .ink2 { color: var(--ink-2); } .nowrap { white-space: nowrap; }
.small { font-size: 13px; }
.chip { display: inline-block; font-size: 12px; font-weight: 600; border: 1px solid var(--axis);
  border-radius: 4px; padding: 0 6px; margin: 2px 4px 0 0; color: var(--ink-2);
  text-decoration: none; }
a.chip:hover { border-color: var(--ink-2); color: var(--ink); }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 3px;
  margin-right: 6px; vertical-align: 0; }
.flag { display: inline-block; font-size: 12px; border-radius: 4px; padding: 0 6px;
  margin: 1px 4px 1px 0; background: var(--code-bg); color: var(--ink-2); }
.auth { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.auth > div { border: 1px solid var(--grid); border-radius: 10px; padding: 12px 14px; }
.auth b { font-size: 18px; margin-right: 8px; }
ol.hops { margin: 0; padding-left: 22px; }
ol.hops li { padding: 4px 0; }
ul.ev { margin: 0; padding-left: 18px; }
.notes { margin: 12px 0 0; padding-left: 18px; color: var(--ink-2); font-size: 14px; }
footer { color: var(--muted); font-size: 13px; text-align: center; }
@media (max-width: 720px) {
  .auth, .hero { grid-template-columns: 1fr; }
}
@media (forced-colors: active) { .seg, .fill, .pill { border: 1px solid CanvasText; } }
"""


def to_html(result: TriageResult, *, defang: bool = True) -> str:
    """The full report as a standalone HTML document."""
    rec, sc = result.record, result.score
    name = Path(rec.source).name if rec.source else "email"
    title = f"phishtriage: {sc.verdict} {sc.score}/100 - {name}"
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        # Nothing may load: no scripts, images, fonts, frames or remote styles.
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
        '<meta name="referrer" content="no-referrer">',
        f"<title>{_e(title)}</title>",
        f"<style>{_CSS}</style>",
        '</head><body><div class="pt"><main class="wrap">',
        _header(result, defang),
        _breakdown(result),
        _auth(result, defang),
        _hops(result, defang),
        _indicators(result, defang),
        _attachments(result),
        _why(result, defang),
        _footer(result),
        "</main></div></body></html>",
    ]
    return "\n".join(p for p in parts if p) + "\n"


def write_html(result: TriageResult, path: str | Path, *, defang: bool = True) -> None:
    Path(path).write_text(to_html(result, defang=defang), encoding="utf-8")


# --------------------------------------------------------------------------- sections


def _header(result: TriageResult, defang: bool) -> str:
    rec, sc = result.record, result.score
    style, icon = _VERDICT_STYLE[sc.verdict]
    sender = f"{rec.from_display} <{rec.from_addr}>" if rec.from_display else rec.from_addr
    rows = [("From", _code(_d(sender, defang)) if sender else "(none)")]
    if rec.reply_to_addr:
        rows.append(("Reply-To", _code(_d(rec.reply_to_addr, defang))))
    if rec.return_path:
        rows.append(("Return-Path", _code(_d(rec.return_path, defang))))
    rows.append(("Date", _e(_when(result))))
    name = Path(rec.source).name if rec.source else "email"
    rows.append(("File", _code(name)))
    meta = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
    return (
        '<section class="card">'
        "<h1>phishtriage report</h1>"
        f'<p class="subject">{_e(rec.subject or "(no subject)")}</p>'
        f'<dl class="meta">{meta}</dl>'
        '<div class="hero"><div>'
        f'<div class="score">{sc.score}<small> / 100</small></div>'
        f'<span class="pill lg {style}" role="status">'
        f'<span aria-hidden="true">{icon}</span>{_e(str(sc.verdict))}</span>'
        f"</div>{_meter(result)}</div>"
        "</section>"
    )


def _meter(result: TriageResult) -> str:
    sc = result.score
    style, _ = _VERDICT_STYLE[sc.verdict]
    floors = [(str(v), f) for v, f in _bands()]
    ticks = "".join(
        f'<span class="tick" style="left:calc({f}% - 1px)"></span>' for _, f in floors if f
    )
    *lower, (top_name, top_floor) = floors
    labels = "".join(f'<span style="left:{f}%">{_e(name)} {f}+</span>' for name, f in lower)
    labels += f'<span style="right:0">{_e(top_name)} {top_floor}+</span>'
    return (
        '<div aria-label="score meter">'
        f'<div class="meter"><span class="fill {style}" style="width:{sc.score}%"></span>'
        f"{ticks}</div>"
        f'<div class="bands">{labels}</div>'
        "</div>"
    )


def _bands() -> list[tuple[Verdict, int]]:
    """Verdict floors from scoring.yaml, so the meter matches the scorer."""
    try:
        return list(load_rules().verdicts)
    except RuleError:
        return [
            (Verdict.CLEAN, 0),
            (Verdict.SUSPICIOUS, 20),
            (Verdict.LIKELY_PHISH, 50),
            (Verdict.MALICIOUS, 80),
        ]


def _slot(category: str) -> str:
    try:
        return f"var(--s{CATEGORY_ORDER.index(category) + 1})"
    except ValueError:
        return "var(--muted)"


def _dark_ink(category: str) -> bool:
    return category == "links"  # slot 4 (yellow) takes dark text, per the palette


def _breakdown(result: TriageResult) -> str:
    sc = result.score
    if not sc.fired:
        return (
            '<section class="card"><h2>Where the points came from</h2>'
            '<p class="ink2">No rules fired.</p></section>'
        )
    order = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    ranked = sorted(sc.fired, key=lambda r: (order.get(r.category, 99), -r.weight, r.id))
    scale = max(100, sc.raw_score)
    segs = []
    for rule in ranked:
        width = rule.weight / scale * 100
        label = f"+{rule.weight}" if width >= 4 else ""
        ink = " dark-ink" if _dark_ink(rule.category) else ""
        tip = f"{rule.description} ({rule.category}, +{rule.weight})"
        segs.append(
            f'<div class="seg{ink}" title="{_e(tip)}" '
            f'style="flex:0 0 calc({width:.3f}% - 2px);background:{_slot(rule.category)}">'
            f"{label}</div>"
        )
    totals: dict[str, int] = defaultdict(int)
    for rule in ranked:
        totals[rule.category] += rule.weight
    legend = "".join(
        f'<span><i style="background:{_slot(c)}"></i>{_e(c)} +{w}</span>' for c, w in totals.items()
    )
    cap = (
        f"Raw total {sc.raw_score}, capped at 100. Bar scale is the raw total."
        if sc.raw_score > 100
        else "Bar scale is 0-100 points. Hover a segment for the rule."
    )
    return (
        '<section class="card"><h2>Where the points came from</h2>'
        f'<div class="stack" role="img" aria-label="score breakdown by rule">{"".join(segs)}</div>'
        f'<div class="cap">{_e(cap)}</div>'
        f'<div class="legend">{legend}</div>'
        "</section>"
    )


def _auth(result: TriageResult, defang: bool) -> str:
    a = result.auth

    def card(res: AuthResult, aligned: bool | None) -> str:
        style = _AUTH_STYLE.get(res.status, "neutral")
        aligned_txt = (
            "" if aligned is None else f'<div class="small ink2">aligned: {_yes_no(aligned)}</div>'
        )
        domain = _code(_d(res.domain, defang)) if res.domain else '<span class="muted">-</span>'
        detail = f'<div class="small muted">{_e(res.detail)}</div>' if res.detail else ""
        return (
            f"<div><b>{_e(res.mechanism.upper())}</b>"
            f'<span class="pill sm {style}">{_e(str(res.status))}</span>'
            f'{aligned_txt}<div class="small">{domain}</div>{detail}</div>'
        )

    notes = "".join(f"<li>{_e(_d(f, defang))}</li>" for f in a.flags)
    return (
        '<section class="card"><h2>Authentication</h2><div class="auth">'
        + card(a.spf, a.spf_aligned)
        + card(a.dkim, a.dkim_aligned)
        + card(a.dmarc, None)
        + "</div>"
        + (f'<ul class="notes">{notes}</ul>' if notes else "")
        + "</section>"
    )


def _hops(result: TriageResult, defang: bool) -> str:
    h = result.hops
    if not h.hops:
        items = '<p class="ink2">No Received headers.</p>'
    else:
        lis = []
        for hop in h.hops:
            src = _d(hop.from_host, defang) if hop.from_host else "?"
            if hop.from_ip:
                src += f" [{_d(hop.from_ip, defang)}]"
            by = _d(hop.by_host, defang) if hop.by_host else "?"
            proto = f' <span class="muted small">{_e(hop.with_protocol)}</span>'
            when = (
                f' <span class="muted small">{_e(hop.timestamp.isoformat())}</span>'
                if hop.timestamp
                else ""
            )
            flags = "".join(f'<span class="flag">{_e(f)}</span>' for f in hop.flags)
            lis.append(
                f"<li>{_code(src)} &rarr; {_code(by)}"
                f"{proto if hop.with_protocol else ''}{when} {flags}</li>"
            )
        items = f'<ol class="hops">{"".join(lis)}</ol>'
    origin = ""
    if h.first_external_ip:
        country = f" ({_e(h.origin_country)})" if h.origin_country else ""
        origin = (
            f'<p class="ink2">External origin: {_code(_d(h.first_external_ip, defang))}'
            f"{country}</p>"
        )
    return f'<section class="card"><h2>Hop chain, origin first</h2>{items}{origin}</section>'


def _indicators(result: TriageResult, defang: bool) -> str:
    ind = result.indicators
    rows = []
    for item in ind.urls + ind.domains + ind.ips:
        flags = "".join(f'<span class="flag">{_e(f)}</span>' for f in item.flags)
        rows.append(
            f'<tr><td class="nowrap">{_e(str(item.type))}</td>'
            f"<td>{_code(_d(item.value, defang))}</td>"
            f"<td>{flags}</td><td>{_enrichment(result, item.enrichment)}</td></tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="4" class="ink2">No indicators.</td></tr>')
    mism = "".join(
        f"<li>Link text {_code(_d(m.text[:60], defang))} points to {_code(_d(m.href, defang))}</li>"
        for m in ind.link_mismatches
    )
    return (
        '<section class="card"><h2>Indicators</h2><table>'
        "<thead><tr><th>Type</th><th>Value (defanged)</th><th>Flags</th><th>Enrichment</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        + (f'<ul class="notes">{mism}</ul>' if mism else "")
        + "</section>"
    )


def _attachments(result: TriageResult) -> str:
    atts = result.indicators.attachments
    if not atts:
        return ""
    rows = []
    for att in atts:
        flags = "".join(f'<span class="flag">{_e(f)}</span>' for f in att.flags)
        rows.append(
            f"<tr><td>{_code(att.filename)}</td><td>{_e(att.declared_mime)}<br>"
            f'<span class="muted small">magic: {_e(att.magic_mime or "?")}</span></td>'
            f'<td class="num">{att.size:,}</td>'
            f'<td><code>{_e(att.sha256)}</code><br><span class="muted small">md5 '
            f"{_e(att.md5)}</span></td><td>{flags}</td>"
            f"<td>{_enrichment(result, att.enrichment)}</td></tr>"
        )
    return (
        '<section class="card"><h2>Attachments</h2><table><thead><tr><th>File</th>'
        "<th>Type</th><th>Bytes</th><th>Hashes</th><th>Flags</th><th>Enrichment</th></tr>"
        f"</thead><tbody>{''.join(rows)}</tbody></table>"
        '<p class="small muted">Hashed and type-sniffed only. Never opened or executed.</p>'
        "</section>"
    )


def _why(result: TriageResult, defang: bool) -> str:
    sc = result.score
    if not sc.fired:
        body = '<p class="ink2">No rules fired.</p>'
    else:
        body = (
            "<table><thead><tr><th>Points</th><th>Rule</th><th>Evidence</th></tr></thead>"
            f"<tbody>{''.join(_why_row(r, defang) for r in sc.fired)}</tbody></table>"
        )
    total = f"Total {sc.score}/100" + (
        f" (raw {sc.raw_score}, capped)" if sc.raw_score > 100 else ""
    )
    return (
        f'<section class="card"><h2>Why this verdict</h2>{body}<p><b>{_e(total)}</b></p></section>'
    )


def _why_row(rule: FiredRule, defang: bool) -> str:
    chips = "".join(
        f'<a class="chip" href="{_attack_url(t)}" rel="noreferrer noopener" '
        f'target="_blank">ATT&amp;CK {_e(t)}</a>'
        for t in rule.attack
    )
    evidence = "".join(f"<li>{_e(_d(ev, defang))}</li>" for ev in rule.evidence)
    return (
        f'<tr><td class="num">+{rule.weight}</td><td>'
        f'<span class="dot" style="background:{_slot(rule.category)}"></span>'
        f"<b>{_e(rule.description)}</b><br>"
        f'<span class="small muted"><code>{_e(rule.id)}</code> {_e(rule.category)}</span> '
        f'{chips}<div class="small ink2">{_e(rule.rationale)}</div></td>'
        f'<td><ul class="ev">{evidence}</ul></td></tr>'
    )


def _footer(result: TriageResult) -> str:
    s = result.enrichment_stats
    mode = "offline" if result.offline else f"{s.lookups} enrichment lookups ({s.cached} cached)"
    warnings = ""
    if result.record.warnings:
        items = "".join(f"<li>{_e(w)}</li>" for w in result.record.warnings)
        warnings = f'<section class="card"><h2>Parser warnings</h2><ul>{items}</ul></section>'
    return (
        f"{warnings}<footer>phishtriage {_e(__version__)} &middot; {_e(mode)} &middot; "
        f"took {result.elapsed_seconds:.1f}s<br>Indicators are defanged and never linked. "
        "This file runs no scripts and loads nothing from the network.</footer>"
    )


# --------------------------------------------------------------------------- helpers


def _enrichment(result: TriageResult, results: list[EnrichmentResult]) -> str:
    if not results:
        return '<span class="muted">not checked (offline)</span>' if result.offline else ""
    out = []
    for r in results:
        style = _ENRICH_STYLE.get(r.status)
        badge = (
            f'<span class="pill sm {style}">{_e(str(r.status))}</span>'
            if style
            else f'<span class="muted">{_e(str(r.status))}</span>'
        )
        detail = f' <span class="small ink2">{_e(r.detail)}</span>' if r.detail else ""
        out.append(f"<div>{_e(r.source)} {badge}{detail}</div>")
    return "".join(out)


def _attack_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + escape(technique.replace(".", "/")) + "/"


def _when(result: TriageResult) -> str:
    rec = result.record
    if rec.date is None:
        return rec.date_raw or "(missing)"
    return rec.date.strftime("%Y-%m-%d %H:%M:%S %z").strip()


def _yes_no(value: bool | None) -> str:
    return "n/a" if value is None else ("yes" if value else "no")


def _d(value: str, defang: bool) -> str:
    return _defang(value) if defang else value


def _e(value: str) -> str:
    return escape(value, quote=True)


def _code(value: str) -> str:
    return f"<code>{_e(value)}</code>"
