"""Render a :class:`TriageResult` for the terminal, as JSON, or as Markdown."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishtriage.indicators import defang as _defang
from phishtriage.models import (
    AttachmentAnalysis,
    AuthResult,
    AuthStatus,
    Indicator,
    TriageResult,
    Verdict,
    to_jsonable,
)

VERDICT_COLORS = {
    Verdict.CLEAN: "green",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.LIKELY_PHISH: "dark_orange",
    Verdict.MALICIOUS: "red",
}

_STATUS_STYLE = {
    AuthStatus.PASS: "green",
    AuthStatus.FAIL: "red",
    AuthStatus.SOFTFAIL: "dark_orange",
    AuthStatus.PERMERROR: "red",
    AuthStatus.TEMPERROR: "yellow",
    AuthStatus.NONE: "yellow",
    AuthStatus.MISSING: "yellow",
    AuthStatus.NEUTRAL: "yellow",
    AuthStatus.POLICY: "yellow",
}


def _d(value: str, defang: bool) -> str:
    return _defang(value) if defang else value


def _when(value: datetime | None, raw: str = "") -> str:
    if value is None:
        return raw or "(missing)"
    return value.strftime("%Y-%m-%d %H:%M:%S %z").strip()


def _yes_no(value: bool | None) -> str:
    if value is None:
        return "n/a"
    return "yes" if value else "no"


def score_bar(score: int, width: int = 20, *, ascii_only: bool = False) -> str:
    filled = round(score / 100 * width)
    full, empty = ("#", "-") if ascii_only else ("█", "░")
    return full * filled + empty * (width - filled)


def _ascii_only(console: Console) -> bool:
    return not (console.encoding or "").lower().replace("-", "").startswith("utf")


# --------------------------------------------------------------------------- terminal


def render_terminal(result: TriageResult, console: Console, *, defang: bool = True) -> None:
    console.print(_header_panel(result, ascii_only=_ascii_only(console)))
    console.print(_auth_table(result))
    console.print(_hops_panel(result))
    console.print(_indicators_table(result, defang))
    if result.indicators.attachments:
        console.print(_attachments_table(result))
    console.print(_why_panel(result, defang))
    if result.record.warnings:
        console.print(Text("Warnings: " + "; ".join(result.record.warnings), style="dim"))
    console.print(_footer(result), style="dim")


def _header_panel(result: TriageResult, *, ascii_only: bool = False) -> Panel:
    rec, sc = result.record, result.score
    color = VERDICT_COLORS[sc.verdict]
    body = Table.grid(padding=(0, 2))
    body.add_column(style="bold", no_wrap=True)
    body.add_column()
    body.add_row("Subject", rec.subject or "(none)")
    sender = (
        f"{rec.from_display} <{rec.from_addr}>" if rec.from_display else rec.from_addr or "(none)"
    )
    body.add_row("From", sender)
    body.add_row("Date", _when(rec.date, rec.date_raw))
    body.add_row("Verdict", Text(f"{sc.verdict}  {sc.score}/100", style=f"bold {color}"))
    body.add_row("", Text(score_bar(sc.score, ascii_only=ascii_only), style=color))
    title = Path(rec.source).name if rec.source else "phishtriage"
    return Panel(body, title=f"[bold]{title}[/bold]", border_style=color, expand=True)


def _auth_table(result: TriageResult) -> Table:
    a = result.auth
    t = Table(title="Authentication", box=box.SIMPLE_HEAD, show_edge=False, expand=True)
    t.add_column("Mechanism", style="bold")
    t.add_column("Result")
    t.add_column("Aligned?")
    t.add_column("Domain checked")
    t.add_column("Notes", overflow="fold")

    def row(res: AuthResult, aligned: bool | None) -> None:
        style = _STATUS_STYLE.get(res.status, "")
        t.add_row(
            res.mechanism.upper(),
            Text(str(res.status), style=style),
            _yes_no(aligned),
            res.domain or "-",
            res.detail or "",
        )

    row(a.spf, a.spf_aligned)
    row(a.dkim, a.dkim_aligned)
    row(a.dmarc, None)
    extras: list[str] = []
    if a.no_auth_headers:
        extras.append("no Authentication-Results header present")
    if a.reply_to_mismatch:
        extras.append(f"Reply-To mismatch: {result.record.reply_to_addr}")
    if a.display_name_spoof:
        extras.append(f"display-name spoof: {a.display_name_spoof_reason}")
    if a.live_dns_detail:
        extras.append(a.live_dns_detail)
    if extras:
        t.caption = " | ".join(extras)
        t.caption_justify = "left"
    return t


def _hops_panel(result: TriageResult) -> Panel:
    h = result.hops
    lines: list[Text] = []
    if not h.hops:
        lines.append(Text("No Received headers", style="yellow"))
    for i, hop in enumerate(h.hops, 1):
        src = hop.from_host or "?"
        if hop.from_ip:
            src += f" [{hop.from_ip}]"
        line = Text(f"{i:>2}. {src} -> {hop.by_host or '?'}")
        if hop.with_protocol:
            line.append(f"  ({hop.with_protocol})", style="dim")
        line.append(f"  {_when(hop.timestamp)}", style="dim")
        for flag in hop.flags:
            style = "dim" if "internal relay" in flag else "red"
            line.append(f"  <{flag}>", style=style)
        lines.append(line)
    if h.first_external_ip:
        origin = Text(f"External origin: {h.first_external_ip}", style="bold")
        if h.origin_country:
            origin.append(f" ({h.origin_country})")
        lines.append(origin)
    return Panel(Group(*lines), title="Hop chain (origin first)", box=box.SIMPLE, expand=True)


def _indicators_table(result: TriageResult, defang: bool) -> Table:
    ind = result.indicators
    t = Table(title="Indicators", box=box.SIMPLE_HEAD, show_edge=False, expand=True)
    t.add_column("Type", style="bold", no_wrap=True)
    t.add_column("Value", overflow="fold")
    t.add_column("Flags", overflow="fold")
    t.add_column("Enrichment", overflow="fold")

    def add(item: Indicator) -> None:
        flags = ", ".join(item.flags)
        enrich = "; ".join(r.summary for r in item.enrichment) or (
            "not checked (offline)" if result.offline else ""
        )
        t.add_row(
            str(item.type),
            _d(item.value, defang),
            Text(flags, style="red" if flags else ""),
            enrich,
        )

    for item in ind.urls + ind.domains + ind.ips:
        add(item)
    if not (ind.urls or ind.domains or ind.ips):
        t.add_row("-", "(no indicators)", "", "")
    if ind.link_mismatches:
        t.caption = "Link mismatches: " + " | ".join(
            f"'{_d(m.text[:40], defang)}' -> {_d(m.href, defang)}" for m in ind.link_mismatches
        )
        t.caption_justify = "left"
    return t


def _attachments_table(result: TriageResult) -> Table:
    t = Table(title="Attachments", box=box.SIMPLE_HEAD, show_edge=False, expand=True)
    t.add_column("Filename", overflow="fold")
    t.add_column("Declared")
    t.add_column("Magic")
    t.add_column("Size", justify="right")
    t.add_column("SHA-256", overflow="fold")
    t.add_column("Flags", overflow="fold")
    t.add_column("Enrichment", overflow="fold")
    for att in result.indicators.attachments:
        flags = ", ".join(att.flags)
        enrich = "; ".join(r.summary for r in att.enrichment) or (
            "not checked (offline)" if result.offline else ""
        )
        t.add_row(
            att.filename,
            att.declared_mime,
            att.magic_mime or "?",
            str(att.size),
            att.sha256,
            Text(flags, style="red" if flags else ""),
            enrich,
        )
    return t


def _why_panel(result: TriageResult, defang: bool = True) -> Panel:
    sc = result.score
    t = Table(box=box.SIMPLE_HEAD, show_edge=False, expand=True)
    t.add_column("Weight", justify="right", style="bold")
    t.add_column("Rule")
    t.add_column("Evidence", overflow="fold")
    if not sc.fired:
        t.add_row("0", "No rules fired", "")
    for rule in sc.fired:
        t.add_row(
            f"+{rule.weight}",
            f"{rule.description}\n[dim]{rule.id} | {rule.category}[/dim]",
            "\n".join(_d(ev, defang) for ev in rule.evidence),
        )
    total = f"Total {sc.score}/100"
    if sc.raw_score > 100:
        total += f" (raw {sc.raw_score}, capped)"
    color = VERDICT_COLORS[sc.verdict]
    return Panel(
        Group(t, Text(total, style=f"bold {color}")),
        title="Why this verdict",
        box=box.SIMPLE,
        expand=True,
    )


def _footer(result: TriageResult) -> str:
    s = result.enrichment_stats
    mode = " (offline)" if result.offline else ""
    return (
        f"{s.lookups} enrichment lookups ({s.cached} cached){mode}, "
        f"took {result.elapsed_seconds:.1f}s"
    )


# --------------------------------------------------------------------------- JSON


def to_dict(result: TriageResult) -> dict[str, Any]:
    data = to_jsonable(result)
    data["version"] = 1
    return data


def write_json(result: TriageResult, path: str | Path) -> None:
    Path(path).write_text(json.dumps(to_dict(result), indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- Markdown


def to_markdown(result: TriageResult, *, defang: bool = True) -> str:
    rec, a, h, ind, sc = result.record, result.auth, result.hops, result.indicators, result.score
    out: list[str] = []
    name = Path(rec.source).name if rec.source else "email"
    out.append(f"# Phishing triage: {name}")
    out.append("")
    out.append(f"**Verdict: {sc.verdict} ({sc.score}/100)**")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| Subject | {_md(rec.subject)} |")
    sender = f"{rec.from_display} <{rec.from_addr}>" if rec.from_display else rec.from_addr
    out.append(f"| From | {_md(_d(sender, defang))} |")
    if rec.reply_to_addr:
        out.append(f"| Reply-To | {_md(_d(rec.reply_to_addr, defang))} |")
    if rec.return_path:
        out.append(f"| Return-Path | {_md(_d(rec.return_path, defang))} |")
    out.append(f"| Date | {_when(rec.date, rec.date_raw)} |")
    out.append(f"| Message-ID | {_md(rec.message_id or '(missing)')} |")
    out.append("")

    out.append("## Authentication")
    out.append("")
    out.append("| Mechanism | Result | Aligned | Domain | Notes |")
    out.append("|---|---|---|---|---|")
    for res, aligned in ((a.spf, a.spf_aligned), (a.dkim, a.dkim_aligned), (a.dmarc, None)):
        out.append(
            f"| {res.mechanism.upper()} | {res.status} | {_yes_no(aligned)} | "
            f"{_md(res.domain or '-')} | {_md(res.detail)} |"
        )
    for flag in a.flags:
        out.append(f"- {_md(flag)}")
    out.append("")

    out.append("## Hop chain (origin first)")
    out.append("")
    if not h.hops:
        out.append("_No Received headers._")
    for i, hop in enumerate(h.hops, 1):
        src = hop.from_host or "?"
        if hop.from_ip:
            src += f" [{_d(hop.from_ip, defang)}]"
        line = f"{i}. {_md(src)} -> {_md(hop.by_host or '?')} ({_when(hop.timestamp)})"
        if hop.flags:
            line += " **" + "; ".join(hop.flags) + "**"
        out.append(line)
    if h.first_external_ip:
        origin = f"External origin: {_d(h.first_external_ip, defang)}"
        if h.origin_country:
            origin += f" ({h.origin_country})"
        out.append("")
        out.append(origin)
    out.append("")

    out.append("## Indicators")
    out.append("")
    out.append("| Type | Value | Flags | Enrichment |")
    out.append("|---|---|---|---|")
    for item in ind.urls + ind.domains + ind.ips:
        enrich = "; ".join(r.summary for r in item.enrichment)
        value = _md(_d(item.value, defang))
        out.append(f"| {item.type} | `{value}` | {', '.join(item.flags)} | {_md(enrich)} |")
    if ind.link_mismatches:
        out.append("")
        for m in ind.link_mismatches:
            out.append(f"- Link text `{_md(m.text[:60])}` points to `{_md(_d(m.href, defang))}`")
    out.append("")

    if ind.attachments:
        out.append("## Attachments")
        out.append("")
        out.append("| Filename | Declared | Magic | Size | SHA-256 | Flags |")
        out.append("|---|---|---|---:|---|---|")
        for att in ind.attachments:
            out.append(_md_attachment(att))
        out.append("")

    out.append("## Why this verdict")
    out.append("")
    if not sc.fired:
        out.append("_No rules fired._")
    for rule in sc.fired:
        out.append(f"- **+{rule.weight} {rule.description}** (`{rule.id}`)")
        for ev in rule.evidence:
            out.append(f"  - {_md(_d(ev, defang))}")
        out.append(f"  - _{rule.rationale}_")
    out.append("")
    out.append(
        f"Total: **{sc.score}/100**" + (f" (raw {sc.raw_score})" if sc.raw_score > 100 else "")
    )
    out.append("")
    out.append(f"_{_footer(result)}_")
    return "\n".join(out) + "\n"


def _md_attachment(att: AttachmentAnalysis) -> str:
    return (
        f"| `{_md(att.filename)}` | {att.declared_mime} | {att.magic_mime or '?'} | {att.size} | "
        f"`{att.sha256}` | {', '.join(att.flags)} |"
    )


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def write_markdown(result: TriageResult, path: str | Path, *, defang: bool = True) -> None:
    Path(path).write_text(to_markdown(result, defang=defang), encoding="utf-8")
