"""Command-line interface: ``phishtriage analyze | batch | rules | cache``."""

from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from phishtriage import __version__
from phishtriage.enrich.base import Cache
from phishtriage.models import TriageResult, Verdict
from phishtriage.pipeline import EnrichmentRunner, eml_files, triage
from phishtriage.report import VERDICT_COLORS, render_terminal, write_json, write_markdown
from phishtriage.scoring import RuleError, load_rules

app = typer.Typer(
    help="SOC-style phishing email triage. Parses .eml files, checks auth and alignment, "
    "walks the Received chain, extracts indicators, enriches them, and scores a verdict.",
    no_args_is_help=True,
    add_completion=False,
)
cache_app = typer.Typer(help="Manage the enrichment cache.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")

console = Console()
err_console = Console(stderr=True)


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env loader: KEY=value lines, no expansion, never overrides real env."""
    path = path or Path.cwd() / ".env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def _version(value: bool) -> None:
    if value:
        console.print(f"phishtriage {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    load_dotenv()


def _runner(offline: bool) -> EnrichmentRunner | None:
    if offline:
        return None
    try:
        from phishtriage.enrich.runner import build_runner
    except ImportError:  # pragma: no cover - only before step 6 lands
        err_console.print("[yellow]Enrichment not available; running offline.[/yellow]")
        return None
    return build_runner()


OfflineOpt = Annotated[bool, typer.Option("--offline", help="Skip all enrichment lookups.")]
LiveDnsOpt = Annotated[
    bool, typer.Option("--live-dns", help="Resolve SPF and reverse DNS live (needs dnspython).")
]


@app.command()
def analyze(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    offline: OfflineOpt = False,
    live_dns: LiveDnsOpt = False,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write the full structured result to this file.")
    ] = None,
    markdown_out: Annotated[
        Path | None, typer.Option("--markdown", help="Write a Markdown report to this file.")
    ] = None,
    no_defang: Annotated[
        bool, typer.Option("--no-defang", help="Print live URLs instead of hxxp://x[.]y.")
    ] = False,
) -> None:
    """Triage one .eml file and print the report."""
    try:
        result = triage(file, offline=offline, live_dns=live_dns, enricher=_runner(offline))
    except RuleError as exc:
        err_console.print(f"[red]Rules error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    render_terminal(result, console, defang=not no_defang)
    if json_out is not None:
        write_json(result, json_out)
        console.print(f"[dim]JSON written to {json_out}[/dim]")
    if markdown_out is not None:
        write_markdown(result, markdown_out, defang=not no_defang)
        console.print(f"[dim]Markdown written to {markdown_out}[/dim]")


@app.command()
def batch(
    directory: Annotated[Path, typer.Argument(exists=True, file_okay=False, readable=True)],
    offline: OfflineOpt = False,
    live_dns: LiveDnsOpt = False,
    csv_out: Annotated[
        Path | None, typer.Option("--csv", help="Write one row per email to this CSV file.")
    ] = None,
) -> None:
    """Triage every .eml under a directory and print a summary table.

    If the files live under folders named 'phish' and 'benign', a confusion
    matrix is printed at the bottom (phish should score >= 50, benign < 50).
    """
    files = eml_files(directory)
    if not files:
        err_console.print(f"[yellow]No .eml files found under {directory}[/yellow]")
        raise typer.Exit(code=1)
    runner = _runner(offline)
    results: list[tuple[Path, TriageResult]] = []
    with console.status("Analysing...") as status:
        for path in files:
            status.update(f"Analysing {path.name}")
            results.append(
                (path, triage(path, offline=offline, live_dns=live_dns, enricher=runner))
            )

    console.print(_batch_table(results, directory))
    matrix = _confusion(results)
    if matrix is not None:
        console.print(matrix)
    if csv_out is not None:
        _write_csv(results, directory, csv_out)
        console.print(f"[dim]CSV written to {csv_out}[/dim]")


def _label(path: Path) -> str | None:
    parts = {p.lower() for p in path.parts}
    if "phish" in parts:
        return "phish"
    if "benign" in parts:
        return "benign"
    return None


def _batch_table(results: list[tuple[Path, TriageResult]], base: Path) -> Table:
    t = Table(title=f"phishtriage batch: {base}", box=box.SIMPLE_HEAD, expand=True)
    t.add_column("File", overflow="fold")
    t.add_column("From", overflow="fold")
    t.add_column("Subject", overflow="fold", max_width=40)
    t.add_column("Score", justify="right")
    t.add_column("Verdict")
    t.add_column("Top rule", overflow="fold")
    for path, r in results:
        try:
            shown = str(path.relative_to(base))
        except ValueError:
            shown = path.name
        color = VERDICT_COLORS[r.score.verdict]
        top = r.score.fired[0].id if r.score.fired else "-"
        t.add_row(
            shown,
            r.record.from_addr or "(none)",
            r.record.subject,
            Text(str(r.score.score), style=color),
            Text(str(r.score.verdict), style=f"bold {color}"),
            top,
        )
    return t


def _confusion(results: list[tuple[Path, TriageResult]]) -> Table | None:
    labelled = [(lbl, r) for p, r in results if (lbl := _label(p)) is not None]
    if not labelled:
        return None
    tp = sum(1 for lbl, r in labelled if lbl == "phish" and r.score.score >= 50)
    fn = sum(1 for lbl, r in labelled if lbl == "phish" and r.score.score < 50)
    tn = sum(1 for lbl, r in labelled if lbl == "benign" and r.score.score < 50)
    fp = sum(1 for lbl, r in labelled if lbl == "benign" and r.score.score >= 50)
    t = Table(title="Confusion matrix (threshold 50)", box=box.SIMPLE_HEAD)
    t.add_column("")
    t.add_column("scored >= 50", justify="right")
    t.add_column("scored < 50", justify="right")
    t.add_row("phish/", Text(str(tp), style="green"), Text(str(fn), style="red" if fn else ""))
    t.add_row("benign/", Text(str(fp), style="red" if fp else ""), Text(str(tn), style="green"))
    total = tp + fn + tn + fp
    t.caption = f"{tp + tn}/{total} correct; {fn} missed, {fp} false alarms"
    return t


def _write_csv(results: list[tuple[Path, TriageResult]], base: Path, out: Path) -> None:
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["file", "label", "from", "subject", "score", "verdict", "top_rule", "rules"])
        for path, r in results:
            try:
                shown = str(path.relative_to(base))
            except ValueError:
                shown = path.name
            w.writerow(
                [
                    shown,
                    _label(path) or "",
                    r.record.from_addr,
                    r.record.subject,
                    r.score.score,
                    str(r.score.verdict),
                    r.score.fired[0].id if r.score.fired else "",
                    " ".join(f"{f.id}({f.weight})" for f in r.score.fired),
                ]
            )


@app.command()
def rules() -> None:
    """Print every scoring rule from rules/scoring.yaml."""
    try:
        rs = load_rules()
    except RuleError as exc:
        err_console.print(f"[red]Rules error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    t = Table(title=f"Scoring rules ({rs.source})", box=box.SIMPLE_HEAD, expand=True)
    t.add_column("ID", style="bold", no_wrap=True)
    t.add_column("Category", no_wrap=True)
    t.add_column("Weight", justify="right")
    t.add_column("Description", overflow="fold")
    t.add_column("Rationale", overflow="fold")
    for rule in rs.rules:
        weight = str(rule.weight)
        if rule.max_weight is not None:
            weight += f" (max {rule.max_weight})"
        t.add_row(rule.id, rule.category, weight, rule.description, rule.rationale)
    console.print(t)
    bands = ", ".join(f"{v} >= {floor}" for v, floor in rs.verdicts if v is not Verdict.CLEAN)
    console.print(f"[dim]Verdicts: CLEAN below the first band; {bands}[/dim]")


@cache_app.command("clear")
def cache_clear() -> None:
    """Delete every cached enrichment result."""
    cache = Cache.default()
    removed = cache.clear()
    console.print(f"Removed {removed} cached result(s) from {cache.root}")


@cache_app.command("info")
def cache_info() -> None:
    """Show where the cache lives and how many entries it holds."""
    cache = Cache.default()
    console.print(
        f"{cache.root}: {cache.count()} cached result(s), TTL {cache.ttl_seconds // 3600}h"
    )


if __name__ == "__main__":  # pragma: no cover
    app()
