"""Render phishtriage output to PNG for the README and writeup.

Rich records the exact terminal rendering as HTML; a headless Edge/Chrome
turns that into a PNG. No extra Python dependencies.

Usage:
    uv run python scripts/screenshot.py                     # all shots, offline
    uv run python scripts/screenshot.py analyze             # just one
    uv run python scripts/screenshot.py --online            # with URLhaus/VirusTotal/RDAP

--online reads API keys from .env like the CLI does. VirusTotal's free tier
allows 4 lookups a minute, so the first online batch shot can take a long
time; results are cached for 24 hours, so reruns are fast.
"""

from __future__ import annotations

import dataclasses
import io
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from rich.console import Console
from rich.terminal_theme import TerminalTheme

from phishtriage.cli import (
    _batch_table,
    _confusion,
    _print_compare,
    _runner,
    load_dotenv,
    rules_table,
)
from phishtriage.htmlreport import to_html
from phishtriage.models import TriageResult
from phishtriage.pipeline import EnrichmentRunner, eml_files, triage
from phishtriage.report import render_terminal
from phishtriage.scoring import load_rules, score

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
WIDTH = 112
BATCH_WIDTH = 150
FONT_PX = 15
LINE_HEIGHT = 1.32
CHAR_W = 9.05  # px per column at 15px Cascadia/Consolas
OFFLINE = True
"""Set by ``--online``; every analyze/batch shot uses the same mode."""
RUNNER: EnrichmentRunner | None = None
"""One runner for the whole run, so VirusTotal's per-minute bucket is shared."""

BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]

# A dark theme close to Windows Terminal's "One Half Dark".
THEME = TerminalTheme(
    (40, 44, 52),
    (220, 223, 228),
    [
        (40, 44, 52),
        (224, 108, 117),
        (152, 195, 121),
        (229, 192, 123),
        (97, 175, 239),
        (198, 120, 221),
        (86, 182, 194),
        (220, 223, 228),
    ],
    [
        (92, 99, 112),
        (224, 108, 117),
        (152, 195, 121),
        (229, 192, 123),
        (97, 175, 239),
        (198, 120, 221),
        (86, 182, 194),
        (255, 255, 255),
    ],
)

CSS = f"""
<style>
  body {{ background: #1e2127; margin: 0; padding: 28px; }}
  pre {{ font-family: "Cascadia Code", "Cascadia Mono", "JetBrains Mono", Consolas, monospace !important;
        font-size: {FONT_PX}px !important; line-height: {LINE_HEIGHT} !important; margin: 0; }}
  .window {{ display: inline-block; background: #282c34; border-radius: 10px; padding: 18px 22px 22px;
            box-shadow: 0 12px 40px rgba(0,0,0,.55); }}
  .bar {{ height: 12px; margin-bottom: 14px; }}
  .bar span {{ display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
</style>
"""
DOTS = (
    '<div class="bar"><span style="background:#ff5f56"></span>'
    '<span style="background:#ffbd2e"></span><span style="background:#27c93f"></span></div>'
)


def _console(width: int = WIDTH) -> Console:
    # StringIO file: nothing echoes to stdout, the encoding reads as UTF-8 so the
    # score bar renders as blocks, and legacy_windows=False keeps box-drawing characters.
    return Console(
        file=io.StringIO(),
        record=True,
        width=width,
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
    )


def _flag() -> str:
    return " --offline" if OFFLINE else ""


def _triage(path: Path) -> TriageResult:
    return triage(path, offline=OFFLINE, enricher=RUNNER)


def shot_analyze(sample: str, name: str) -> tuple[str, Console]:
    console = _console()
    console.print(
        f"[bold green]$[/bold green] [bold]phishtriage analyze samples/{sample}{_flag()}[/bold]"
    )
    render_terminal(_triage(Path("samples") / sample), console)
    return name, console


def shot_batch() -> tuple[str, Console]:
    console = _console(width=BATCH_WIDTH)
    console.print(f"[bold green]$[/bold green] [bold]phishtriage batch samples/{_flag()}[/bold]")
    base = Path("samples")
    results = [(p, _triage(p)) for p in eml_files(base)]
    console.print(_batch_table(results, base))
    matrix = _confusion(results)
    if matrix is not None:
        console.print(matrix)
    return "batch", console


def shot_rules(limit: int = 12) -> tuple[str, Console]:
    console = _console(width=BATCH_WIDTH)
    console.print(
        "[bold green]$[/bold green] [bold]phishtriage rules[/bold]  [dim](first rows)[/dim]"
    )
    rs = load_rules()
    console.print(rules_table(rs, limit=limit))
    console.print(f"[dim]... {len(rs.rules) - limit} more rules[/dim]")
    return "rules", console


def shot_compare() -> tuple[str, Console]:
    console = _console(width=BATCH_WIDTH)
    overlay = Path("rules/examples/content-heavy.yaml")
    console.print(
        f"[bold green]$[/bold green] [bold]phishtriage batch samples/{_flag()} "
        f"--compare {overlay.as_posix()}[/bold]"
    )
    base = Path("samples")
    rs_a, rs_b = load_rules(), load_rules(overlay.resolve())
    results = [(p, _triage(p)) for p in eml_files(base)]
    rescored = [
        (p, dataclasses.replace(r, score=score(r.record, r.auth, r.hops, r.indicators, rs_b)))
        for p, r in results
    ]
    _print_compare(results, rescored, base, rs_a, rs_b, out=console)
    return "compare", console


def shot_html_report(browser: str) -> Path:
    """The HTML report itself, rendered in the browser (light theme, top of page)."""
    out = OUT / "html-report.png"
    result = _triage(Path("samples/phish/real-01-mychart-medicare-kit.eml"))
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "report.html"
        page.write_text(to_html(result), encoding="utf-8")
        _browser_png(browser, page, out, width=1100, height=1500, tmp=Path(tmp))
    return out


SHOTS = {
    "analyze": lambda: shot_analyze("phish/10-dmarc-fail-dkim-unrelated.eml", "analyze"),
    "analyze-real-mychart": lambda: shot_analyze(
        "phish/real-01-mychart-medicare-kit.eml", "analyze-real-mychart"
    ),
    "analyze-real-uc-scam": lambda: shot_analyze(
        "phish/real-02-uc-account-job-scam-admin.eml", "analyze-real-uc-scam"
    ),
    "analyze-real-isc2": lambda: shot_analyze(
        "benign/real-03-isc2-webinar.eml", "analyze-real-isc2"
    ),
    "batch": shot_batch,
    "rules": shot_rules,
    "compare": shot_compare,
}
BROWSER_SHOTS = {"html-report": shot_html_report}


def find_browser() -> str | None:
    for candidate in BROWSERS:
        if Path(candidate).is_file():
            return candidate
    return shutil.which("msedge") or shutil.which("chrome") or shutil.which("chromium")


def to_png(html: str, out: Path, browser: str, columns: int, lines: int) -> None:
    height = int(lines * FONT_PX * LINE_HEIGHT) + 28 * 2 + 18 + 22 + 26 + 12
    width = int(columns * CHAR_W) + 28 * 2 + 44
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "shot.html"
        page.write_text(html, encoding="utf-8")
        _browser_png(browser, page, out, width=width, height=height, tmp=Path(tmp))


def _browser_png(
    browser: str, page: Path, out: Path, *, width: int, height: int, tmp: Path
) -> None:
    before = out.stat().st_mtime if out.exists() else None
    subprocess.run(
        [
            browser,
            "--headless=new",
            # Own profile, or a running Edge swallows the job and exits 0.
            f"--user-data-dir={tmp / 'profile'}",
            "--disable-gpu",
            "--hide-scrollbars",
            "--force-device-scale-factor=2",
            f"--window-size={width},{height}",
            f"--screenshot={out}",
            page.as_uri(),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    if not out.exists() or out.stat().st_mtime == before:
        raise RuntimeError(f"{browser} exited without writing {out}")


def main(argv: list[str]) -> int:
    global OFFLINE, RUNNER
    os.chdir(ROOT)
    if "--online" in argv:
        argv = [a for a in argv if a != "--online"]
        OFFLINE = False
        load_dotenv()
        RUNNER = _runner(offline=False)
    browser = find_browser()
    if browser is None:
        print("No Edge/Chrome found; cannot render PNGs.", file=sys.stderr)
        return 1
    wanted = argv or [*SHOTS, *BROWSER_SHOTS]
    OUT.mkdir(parents=True, exist_ok=True)
    for key in wanted:
        if key in BROWSER_SHOTS:
            out = BROWSER_SHOTS[key](browser)
            print(f"wrote {out.relative_to(ROOT)}")
            continue
        if key not in SHOTS:
            choices = ", ".join([*SHOTS, *BROWSER_SHOTS])
            print(f"unknown shot {key!r}; choose from {choices}", file=sys.stderr)
            return 2
        name, console = SHOTS[key]()
        lines = console.export_text(clear=False).rstrip("\n").count("\n") + 1
        html = console.export_html(theme=THEME, inline_styles=True)
        html = html.replace("<body>", f"<body>{CSS}<div class='window'>{DOTS}").replace(
            "</body>", "</div></body>"
        )
        out = OUT / f"{name}.png"
        to_png(html, out, browser, console.width, lines)
        print(f"wrote {out.relative_to(ROOT)} ({console.width} cols x {lines} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
