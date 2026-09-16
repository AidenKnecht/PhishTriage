"""Render phishtriage output to PNG for the README and writeup.

Rich records the exact terminal rendering as HTML; a headless Edge/Chrome
turns that into a PNG. No extra Python dependencies.

Usage:
    uv run python scripts/screenshot.py            # all shots into docs/screenshots/
    uv run python scripts/screenshot.py analyze    # just one
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table
from rich.terminal_theme import TerminalTheme

from phishtriage.cli import _batch_table, _confusion
from phishtriage.pipeline import eml_files, triage
from phishtriage.report import render_terminal
from phishtriage.scoring import load_rules

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
WIDTH = 112
BATCH_WIDTH = 150
FONT_PX = 15
LINE_HEIGHT = 1.32
CHAR_W = 9.05  # px per column at 15px Cascadia/Consolas

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


def shot_analyze(sample: str, name: str) -> tuple[str, Console]:
    console = _console()
    console.print(
        f"[bold green]$[/bold green] [bold]phishtriage analyze samples/{sample} --offline[/bold]"
    )
    render_terminal(triage(Path("samples") / sample, offline=True), console)
    return name, console


def shot_batch() -> tuple[str, Console]:
    console = _console(width=BATCH_WIDTH)
    console.print("[bold green]$[/bold green] [bold]phishtriage batch samples/ --offline[/bold]")
    base = Path("samples")
    results = [(p, triage(p, offline=True)) for p in eml_files(base)]
    console.print(_batch_table(results, base))
    matrix = _confusion(results)
    if matrix is not None:
        console.print(matrix)
    return "batch", console


def shot_rules(limit: int = 12) -> tuple[str, Console]:
    console = _console()
    console.print(
        "[bold green]$[/bold green] [bold]phishtriage rules[/bold]  [dim](first rows)[/dim]"
    )
    rs = load_rules()
    t = Table(title="Scoring rules (rules/scoring.yaml)", box=box.SIMPLE_HEAD, expand=True)
    t.add_column("ID", style="bold", no_wrap=True)
    t.add_column("Category", no_wrap=True)
    t.add_column("Weight", justify="right")
    t.add_column("Description", overflow="fold")
    t.add_column("Rationale", overflow="fold")
    for rule in rs.rules[:limit]:
        t.add_row(rule.id, rule.category, str(rule.weight), rule.description, rule.rationale)
    console.print(t)
    console.print(f"[dim]... {len(rs.rules) - limit} more rules[/dim]")
    return "rules", console


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
}


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
        subprocess.run(
            [
                browser,
                "--headless=new",
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


def main(argv: list[str]) -> int:
    os.chdir(ROOT)
    browser = find_browser()
    if browser is None:
        print("No Edge/Chrome found; cannot render PNGs.", file=sys.stderr)
        return 1
    wanted = argv or list(SHOTS)
    OUT.mkdir(parents=True, exist_ok=True)
    for key in wanted:
        if key not in SHOTS:
            print(f"unknown shot {key!r}; choose from {', '.join(SHOTS)}", file=sys.stderr)
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
