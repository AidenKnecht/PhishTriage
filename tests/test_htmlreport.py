import re
from pathlib import Path

from typer.testing import CliRunner

from phishtriage.cli import app
from phishtriage.htmlreport import CATEGORY_ORDER, to_html
from phishtriage.pipeline import triage
from phishtriage.scoring import load_rules

ROOT = Path(__file__).resolve().parents[1]

HOSTILE = (
    'From: "<img src=x onerror=alert(1)>" <service@paypa1.example>\r\n'
    "To: analyst@example.com\r\n"
    'Subject: <script>alert(1)</script> & "quotes"\r\n'
    "Date: Mon, 03 Mar 2025 10:00:00 +0000\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "\r\n"
    '<a href="http://login.paypa1.example/verify">https://www.paypal.com</a>\r\n'
)


def _hostile(tmp_path: Path) -> str:
    eml = tmp_path / "h.eml"
    eml.write_text(HOSTILE, encoding="utf-8", newline="")
    return to_html(triage(eml, offline=True))


def test_html_escapes_everything_from_the_email(tmp_path):
    page = _hostile(tmp_path)
    assert "<script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<img" not in page
    assert "&quot;quotes&quot;" in page


def test_html_never_links_or_loads_anything(tmp_path):
    page = _hostile(tmp_path)
    hrefs = re.findall(r'href="([^"]*)"', page)
    assert hrefs, "expected ATT&CK links"
    assert all(h.startswith("https://attack.mitre.org/techniques/T") for h in hrefs)
    assert not re.search(r"\bsrc=", page.replace("src=x", ""))
    assert "<script" not in page.lower()
    assert "default-src 'none'" in page
    assert "hxxp://login[.]paypa1[.]example/verify" in page
    assert "http://login.paypa1.example" not in page


def test_html_no_defang_still_never_links(tmp_path):
    eml = tmp_path / "h.eml"
    eml.write_text(HOSTILE, encoding="utf-8", newline="")
    page = to_html(triage(eml, offline=True), defang=False)
    assert "http://login.paypa1.example/verify" in page
    assert 'href="http://login' not in page


def test_html_score_breakdown_matches_fired_rules():
    result = triage(ROOT / "samples" / "phish" / "07-double-extension.eml", offline=True)
    page = to_html(result)
    segments = re.findall(r'class="seg[^"]*" title="([^"]*)"', page)
    assert len(segments) == len(result.score.fired)
    assert f'<div class="score">{result.score.score}<small>' in page
    assert "LIKELY PHISH" in page or "MALICIOUS" in page
    assert "https://attack.mitre.org/techniques/T1036/007/" in page


def test_every_rule_category_has_a_fixed_colour_slot():
    categories = {r.category for r in load_rules().rules}
    assert categories <= set(CATEGORY_ORDER)
    assert len(CATEGORY_ORDER) <= 8  # the reference palette has eight slots


def test_html_clean_email_and_cli_flag(tmp_path):
    out = tmp_path / "r.html"
    r = CliRunner().invoke(
        app,
        [
            "analyze",
            str(ROOT / "samples" / "benign" / "03-github-notification.eml"),
            "--offline",
            "--html",
            str(out),
        ],
    )
    assert r.exit_code == 0, r.output
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>")
    assert "No rules fired." in page
    assert "CLEAN" in page
