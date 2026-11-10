import json
import os
import re
from pathlib import Path

from typer.testing import CliRunner

from phishtriage import cli as cli_module
from phishtriage.cli import app, load_dotenv
from phishtriage.pipeline import triage
from phishtriage.report import to_markdown
from phishtriage.scoring import RuleError

ROOT = Path(__file__).resolve().parents[1]
PHISH = ROOT / "samples" / "phish" / "10-dmarc-fail-dkim-unrelated.eml"
BENIGN = ROOT / "samples" / "benign" / "05-invoice-pdf.eml"

runner = CliRunner()


def _run(*args):
    env = {"COLUMNS": "160", "TERM": "dumb", "NO_COLOR": "1"}
    return runner.invoke(app, list(args), env=env, catch_exceptions=False)


def test_help_and_version():
    r = _run("--help")
    assert r.exit_code == 0
    assert "analyze" in r.output and "batch" in r.output

    r = _run("--version")
    assert r.exit_code == 0
    assert "phishtriage" in r.output


def test_analyze_offline_phish(tmp_path):
    out_json = tmp_path / "r.json"
    out_md = tmp_path / "r.md"
    r = _run("analyze", str(PHISH), "--offline", "--json", str(out_json), "--markdown", str(out_md))

    assert r.exit_code == 0, r.output
    assert "MALICIOUS" in r.output
    assert "Why this verdict" in r.output
    assert "dmarc_fail" in r.output
    assert "chase-secure-alerts[.]example" in r.output  # defanged
    assert "https://chase-secure-alerts.example" not in r.output
    assert "enrichment lookups" in r.output

    data = json.loads(out_json.read_text())
    assert data["version"] == 1
    assert data["score"]["verdict"] == "MALICIOUS"
    assert data["record"]["from_domain"] == "chase.com"
    assert "data" not in json.dumps(data["record"]["attachments"])  # bytes dropped

    md = out_md.read_text(encoding="utf-8")
    assert md.startswith("# Phishing triage: 10-dmarc-fail-dkim-unrelated.eml")
    assert "**Verdict: MALICIOUS (80/100)**" in md
    assert "## Why this verdict" in md
    assert "hxxps://chase-secure-alerts[.]example/review" in md


def test_analyze_no_defang():
    r = _run("analyze", str(PHISH), "--offline", "--no-defang")
    assert r.exit_code == 0
    assert "https://chase-secure-alerts.example/review" in r.output


def test_analyze_benign_with_attachment():
    r = _run("analyze", str(BENIGN), "--offline")
    assert r.exit_code == 0
    assert "CLEAN" in r.output
    assert "Attachments" in r.output
    assert "invoice-4471.pdf" in r.output
    assert "No rules fired" in r.output


def test_analyze_missing_file():
    r = _run("analyze", "does-not-exist.eml", "--offline")
    assert r.exit_code != 0


def test_analyze_garbage_never_crashes(fixtures):
    r = _run("analyze", str(fixtures / "garbage.eml"), "--offline")
    assert r.exit_code == 0
    assert "Warnings" in r.output


def test_batch_with_confusion_matrix_and_csv(tmp_path):
    out_csv = tmp_path / "summary.csv"
    r = _run("batch", str(ROOT / "samples"), "--offline", "--csv", str(out_csv))

    assert r.exit_code == 0, r.output
    assert "Confusion matrix" in r.output
    assert re.search(r"\d+ missed, 0 false alarms", r.output)
    assert "01-lookalike-domain.eml" in r.output

    rows = out_csv.read_text(encoding="utf-8").splitlines()
    assert rows[0].startswith("file,label,from,subject,score,verdict,top_rule,rules")
    assert len(rows) == 1 + len(list((ROOT / "samples").rglob("*.eml")))
    assert any(",phish," in row and ",MALICIOUS," in row for row in rows)


def test_batch_without_labels_has_no_matrix(tmp_path):
    (tmp_path / "a.eml").write_bytes(BENIGN.read_bytes())
    r = _run("batch", str(tmp_path), "--offline")
    assert r.exit_code == 0
    assert "Confusion matrix" not in r.output
    assert "a.eml" in r.output


def test_batch_empty_dir(tmp_path):
    r = _run("batch", str(tmp_path), "--offline")
    assert r.exit_code == 1


def test_rules_table():
    r = _run("rules")
    assert r.exit_code == 0
    assert "dmarc_fail" in r.output
    assert "lure_keywords" in r.output
    assert "max 15" in r.output


def test_cache_clear_and_info(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHTRIAGE_CACHE_DIR", str(tmp_path / "cache"))
    (tmp_path / "cache" / "urlhaus").mkdir(parents=True)
    (tmp_path / "cache" / "urlhaus" / "x.json").write_text("{}")

    r = _run("cache", "info")
    assert "1 cached" in r.output

    r = _run("cache", "clear")
    assert r.exit_code == 0
    assert "Removed 1" in r.output
    assert not list((tmp_path / "cache").rglob("*.json"))


def test_load_dotenv_does_not_override(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('# comment\nVT_API_KEY="abc"\nEMPTY=\nPHISHTRIAGE_TEST_X=1\n', encoding="utf-8")
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("PHISHTRIAGE_TEST_X", "keep")

    load_dotenv(env)

    assert os.environ["VT_API_KEY"] == "abc"
    assert os.environ["PHISHTRIAGE_TEST_X"] == "keep"
    assert os.environ.get("EMPTY") == ""
    monkeypatch.delenv("VT_API_KEY")
    monkeypatch.delenv("EMPTY")
    load_dotenv(tmp_path / "missing.env")  # silently ignored


def test_markdown_escapes_pipes_and_lists_rules(fixtures):
    result = triage(fixtures / "multipart.eml", offline=True)
    result.record.subject = "a | b"
    md = to_markdown(result)
    assert "a \\| b" in md
    assert "## Attachments" in md
    assert "invoice-4471.pdf" in md


HOSTILE = (
    'From: "[bold]Pay[/bold]Pal" <service@paypa1.example>\r\n'
    "To: analyst@example.com\r\n"
    "Subject: [/b] [external] Invoice `x` <script>alert(1)</script> | due\r\n"
    "Date: Mon, 03 Mar 2025 10:00:00 +0000\r\n"
    "Message-ID: <hostile@example.com>\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Log in at http://admin@login.paypa1.example/verify now.\r\n"
)


def test_analyze_survives_markup_in_email_text(tmp_path):
    """Email text is data, not rich markup: no crash, nothing swallowed."""
    eml = tmp_path / "[red]hostile.eml"
    eml.write_text(HOSTILE, encoding="utf-8", newline="")
    r = _run("analyze", str(eml), "--offline")
    assert r.exit_code == 0, r.output
    assert "[/b] [external] Invoice" in r.output
    assert "[bold]Pay[/bold]Pal" in r.output
    assert "admin[@]login[.]paypa1[.]example" in r.output
    assert "[red]hostile.eml" in r.output


def test_batch_survives_markup_and_bad_files(tmp_path, monkeypatch):
    (tmp_path / "good.eml").write_text(HOSTILE, encoding="utf-8", newline="")
    (tmp_path / "bad.eml").write_bytes(b"x")
    real_triage = cli_module.triage

    def flaky(path, **kwargs):
        if Path(path).name == "bad.eml":
            raise OSError("disk on fire")
        return real_triage(path, **kwargs)

    monkeypatch.setattr(cli_module, "triage", flaky)
    r = runner.invoke(app, ["batch", str(tmp_path), "--offline"], env={"COLUMNS": "200"})
    assert r.exit_code == 1
    assert "good.eml" in r.output
    assert "[/b] [external]" in r.output
    assert "ERROR bad.eml: OSError: disk on fire" in r.output


def test_batch_rules_error_exits_2(tmp_path, monkeypatch):
    (tmp_path / "a.eml").write_bytes(BENIGN.read_bytes())

    def broken(path=None):
        raise RuleError("bad yaml")

    monkeypatch.setattr(cli_module, "load_rules", broken)
    r = runner.invoke(app, ["batch", str(tmp_path), "--offline"])
    assert r.exit_code == 2
    assert "bad yaml" in r.output


def test_markdown_escapes_hostile_text(tmp_path):
    eml = tmp_path / "h.eml"
    eml.write_text(HOSTILE, encoding="utf-8", newline="")
    md = to_markdown(triage(eml, offline=True))
    assert "<script>" not in md
    assert r"\<script\>" in md
    assert r"\| due" in md
    assert r"\`x\`" in md  # backticks in plain text are escaped, not a code span
    assert "`hxxp://admin[@]login[.]paypa1[.]example/verify`" in md
    assert "not checked (offline)" in md
    # The From cell is a code span, so <addr> can't be eaten as an HTML tag.
    assert "| From | `[bold]Pay[/bold]Pal <service@paypa1[.]example>` |" in md
    # Defanged evidence stays readable: [.] is not backslash-escaped.
    assert "login[.]paypa1[.]example looks like paypal" in md


def test_markdown_neutralises_inline_links(tmp_path):
    eml = tmp_path / "l.eml"
    eml.write_text(
        HOSTILE.replace("Subject: [/b]", "Subject: [click](http://evil.example) [/b]"),
        encoding="utf-8",
        newline="",
    )
    md = to_markdown(triage(eml, offline=True))
    assert "[click](" not in md
    assert r"[click]\(" in md
