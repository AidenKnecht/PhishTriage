import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "sanitize", Path(__file__).resolve().parents[1] / "scripts" / "sanitize.py"
)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
sanitize = _MODULE.sanitize


RAW = (
    b"Delivered-To: real.person@corp.example\n"
    b"X-Original-To: real.person@corp.example\n"
    b"Received: from a (a [203.0.113.1]) by mx for <Real.Person@corp.example>;\n"
    b"\tMon, 02 Sep 2024 10:15:22 +0000\n"
    b"From: Bad Guy <bad@evil.example>\n"
    b"To: Real Person <real.person@corp.example>\n"
    b"Subject: hi\n\n"
    b"Click https://evil.example/t/aB3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW?u=real.person%40corp.example"
    b"&tok=0123456789abcdef0123456789abcdef&x=1\n"
)


def test_sanitize_replaces_recipient_and_tokens():
    out = sanitize(RAW, "real.person@corp.example", "Real Person")

    assert b"real.person" not in out.lower()
    assert b"analyst@example.com" in out
    assert b"Analyst <analyst@example.com>" in out
    assert b"Delivered-To" not in out and b"X-Original-To" not in out
    assert b"Received: from a" in out  # kept, with the for-clause rewritten
    assert b"for <analyst@example.com>" in out
    assert b"bad@evil.example" in out  # sender is evidence, untouched
    assert b"/t/REDACTED?u=" in out
    assert b"&tok=REDACTED&x=1" in out


def test_sanitize_without_name_and_crlf():
    raw = RAW.replace(b"\n", b"\r\n")
    out = sanitize(raw, "real.person@corp.example")
    assert b"analyst@example.com" in out
    assert b"Real Person <analyst@example.com>" in out
