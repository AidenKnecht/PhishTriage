import email
import importlib.util
from email import policy
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
    b'<img src="https://cl.s12.exct.net/open.aspx?MGKG4Q6SUPWEPDSFURS3WL4DNI.120045&d=120045">\n'
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
    assert b"open.aspx?REDACTED&d=120045" in out


def test_sanitize_without_name_and_crlf():
    raw = RAW.replace(b"\n", b"\r\n")
    out = sanitize(raw, "real.person@corp.example")
    assert b"analyst@example.com" in out
    assert b"Real Person <analyst@example.com>" in out


QP_RAW = (
    b'From: "Doe, Jane (jdoe)" <jdoe@uni.example>\n'
    b"To: real.person@corp.example\n"
    b"Subject: hi\n"
    b"MIME-Version: 1.0\n"
    b"Content-Type: text/html; charset=utf-8\n"
    b"Content-Transfer-Encoding: quoted-printable\n\n"
    b'<p>Hi Real Person, from Jane Doe</p><a href=3D"https://svc.example/login?domain=3Dx.ex=\n'
    b"ample&amp;al=3DeyJmYWtlIjoidG9rZW4iLCJ4IjoxMjM0NTY3OH0.Zm9vYmFyYmF6cXV1eA=\n"
    b'F-FakeFakeFakeFakeFakeFak">open</a>\n'
)


def test_sanitize_decodes_quoted_printable_before_redacting():
    out = sanitize(QP_RAW, "real.person@corp.example", "Real Person")
    assert b"eyJmYWtl" not in out
    assert b"Zm9vYmFy" not in out
    assert b"Content-Transfer-Encoding: quoted-printable" in out

    body = email.message_from_bytes(out, policy=policy.default).get_content()
    assert "al=REDACTED" in body
    assert "Hi Analyst" in body
    assert "https://svc.example/login?domain=x.example" in body  # host and short params kept


def test_sanitize_pseudonymises_third_parties_in_headers_and_body():
    out = sanitize(
        QP_RAW,
        "real.person@corp.example",
        replace={"Doe, Jane": "Student, A", "Jane Doe": "A Student", "jdoe": "studenta"},
    )
    assert b"jdoe" not in out.lower() and b"jane" not in out.lower()
    assert b'From: "Student, A (studenta)" <studenta@uni.example>' in out
    assert b"from A Student" in out
