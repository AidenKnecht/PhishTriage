import hashlib
from datetime import UTC, datetime, timedelta, timezone

from phishtriage.parser import parse_bytes, parse_file


def test_simple_headers(fixtures):
    rec = parse_file(fixtures / "simple.eml")

    assert rec.message_id == "<simple-001@example.net>"
    assert rec.subject == "Lunch on Thursday?"
    assert rec.date == datetime(2024, 9, 2, 10, 15, 19, tzinfo=UTC)
    assert rec.from_display == "Alice Example"
    assert rec.from_addr == "alice@example.net"
    assert rec.from_domain == "example.net"
    assert rec.reply_to_addr == "alice@example.net"
    assert rec.return_path == "bounce@example.net"
    assert rec.return_path_domain == "example.net"
    assert rec.to == ["analyst@example.com", "bob@example.com"]
    assert rec.source.endswith("simple.eml")
    assert rec.warnings == []


def test_simple_received_and_auth_order(fixtures):
    rec = parse_file(fixtures / "simple.eml")

    assert len(rec.received_headers) == 2
    # Header order preserved: first is the most recent hop.
    assert rec.received_headers[0].startswith("from mail.example.net")
    assert "\n" not in rec.received_headers[0]  # unfolded
    assert len(rec.authentication_results) == 1
    assert "spf=pass" in rec.authentication_results[0]


def test_raw_headers_preserve_duplicates(fixtures):
    rec = parse_file(fixtures / "simple.eml")

    assert len(rec.raw_headers["Received"]) == 2
    assert rec.header("subject") == "Lunch on Thursday?"
    assert rec.headers("RECEIVED") == rec.raw_headers["Received"]
    assert rec.header("X-Nope") is None


def test_simple_body(fixtures):
    rec = parse_file(fixtures / "simple.eml")

    assert "https://example.net/menu" in rec.body_text
    assert rec.body_html == ""
    assert rec.attachments == []


def test_multipart_bodies_decoded(fixtures):
    rec = parse_file(fixtures / "multipart.eml")

    assert "€1,200" in rec.body_text  # quoted-printable
    assert 'href="https://billing.example.net/invoice/4471"' in rec.body_html  # base64


def test_multipart_attachments_hashed(fixtures):
    rec = parse_file(fixtures / "multipart.eml")

    names = [a.filename for a in rec.attachments]
    assert names == ["invoice-4471.pdf", "logo.png"]

    pdf = rec.attachments[0]
    assert pdf.content_type == "application/pdf"
    assert pdf.data.startswith(b"%PDF-1.4")
    assert pdf.size == len(pdf.data)
    assert pdf.sha256 == hashlib.sha256(pdf.data).hexdigest()
    assert pdf.md5 == hashlib.md5(pdf.data).hexdigest()

    png = rec.attachments[1]
    assert png.content_type == "image/png"
    assert png.data.startswith(b"\x89PNG")


def test_malformed_degrades_with_warnings(fixtures):
    rec = parse_file(fixtures / "malformed.eml")

    assert rec.date is None
    assert rec.date_raw == "Thursday 45 Foo 2024 99:99:99"
    assert rec.message_id == ""
    assert rec.return_path == ""
    assert rec.from_display == "Security Team 🔡"
    assert rec.from_addr == "security@example.net"
    assert rec.subject == "Action required: verify your account"
    assert rec.to == ["andre@example.com"]
    assert rec.received_headers[0].endswith("not a date at all")

    joined = " ".join(rec.warnings)
    assert "unparseable Date" in joined
    assert "missing Message-ID" in joined


def test_garbage_never_crashes(fixtures):
    rec = parse_file(fixtures / "garbage.eml")

    assert rec.from_addr == ""
    assert rec.subject == ""
    assert rec.warnings  # something was recorded


def test_bare_from_address(fixtures):
    rec = parse_file(fixtures / "bare-from.eml")

    assert rec.from_display == ""
    assert rec.from_addr == "bob@example.net"
    assert rec.date == datetime(2024, 9, 4, 12, 0, tzinfo=timezone(timedelta(hours=-5)))


def test_empty_bytes():
    rec = parse_bytes(b"")

    assert rec.from_addr == ""
    assert rec.body_text == ""


def test_date_with_comment_and_junk():
    rec = parse_bytes(b"Date: Mon, 02 Sep 2024 10:15:19 +0000 (UTC)\n\nx")
    assert rec.date == datetime(2024, 9, 2, 10, 15, 19, tzinfo=UTC)

    rec = parse_bytes(b"Date: 02 Sep 2024 10:15:19 +0000 extra\n\nx")
    assert rec.date == datetime(2024, 9, 2, 10, 15, 19, tzinfo=UTC)


def test_nonstandard_from_recovers_address():
    rec = parse_bytes(b'From: "PayPal" <service@paypal.com> <attacker@example.net>\n\nx')

    assert rec.from_addr in {"service@paypal.com", "attacker@example.net"}
    assert rec.from_display


def test_uppercase_addresses_normalised():
    rec = parse_bytes(b"From: Bob <BOB@Example.NET>\nReturn-Path: <Bounce@EXAMPLE.net>\n\nx")

    assert rec.from_addr == "bob@example.net"
    assert rec.from_domain == "example.net"
    assert rec.return_path_domain == "example.net"


def test_attachment_named_only_in_content_type():
    raw = (
        b"From: a@example.net\nMIME-Version: 1.0\n"
        b'Content-Type: multipart/mixed; boundary="b"\n\n'
        b"--b\nContent-Type: text/plain\n\nhello\n"
        b'--b\nContent-Type: application/zip; name="files.zip"\n'
        b"Content-Transfer-Encoding: base64\n\nUEsDBAoAAAAAAA==\n--b--\n"
    )
    rec = parse_bytes(raw)

    assert rec.body_text.strip() == "hello"
    assert [a.filename for a in rec.attachments] == ["files.zip"]
    assert rec.attachments[0].data.startswith(b"PK\x03\x04")
