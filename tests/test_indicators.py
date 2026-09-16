import io
import zipfile

from phishtriage.indicators import (
    analyze_attachment,
    analyze_indicators,
    defang,
    extract_links_html,
    extract_urls_text,
    find_lookalike,
    html_to_text,
    match_keywords,
    sniff_mime,
)
from phishtriage.models import Attachment
from phishtriage.parser import parse_bytes, parse_file
from phishtriage.rulesdata import Brand

BRANDS = (
    Brand("microsoft", ("microsoft.com", "office.com")),
    Brand("paypal", ("paypal.com",)),
    Brand("amazon", ("amazon.com",)),
    Brand("ups", ("ups.com",)),
    Brand("docusign", ("docusign.com", "docusign.net")),
)
SHORTENERS = ("bit.ly", "t.co")
FILEHOSTS = ("dropbox.com", "drive.google.com")
KEYWORDS = {
    "urgency": ("urgent", "within 24 hours"),
    "credential": ("verify your account",),
}


def _analyze(raw: bytes, **kw):
    return analyze_indicators(
        parse_bytes(raw),
        brands=BRANDS,
        shorteners=SHORTENERS,
        filehosts=FILEHOSTS,
        keywords=KEYWORDS,
        **kw,
    )


def _att(name: str, data: bytes, ctype: str = "application/octet-stream") -> Attachment:
    return Attachment(name, ctype, len(data), "s", "m", data)


def _zip(entries: dict[str, bytes], encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    data = bytearray(buf.getvalue())
    if encrypted:
        # Set the encryption bit in every local (offset 6) and central (offset 8) header.
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = data.find(sig)
            while i != -1:
                data[i + off] |= 0x01
                i = data.find(sig, i + 1)
    return bytes(data)


# --------------------------------------------------------------------------- extraction


def test_extract_urls_text():
    text = (
        "See https://example.net/menu. Also http://203.0.113.5/login, www.example.com/x, "
        "and (https://en.wikipedia.org/wiki/Foo_(bar)) plus <https://a.example/y>."
    )
    urls = extract_urls_text(text)

    assert urls == [
        "https://example.net/menu",
        "http://203.0.113.5/login",
        "http://www.example.com/x",
        "https://en.wikipedia.org/wiki/Foo_(bar)",
        "https://a.example/y",
    ]
    assert extract_urls_text("") == []
    assert extract_urls_text("no urls here, user@example.com") == []


def test_extract_links_html():
    html = (
        '<p>Hi <a href="https://evil.example/login">https://paypal.com/secure</a> '
        '<a href="mailto:x@example.com">mail</a> <a href="#top">top</a> '
        '<form action="http://203.0.113.9/post"><input></form>'
        "<a href='https://ok.example/a'>Click <b>here</b></a></p>"
    )
    links = extract_links_html(html)

    assert links == [
        ("https://evil.example/login", "https://paypal.com/secure"),
        ("http://203.0.113.9/post", "(form action)"),
        ("https://ok.example/a", "Click here"),
    ]
    assert extract_links_html("") == []
    assert extract_links_html("<a href=") == []


def test_html_to_text_strips_scripts():
    assert html_to_text("<p>Hello <b>world</b></p><script>x()</script><style>a{}</style>") == (
        "Hello world"
    )


def test_defang():
    assert (
        defang("https://evil.example.com/a.php?x=1") == "hxxps://evil[.]example[.]com/a[.]php?x=1"
    )
    assert defang("http://203.0.113.5/") == "hxxp://203[.]0[.]113[.]5/"
    assert defang("evil.example") == "evil[.]example"
    assert defang("http://user@evil.example/") == "hxxp://user[@]evil[.]example/"
    assert defang("") == ""


def test_match_keywords_word_boundaries():
    hits = match_keywords("this is urgent: verify your account within 24 hours", KEYWORDS)
    assert hits == {"urgency": ["urgent", "within 24 hours"], "credential": ["verify your account"]}
    assert match_keywords("urgently is not urgent", KEYWORDS) == {"urgency": ["urgent"]}
    assert match_keywords("nothing", KEYWORDS) == {}


# --------------------------------------------------------------------------- url flags


def test_url_flags():
    a = _analyze(
        b"From: a@example.net\nContent-Type: text/plain\n\n"
        b"http://203.0.113.5/login https://bit.ly/abc https://www.dropbox.com/s/x "
        b"http://xn--pypal-4ve.example/ http://a.b.c.d.e.example.com/ "
        b"https://paypal.com@evil.example/ https://fine.example/\n"
    )
    by_url = {u.value: u for u in a.urls}

    assert by_url["http://203.0.113.5/login"].flags == ["raw_ip_url"]
    assert by_url["https://bit.ly/abc"].flags == ["shortener"]
    assert by_url["https://www.dropbox.com/s/x"].flags == ["file_hosting"]
    assert "punycode" in by_url["http://xn--pypal-4ve.example/"].flags
    assert "subdomain_depth" in by_url["http://a.b.c.d.e.example.com/"].flags
    assert "credentials_in_url" in by_url["https://paypal.com@evil.example/"].flags
    assert by_url["https://fine.example/"].flags == []

    assert [i.value for i in a.ips] == ["203.0.113.5"]
    assert "evil.example" in [d.value for d in a.domains]
    assert "example.net" in [d.value for d in a.domains]
    assert "raw_ip_url" in a.flags and "shortener" in a.flags


def test_unicode_host_flagged():
    cyrillic_a = chr(0x430)
    a = _analyze(f"From: a@example.net\n\nhttp://p{cyrillic_a}ypal.example/\n".encode())
    assert any("punycode" in u.flags for u in a.urls)


def test_lookalike_detection():
    assert find_lookalike("paypal.com", BRANDS) is None
    assert find_lookalike("www.paypal.com", BRANDS) is None
    assert find_lookalike("example.net", BRANDS) is None
    assert find_lookalike("groups.example", BRANDS) is None  # "ups" needs a whole token

    brand, reason = find_lookalike("paypal-secure.example", BRANDS)
    assert brand.name == "paypal" and "contains" in reason

    brand, reason = find_lookalike("login.microsoft.example.net", BRANDS)
    assert brand.name == "microsoft"

    brand, reason = find_lookalike("paypa1.com", BRANDS)
    assert brand.name == "paypal" and "homoglyph" in reason

    brand, reason = find_lookalike("arnazon.com", BRANDS)
    assert brand.name == "amazon" and "homoglyph" in reason

    brand, reason = find_lookalike("micosoft.com", BRANDS)
    assert brand.name == "microsoft" and "typosquat" in reason

    brand, reason = find_lookalike("ups-delivery.example", BRANDS)
    assert brand.name == "ups"

    assert find_lookalike("paypalx.com", BRANDS) is not None  # contains
    assert find_lookalike("payroll.example", BRANDS) is None  # distance too far


def test_sender_domains_get_lookalike_flag():
    a = _analyze(b"From: x@micr0soft-login.example\nReply-To: y@paypa1.com\n\nhello")
    flagged = {d.value: d.flags for d in a.domains}

    assert "lookalike_domain" in flagged["micr0soft-login.example"]
    assert "lookalike_domain" in flagged["paypa1.com"]
    assert a.domains[0].context == "From"


def test_origin_ip_added():
    a = _analyze(b"From: a@example.net\n\nx", origin_ip="203.0.113.77")
    assert [(i.value, i.context) for i in a.ips] == [("203.0.113.77", "origin hop")]


# --------------------------------------------------------------------------- link mismatch


def test_link_text_mismatch_url_text():
    a = _analyze(
        b"From: a@example.net\nContent-Type: text/html\n\n"
        b'<a href="https://evil.example/x">https://www.paypal.com/login</a>'
        b'<a href="https://mail.example.net/x">example.net</a>'
    )

    assert len(a.link_mismatches) == 1
    mm = a.link_mismatches[0]
    assert mm.href == "https://evil.example/x"
    assert "paypal.com" in mm.reason and "evil.example" in mm.reason
    assert "link_text_mismatch" in a.urls[0].flags
    assert a.urls[1].flags == []


def test_link_text_mismatch_brand_text():
    a = _analyze(
        b"From: a@example.net\nContent-Type: text/html\n\n"
        b'<a href="https://evil.example/x">Sign in to Microsoft</a>'
        b'<a href="https://login.microsoft.com/x">Sign in to Microsoft</a>'
        b'<a href="https://evil.example/y">Click here</a>'
    )

    assert [m.href for m in a.link_mismatches] == ["https://evil.example/x"]
    assert "microsoft" in a.link_mismatches[0].reason


def test_html_and_text_urls_deduped(fixtures):
    a = analyze_indicators(
        parse_file(fixtures / "multipart.eml"),
        brands=BRANDS,
        shorteners=SHORTENERS,
        filehosts=FILEHOSTS,
        keywords=KEYWORDS,
    )
    assert [u.value for u in a.urls] == ["https://billing.example.net/invoice/4471"]
    assert a.urls[0].context == "View online"


# --------------------------------------------------------------------------- attachments


def test_sniff_mime():
    assert sniff_mime(b"MZ\x90\x00" + b"\x00" * 60) == "application/x-dosexec"
    assert sniff_mime(b"%PDF-1.7\n") == "application/pdf"
    assert sniff_mime(b"PK\x03\x04rest") == "application/zip"
    assert sniff_mime(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1ole") == "application/x-ole-storage"
    assert sniff_mime(b"{\\rtf1") == "text/rtf"
    assert sniff_mime(b"\x1f\x8b\x08") == "application/gzip"
    assert sniff_mime(b"7z\xbc\xaf\x27\x1c") == "application/x-7z-compressed"
    assert sniff_mime(b"Rar!\x1a\x07\x01\x00") == "application/x-rar"
    assert sniff_mime(b"\x89PNG\r\n\x1a\n") == "image/png"
    assert sniff_mime(b"\xff\xd8\xff\xe0") == "image/jpeg"
    assert sniff_mime(b"GIF89a") == "image/gif"
    assert sniff_mime(b"\x4c\x00\x00\x00\x01\x14\x02\x00rest") == "application/x-ms-shortcut"
    assert sniff_mime(b"\x7fELF") == "application/x-elf"
    assert sniff_mime(b"\xcf\xfa\xed\xfe") == "application/x-mach-binary"
    assert sniff_mime(b"\x00" * 0x8001 + b"CD001" + b"\x00" * 10) == "application/x-iso9660-image"
    assert sniff_mime(b"  <!DOCTYPE html><html>") == "text/html"
    assert sniff_mime(b"<script>alert(1)</script>") == "text/html"
    assert sniff_mime(b'<?xml version="1.0"?><foo/>') == "text/xml"
    assert sniff_mime(b"just some text") == "text/plain"
    assert sniff_mime(b"\x00\x01\x02\xff\xfe") == "application/octet-stream"
    assert sniff_mime(b"") == ""


def test_clean_pdf_no_flags():
    r = analyze_attachment(_att("report.pdf", b"%PDF-1.4 ...", "application/pdf"))

    assert r.extension == "pdf"
    assert r.magic_mime == "application/pdf"
    assert r.flags == []
    assert r.details == {}


def test_double_extension_and_mime_mismatch():
    r = analyze_attachment(_att("invoice.pdf.exe", b"MZ\x90\x00" + b"\x00" * 64, "application/pdf"))

    assert "double_extension" in r.flags
    assert "executable" in r.flags
    assert "mime_mismatch" not in r.flags  # .exe and PE bytes agree
    assert "declared_mime_differs" in r.details

    r = analyze_attachment(_att("scan.pdf", b"MZ\x90\x00" + b"\x00" * 64, "application/pdf"))
    assert "mime_mismatch" in r.flags
    assert "executable" in r.flags


def test_double_extension_with_document_first():
    r = analyze_attachment(_att("photo.jpg.scr", b"MZ" + b"\x00" * 64))
    assert "double_extension" in r.flags

    r = analyze_attachment(_att("archive.tar.gz", b"\x1f\x8b\x08"))
    assert "double_extension" not in r.flags
    assert "archive" in r.flags

    r = analyze_attachment(_att("report.final.pdf", b"%PDF-1.4", "application/pdf"))
    assert r.flags == []

    r = analyze_attachment(_att("invoice.pdf                    .exe", b"MZ" + b"\x00" * 64))
    assert "double_extension" in r.flags


def test_macro_enabled_by_extension_and_by_content():
    r = analyze_attachment(_att("q3.xlsm", _zip({"xl/vbaProject.bin": b"x"})))
    assert "macro_enabled" in r.flags
    assert "mime_mismatch" not in r.flags

    r = analyze_attachment(
        _att(
            "q3.docx",
            _zip({"[Content_Types].xml": b"<x/>", "word/vbaProject.bin": b"x"}),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    )
    assert "macro_enabled" in r.flags
    assert "vbaProject" in r.details["macro_enabled"]
    assert "declared_mime_differs" not in r.details

    r = analyze_attachment(_att("q3.docx", _zip({"word/document.xml": b"<x/>"})))
    assert r.flags == []


def test_container_types():
    for name in ("disk.iso", "drive.img", "open.lnk", "page.html", "page.htm"):
        r = analyze_attachment(_att(name, b"whatever"))
        assert "dangerous_container" in r.flags, name

    r = analyze_attachment(_att("statement.pdf", b"<html><body>x</body></html>", "text/html"))
    assert "dangerous_container" in r.flags
    assert "mime_mismatch" in r.flags

    r = analyze_attachment(_att("shortcut.txt", b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 8))
    assert "dangerous_container" in r.flags


def test_password_protected_zip_and_exe_inside():
    r = analyze_attachment(_att("docs.zip", _zip({"invoice.exe": b"MZ"}, encrypted=True)))

    assert "archive" in r.flags
    assert "password_protected_archive" in r.flags
    assert "archive_contains_executable" in r.flags
    assert ".exe" in r.details["archive_contains_executable"]

    r = analyze_attachment(_att("docs.zip", _zip({"readme.txt": b"hi"})))
    assert r.flags == ["archive"]

    r = analyze_attachment(_att("broken.zip", b"PK\x03\x04garbage"))
    assert r.flags == ["archive"]


def test_no_extension_attachment():
    r = analyze_attachment(_att("README", b"hello"))
    assert r.extension == ""
    assert r.flags == []


def test_attachments_and_keywords_in_full_analysis():
    raw = (
        b"From: a@example.net\nSubject: URGENT: verify your account\nMIME-Version: 1.0\n"
        b'Content-Type: multipart/mixed; boundary="b"\n\n'
        b"--b\nContent-Type: text/plain\n\nplease respond within 24 hours\n"
        b'--b\nContent-Type: application/octet-stream; name="doc.pdf.exe"\n'
        b"Content-Transfer-Encoding: base64\n\nTVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA\n--b--\n"
    )
    a = _analyze(raw)

    assert a.keyword_categories == {
        "urgency": ["urgent", "within 24 hours"],
        "credential": ["verify your account"],
    }
    assert len(a.attachments) == 1
    assert "double_extension" in a.attachments[0].flags
    assert "double_extension" in a.flags
    assert "executable" in a.flags
