"""Pull URLs, domains, IPs and attachment facts out of an email and flag them.

Flags are short stable identifiers (``shortener``, ``double_extension``, ...)
so ``rules/scoring.yaml`` can reference them by name. A human-readable
explanation for each flag is kept in ``details`` for the report.

Nothing here ever touches the network. Attachments are hashed and sniffed,
never opened beyond reading ZIP directory entries.
"""

from __future__ import annotations

import io
import ipaddress
import re
import zipfile
from collections.abc import Callable
from html.parser import HTMLParser
from urllib.parse import urlsplit

from phishtriage.models import (
    Attachment,
    AttachmentAnalysis,
    EmailRecord,
    Indicator,
    IndicatorAnalysis,
    IndicatorType,
    LinkMismatch,
)
from phishtriage.rulesdata import (
    Brand,
    load_brands,
    load_keywords,
    load_list,
    organizational_domain,
    same_org,
)

_URL_RE = re.compile(
    r"""(?<![\w@.])(?:https?://|hxxps?://|www\.)[^\s<>"'`\]\[]+""",
    re.IGNORECASE,
)
_TRAILING_PUNCT = ".,;:!?)>]}'\""
_DOMAINISH = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)(?:/\S*)?$", re.IGNORECASE
)
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})

EXECUTABLE_EXTS = frozenset(
    [
        "exe",
        "scr",
        "com",
        "pif",
        "bat",
        "cmd",
        "js",
        "jse",
        "vbs",
        "vbe",
        "wsf",
        "wsh",
        "hta",
        "ps1",
        "psm1",
        "msi",
        "msp",
        "jar",
        "cpl",
        "reg",
        "dll",
        "app",
        "apk",
        "py",
        "rb",
        "pl",
        "sh",
    ]
)
MACRO_EXTS = frozenset(["docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"])
CONTAINER_EXTS = frozenset(
    [
        "iso",
        "img",
        "vhd",
        "vhdx",
        "udf",
        "lnk",
        "html",
        "htm",
        "shtml",
        "xhtml",
        "mht",
        "mhtml",
        "svg",
        "one",
    ]
)
ARCHIVE_EXTS = frozenset(
    ["zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "ace", "arj", "z"]
)
DOC_EXTS = frozenset(
    [
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "rtf",
        "txt",
        "csv",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "odt",
        "ods",
    ]
)

# Extension -> MIME family we expect the magic bytes to agree with.
_EXT_MIME = {
    "pdf": "application/pdf",
    "doc": "application/x-ole-storage",
    "xls": "application/x-ole-storage",
    "ppt": "application/x-ole-storage",
    "msg": "application/x-ole-storage",
    "docx": "application/zip",
    "docm": "application/zip",
    "xlsx": "application/zip",
    "xlsm": "application/zip",
    "pptx": "application/zip",
    "pptm": "application/zip",
    "zip": "application/zip",
    "jar": "application/zip",
    "apk": "application/zip",
    "rtf": "text/rtf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "exe": "application/x-dosexec",
    "dll": "application/x-dosexec",
    "scr": "application/x-dosexec",
    "gz": "application/gzip",
    "tgz": "application/gzip",
    "7z": "application/x-7z-compressed",
    "rar": "application/x-rar",
    "iso": "application/x-iso9660-image",
    "lnk": "application/x-ms-shortcut",
    "html": "text/html",
    "htm": "text/html",
}

_TEXT_MIMES = frozenset({"text/plain", "text/html", "text/rtf", "text/csv"})


# --------------------------------------------------------------------------- public API


def analyze_indicators(
    record: EmailRecord,
    *,
    origin_ip: str = "",
    brands: tuple[Brand, ...] | None = None,
    shorteners: tuple[str, ...] | None = None,
    filehosts: tuple[str, ...] | None = None,
    keywords: dict[str, tuple[str, ...]] | None = None,
) -> IndicatorAnalysis:
    """Extract and flag every indicator in the record."""
    brands = load_brands() if brands is None else brands
    shorteners = load_list("shorteners.txt") if shorteners is None else shorteners
    filehosts = load_list("filehosts.txt") if filehosts is None else filehosts
    keywords = load_keywords() if keywords is None else keywords

    analysis = IndicatorAnalysis()

    links = extract_links_html(record.body_html)
    text_urls = extract_urls_text(record.body_text)
    html_text = html_to_text(record.body_html)
    html_text_urls = extract_urls_text(html_text)

    seen: dict[str, Indicator] = {}
    for href, text in links:
        ind = _url_indicator(href, seen, context=text)
        if ind is not None and text:
            mismatch = _link_mismatch(text, href, brands)
            if mismatch is not None:
                analysis.link_mismatches.append(mismatch)
                _flag(ind, "link_text_mismatch", mismatch.reason)
    for url in text_urls + html_text_urls:
        _url_indicator(url, seen)
    analysis.urls = list(seen.values())

    domains: dict[str, Indicator] = {}
    ips: dict[str, Indicator] = {}
    for ind in analysis.urls:
        _flag_url(ind, brands, shorteners, filehosts)
        host = _host_of(ind.value)
        if not host:
            continue
        if _is_ip(host):
            ips.setdefault(host, Indicator(IndicatorType.IP, host, context="url host"))
        else:
            domains.setdefault(host, Indicator(IndicatorType.DOMAIN, host, context="url host"))

    sender_domains = (
        (record.from_domain, "From"),
        (record.reply_to_domain, "Reply-To"),
        (record.return_path_domain, "Return-Path"),
    )
    for domain, ctx in sender_domains:
        if domain and domain not in domains:
            domains[domain] = Indicator(IndicatorType.DOMAIN, domain, context=ctx)
        elif domain:
            domains[domain].context += f", {ctx}"
    if origin_ip and origin_ip not in ips:
        ips[origin_ip] = Indicator(IndicatorType.IP, origin_ip, context="origin hop")

    for ind in domains.values():
        _flag_domain(ind, brands)
    analysis.domains = list(domains.values())
    analysis.ips = list(ips.values())

    analysis.attachments = [analyze_attachment(a) for a in record.attachments]

    haystack = "\n".join([record.subject, record.body_text, html_text]).lower()
    analysis.keyword_categories = match_keywords(haystack, keywords)

    _summarise(analysis)
    return analysis


def defang(value: str) -> str:
    """``https://evil.example/x`` -> ``hxxps://evil[.]example/x``."""
    if not value:
        return value
    out = re.sub(r"^http(s?)://", r"hxxp\1://", value, flags=re.IGNORECASE)
    out = out.replace(".", "[.]")
    return out.replace("@", "[@]") if "://" in out else out


def extract_urls_text(text: str) -> list[str]:
    """Find URLs in plain text (``http(s)://`` and bare ``www.`` forms)."""
    if not text:
        return []
    found: list[str] = []
    for m in _URL_RE.finditer(text):
        url = _clean_url(m.group(0))
        if url and url not in found:
            found.append(url)
    return found


def extract_links_html(html: str) -> list[tuple[str, str]]:
    """Return ``(href, visible_text)`` for every anchor, plus form actions."""
    if not html:
        return []
    parser = _LinkParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    out: list[tuple[str, str]] = []
    for href, text in parser.links:
        href = _clean_url(href)
        if href and not href.lower().startswith(("mailto:", "tel:", "javascript:", "#", "cid:")):
            out.append((href, " ".join(text.split())))
    return out


def html_to_text(html: str) -> str:
    if not html:
        return ""
    parser = _TextParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    return " ".join(parser.chunks)


def match_keywords(text: str, keywords: dict[str, tuple[str, ...]]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for category, phrases in keywords.items():
        for phrase in phrases:
            if re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", text):
                hits.setdefault(category, []).append(phrase)
    return hits


# --------------------------------------------------------------------------- URLs


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._current: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._current = a["href"] or ""
            self._text = []
        elif tag == "form" and a.get("action"):
            self.links.append((a["action"] or "", "(form action)"))
        elif tag in ("iframe", "script") and a.get("src"):
            self.links.append((a["src"] or "", f"({tag} src)"))

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current is not None:
            self.links.append((self._current, "".join(self._text)))
            self._current = None
            self._text = []


class _TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip and data.strip():
            self.chunks.append(data.strip())


def _clean_url(url: str) -> str:
    url = url.strip().rstrip(_TRAILING_PUNCT)
    # Balance a trailing ')' that was part of the URL, e.g. wikipedia links.
    if url.count("(") > url.count(")"):
        url += ")"
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def _host_of(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _url_indicator(url: str, seen: dict[str, Indicator], context: str = "") -> Indicator | None:
    if not url:
        return None
    key = url.lower()
    if key in seen:
        if context and not seen[key].context:
            seen[key].context = context
        return seen[key]
    ind = Indicator(IndicatorType.URL, url, context=context)
    seen[key] = ind
    return ind


def _flag(ind: Indicator, flag: str, detail: str) -> None:
    if flag not in ind.flags:
        ind.flags.append(flag)
        ind.details[flag] = detail


def _flag_url(
    ind: Indicator,
    brands: tuple[Brand, ...],
    shorteners: tuple[str, ...],
    filehosts: tuple[str, ...],
) -> None:
    url = ind.value
    host = _host_of(url)
    try:
        parts = urlsplit(url)
    except ValueError:
        _flag(ind, "malformed_url", "URL could not be parsed")
        return
    if parts.scheme.lower() not in ("http", "https", "hxxp", "hxxps"):
        _flag(ind, "unusual_scheme", f"scheme {parts.scheme!r}")
    if not host:
        _flag(ind, "malformed_url", "URL has no host")
        return
    if "@" in parts.netloc:
        _flag(ind, "credentials_in_url", "userinfo before @ hides the real host")
    if _is_ip(host):
        _flag(ind, "raw_ip_url", f"host is a bare IP address ({host})")
        return
    if _in_list(host, shorteners):
        _flag(ind, "shortener", f"{host} is a URL shortener; destination is hidden")
    if _in_list(host, filehosts):
        _flag(ind, "file_hosting", f"{host} is a file-hosting/form service often abused for lures")
    _flag_hostname(ind, host, brands)


def _flag_domain(ind: Indicator, brands: tuple[Brand, ...]) -> None:
    _flag_hostname(ind, ind.value, brands)


def _flag_hostname(ind: Indicator, host: str, brands: tuple[Brand, ...]) -> None:
    if "xn--" in host:
        _flag(ind, "punycode", f"{host} uses punycode (IDN); may render as a lookalike")
    elif not host.isascii():
        _flag(ind, "punycode", f"{host} contains non-ASCII characters")
    labels = [label for label in host.split(".") if label]
    if len(labels) >= 5:
        _flag(ind, "subdomain_depth", f"{len(labels)} labels deep")
    lookalike = find_lookalike(host, brands)
    if lookalike is not None:
        brand, reason = lookalike
        _flag(ind, "lookalike_domain", f"{host} looks like {brand.name}: {reason}")


def _in_list(host: str, entries: tuple[str, ...]) -> bool:
    return any(host == e or host.endswith("." + e) for e in entries)


def find_lookalike(host: str, brands: tuple[Brand, ...]) -> tuple[Brand, str] | None:
    """Return ``(brand, reason)`` if ``host`` impersonates a known brand."""
    host = host.lower()
    org = organizational_domain(host)
    sld = org.split(".")[0] if org else ""
    tokens = [t for t in re.split(r"[.\-_]", host) if t]
    tokens_norm = [_normalise(t) for t in tokens]
    normalised_sld = _normalise(sld)

    for brand in brands:
        name = brand.name.replace(" ", "")
        if brand.is_legitimate_domain(host):
            continue
        # Brand embedded anywhere in the hostname: paypal-secure.example, login.microsoft.example
        if (len(name) >= 4 and any(name in t for t in tokens)) or name in tokens:
            return brand, f"contains {name!r} but is not a {brand.name} domain"
        if len(name) >= 4 and any(name in t for t in tokens_norm):
            return brand, f"contains a homoglyph of {name!r}"
        candidates = {name} | {organizational_domain(d).split(".")[0] for d in brand.domains}
        for cand in candidates:
            if len(cand) < 4:
                continue
            if normalised_sld == cand and sld != cand:
                return brand, f"homoglyph of {cand!r} ({sld})"
            limit = 1 if len(cand) <= 6 else 2
            if sld != cand and 0 < _levenshtein(sld, cand) <= limit:
                return brand, f"typosquat of {cand!r} ({sld})"
    return None


def _normalise(label: str) -> str:
    """Fold common homoglyph substitutions: 0->o, 1->l, rn->m, vv->w."""
    return label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _link_mismatch(text: str, href: str, brands: tuple[Brand, ...]) -> LinkMismatch | None:
    text = text.strip()
    href_host = _host_of(href)
    if not text or not href_host or text.startswith("("):
        return None
    m = _DOMAINISH.match(text)
    if m:
        text_host = m.group(1).lower()
        if not same_org(text_host, href_host):
            return LinkMismatch(text, href, f"text says {text_host} but link goes to {href_host}")
        return None
    lowered = text.lower()
    for brand in brands:
        if re.search(rf"(?<![a-z0-9]){re.escape(brand.name)}(?![a-z0-9])", lowered) and not (
            brand.is_legitimate_domain(href_host)
        ):
            return LinkMismatch(
                text, href, f"text mentions {brand.name} but link goes to {href_host}"
            )
    return None


# --------------------------------------------------------------------------- attachments


def analyze_attachment(att: Attachment) -> AttachmentAnalysis:
    name = att.filename or ""
    exts = [e.lower() for e in name.split(".")[1:]] if "." in name else []
    ext = exts[-1] if exts else ""
    magic = sniff_mime(att.data)
    out = AttachmentAnalysis(
        filename=name,
        extension=ext,
        declared_mime=att.content_type,
        magic_mime=magic,
        size=att.size,
        sha256=att.sha256,
        md5=att.md5,
    )

    def flag(fid: str, detail: str) -> None:
        if fid not in out.flags:
            out.flags.append(fid)
            out.details[fid] = detail

    if len(exts) >= 2 and ext in (EXECUTABLE_EXTS | CONTAINER_EXTS | MACRO_EXTS):
        flag("double_extension", f"{name!r} ends in .{ext} behind .{exts[-2]}")
    elif len(exts) >= 2 and exts[-2] in DOC_EXTS and ext not in DOC_EXTS | ARCHIVE_EXTS:
        flag("double_extension", f"{name!r} has a document extension followed by .{ext}")
    if re.search(r"\s{3,}\.", name):
        flag("double_extension", f"{name!r} pads the real extension with spaces")

    if ext in EXECUTABLE_EXTS:
        flag("executable", f".{ext} is directly executable")
    if ext in MACRO_EXTS:
        flag("macro_enabled", f".{ext} is a macro-enabled Office format")
    if ext in CONTAINER_EXTS:
        flag("dangerous_container", f".{ext} attachments are a common malware delivery wrapper")
    if ext in ARCHIVE_EXTS:
        flag("archive", f".{ext} archive; contents not extracted")

    if magic == "application/x-dosexec":
        flag("executable", "magic bytes identify a Windows PE executable")
    if magic == "application/x-ms-shortcut" and "dangerous_container" not in out.flags:
        flag("dangerous_container", "magic bytes identify a Windows .lnk shortcut")
    if magic == "text/html" and ext not in ("html", "htm", "xhtml", "shtml", "mht", "mhtml"):
        flag("dangerous_container", "content is HTML regardless of its extension")

    expected = _EXT_MIME.get(ext)
    if expected and magic not in ("", "application/octet-stream") and magic != expected:
        flag("mime_mismatch", f".{ext} should be {expected} but bytes look like {magic}")
    declared = (att.content_type or "").lower()
    if (
        magic
        and declared
        and declared != "application/octet-stream"
        and magic != declared
        and not (declared in _TEXT_MIMES and magic in _TEXT_MIMES)
        and not _zip_family(declared, magic)
    ):
        out.details["declared_mime_differs"] = f"declared {declared}, bytes look like {magic}"

    if magic == "application/zip":
        _inspect_zip(att.data, ext, flag)
    return out


def _zip_family(declared: str, magic: str) -> bool:
    zip_like = ("zip", "officedocument", "java-archive", "vnd.ms-excel.sheet.macro", "vnd.ms-")
    return magic == "application/zip" and any(z in declared for z in zip_like)


def _inspect_zip(data: bytes, ext: str, flag: Callable[[str, str], None]) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
    except Exception:
        return
    lowered = [i.filename.lower() for i in infos]
    if any(i.flag_bits & 0x1 for i in infos):
        flag(
            "password_protected_archive", "ZIP entries are encrypted; scanners cannot inspect them"
        )
    if any(n.endswith("vbaproject.bin") for n in lowered):
        flag("macro_enabled", "OOXML package contains vbaProject.bin (VBA macros)")
    if ext in ARCHIVE_EXTS:
        inner_exts = {n.rsplit(".", 1)[-1] for n in lowered if "." in n and not n.endswith("/")}
        bad = sorted(inner_exts & (EXECUTABLE_EXTS | CONTAINER_EXTS | MACRO_EXTS))
        if bad:
            flag("archive_contains_executable", f"archive contains .{', .'.join(bad)}")


def sniff_mime(data: bytes) -> str:
    """Identify common file types from magic bytes. Returns ``""`` if unknown."""
    if not data:
        return ""
    head = data[:16]
    if head.startswith(b"MZ"):
        return "application/x-dosexec"
    if head.startswith(b"\x7fELF"):
        return "application/x-elf"
    if head.startswith(b"%PDF"):
        return "application/pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "application/zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/x-ole-storage"
    if head.startswith(b"{\\rtf"):
        return "text/rtf"
    if head.startswith(b"\x1f\x8b"):
        return "application/gzip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"
    if head.startswith(b"Rar!\x1a\x07"):
        return "application/x-rar"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "application/x-ms-shortcut"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "application/x-iso9660-image"
    if head[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
    ):
        return "application/x-mach-binary"
    snippet = data[:512].lstrip().lower()
    if snippet.startswith((b"<!doctype html", b"<html", b"<script", b"<head", b"<body", b"<?xml")):
        return "text/html" if b"html" in snippet or b"<script" in snippet else "text/xml"
    try:
        data[:512].decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    return "text/plain"


# --------------------------------------------------------------------------- summary


def _summarise(analysis: IndicatorAnalysis) -> None:
    flags: list[str] = []
    for ind in analysis.urls + analysis.domains + analysis.ips:
        for f in ind.flags:
            if f not in flags:
                flags.append(f)
    for att in analysis.attachments:
        for f in att.flags:
            if f not in flags:
                flags.append(f)
    analysis.flags = flags
