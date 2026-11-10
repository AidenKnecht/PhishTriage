"""Build the Queen City Con slide deck from the repo's screenshots and talk outline.

python-pptx is not a phishtriage dependency; run this in a throwaway env:

    uv run --with python-pptx python scripts/make_deck.py

Writes out/talk/phishtriage-queen-city-con.pptx (out/ is gitignored). The
deck is a starting point: apply your own theme in PowerPoint afterwards.
Speaker notes on every slide come from docs/talk-outline.md.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parents[1]
SHOTS = ROOT / "docs" / "screenshots"
OUT = ROOT / "out" / "talk" / "phishtriage-queen-city-con.pptx"

# Dark, high-contrast palette close to the terminal screenshots, so images
# sit on the slide without a bright frame around them.
BG = RGBColor(0x1B, 0x1D, 0x22)
PANEL = RGBColor(0x26, 0x29, 0x30)
INK = RGBColor(0xF0, 0xEF, 0xEC)
INK2 = RGBColor(0xC3, 0xC2, 0xB7)
MUTED = RGBColor(0x8F, 0x8D, 0x87)
ACCENT = RGBColor(0xEC, 0x83, 0x5A)  # "serious" orange: kicker labels, demo cues
BAD = RGBColor(0xE0, 0x5A, 0x5A)
GOOD = RGBColor(0x3C, 0xC4, 0x6A)
SANS = "Segoe UI"
SANS_BOLD = "Segoe UI Semibold"
MONO = "Cascadia Mono"

W, H = Inches(13.333), Inches(7.5)
MARGIN = Inches(0.6)


@dataclass
class Img:
    path: Path
    crop_top: float = 0.0
    crop_bottom: float = 0.0
    crop_left: float = 0.0
    crop_right: float = 0.0

    def aspect(self) -> float:
        pw, ph = png_size(self.path)
        return (pw * (1 - self.crop_left - self.crop_right)) / (
            ph * (1 - self.crop_top - self.crop_bottom)
        )


@dataclass
class Slide:
    kicker: str = ""
    title: str = ""
    bullets: list[str] = field(default_factory=list)
    image: Img | None = None
    demo: str = ""
    notes: str = ""


def png_size(path: Path) -> tuple[int, int]:
    head = path.read_bytes()[:24]
    return struct.unpack(">II", head[16:24])


def bg(slide) -> None:
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = BG


def text(
    slide,
    left,
    top,
    width,
    height,
    runs,
    *,
    size=20,
    color=INK,
    font=SANS,
    align=PP_ALIGN.LEFT,
    anchor=MSO_ANCHOR.TOP,
    spacing=1.1,
):
    """``runs`` is a list of paragraphs; each paragraph a str or list of (text, overrides)."""
    box = slide.shapes.add_textbox(left, top, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    for i, para in enumerate(runs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.line_spacing = spacing
        pieces = [(para, {})] if isinstance(para, str) else para
        for chunk, over in pieces:
            r = p.add_run()
            r.text = chunk
            f = r.font
            f.name = over.get("font", font)
            f.size = Pt(over.get("size", size))
            f.bold = over.get("bold", False)
            f.color.rgb = over.get("color", color)
    return box


def picture(slide, img: Img, left, top, max_w, max_h) -> None:
    """Fit an image (after cropping) inside a box, centred, aspect preserved."""
    pw, ph = png_size(img.path)
    visible_w = pw * (1 - img.crop_left - img.crop_right)
    visible_h = ph * (1 - img.crop_top - img.crop_bottom)
    scale = min(max_w / visible_w, max_h / visible_h)
    w, h = int(visible_w * scale), int(visible_h * scale)
    x = left + (max_w - w) // 2
    y = top + (max_h - h) // 2
    pic = slide.shapes.add_picture(str(img.path), Emu(x), Emu(y), Emu(w), Emu(h))
    pic.crop_top, pic.crop_bottom = img.crop_top, img.crop_bottom
    pic.crop_left, pic.crop_right = img.crop_left, img.crop_right
    pic.line.color.rgb = PANEL
    pic.line.width = Pt(1)


def demo_pill(slide, label: str) -> None:
    w, h = Inches(3.4), Inches(0.42)
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, W - MARGIN - w, Inches(0.38), w, h)
    shape.fill.solid()
    shape.fill.fore_color.rgb = ACCENT
    shape.line.fill.background()
    tf = shape.text_frame
    tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = label
    r.font.name, r.font.size, r.font.bold = SANS_BOLD, Pt(14), True
    r.font.color.rgb = RGBColor(0x11, 0x11, 0x11)


def footer(slide, n: int, total: int) -> None:
    text(
        slide,
        MARGIN,
        H - Inches(0.45),
        Inches(8),
        Inches(0.3),
        ["phishtriage  ·  Queen City Con"],
        size=11,
        color=MUTED,
    )
    text(
        slide,
        W - MARGIN - Inches(1),
        H - Inches(0.45),
        Inches(1),
        Inches(0.3),
        [f"{n} / {total}"],
        size=11,
        color=MUTED,
        align=PP_ALIGN.RIGHT,
    )


def header(slide, s: Slide) -> float:
    """Kicker + title; returns the y (EMU) where content can start."""
    y = Inches(0.45)
    if s.kicker:
        text(
            slide,
            MARGIN,
            y,
            Inches(8.5),
            Inches(0.35),
            [s.kicker.upper()],
            size=14,
            color=ACCENT,
            font=SANS_BOLD,
        )
        y += Inches(0.42)
    two_lines = len(s.title) > 60
    text(
        slide,
        MARGIN,
        y,
        W - 2 * MARGIN,
        Inches(1.4 if two_lines else 0.8),
        [s.title],
        size=34,
        font=SANS_BOLD,
        spacing=1.0,
    )
    return y + Inches(1.6 if two_lines else 1.05)


def bullet_runs(items: list[str]) -> list:
    out = []
    for item in items:
        if item.startswith("`") and item.endswith("`"):
            out.append([(item.strip("`"), {"font": MONO, "color": INK2, "size": 20})])
        else:
            out.append([("•  ", {"color": ACCENT}), (item, {})])
    return out


def content_slide(prs, s: Slide, n: int, total: int) -> None:
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    bg(slide)
    if s.demo:
        demo_pill(slide, s.demo)
    top = header(slide, s)
    bottom = H - Inches(0.7)
    if s.image and s.bullets and s.image.aspect() > 2.2:
        img_h = min(Inches(3.6), int((W - 2 * MARGIN) / s.image.aspect()))
        picture(slide, s.image, MARGIN, top, W - 2 * MARGIN, img_h)
        half = (len(s.bullets) + 1) // 2
        col_w = (W - 2 * MARGIN - Inches(0.5)) // 2
        y = top + img_h + Inches(0.3)
        for i, chunk in enumerate((s.bullets[:half], s.bullets[half:])):
            text(
                slide,
                MARGIN + i * (col_w + Inches(0.5)),
                y,
                col_w,
                bottom - y,
                bullet_runs(chunk),
                size=19,
                spacing=1.15,
            )
    elif s.image and s.bullets:
        col = Inches(4.3)
        text(slide, MARGIN, top, col, bottom - top, bullet_runs(s.bullets), size=20, spacing=1.2)
        picture(
            slide,
            s.image,
            MARGIN + col + Inches(0.4),
            top,
            W - 2 * MARGIN - col - Inches(0.4),
            bottom - top,
        )
    elif s.image:
        picture(slide, s.image, MARGIN, top, W - 2 * MARGIN, bottom - top)
    else:
        text(
            slide,
            MARGIN,
            top,
            W - 2 * MARGIN,
            bottom - top,
            bullet_runs(s.bullets),
            size=24,
            spacing=1.25,
        )
    footer(slide, n, total)
    slide.notes_slide.notes_text_frame.text = s.notes


# --------------------------------------------------------------------------- bespoke slides


def title_slide(prs, total: int) -> None:
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    bg(slide)
    text(
        slide,
        MARGIN,
        Inches(1.6),
        Inches(11.5),
        Inches(0.4),
        ["QUEEN CITY CON"],
        size=16,
        color=ACCENT,
        font=SANS_BOLD,
    )
    text(
        slide,
        MARGIN,
        Inches(2.1),
        Inches(12),
        Inches(2.2),
        ["18 for 18 on mail I wrote.", "10 for 15 on mail I got."],
        size=48,
        font=SANS_BOLD,
    )
    text(
        slide,
        MARGIN,
        Inches(4.25),
        Inches(11.5),
        Inches(0.9),
        ["Building a phishing triage tool, then running my own inbox through it"],
        size=24,
        color=INK2,
    )
    text(
        slide,
        MARGIN,
        Inches(5.6),
        Inches(11.5),
        Inches(0.9),
        [
            [("Aiden Knecht", {"font": SANS_BOLD, "color": INK})],
            [("github.com/AidenKnecht/PhishTriage", {"font": MONO, "size": 16, "color": MUTED})],
        ],
        size=20,
    )
    slide.notes_slide.notes_text_frame.text = (
        "I did phishing triage on a corporate IT security team for a co-op rotation. "
        "Then I tried to write down what I was doing, as code. This talk is what happened "
        "when I pointed that code at my own inbox."
    )


def scoreboard_slide(prs, n: int, total: int) -> None:
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    bg(slide)
    demo_pill(slide, "LIVE DEMO  ·  step 5")
    top = header(slide, Slide(kicker="The finding", title="The scoreboard"))
    col_w = Inches(5.6)
    for i, (big, label, sub, color) in enumerate(
        [
            ("18 / 18", "synthetic emails I wrote", "12 phish, 6 benign. Every one right.", GOOD),
            ("10 / 15", "real emails I received", "9 benign right. 1 of 6 phish caught.", BAD),
        ]
    ):
        x = MARGIN + i * (col_w + Inches(0.9))
        panel = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, top, col_w, Inches(3.6))
        panel.fill.solid()
        panel.fill.fore_color.rgb = PANEL
        panel.line.fill.background()
        panel.adjustments[0] = 0.06
        text(
            slide,
            x + Inches(0.5),
            top + Inches(0.45),
            col_w - Inches(1),
            Inches(1.6),
            [big],
            size=88,
            font=SANS_BOLD,
            color=color,
        )
        text(
            slide,
            x + Inches(0.5),
            top + Inches(2.1),
            col_w - Inches(1),
            Inches(1.3),
            [[(label, {"font": SANS_BOLD, "size": 24})], [(sub, {"color": INK2, "size": 18})]],
        )
    text(
        slide,
        MARGIN,
        top + Inches(4.0),
        W - 2 * MARGIN,
        Inches(0.8),
        [
            "Threshold: 50 = LIKELY PHISH.  Zero false alarms in either set.  "
            "Guess which number matters."
        ],
        size=20,
        color=INK2,
    )
    footer(slide, n, total)
    slide.notes_slide.notes_text_frame.text = (
        "Run demo step 5: batch over all 33 samples. Pause on the confusion matrix. "
        "18 of 18 on mail I wrote. 10 of 15 on mail I actually got. Five real phish missed, "
        "zero false alarms. Fallback: docs/screenshots/batch.png."
    )


def before_after_slide(prs, n: int, total: int) -> None:
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    bg(slide)
    top = header(slide, Slide(kicker="Threat intel", title="Right verdict, wrong reason"))
    amber = RGBColor(0xFA, 0xB2, 0x19)
    panels = [
        (
            "BEFORE",
            "90",
            "MALICIOUS",
            BAD,
            [
                ("+40", "URLhaus: 8 malware URLs on host"),
                ("+15", "1 VirusTotal vendor flags the host"),
                ("  0", "the scam's own link: never seen"),
            ],
        ),
        (
            "AFTER THE FIX",
            "35",
            "SUSPICIOUS",
            amber,
            [
                ("  0", "shortener host = shared hosting"),
                ("  0", "listing shown to analyst, not scored"),
                ("+40", "still fires on the exact URL"),
            ],
        ),
    ]
    gap = Inches(0.9)
    col_w = (W - 2 * MARGIN - gap) // 2
    panel_h = Inches(3.7)
    for i, (label, num, verdict, color, rows) in enumerate(panels):
        x = MARGIN + i * (col_w + gap)
        box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, top, col_w, panel_h)
        box.fill.solid()
        box.fill.fore_color.rgb = PANEL
        box.line.fill.background()
        box.adjustments[0] = 0.06
        inner = x + Inches(0.45)
        text(
            slide,
            inner,
            top + Inches(0.3),
            col_w,
            Inches(0.4),
            [label],
            size=16,
            font=SANS_BOLD,
            color=MUTED,
        )
        text(
            slide,
            inner,
            top + Inches(0.7),
            col_w,
            Inches(1.2),
            [
                [
                    (num, {"size": 72, "font": SANS_BOLD, "color": color}),
                    ("  " + verdict, {"size": 24, "font": SANS_BOLD, "color": color}),
                ]
            ],
        )
        text(
            slide,
            inner,
            top + Inches(2.05),
            col_w - Inches(0.8),
            Inches(1.6),
            [
                [
                    (pts + "  ", {"font": MONO, "color": color if pts.strip() != "0" else MUTED}),
                    (why, {}),
                ]
                for pts, why in rows
            ],
            size=17,
            spacing=1.25,
        )
    text(
        slide,
        MARGIN,
        top + panel_h + Inches(0.3),
        W - 2 * MARGIN,
        Inches(0.8),
        [
            "Same story with MyChart: a raw 120 because storage.googleapis.com hosts 2,242 "
            "malware URLs. Shared platforms carry everyone's reputation."
        ],
        size=18,
        color=INK2,
    )
    footer(slide, n, total)
    slide.notes_slide.notes_text_frame.text = (
        "With live threat intel, the classmate job scam jumped from 35 to 90 MALICIOUS. "
        "Not because of anything in the email: URLhaus lists 8 malware URLs on shorturl.at, "
        "and one VirusTotal vendor flags it. The specific short link was never seen. "
        "Same thing happened with MyChart: raw 120 because Google Cloud Storage hosts "
        "2,242 malware URLs. Both verdicts 'right', both for the wrong reason. "
        "Fix: a shared_hosting flag. Host-level reputation on file hosts and shorteners "
        "no longer scores; a hit on the exact URL still does. Right now it's 35 again, "
        "and the report still shows the listing so an analyst sees it. "
        "Screenshots if asked: out/before-90.png (before) and "
        "docs/screenshots/analyze-real-uc-scam.png (after)."
    )


# --------------------------------------------------------------------------- content


def slides() -> list:
    return [
        title_slide,
        Slide(
            kicker="The job",
            title="A user forwards a suspicious email. Now what?",
            bullets=[
                "Who really sent it? SPF, DKIM, DMARC, and do they align?",
                "Where did it come from? Walk the Received chain back to the origin",
                "What's in it? Every link, every attachment",
                "What does the internet know? Reputation and domain age",
                "A verdict someone else can defend, in a ticket",
            ],
            notes=(
                "First five minutes of a phishing ticket. This is the checklist I ran by hand. "
                "phishtriage does exactly this, in this order."
            ),
        ),
        Slide(
            kicker="Ground rules",
            title="Rules I set myself",
            bullets=[
                "No ML. Every point traces to a line of YAML",
                "Never fetch a URL from an email. APIs only",
                "Never open an attachment. Hash it, sniff the type, look it up",
                "Defang everything in output",
                "Works fully offline",
            ],
            notes=(
                "Explainability is the point. If someone asks why it scored 65, the answer "
                "is a list of lines in a file. Offline mode matters: it's what I'm demoing "
                "today, so the conference Wi-Fi can't hurt me."
            ),
        ),
        Slide(
            kicker="Rules are data",
            title="Every rule: a weight, a reason, a technique",
            image=Img(SHOTS / "rules.png", crop_top=0.03, crop_bottom=0.62),
            demo="LIVE DEMO  ·  step 1",
            notes=(
                "Demo step 1: phishtriage rules. Point at one row: weight, rationale, ATT&CK id. "
                "34 rules. Changing a weight is a text edit, and the test suite re-checks the "
                "whole sample corpus. Fallback: rules.png."
            ),
        ),
        Slide(
            kicker="Authentication",
            title="Authenticated is not aligned",
            bullets=[
                "SPF: pass",
                "DKIM: pass, for notify-mailer.example",
                "From: chase.com",
                "DMARC: fail. That's the one that matters",
            ],
            image=Img(SHOTS / "analyze.png", crop_bottom=0.6, crop_right=0.36),
            demo="LIVE DEMO  ·  step 2",
            notes=(
                "Demo step 2, synthetic Chase sample. SPF and DKIM both pass. But DKIM is a "
                "valid signature for some other domain. 'DKIM pass' only means someone signed "
                "it. DMARC asks whether the signer matches the From domain, and it fails. "
                "Lookalike link on top: 80 MALICIOUS. Fallback: analyze.png."
            ),
        ),
        Slide(
            kicker="A real one",
            title='"MyChart": every check that can pass, passes',
            bullets=[
                "Display name: MyChart. Sender: a random .us domain",
                "SPF passes, for a 7-label bounce domain nobody sees",
                "Landing page on storage.googleapis.com",
                "65: LIKELY PHISH",
            ],
            image=Img(SHOTS / "html-report.png", crop_top=0.0, crop_bottom=0.6),
            demo="LIVE DEMO  ·  step 3",
            notes=(
                "Demo step 3: analyze the real MyChart phish, writes an HTML report and opens it. "
                "Walk the 'where the points came from' bar: every colour is a rule category, "
                "every segment is a line of YAML. The HTML runs no scripts and loads nothing "
                "from the network. Fallback: html-report.png, analyze-real-mychart.png."
            ),
        ),
        Slide(
            kicker="Speak the SOC's language",
            title="Every fired rule maps to ATT&CK",
            bullets=[
                "`T1684.002   Email Spoofing          dmarc_fail, spf_misaligned`",
                "`T1684.001   Impersonation           display_name_spoof, reply_to`",
                "`T1036.007   Double File Extension   invoice.pdf.exe`",
                "`T1566.002   Spearphishing Link      link_text_mismatch`",
                "Check your mappings: in ATT&CK v20.1, spoofing and impersonation "
                "live under T1684 Social Engineering",
            ],
            notes=(
                "Tags are evidence-of, not attribution. A DMARC fail is evidence of email "
                "spoofing, not proof. The hop-chain rules are deliberately untagged: weird "
                "Received headers are plumbing, not a technique. Heads-up for the room: "
                "spoofing and impersonation sit under T1684 in the current release, so older "
                "blog-post mappings may be stale."
            ),
        ),
        scoreboard_slide,
        Slide(
            kicker="The misses",
            title="My misses came from my classmates",
            bullets=[
                "Job scams and password lures from real, compromised student accounts",
                "Inside the university's own Microsoft 365 tenant",
                "No Authentication-Results. No external hop. Real uc.edu sender",
                "ATT&CK T1586.002: Compromise Accounts: Email Accounts",
            ],
            image=Img(SHOTS / "analyze-real-uc-scam.png", crop_bottom=0.36, crop_right=0.04),
            demo="LIVE DEMO  ·  step 4",
            notes=(
                "Demo step 4. Four of five misses are the same thing: intra-tenant mail from "
                "compromised student accounts. It never crosses a mail boundary, so there's "
                "nothing to authenticate. Every infrastructure check passes because the "
                "infrastructure is fine. Only the words are wrong. The students are victims; "
                "they're pseudonymised in every sample."
            ),
        ),
        Slide(
            kicker="The worst miss",
            title="The fifth one scores CLEAN",
            bullets=[
                '"Set up an account with Microsoft Teams to meet our senior technical '
                'recruiter for an online briefing."',
                "Polite. Authenticated. Nothing structurally wrong",
                "Impersonates a real company as a recruiter. Not sent by them",
                "Score: 5",
            ],
            notes=(
                "Fake-interview scam. The interview never leaves a chat window. There is "
                "nothing for a header rule to see. This is the case that tells you where "
                "the limit of rule-based triage is."
            ),
        ),
        Slide(
            kicker="Tuning",
            title="Weight the words more? Measure it first.",
            image=Img(SHOTS / "compare.png"),
            demo="LIVE DEMO  ·  step 6",
            notes=(
                "Demo step 6: batch --compare with a five-line proposal file that doubles "
                "keyword weight. Catches one more scam, 14 of 18. Cost: a password reset and "
                "a real internship assessment email move from CLEAN to SUSPICIOUS. "
                "A tuning change is a hypothesis; measure it on real mail before you ship it. "
                "Fallback: compare.png."
            ),
        ),
        before_after_slide,
        Slide(
            kicker="Lesson I didn't plan",
            title="The email is attacker input, all the way to the last line",
            bullets=[
                "`Subject: [/b] [external] Your account is on hold`",
                "My terminal report read email text as markup",
                "That subject crashed it. Defanged [@] silently vanished",
                "Same bug class as XSS in a webmail client, in a phishing tool",
                "Fixed: email text is data. HTML report: no scripts, CSP default-src 'none'",
            ],
            demo="LIVE DEMO  ·  step 7",
            notes=(
                "Bonus demo step 7 if time allows. The rich terminal library interprets "
                "[bold] style tags. A subject containing [/b] raised an exception and killed "
                "the whole batch run. Found it during the polish pass. Now every value from "
                "the email is rendered as literal text."
            ),
        ),
        Slide(
            kicker="Takeaways",
            title="What I'd tell my co-op self",
            bullets=[
                "Authentication says who sent it, not whether to trust it. Check alignment",
                "Compromised internal accounts beat every header check",
                "Reputation on shared infrastructure describes the neighbours",
                "Synthetic samples test what you already thought of. Test on real mail",
            ],
            notes="Four lines. Slow down here.",
        ),
        Slide(
            kicker="Thanks",
            title="Questions?",
            bullets=[
                "`github.com/AidenKnecht/PhishTriage`",
                "`aidenknecht.dev/writeups`",
                "Why no ML? Explainability, and 33 samples is not a training set",
                "Catching the classmate scams: behaviour, not headers. Next on the list",
            ],
            notes=(
                "Likely questions. Why no ML: explainability, small corpus. Compromised accounts: "
                "first-time sender to a list, external reply address or phone number in internal "
                "mail, mass sends. Detonation: no, by design. API limits: VT 4/min, rate-limited, "
                "24h cache, per-email budget, reserved names never sent."
            ),
        ),
    ]


def main() -> int:
    prs = Presentation()
    prs.slide_width, prs.slide_height = W, H
    deck = slides()
    total = len(deck)
    for n, item in enumerate(deck, 1):
        if isinstance(item, Slide):
            content_slide(prs, item, n, total)
        elif item is title_slide:
            item(prs, total)
        else:
            item(prs, n, total)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUT)
    print(f"wrote {OUT.relative_to(ROOT)} ({total} slides)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
