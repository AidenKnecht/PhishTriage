# phishtriage — Phishing Email Analyzer CLI

## What this is

A Python command-line tool that takes a raw `.eml` file and produces a triage verdict the way a SOC analyst would: parse the headers, check SPF/DKIM/DMARC authentication results, walk the `Received:` chain, extract every URL and attachment, enrich indicators against free threat-intel APIs, and print a scored report. It is a portfolio project for a cybersecurity student who did phishing triage on a corporate IT security team, so the output should look like something a real analyst would paste into a ticket.

Build it end to end in this repo. Ask me only if something is genuinely ambiguous; otherwise make reasonable choices and note them in `DECISIONS.md`.

## Non-goals

- No web UI. CLI only.
- No machine learning. Every score must come from a rule I can read and explain.
- Don't sandbox or detonate attachments. Hash them and look the hashes up; that's it.
- Don't fetch any URL found in an email. Ever. Enrichment goes through APIs only.

## Stack and constraints

- Python 3.11+, `uv` for env/deps, `pyproject.toml` (no `requirements.txt`).
- Stdlib `email` package for parsing. `rich` for terminal output. `httpx` for API calls. `typer` for the CLI. `pytest` for tests. `ruff` for lint/format. Nothing else unless you justify it in `DECISIONS.md`.
- All API keys via environment variables, loaded from a `.env` that is gitignored. Ship a `.env.example`.
- The tool must run fully offline with `--offline` (skips enrichment, everything else works). Tests must never hit the network.
- Type hints everywhere. `ruff check` and `ruff format --check` must pass clean.

## Repo layout

```
phishtriage/
├── CLAUDE.md               (this file)
├── README.md
├── DECISIONS.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── src/phishtriage/
│   ├── __init__.py
│   ├── cli.py              typer app, entry point `phishtriage`
│   ├── parser.py           .eml -> EmailRecord dataclass
│   ├── auth.py             SPF / DKIM / DMARC / alignment checks
│   ├── hops.py             Received: chain parsing and anomaly detection
│   ├── indicators.py       URL, domain, IP, attachment hash extraction
│   ├── enrich/
│   │   ├── __init__.py
│   │   ├── base.py         Enricher protocol + caching
│   │   ├── urlhaus.py
│   │   ├── virustotal.py
│   │   └── rdap.py         domain age via RDAP (no key needed)
│   ├── scoring.py          rules -> score + verdict
│   ├── report.py           rich terminal report + JSON export
│   └── models.py           dataclasses shared across modules
├── rules/
│   └── scoring.yaml        every scoring rule, weight, and rationale
├── samples/
│   ├── README.md           where samples came from, how they were sanitized
│   ├── benign/             at least 5 .eml files
│   └── phish/              at least 10 .eml files
├── tests/
│   ├── fixtures/           small hand-built .eml files for unit tests
│   ├── test_parser.py
│   ├── test_auth.py
│   ├── test_hops.py
│   ├── test_indicators.py
│   ├── test_scoring.py
│   └── test_cli.py
└── docs/
    ├── screenshots/        (I'll fill these; create the dir)
    └── writeup-outline.md
```

## Functional spec

### 1. Parsing (`parser.py`)

Produce an `EmailRecord` with at minimum: `message_id`, `date`, `from_display`, `from_addr`, `from_domain`, `reply_to_addr`, `return_path`, `to`, `subject`, `received_headers` (list, in order), `authentication_results` (raw header list), `body_text`, `body_html`, `attachments` (filename, content type, size, sha256, md5), and `raw_headers` (dict, preserving duplicates).

Handle multipart, nested multipart, base64 and quoted-printable, malformed dates, missing headers, and RFC 2047 encoded display names. Never crash on a bad email; degrade and record a warning on the record.

### 2. Authentication (`auth.py`)

Parse the `Authentication-Results` header(s) (RFC 8601) and, if present, `Received-SPF`, `DKIM-Signature`, and `ARC-Authentication-Results`. Extract pass/fail/none/softfail/temperror for SPF, DKIM, DMARC.

Then compute **alignment** separately, because a DKIM pass on an unrelated domain is a classic trick:
- SPF alignment: does the `Return-Path` domain match the `From:` domain (relaxed: same organizational domain)?
- DKIM alignment: does the `d=` in the DKIM signature match the `From:` domain?
- Flag `Reply-To` domain mismatching `From:` domain.
- Flag display-name spoofing: display name contains a brand or an email address that doesn't match `from_addr`.

Optionally, with `--live-dns`, actually resolve the SPF record for the sending domain and check whether the last external hop IP is authorized. Use `dnspython` for this if you add it (justify in DECISIONS.md).

### 3. Hop analysis (`hops.py`)

Parse every `Received:` header into `(from_host, from_ip, by_host, with_protocol, timestamp)`. Reverse the chain so it reads origin → destination. Flag:
- Private/reserved IPs appearing as an external origin.
- Timestamps that go backwards or jump more than 24h between hops.
- Hostname in `from` that doesn't reverse-resolve to the stated IP (only under `--live-dns`).
- The first external hop's IP and its country (use the RDAP enricher for country, no GeoIP database).

### 4. Indicator extraction (`indicators.py`)

- URLs from both text and HTML bodies. In HTML, capture both the `href` and the visible link text, and flag any mismatch where the text looks like a URL or brand name pointing elsewhere.
- Defang everything in output by default (`hxxp://`, `[.]`). `--no-defang` to disable.
- Detect: URL shorteners (maintain a list), raw-IP URLs, punycode/IDN domains, lookalike domains against a short brand list (`rules/brands.txt`: microsoft, office365, paypal, docusign, dropbox, amazon, apple, google, chase, wellsfargo, ups, fedex, plus whatever I add), excessive subdomain depth, and known file-hosting abuse domains.
- Attachments: extension, declared MIME type, magic-byte MIME type (use `filetype` lib or hand-roll the common ones), and flag mismatches, double extensions (`invoice.pdf.exe`), macro-enabled Office types, `.iso`/`.img`/`.lnk`/`.html` attachments, and password-protected archives.
- Hash every attachment (sha256 + md5).

### 5. Enrichment (`enrich/`)

Define an `Enricher` protocol with `lookup(indicator) -> EnrichmentResult`. Implement:
- **URLhaus** (abuse.ch, free, no key required for the lookup API): URL and host lookups.
- **VirusTotal** v3 (free tier, key from `VT_API_KEY`): URL, domain, and file-hash lookups. Respect the 4 req/min limit with a simple token bucket; never spam it.
- **RDAP**: domain registration date → age in days. Flag domains under 30 days old. Also returns country for IPs.

Cache every result on disk in `~/.cache/phishtriage/` as JSON keyed by indicator, with a 24h TTL, so re-running on the same sample is instant and doesn't burn quota. Graceful degradation: if a key is missing or an API errors, the report says "not checked (no key)" or "not checked (API error)" rather than silently reporting clean.

### 6. Scoring (`scoring.py` + `rules/scoring.yaml`)

Every signal above maps to a rule in `scoring.yaml` with an `id`, `description`, `weight`, `category`, and `rationale` (one sentence explaining why an analyst cares). The scorer applies rules to the record and enrichment results, sums weights, and returns:
- Score 0–100 (cap at 100).
- Verdict: `CLEAN` (0–19), `SUSPICIOUS` (20–49), `LIKELY PHISH` (50–79), `MALICIOUS` (80+).
- The list of rules that fired, sorted by weight, each with the evidence that triggered it.

Suggested starting weights (tune them, then document the tuning in DECISIONS.md):
- DMARC fail: 25. SPF fail: 15. DKIM fail/none: 10. Any auth result missing entirely: 10.
- From/Return-Path misalignment: 15. Reply-To mismatch: 15. Display-name spoofing: 20.
- Link text/href mismatch: 20. Lookalike domain: 25. Raw-IP URL: 15. Shortener: 5. Punycode: 15.
- URLhaus hit: 40. VT malicious ≥ 3 vendors: 40. VT suspicious 1–2: 15.
- Domain age < 30 days: 20. < 7 days: 30.
- Double extension / MIME mismatch: 30. Macro-enabled attachment: 20. .iso/.lnk/.html attachment: 25.
- Urgency keywords in subject/body (maintain list in `rules/keywords.txt`): 5 per category, max 15.
- Timestamp anomaly in hops: 10. Private IP as external origin: 10.

Rules must be data, not code: adding a keyword or changing a weight should not require touching Python.

### 7. Report (`report.py`)

Terminal output using `rich`, in this order:
1. A header panel: subject, from (display + addr), date, verdict in color (green/yellow/orange/red), score bar.
2. Authentication table: SPF / DKIM / DMARC result, aligned? yes/no, domain checked.
3. Hop chain, origin first, with flags inline.
4. Indicators table: type, value (defanged), flags, enrichment result.
5. Attachments table.
6. "Why this verdict": every fired rule, weight, evidence.
7. A footer line: `N enrichment lookups (M cached), took X.Xs`.

`--json` writes the full structured result to a file. `--markdown` writes a report I can paste straight into a ticket or a blog post.

### 8. CLI (`cli.py`)

```
phishtriage analyze <file.eml> [--offline] [--live-dns] [--json out.json] [--markdown out.md] [--no-defang]
phishtriage batch <dir> [--offline] [--csv summary.csv]     one row per email: file, from, subject, score, verdict, top rule
phishtriage rules                                          print every scoring rule from scoring.yaml as a table
phishtriage cache clear
```

`batch` is the important one for the writeup: I want to point it at `samples/` and get a table showing every phish scored high and every benign email scored low, with a confusion-matrix summary at the bottom.

## Sample corpus (`samples/`)

I will supply real `.eml` files exported from my own inbox and spam folder. Until I do:
- Generate at least 10 synthetic phishing `.eml` files and 5 benign ones covering distinct techniques: credential harvest with lookalike domain, display-name spoof of a known brand, Reply-To hijack, link-text mismatch, shortened URL, raw-IP URL, malicious-looking attachment (double extension), macro doc, invoice/payment urgency lure, DMARC fail with DKIM pass on an unrelated domain (the "aligned vs authenticated" case). Benign ones should include a legitimate newsletter, a real-looking password reset, a GitHub notification, and an internal-style email with no auth headers at all (should be SUSPICIOUS, not MALICIOUS — that's a deliberate calibration case).
- Use `example.com`/`example.net` and RFC 5737 IP ranges so nothing points at a real host.
- Write `samples/README.md` explaining each file and what it should score.

When I drop real samples in, write a `scripts/sanitize.py` that strips my real recipient address, replaces it with `analyst@example.com`, and rewrites any tracking tokens, so I can commit them safely.

## Tests

- Unit tests per module against small fixture `.eml` files in `tests/fixtures/`.
- Enrichers are mocked; a test that makes a real HTTP call is a bug.
- `test_scoring.py` must include a test that loads `scoring.yaml`, applies it to every file in `samples/`, and asserts every `phish/` file scores ≥ 50 and every `benign/` file scores < 50. This is the regression test I'll rely on when tuning weights.
- Target ≥ 85% coverage on `src/`. Don't chase 100%.

## README.md

Written for a hiring manager who has 90 seconds. Sections, in order:
1. One-paragraph description and a terminal screenshot placeholder (`docs/screenshots/analyze.png`).
2. Quickstart: `uv sync`, copy `.env.example`, `phishtriage analyze samples/phish/01-lookalike-domain.eml`.
3. What it checks (a compact table: category → signals).
4. How scoring works, with a link to `rules/scoring.yaml`.
5. Batch results table (I'll paste the real one after running it).
6. Limitations, stated plainly: no sandboxing, heuristic scoring, free-tier API limits, no ML.
7. What I'd build next.

No emoji, no badges except a CI status badge, no "🚀 Features" style headers.

## CI

GitHub Actions workflow: `ruff check`, `ruff format --check`, `pytest` on push and PR, Python 3.11 and 3.12. Add the status badge to the README.

## docs/writeup-outline.md

Draft an outline for the blog writeup I'll publish at aidenknecht.dev/writeups. Working title: "Building a phishing triage tool, then running my own spam folder through it." Structure it around a finding, not a feature list: the outline should leave a slot for the most interesting thing the batch run surfaces (e.g. a phish that passed SPF and DKIM but failed alignment, a benign newsletter that scored suspiciously high and why, a domain registered 3 days before the email arrived). Include a list of the 4–6 screenshots I should take and what each one needs to show.

## Order of work

1. Scaffold repo, `pyproject.toml`, models, parser, tests for parser. Commit.
2. Auth + hops + tests. Commit.
3. Indicators + attachment analysis + tests. Commit.
4. Scoring engine + `scoring.yaml` + synthetic samples + regression test. Commit.
5. Report + CLI + `batch`. Commit.
6. Enrichers with caching + mocked tests. Commit.
7. README, CI, DECISIONS.md, writeup outline. Commit.

Commit messages in conventional-commits style. Stop after step 4 and show me the batch output before continuing, so I can sanity-check the calibration.

## Definition of done

- `uv run phishtriage batch samples/ --offline` prints a table where every phish is ≥ 50 and every benign is < 50.
- `uv run pytest` green, `uv run ruff check` clean, CI green.
- I can read `rules/scoring.yaml` and explain every rule in an interview without opening the Python.
