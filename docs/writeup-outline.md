# The phish my tool missed came from my classmates

Working outline for aidenknecht.dev/writeups. Alternate titles:
"Building a phishing triage tool, then running my own spam folder through it" and
"Right verdict, wrong reason: what threat intel did to my phishing scores".

Structure the piece around what the real-mail run surfaced, not around the
feature list. Every number below comes from the repo as of 2026-09-30. Anything
marked **[TODO]** still needs a run or a decision.

## 0. The story in three beats

1. I wrote down the checks I did by hand for a year as 34 YAML rules. The rules
   went 18/18 on the synthetic emails I built to test them.
2. On 15 real emails from my own inboxes they missed 5 phish, and four of those
   came from my classmates' compromised university accounts. Every
   infrastructure check passed, because the infrastructure was clean.
3. Turning on threat intel "caught" one of those misses, but for the wrong
   reason: it judged a URL shortener by other people's links. The same flaw
   pushed a real phish to a raw score of 120. Fixing that bug is the lesson.

## 1. The hook (150-250 words)

Pick one opening. My recommendation is (a).

- **(a) The miss.** "Office Administrative Job Opportunity", sent from a real
  `mail.uc.edu` student account to other students. It had no
  `Authentication-Results`, no external hop, and a sender domain that really was
  the university's. My tool scored it 35: SUSPICIOUS, not phish. Nothing in the
  headers was wrong, because nothing in the headers *was* wrong. The account had
  been taken over, and only the text gave it away.
- **(b) The 120.** With live threat intel on, a MyChart phish scored a raw 120 out
  of 100. Fifty-five of those points came from Google Cloud Storage's reputation,
  not from the email. The verdict was right; the reasoning was nonsense.
- **(c) The textbook case.** A "Chase" alert where SPF *and* DKIM both pass and
  DMARC still fails, because the domain that authenticated wasn't the one in
  `From:`. It's the cleanest way to teach aligned vs. authenticated, but it's a
  synthetic sample, so use it in section 2 rather than as the hook.

Then one paragraph on the setup: a year of doing this by hand on a corporate IT
security team, the same checks every time, and the decision to write them down
as rules.

## 2. What triage actually is (300 words)

- The analyst's checklist: who sent it, did the infrastructure vouch for them,
  where did it physically come from, and what does it want me to click or open.
- **Authenticated vs. aligned**, worked through on
  `phish/10-dmarc-fail-dkim-unrelated.eml`: SPF pass and DKIM pass, both for
  `notify-mailer.example`; `From: alerts@chase.com`; DMARC fails. It scores 80
  MALICIOUS offline. Show the Authentication table with the two green passes and
  "Aligned? no" next to them (`analyze.png`).
- Why the output has to look like something you'd paste into a ticket: defanged
  indicators, and evidence next to every point.

## 3. Design choices worth defending (400 words)

- **Rules as data.** 34 rules in `rules/scoring.yaml`, each with a weight,
  category, condition and a one-sentence rationale. Show two or three verbatim,
  rationale included (`rules.png`).
- **No machine learning, on purpose.** The interview-question test: can I explain
  every point on the score? Every point traces to a rule.
- **Never fetch a URL, never open an attachment.** Hash it, sniff the magic bytes,
  then ask APIs about the indicators.
- **Text is capped at 15 points.** Lure keywords alone can't push an email over
  50. That choice is exactly why the classmate scams are misses (section 6), and
  I'd keep it anyway: a keyword-driven score is easy to game and noisy on
  marketing mail.
- **Known misses are written down, not tuned away.** `samples/known-misses.txt`
  lists 5 phish the rules under-score. The regression test holds each one at its
  documented floor and fails if one quietly crosses 50, so the list can't go
  stale.

## 4. The build, briefly (300 words)

Keep this short; it's the least interesting part to a reader.

- Python CLI, 93% test coverage, and CI running lint, format, tests and a batch
  smoke test on every push.
- **The boundary hop.** Walk the `Received:` chain back to the first hop where the
  recipient's infrastructure accepted mail from outside. The first version
  flagged the sender's own `[10.x]` submission hop as a "private IP origin".
- **The YAML `on:` key.** PyYAML reads a bare `on` as boolean `true`, so
  `on: urls` silently became an unscoped match. A unit test caught it, and the
  key is now `scope:`. Small, real, and funny.
- **Real mail broke the hop logic.** Microsoft 365 never shows the recipient's
  domain in its `by` hosts, and Gmail's last hop is a bare IPv6 literal. The fix
  was to group servers into provider families (`google`, `microsoft`) rather than
  domains.

## 5. Running my own inboxes (the centre of the piece)

**The corpus.** 15 real emails exported on 2026-09-16 from my Gmail and
university Microsoft 365 inboxes: 6 phish and 9 benign, including four "internship"
emails that all landed in spam. I classified those four by reading them, not by
where the provider filed them: three were legitimate and one was a scam.
Alongside them are 18 synthetic samples (12 phish, 6 benign).

**Offline results (headers, links and text only).**

- Synthetic: 18/18 correct.
- Whole corpus at threshold 50: 28/33 correct, 5 phish missed, 0 false alarms
  (`batch.png`).
- The highest-scoring benign email was an ISC2 webinar at 25. Salesforce rewrites
  every link through `cl.s12.exct.net` while the visible text says `isc2.org`,
  so it's a real link-text mismatch that every email-marketing platform produces.

**The walkthrough email.** Use the MyChart phish (`analyze-real-mychart.png`) and
go through it top to bottom:

- Header panel: "Analyst, Your MyChart Medicare Kit Awaits" from `MyChart
  <...@pvozylejk.us>`, a random `.us` domain with no RDAP record.
- Auth table: SPF *passes*, but for a seven-label randomised bounce domain that
  doesn't align with `From`. DKIM and DMARC weren't reported.
- Hop chain: origin `46.250.247.17` on UK hosting (YorkshireTech) with a HELO of
  `wildernessexp.com`, which fits neither MyChart nor the sender domain.
- Indicators: the landing page is on `storage.googleapis.com`, and the per-victim
  tracking ID in the link fragment is redacted.
- Verdict: 65, LIKELY PHISH. Display-name spoof (+20), Return-Path misaligned
  (+15), DKIM none (+10), then +5 each for DMARC none, file-hosting link, urgency
  wording and the deep subdomain.

**[TODO]** Run `uv run phishtriage batch samples/` online (no `--offline`) and
record the confusion matrix and how long it took. VirusTotal's free tier allows 4
lookups a minute: one uncached email took 56.8 s for 8 lookups, and later runs
come from the 24-hour cache.

## 6. What the rules got wrong

**Misses: the classmate scams.** Four emails came from real students' accounts
inside the university's Microsoft 365 tenant: two job scams ("personal
assistant, $650 weekly"), and two "system maintenance, update your school email
and password within 48 hours" lures pointing at a Google Form. They scored 25-40
SUSPICIOUS offline. It's intra-tenant mail, so there's no external hop and no
authentication headers, and the sender domain is genuine. What gave them away
was job-scam and credential wording plus a URL shortener, and text is capped by
design.

- Say plainly that the account owners are victims. Their names are pseudonymised
  in the repo (`Student, A` through `Student, D`); never name them in the post.

**The worst miss: the fake Teams interview.** "Set up a Microsoft Teams account
to meet a senior technical recruiter for an online briefing." It was sent via
Zoho and written in polite corporate boilerplate. It scores 5, CLEAN. Nothing
structural is wrong, so it's listed as a miss that's allowed to score CLEAN
(`floor=0`) rather than one I pretend is SUSPICIOUS.

**Right verdict, wrong reason: threat intel on shared infrastructure.** This is
the strongest technical section.

- With live keys, the MyChart phish scored a raw 120. URLhaus gave +40 because it
  lists `storage.googleapis.com` as a host with 2,242 malware URLs. VirusTotal
  gave +15 because one vendor flags the same domain. The specific URL was listed
  nowhere.
- Fix: domains on the file-hosting list get a `shared_hosting` flag, and the
  reputation rules skip them. A hit on the *exact URL* still counts. Result: 65.
  Show the before/after "why this verdict" panels.
- Then it happened again. The classmate job scam went from 35 to **90
  MALICIOUS** online: +40 because URLhaus lists 8 malware URLs on `shorturl.at`,
  +15 because one VirusTotal vendor flags it. The shortened link itself was
  "never seen". The ISC2 newsletter went from 25 to 40 because one vendor flags
  Salesforce's click-tracker domain (`analyze-real-uc-scam.png`,
  `analyze-real-isc2.png`).
- The point: a URL shortener, a cloud bucket and a marketing click-tracker are
  shared by millions of senders. Their reputation describes the other tenants,
  not your email. A verdict that's right for the wrong reason is a false
  positive waiting to happen.
- **[TODO]** Decide whether to extend `shared_hosting` to URL shorteners and ESP
  click-trackers before publishing, then retake those two screenshots. If you
  fix it, the post shows the full loop: found, fixed, found again, generalised.

**Calibration fixes real mail forced** (one line each):

- Hop boundaries grouped by provider family, not by domain (Microsoft 365 and
  Gmail).
- Alignment only scores when DMARC itself didn't pass. Tenants signing with
  `*.onmicrosoft.com` are normal.
- `storage.googleapis.com` was being scored as a Google *lookalike* (25) instead
  of a file-hosting link (5).
- The Return-Path domain became an indicator, which is how the MyChart bounce
  domain got caught by the deep-subdomain rule.

**One thing a human caught immediately:** the fake Teams interview. Anyone who
has applied for jobs knows recruiters don't make you install software to "meet"
them. No header check can see that.

## 7. Sharing real phish safely (optional, 200 words)

Worth including if you want a practical-security angle; cut it if the post runs
long.

- Real emails are full of identifiers: your address in bounce addresses, your
  name in greetings, and per-recipient tracking tokens in every link.
- My first sanitiser matched raw bytes and missed URLs that quoted-printable
  encoding had split across lines (the `=` soft line break, or `=3D` in place of
  `=`). One sample still had a working auto-login link to an account of mine. The
  fix decodes each body part, redacts it, re-encodes it, and splices it back
  without touching the headers, because the headers are the evidence.
- Victims get pseudonyms. The senders of the compromised-account scams are
  people, not threat actors.
- Git remembers, so cleaning the files meant rewriting history.

## 8. What I'd build next (150 words)

The two the real run made obviously necessary:

- **Treat shared infrastructure as shared everywhere.** Extend the fix above into
  a maintained data file of shorteners, cloud storage and ESP click-trackers, and
  resolve shortened links' destinations through an API rather than scoring the
  shortener's host.
- **A content signal that can see job and interview scams** without lifting the
  15-point text cap: for example, a combined rule where "first contact + job
  offer + move to text or install software" fires only together.

Also from the README list: IDN decoding for lookalike checks, QR-code extraction
(quishing), `.msg` support, and a `--compare` mode for tuning weights.

## Screenshots

All are in `docs/screenshots/`. The four `analyze` shots are my own terminal,
taken with enrichment on. `batch.png` and `rules.png` are generated by
`scripts/screenshot.py`.

| File | Shows | Use in section |
|---|---|---|
| `analyze.png` | Chase sample: SPF/DKIM pass, DMARC fail, 80 MALICIOUS | 2 |
| `analyze-real-mychart.png` | MyChart phish, 65 after the shared-hosting fix | 5, 6 |
| `analyze-real-uc-scam.png` | Classmate job scam, 90 via `shorturl.at` reputation | 6 |
| `analyze-real-isc2.png` | ISC2 newsletter, 40 via click-tracker reputation | 6 |
| `batch.png` | Whole corpus offline, with the confusion matrix | 5 |
| `rules.png` | First rows of the rules table, rationale column visible | 3 |

Still worth taking:

- **Before/after for the 120.** The MyChart "why this verdict" panel before and
  after the shared-hosting fix. The "before" state is at commit `94e9ba0`: check
  it out, run `analyze` online, and take the shot, then return to `main`.
- **[TODO]** Retake `analyze-real-uc-scam.png` and `analyze-real-isc2.png` if the
  shortener and click-tracker fix goes in.
- Optional: an offline `analyze.png`. The online one shows "virustotal: not
  checked (API error: HTTP 400)" on the synthetic `.example` domains, which reads
  like a bug.
