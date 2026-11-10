# Talk outline: Queen City Con

**Working title:** "18 for 18 on mail I wrote, 10 for 15 on mail I got: building a phishing triage tool and running my own inbox through it"

**Alternate:** "The phish my tool missed came from my classmates"

**Slot assumed:** 25 minutes plus questions. Cut list at the bottom if the slot is 15.

**The one idea to leave the room with:** every infrastructure check can pass and the email can still be a phish. Authentication tells you *who sent it*, not *whether to trust it*, and threat-intel reputation can give you the right verdict for the wrong reason.

Demo commands are in `scripts/demo.ps1` (all `--offline`, so the Wi-Fi can't hurt you). Step numbers below refer to it. Every demo step has a screenshot fallback in `docs/screenshots/`.

---

## Act 1: What an analyst actually does (about 4 min)

**1. Title slide.** Name, one line: "I did phishing triage on a corporate IT security team for a co-op rotation. Then I tried to write down what I was doing."

**2. The ticket.** A user forwards a suspicious email. What does an analyst check in the first five minutes? Headers, SPF/DKIM/DMARC, the Received chain, every link and attachment, a few reputation lookups, then a verdict someone can defend. Slide: the checklist as six short lines.

**3. Design rules I set myself.** No ML, every point traces to a line of YAML. Never fetch a URL from an email. Never open an attachment, only hash it. Defang everything in output. Offline mode that still works. (One slide, these five bullets.)

**4. Demo 1: the rules file.** `demo.ps1` step 1. Point at one row: weight, rationale, ATT&CK id. "If someone asks why it scored 65, the answer is a list of lines in this file." Fallback: `rules.png`.

## Act 2: The checks that matter, by example (about 6 min)

**5. Authenticated is not aligned.** Demo step 2 (synthetic Chase sample). SPF and DKIM pass; DKIM is for an unrelated domain; DMARC fails. This is the trick most people miss: "DKIM pass" means a valid signature for *some* domain. Fallback: `analyze.png`.

**6. A real one: MyChart.** Demo step 3. Display name says MyChart, sender is a random `.us` domain, SPF passes for a seven-label bounce domain nobody sees, landing page on `storage.googleapis.com`. Open the HTML report the step writes and show "where the points came from": every colour is a rule category, every segment a line of YAML. Fallback: `html-report.png`, `analyze-real-mychart.png`.

**7. ATT&CK mapping (one slide, no demo).** Show three fired rules with their technique ids: T1684.002 Email Spoofing, T1684.001 Impersonation, T1036.007 Double File Extension. Point: the output speaks the language the SOC already uses. Mention that in the current ATT&CK release (v20.1) Email Spoofing and Impersonation live under T1684 Social Engineering, so mappings copied from older blog posts may be out of date.

## Act 3: The finding (about 8 min, the heart of the talk)

**8. The scoreboard.** Synthetic corpus: 18 of 18. Then 15 real emails from my own Gmail and university inbox: 10 of 15. Demo step 5 (batch). Fallback: `batch.png`. Pause on the confusion matrix.

**9. The misses came from my classmates.** Four of the five misses are job scams and "update your password" lures sent from real, compromised student accounts *inside* the university's Microsoft 365 tenant. Demo step 4. No `Authentication-Results` (intra-tenant mail never crosses a boundary), no external hop, sender domain genuinely `uc.edu`. Every infrastructure check passes because the infrastructure is fine. ATT&CK has a name for this: T1586.002, Compromise Accounts: Email Accounts. No header rule can see it. (The victims are pseudonymised in every sample; say so on the slide.)

**10. The fifth miss scores CLEAN.** Fake recruiter: "install Microsoft Teams to meet a senior technical recruiter for an online briefing." Polite, authenticated, nothing structurally wrong. It impersonates a real company's name as a recruiter; it was not sent by them.

**11. So just weight the words more?** Demo step 6, `batch --compare` with `rules/examples/content-heavy.yaml`. Doubling keyword weight catches one more scam (14/18) and moves a real internship assessment email and a password reset from CLEAN to SUSPICIOUS. Fallback: `compare.png`. Line to land: "a tuning change is a hypothesis; measure it on real mail before you ship it."

**12. Right verdict, wrong reason.** With live threat intel, the MyChart phish hit a raw 120, because URLhaus lists `storage.googleapis.com` with 2,242 malware URLs and a VirusTotal vendor flags it. The classmate scam jumped from 35 to 90 because `shorturl.at` is on URLhaus. Both verdicts were "right", and both for reasons that have nothing to do with the email: shared platforms carry everyone's reputation. Fix: a `shared_hosting` flag, host-level reputation on file hosts and shorteners no longer scores, the specific URL still does. Slide: the before/after numbers.

## Act 4: Lessons (about 4 min)

**13. The email is attacker input all the way to the last line.** Demo step 7 (bonus, if time). My own report used to crash on a subject containing `[/b]`, because the terminal library read email text as markup, and it silently ate the `[@]` from defanged URLs. Same class of bug as XSS in a webmail client, in a tool built to look at phishing. The HTML report now ships with a `default-src 'none'` CSP and no scripts.

**14. Takeaways.**
- Authentication answers "who sent it", not "should I trust it". Check alignment, not just pass/fail.
- Compromised internal accounts beat every header check. Detect them from behaviour and content, and accept the false-positive cost knowingly.
- Reputation on shared infrastructure describes the neighbours. Score the URL, not the platform.
- Test on real mail. Synthetic samples test what you already thought of.

**15. Links and thanks.** Repo (`github.com/AidenKnecht/PhishTriage`), the writeup at aidenknecht.dev/writeups, contact.

---

## Likely questions (have an answer ready)

- **"Why no ML?"** Explainability for a triage verdict, and 33 samples is not a training set. A rules engine you can argue with beats a score you can't.
- **"What would catch the compromised-account scams?"** Behavioural signals: first-time sender to a mailing list, external free-mail reply address or phone number in an internal email, mass send to students. That is next on the list.
- **"Does it detonate attachments?"** No, by design. Hash, type-sniff, look up.
- **"Free-tier API limits?"** VirusTotal is 4/min; the tool rate-limits itself, caches 24 h, and budgets lookups per email, flagged indicators first. Reserved names and private IPs are never sent anywhere.

## Before the talk

- Run `uv sync` on the presenting laptop, then `scripts/demo.ps1` once end to end with Wi-Fi off.
- Terminal at about 150 columns, large font, dark theme.
- Optional online segment: the day of the talk, run `uv run phishtriage batch samples` once with keys in `.env` to fill the 24 h cache, so an online demo replays from cache.
- Screenshots are current as of 2026-11-09. The "90" before-shot of the classmate scam (slide 12) is in git: `git show 8162403:docs/screenshots/analyze-real-uc-scam.png > before-90.png`.

## If the slot is 15 minutes

Drop slides 3, 7, 10 and 13. Merge 5 and 6 into one demo (MyChart only).
