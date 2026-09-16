# Building a phishing triage tool, then running my own spam folder through it

Working outline for aidenknecht.dev/writeups. Structure the piece around the
most surprising thing the batch run surfaces, not around the feature list.
Sections marked **[SLOT]** get filled in after the real-sample run.

## 1. The hook (150-250 words)

Open on the finding, not the tool. Candidates, pick whichever the real run
delivers (see section 5):

- A phish that passed SPF *and* DKIM and still failed, because the domain that
  authenticated was not the domain in `From:`. Lead with the two green checks
  in the Authentication table and the "Aligned? no" next to them.
- A legitimate newsletter that scored SUSPICIOUS, and the exact three rules that
  did it.
- A sender domain that RDAP says was registered N days before the email arrived.

One paragraph on the setup: a year of doing this by hand on a corporate IT
security team, the same six checks every time, and the decision to write them
down as rules.

## 2. What triage actually is (300 words)

- The analyst's mental checklist: who sent it, did the infrastructure vouch for
  them, where did it physically come from, what does it want me to click or open.
- Why "authenticated" and "aligned" are different questions. Short worked
  example with a DKIM `d=` that does not match `From:`.
- Why the output has to look like something you'd paste into a ticket.

## 3. Design choices worth defending (400 words)

- Rules as data: every score comes from a YAML rule with a one-line rationale.
  Show three rules verbatim, including the rationale field.
- No ML, on purpose. The interview-question test: can I explain every point?
- Never fetch a URL, never open an attachment. Hash and sniff, then ask APIs.
- The calibration set: 12 synthetic phish, 6 benign, one of them an
  internal email with no auth headers that *should* land at SUSPICIOUS and
  nowhere higher. Why that case matters.

## 4. The build, briefly (300 words)

Keep this short; it's the least interesting part to a reader.

- Parser hardening: two parses per message, warnings instead of crashes.
- The boundary-hop idea in `Received:` analysis and the bug it fixed (the
  sender's own `[10.x]` submission hop being flagged as a private origin).
- The YAML `on:` key that PyYAML reads as boolean `true`. Small, real, funny.

## 5. Running the spam folder **[SLOT]**

- How many emails, how sanitised (`scripts/sanitize.py`), how long the run took
  with enrichment on.
- The batch table and confusion matrix. Be honest about false positives and
  misses.
- **[SLOT] The finding.** One email, walked top to bottom through the report:
  header panel, auth table, hop chain, indicators, "why this verdict". This is
  the centre of the piece. Candidates to look for in the run:
  - Aligned-vs-authenticated (SPF/DKIM pass, DMARC fail, misaligned).
  - Youngest domain by RDAP age. If it is under 7 days, that is the headline.
  - The benign email that scored highest, and what that says about the rules.
  - A URLhaus or VirusTotal hit on something the header checks rated clean.
  - Anything where the hop chain contradicts the From domain (country, hosting
    provider, private origin).

## 6. What the rules got wrong **[SLOT]**

- Which weights moved after the real run, and why (diff of `scoring.yaml`).
- One rule that fired constantly on legitimate mail and had to be softened.
- One thing the tool cannot see that a human caught immediately.

## 7. What I'd build next (150 words)

Pull from the README list; pick the two that the real run made obviously
necessary.

## Screenshots to take

Take them at 110-120 columns in a dark terminal with a UTF-8 locale so the
score bar renders as blocks. Redact nothing that isn't already sanitised.

1. **`analyze` on the headline email**, full report top to bottom. Needs to
   show the verdict colour, the auth table with "Aligned? no", and the "why this
   verdict" panel with evidence. This is `docs/screenshots/analyze.png` in the
   README.
2. **Authentication table close-up** for the aligned-vs-authenticated case:
   SPF pass, DKIM pass, DMARC fail, both alignment columns "no".
3. **Hop chain panel** for the email with the most interesting origin (private
   IP flag, timestamp anomaly, or a country that doesn't fit the brand).
4. **`batch samples/` output** with the confusion matrix visible at the bottom.
   Then the same command on the real corpus, side by side if they fit.
5. **`rules` table**, cropped to eight or so rows so the rationale column is
   readable. Makes the "rules as data" point without prose.
6. **Indicators table with enrichment on**: at least one URLhaus or VirusTotal
   verdict and one RDAP age in the enrichment column, defanged values visible.
