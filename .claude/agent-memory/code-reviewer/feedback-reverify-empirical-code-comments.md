---
name: feedback-reverify-empirical-code-comments
description: When a code comment cites a specific measured number (timing, byte count, iteration count) as justification for a safety-critical design choice, reproduce the measurement in the scratchpad rather than trusting the comment.
metadata:
  type: feedback
---

Rule: a comment like "confirmed against a 160MB adversarial constant: breaking after 10 of ~20,000,000
possible matches took 11ms" is a factual claim, not documentation of intent — treat it the same as a
pinned baseline number ([[verify-measurement-harnesses]]) and re-derive it independently when the claim is
load-bearing for a hostile-input/safety review priority.

**Why:** this is the same failure mode as trusting a stale test-count comment — the number could be wrong,
stale, or measured under different conditions (debug vs release build, different regex engine version).
For a security analyzer whose whole hostile-input story rests on "lazy enumeration + early break is
actually fast," the comment being wrong would be a genuine safety hole, not a cosmetic issue.

**How to apply:** write a standalone throwaway repro OUTSIDE the repo (per the "never mutate shipped files"
rule) in the scratchpad — a `dotnet run -c Release` console project is usually enough — reproducing the
scenario the comment describes, and compare orders of magnitude, not exact numbers. Do this for
timing/memory claims specifically; it is not necessary for claims that are self-evidently true from reading
the code (e.g. "this loop breaks after N iterations").
