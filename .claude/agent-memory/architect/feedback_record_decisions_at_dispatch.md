---
name: record-decisions-at-dispatch-time
description: When a dispatch prompt overrides/narrows anything written in docs/agent/, record it in the doc AT DISPATCH TIME — dispatch prompts are invisible authorization and reviewers correctly flag the diff as unauthorized
metadata:
  type: feedback
---

**When a delegation prompt contradicts, narrows, or supersedes something already written in
`docs/agent/`, amend the document at dispatch time — not after review catches the mismatch.**

**Why:** subagents start with a fresh context and see only what the prompt hands them; future readers
see only `docs/agent/`. A decision that lives solely in a dispatch prompt is invisible to both. The
written constraint keeps looking authoritative while the shipped diff looks unauthorized — and a
reviewer is forced to choose between "the spec is wrong" and "this change was smuggled in". For a
security tool, ambiguity about its own provenance is expensive.

**Observed twice in one session (2026-08-03), both caught by `code-reviewer`, neither by me:**

1. `ldstr-indicator-classifier.md` demanded CLI integration; I scoped it out in the dispatch and
   recorded nothing. Review flagged it as an unmet acceptance criterion — the classifier had shipped
   with **no consumer at all**, and a spec reader would have believed otherwise.
2. `indicator-benign-prevalence.md` said "do not touch `src/`, in particular do not modify
   `IndicatorAnalysis`"; a later dispatch authorized exactly that fix, and the shipped code cited
   that same document as its authorization. Raised as **Critical**.

**How to apply:**
- Before dispatching a task that departs from a written spec, append a dated `ARCHITECT DECISION`
  section saying what changed and why. Two minutes.
- Constraints should be scoped in the text when written ("this constraint applies to the measurement
  run") so a follow-up task is not automatically a violation.
- When a measurement task forbids changing the thing being measured, expect the measurement to
  surface fixes — write the follow-up path into the doc up front.
- Treat "the diff cites a spec that does not actually authorize it" as a real finding, not pedantry.
  It is how unreviewed scope creep looks from the outside.

Related: [[inert-guard-defect-class]] (prose that stops matching reality), [[measure-before-designing]]
