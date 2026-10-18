---
name: inert-guard-defect-class
description: Recurring Silvergun defect class — a rule/test/guard that exists, compiles, loads and CANNOT fire; hit 3x in 3 subsystems, so always prove a guard can go red
metadata:
  type: project
---

**A measurement tool can be inert too, and the environment can do it to you (2026-08-22).** An
independent probe written to cross-check a corpus result returned "nothing found" — because **Windows
PowerShell 5.1's .NET Framework `ZipArchive` silently truncates zip entry enumeration at a name
containing a control character** (1 null name returned for a 10-entry archive). Rewritten on .NET 10,
it worked. Two rules: **any zip tooling in this repo runs on .NET 10, not Windows PowerShell 5.1**, and
**a probe that reports "nothing found" is not a result until it has reported something on a positive
control.** Related, same day: an escaper property-tested "exhaustively over the BMP" could not reach
the astral Tag block at all — *exhaustive over the wrong domain reads exactly like exhaustive*.

Silvergun keeps producing artifacts that **exist, compile, load, and are structurally incapable of
firing**. Three independent instances across three subsystems as of 2026-08-03:

1. **ADR-0021 regression test** asserted a key composition never touches `IMethodReference.Parameters`
   — but ADR-0022 Stage 0 had fixed the underlying defect, so the *forbidden* composition also
   exited 0. The test could not fail.
2. **AppInspector `applies_to` gating** — 12 of 44 embedded OSSGadget rules (27%) are gated to
   languages no file in a `.nupkg` is detected as. `.targets`/`.props`/`.nuspec` are detected as
   *no language at all*, so even `["xml"]` is unreachable.
3. **AppInspector `"type": "string"`** compiles with implicit `\b` word-boundary anchors, so a
   literal starting with a non-word character (`<Exec `) can never match. Rule was born dead.

**Why:** all three are silent. Nothing in the toolchain fails when a guard becomes decoration or a
rule becomes unreachable — the suite stays green and the scan reports "clean". In a security tool
this is the dangerous direction: absence of findings reads as absence of threat.

**How to apply:**
- Every structural guard or detection rule ships with a **mutation check**: construct the forbidden
  shape and prove the guard goes red. Do this against an in-test fixture, not by editing shipped
  data. Make "how did you prove it can fail?" an explicit question in every test delegation.
- When a guard's original failure mode is fixed elsewhere, the guard silently becomes decoration —
  re-verify guards whenever the thing they guard against gets fixed.
- Prefer a **control column** in any detection measurement: something that provably DOES fire on the
  same input. That is what turned the `applies_to` claim from inference into measurement.
- Suspect any third-party matching engine of implicit anchoring/gating semantics. Verify a new rule
  fires end-to-end on a realistic input before believing it exists.

Related: [[detection-calibration]], [[measure-before-designing]], [[hostile-input-threat-model]]

## The sharpest instance yet (2026-08-21): the FIX for an inert guard was itself inert

4. **YARA backend self-reported "available" while its native core failed to load on every scan** —
   zero findings forever, indistinguishable from "no malware matched". Found only by a 100-package
   corpus measurement, never by the suite.
5. **The fix for (4) could not fire for the most common backend.** It derived a
   `YaraScanStatus.Unavailable` from *whether the scan threw* — but every `IYaraScanner` carries an
   explicit "never throws" contract and swallows failures internally. With no backend configured at
   all, the scanner returned empty without throwing and the status read **`Completed`**. It also
   *regressed* the previous check, which had caught that case correctly.

**The unifying root cause, worth more than the instances:**
**inferring health from the absence of a symptom, rather than asking the component whether it works.**
A "never throws" contract makes exception-absence carry *no information*. A "backend selected" check
proves selection, not function.

**How to apply:**
- When wiring up an availability/health/status signal, ask: *what code path sets the failure value,
  and can it actually execute?* If the failure value comes from a catch block, check whether anything
  can reach it.
- Prefer a **positive health signal owned by the component** ("did you initialise?") over an inferred
  one ("did anything blow up?").
- Any optional/pluggable backend needs a **functional** check, not a **selection** check. A backend
  that reports available but cannot function is worse than an absent one, because absence is
  detectable.
- Treat a newly-added status enum as untested until a test pins **every** value against a **real**
  implementation — not just a synthetic double built to reach the branch.
