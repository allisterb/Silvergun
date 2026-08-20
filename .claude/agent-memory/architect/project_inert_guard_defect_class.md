---
name: inert-guard-defect-class
description: Recurring Silvergun defect class — a rule/test/guard that exists, compiles, loads and CANNOT fire; hit 3x in 3 subsystems, so always prove a guard can go red
metadata:
  type: project
---

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
