---
name: exit-code-footer-predicate
description: ADR-0024's "exit 0 <=> footer says Clean" invariant has one live, accepted counterexample (PackageMetadata script findings) and the finding-gate predicate is copied across 4+ sites.
metadata:
  type: project
---

ADR-0024 unified the **completeness** half of the CLI verdict into one `CompletenessAssessment`
(`src/Silvergun.CLI/Reports/AnalysisCompleteness.cs`), but the **findings** half (`attention`) is still
recomputed independently at each site: `Program.RunAnalyze`, `Program.RunScanPackage`,
`AssemblyReportRenderer.Footer`, `PackageReportRenderer.Footer`, plus test replicas in
`CompletenessExitCodeTests` and `ProgramTests`.

Two of those copies genuinely disagree: the package footer's `attention` counts **all**
`ScriptFindings`, while the `--strict` gate counts only `Source == ScriptFindingSource.Script`
(`.nuspec`/`PackageMetadata` findings are advisory per `tasks/script-rule-precision.md`). So a package
whose only finding comes from the manifest, with a complete analysis, prints "Findings present" and
still exits **0 under `--strict`** — a real counterexample to ADR-0024's `(strict, !allowIncomplete)`
invariant. It is pre-existing and out of scope of the completeness work; the invariant test matrix
deliberately excludes it (comment at `CompletenessExitCodeTests.cs` "the shapes use Script-sourced
script findings on purpose").

**Why:** ADR-0024's non-goals forbid touching the finding predicate — calibrating which findings gate
is the deferred risk-scoring ADR. So the divergence cannot be closed by narrowing the gate here.

**How to apply:** when reviewing anything that touches the footer, `ScanExitCode`, or the invariant
matrix, check this axis explicitly rather than trusting a comment that says attention "is exactly what
--strict gates" — that sentence is false for the package renderer. Do not propose changing the gate;
propose pinning the divergence in a test and recording it in the ADR. Related:
[[verify-measurement-harnesses]].

**Highest-churn stale-comment site in the repo (as of 2026-07-30): the ~15-line block above
`SkippedMethodsCaveat` in `AnalysisCompleteness.cs`, plus the mirrored clause in the class-level doc.**
Four separate claims in it were falsified at once by `tasks/per-method-body-read-granularity.md` (the
"body reads fail the whole assembly" measurement, its class-doc twin, a "no lifting involved"
comparison ADR-0009 had already invalidated, and the ordering of the reads in `ScanMethod`). The block
narrates *another file's* control flow — `CapabilityAnalysis.ScanMethod`'s statement order — which is
why it rots without the compiler noticing. **How to apply:** on any review that touches either file,
open `ScanMethod` and check the comment sentence-by-sentence against the actual statement order; also
check `CompletenessExitCodeTests`' class doc, which narrates the same thing and went stale with it.
