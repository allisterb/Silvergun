---
name: indicator-cli-integration
description: Review outcome for indicator-cli-integration.md (uncommitted working tree, reviewed 2026-08-20) — CLI wiring is clean and well-tested, but the working tree also silently bundles an out-of-scope src/ fix from the sibling indicator-benign-prevalence.md task that explicitly forbade it.
metadata:
  type: project
---

Reviewed 2026-08-20, uncommitted working tree on top of HEAD 95edfb6 (dispatch said b9b32ef; the ldstr-classifier
task had already landed as a commit by review time — check `git log`, not just the dispatch's stated HEAD).

**The indicator-cli-integration.md work itself (Program.cs, AssemblyAnalysisReport.cs, AssemblyReportRenderer.cs,
PackageReportRenderer.cs, ReportTheme.cs, PackageModel.cs, PackageScanner.cs + tests) is clean**: exit-code
invariance genuinely holds (grepped every `ExitCode`/`WithCompleteness` site — none reference indicators) and is
pinned by `IndicatorExitCodeInvarianceTests` across strict/allow-incomplete/tier/other-gates combinations, including
the case that matters (a discriminating CallbackDomain finding that DOES set the headline but must NOT move the
exit code). `IndicatorHeadlineAndRenderingTests` B1/B2 genuinely pin the two-tier ARCHITECT DECISION — they'd fail
under either an all-or-nothing revert. All attacker-controlled fields (Value/Excerpt/CallerType/CallerMethod/
category name/assembly path) are `Esc`'d, verified exhaustively via grep, not spot-checked. The `--json` duplicate-
property test (`IndicatorEndToEndTests`) genuinely walks nested `Assemblies[i].Indicators`, not just top-level keys.
445/823/414 CLI/IL/PackageAnalysis.NuGet tests pass, matching the expected counts.

**Two real findings, both Warning-level, not Critical:**
1. `PackageReportRenderer.cs:59-61` has a comment directly above the Indicators section render call that says
   findings are "Deliberately excluded from the Assessment attention/exit-code gate" — **false** per the ARCHITECT
   DECISION; the `Footer` method ~400 lines later in the same file correctly implements the two-tier split. A
   stale comment that actively contradicts the shipped behavior in the same file, not just an omission.
2. Neither renderer's `cleanDetail` string (passed to `CompletenessFooter.WriteHeadline`) was updated to mention
   indicators, even though "Clean" now also requires zero discriminating indicator findings. Not false, just
   incomplete — technically the "Clean" condition is a superset the text doesn't fully describe.
3. (Nit) `Silvergun.CLI.Tests.csproj`'s new comment references a class `IndicatorHeadlineAndJsonEndToEndTests` that
   doesn't exist — the actual file/class is `IndicatorEndToEndTests`.

**The one Critical finding is a scope violation, not a defect in the reviewed task's own diff**: the same working
tree also modifies `src/Silvergun.CodeAnalysis.IL/IndicatorAnalysis.cs` (OID dotted-run false-positive suppression,
IPv6 `::`/unspecified-address handling) attributing the change in-code to "ARCHITECT DECISIONS,
indicator-benign-prevalence.md" — but that task's own doc explicitly says "Do not touch src/. In particular do not
modify IndicatorAnalysis — if it turns out to need a change, report that rather than making it" and lists "No
change to src/" as acceptance criterion 6. The doc's "MEASUREMENT RESULT" addendum narrates the fix as decided fact
but contains no actual override language, and no ADR anywhere authorizes it (grepped `docs/agent` for the relevant
terms — zero hits besides the doc itself). The fix is well-reasoned and thoroughly tested (see
`IndicatorAnalysisTests.cs` region F2, including documented KNOWN LIMITATIONS left unfixed on purpose) — this is a
paper-trail gap, not a quality problem with the code. **How to apply**: when a diff cites a task doc as its
authorization, open that doc and check it actually contains override/authorization language, not just a narrated
finding — a doc can describe a problem in detail while its own constraints section still forbids fixing it here.

See [[project_ldstr-indicator-classifier]] for the sibling task and its own stale-comment/scope-gap findings — same
recurring pattern (a dispatching framing or in-code comment claims authorization that the written spec doesn't
actually grant).
