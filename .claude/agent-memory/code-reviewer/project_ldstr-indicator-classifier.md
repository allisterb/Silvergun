---
name: ldstr-indicator-classifier
description: Review outcome for the ldstr/IndicatorAnalysis classifier (docs/agent/tasks/ldstr-indicator-classifier.md, landed on HEAD b9b32ef) — clean implementation, one stale comment, one undocumented scope gap.
metadata:
  type: project
---

Reviewed 2026-08-20 at HEAD b9b32ef. `IndicatorAnalysis`/`Indicators.cs` (new),
`AssemblyAnalyzer.StringConstants()` seam, and their tests are clean: all regexes carry
`RegexOptions.NonBacktracking` (verified all ~10 sites), `Classify`/`Analyze` are genuinely bounded
(`MaxIndicatorsPerConstant=5000` shared across all match loops in one constant, `MaxDistinctIndicators`
dictionary cap, `Excerpt` computed once and reused by reference). `IsVersionAssignment`'s backward scan
(ARCHITECT DECISION #2) hand-verified correct on all boundary cases (MyVersion=, Version 4.0.0.0 no `=`,
whitespace around `=`, ProductVersion=192.168.1.1). Independently re-ran the "11ms after breaking at 10
of ~20M matches" claim in the `Classify` comment with a 38MB adversarial string in the scratchpad —
confirmed (12ms early-break vs 3055ms full enumeration), see [[feedback-reverify-empirical-code-comments]].
`ObfuscationAnalysis.cs` diff really is doc-comment-only (+11 lines). `StringConstantsSharedSeamTests`
genuinely tests behaviour (invokes both real private entry points by reflection, asserts on runtime
agreement), not just IL structure — a real fix for the structural-guard gap ARCHITECT DECISION #1 called
out. `IndicatorCapFixture` replaced the rejected 134KB bulk fixture as directed (ARCHITECT DECISION #4) —
confirmed 3.7KB hand-written payload, and confirmed via `git status`/`ls` that no NuGet packages were
added and nothing was committed. 805/805 IL tests pass.

Two findings:
1. **Stale comment surviving a design pivot**: `IndicatorAnalysisTests.cs:404-406` still describes
   truncation as tested via "a dedicated, separate fixture assembly of 10,010 distinct ldstr IPv4
   literals" — the design ARCHITECT DECISION #4 explicitly rejected in favor of the injectable-cap
   `IndicatorCapFixture` (~8 constants). The other two mention sites (the fixture's own doc comment and
   the `.csproj` comment) were correctly updated to say "replaces the deleted BulkIndicatorFixture"; this
   third site was missed. **Lesson: when a design pivot lands, grep for every mention of the rejected
   approach across the whole diff — comments cluster at 2-3 sites and it's easy to update most but not
   all.**
2. **Undocumented scope gap**: the task spec's own "## CLI integration (same task, minimal)" section
   requires `analyze` to render indicator findings in terminal + `--json`. Nothing in `Silvergun.CLI`
   references `IndicatorAnalysis`/`IndicatorReport` — confirmed via grep, zero hits. The reviewing
   dispatch's framing asserted this was "deliberate and out of scope," but none of the four ARCHITECT
   DECISIONS in the task doc actually say that (they cover the ObfuscationAnalysis-refactor revert, the
   Version= exclusion, the missing hash pin, and the injectable cap — not CLI wiring). This is a paper-trail
   gap, not necessarily a real defect: **when a dispatching agent's framing contradicts the written spec's
   acceptance criteria and no decision record reconciles them, flag it rather than silently trusting
   either side** — the spec doc should get a fifth ARCHITECT DECISION recording the CLI deferral if that
   really is what happened.

See [[project_capability-map-phase2-gate]] for another example of this project's "ARCHITECT DECISIONS
appended post-implementation" pattern (task specs get amended in place with dated decision sections
rather than superseded by a new doc) — useful to recognize when reading any task spec here.
