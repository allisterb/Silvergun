---
name: feedback-spectre-reports-review
description: What "done" looked like for the Spectre.Console CLI report renderers (ADR 0013/0014) — escaping pattern, the Profile.Capabilities.Unicode-defaults-true trap, and smoke-test gaps to check on future presentation-layer work
metadata:
  type: project
---

Reviewed 2026-07-17: `src/Silvergun.CLI/Reports/{ReportTheme,AssemblyReportRenderer,PackageReportRenderer,SquatReportRenderer}.cs`
and `Program.cs`'s `EmitHumanReport`/`CreateStdoutConsole`/`CreatePlainConsole` against ADR 0013. This was a clean
pass — approved with warnings, not blocked. Recorded here because the pattern and the gap are likely to recur on
future CLI-presentation tasks.

**The escaping pattern that worked:** every untrusted field (names, paths, caller type/method, called API,
dependency ids, script rule id/name/location, squat candidate/reason) is wrapped in `ReportTheme.Esc`
(`Markup.Escape`) *before* being spliced into a markup string; color/severity is chosen via a `switch` that maps
the untrusted value to a **fixed** color-name string (never splices the value into the tag itself). That's the
right shape to hold future renderers to — flag any interpolation that skips `Esc(...)` on report-derived data as
Critical (it's a hostile-input crash surface, see [[project_hostile_input_never_throws]]), and flag any place a
raw value is used to *build* a markup tag name (not just chosen as a switch key) as Critical too.

**Recurring gap to check for:** the CI-safety smoke test (`CiSafetyReportTests.cs`) only covered the `analyze`
verb, not `scan-package`/`check-squat`, despite the task spec asking for "each verb." Worth checking on the next
pass whether this got filled in; if not, keep flagging as a Warning rather than Critical since the three verbs
share the same `EmitHumanReport`/`CreatePlainConsole` plumbing (low residual risk).

Re-checked 2026-07-17 (second pass, same day): still only `analyze` is covered — confirmed still a Warning,
not fixed yet. Also noticed this pass: unrelated in-progress changes (nuspec-content-scan work in
`Silvergun.PackageAnalysis.NuGet/{NuGetPackage,PackageScanner,ScriptRuleScanner}.cs`, `Capabilities.cs` enum
reorder, `Silvergun.sln`, `PackageFixture.cs`) were sitting uncommitted alongside the Spectre diff in the same
working tree — harmless (verified `Capability` serializes as a JSON string, not ordinal, so the enum reorder
doesn't break JSON byte-purity) but worth a quick sanity check each time: confirm out-of-scope modified files
don't touch report record types before waving them off as unrelated.

**Also missing both times so far:** no unit test feeds a report containing raw `[`/`]` or a markup fragment
(e.g. `"[red]pwned[/]"`) through a renderer to prove `Esc` actually prevents a Spectre `InvalidOperationException`
on malformed markup. This is the single most direct test of the hostile-input invariant for this presentation
layer and is cheap to add (render straight to a buffered `AnsiConsoleSettings` console, no process spawn) — keep
suggesting it to `test-engineer` until it lands.

Re-checked 2026-07-17 (third pass, same day, ADR 0014 `--rich` flag): the injection test gap above is now
**filled** — `ReportRendererTests.cs` has `*_WithMarkupMetacharactersInData_RendersLiterallyWithoutThrowing`
(ascii console) and `*_RichConsole_WithInjectionPayload_RendersLiterallyWithoutThrowing` (rich console) for all
three renderers. The CI-safety verb-coverage gap is **still open**: `CiSafetyReportTests.cs` (even after the
0014 update added `--rich`/`--json+--rich` process-level cases) still only spawns `analyze`, never
`scan-package`/`check-squat` — keep flagging as a Warning, low residual risk since all three verbs share
`EmitHumanReport`/`CreateConsole`.

Re-checked 2026-07-22 (ADR 0017 OSV review): verb-coverage gap is now **filled** —
`CiSafetyReportTests.cs` has `ScanPackage_DefaultMode_EmitsSevenBitAsciiOnly`,
`ScanPackage_Rich_Redirected_CompletesWithoutHang`, `ScanPackage_JsonAndRich_IsRejectedBeforeHandlerRuns`
covering `scan-package`. New gap found instead, see [[project_osv_vulnerability_intel_review]]: those two
`scan-package` CI-safety tests spawn the CLI **without `--no-vulns`**, and OSV now runs by default, so they
silently make a real network call to `api.osv.dev` on every test run (verified reachable from this sandbox).
When a verb gains a new default-on network step, check every pre-existing process-level smoke test that
invokes that verb for the matching opt-out flag, not just the new feature's own tests.

**Spectre.Console 0.57.2 trap, confirmed empirically:** `AnsiConsole.Create(new AnsiConsoleSettings { Ansi =
AnsiSupport.No, ColorSystem = ColorSystemSupport.NoColors, ... })` does **not** default
`Profile.Capabilities.Unicode` to `false` — it defaults to `true` even for a non-terminal `AnsiConsoleOutput`
wrapping a plain `TextWriter`. Verified with a throwaway console app against the exact package version. Since
`ReportTheme.IsRich(console) => console.Profile.Capabilities.Unicode` is the single richness axis, any console
builder (production or test) that sets `Ansi`/`ColorSystem` to the "plain" values but forgets
`console.Profile.Capabilities.Unicode = false` silently renders in **rich** glyph/border mode (Unicode box
-drawing, `✔`/`✖`/`·`/`—`) despite having no ANSI/color — a live bug on the first pass of `ReportRendererTests.cs`'s
`PlainConsole()` helper (fixed in the same pass by adding a separate `AsciiConsole()` helper that sets it
explicitly). `Program.CreateConsole` in `src/Silvergun.CLI/Program.cs` always sets this explicitly and was never
affected. **When reviewing any Spectre console-construction code, check for this explicit `Unicode = false`/`true`
line — its absence is easy to miss because it doesn't throw or produce ANSI, it just silently swaps glyph sets.**
