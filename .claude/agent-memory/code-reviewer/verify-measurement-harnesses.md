---
name: verify-measurement-harnesses
description: When reviewing a fix backed by a docs/agent/measurements/*.md report, rebuild and rerun the scratchpad Probe harness rather than trusting the tables as written.
metadata:
  type: feedback
---

For fixes in `ext/analysis-net` that cite a `docs/agent/measurements/*.md` report (e.g.
`dereference-type-nre-fix.md`, `platformtypes-comparison-audit.md`), the implementer's harness
(`Probe/Program.cs` + a `corpus/` of real assemblies) is often still sitting in that task's
`%TEMP%/claude/.../scratchpad/tac-spike/` directory, reused verbatim across follow-on tasks. If it's
there, **rebuild it against the current diff and rerun it** — don't just re-read the doc's tables.

**Why:** did exactly this for the `Dereference.Type` null-guard fix (2026-07-27) — ran `realinfer`
mode against two of the seven corpus assemblies with the fix applied, got numbers matching the doc's
table exactly (completion counts, NRE-origin breakdown, timeout counts, `VAR_NULL`/`VAR_UNKNOWN`
residue). Then `git stash`'d the one-line fix in `ext/analysis-net`, rebuilt, reran the same
assemblies, and reproduced the "before" row exactly too (including the `Dereference`/
`ArrayElementAccess` NRE-origin split). This is far stronger verification than re-deriving the logic
by reading code, and it's cheap when the harness is already built and the corpus already downloaded —
no new NuGet packages, no new files in `src/`/`tests/`, nothing to ask permission for since it's a
throwaway scratch rebuild.

**How to apply:** before accepting a measurement doc's numbers, check whether its harness dir still
exists in scratch. If so: `dotnet build -c Release`, run the mode used for the headline claim against
at least one small assembly and the net45/net472 control (if the audit uses one), and — if the fix is
small enough to `git stash` cheaply — reproduce the "before" state too to confirm causation, not just
correlation. Restore the stash afterward and confirm `git diff` matches what's under review before
reporting. Scratchpad dirs are session-scoped, so this specific path won't survive into a new
session — but the *pattern* (harness usually still lives at
`%TEMP%/claude/<repo>/<session>/scratchpad/tac-spike/{Probe,corpus}` for `ext/analysis-net` TAC work)
is worth checking for on any related follow-up review.

**Confirmed again (2026-07-27, `typeinference-nullguard-fixes.md` review):** used `Glob` for
`**/tac-spike/**` under `%TEMP%/claude/C--Projects-Silvergun/` (not just this session's own scratchpad
path) and found the harness + a fully-populated `phaseI-realinfer-before`/`-after` result set sitting in
*this session's own* scratchpad dir (matching the env-provided path exactly) — evidently reused across
this session's sub-tasks. Rebuilt Debug, reran two assemblies including the net45 control, reproduced
the doc's "after" numbers exactly (including deterministic timeout method names), then stashed the fix
and reproduced "before" exactly too. Worth checking the *current* session's scratchpad path first (cheap,
no Glob needed) before searching other session dirs.

**Confirmed a third time (2026-07-27, `platformtypes-comparison-fix.md` review) — and this time no
measurement doc existed to check against at all.** The task's own acceptance criteria required the
divergence/TAC/type-inference/capability numbers to be reported, but no `docs/agent/measurements/*.md`
was ever committed for this task. Found `results/{baseline,afterfix}` (typediv/realinfer) and a
`capmap-harness/` (with `diff-capmap.ps1` and a freshly regenerated `capmap-before.tsv`) already sitting
in-session; reran `aggregate.ps1` over both directly rather than trusting the launcher-prompt's summary
numbers, and diffed the regenerated capability TSV against the real `docs/agent/measurements/capmap-
before.tsv`. All figures matched exactly (divergence 4.14%/18.49%→0%, TAC 1,140→1,140 row-for-row,
capability 5,128→5,128 byte-identical modulo a BOM sort artifact, non-termination 20→21, completion
−1 method) — so the underlying work was sound even though nothing was written up. **This is the
important case**: when there's no doc to "just re-read," check the scratchpad anyway before assuming
the claimed numbers are unverifiable — they're often still sitting there, and re-deriving them directly
is exactly what closes the gap a missing doc leaves.

**Fourth case (2026-07-30, `per-method-body-read-granularity` review) — a pinned number in a *source
comment* whose subject assembly is unnamed.** `src/Silvergun.CLI/Reports/AnalysisCompleteness.cs` gained
"Measured 2026-07-30: an out-of-range fat-header CodeSize yields 4087/4086/1" without saying on what. No
harness in scratch this time. Cheap recipe that worked: sweep the local NuGet cache with the built CLI —
`Silvergun.CLI.exe analyze <dll> --json` and grep `MethodsTotal` across `~/.nuget/packages/<pkg>/*/lib/*/`
— to attribute the denominator (it was `Newtonsoft.Json 13.0.3/net6.0`, exactly 4087; 13.0.4 is 4107,
netstandard2.0 is 4064, so the number is version+TFM specific). Then rebuilt the fixture corruption in a
~40-line scratch console app using in-box `System.Reflection.Metadata` (find the method's RVA → section
file offset → check low two bits of the header byte == 0b11 → overwrite the 4 bytes at header+4) and
reran the CLI: 4087/4086/1, exit 3, capability findings byte-identical to the clean run. **How to apply:**
when a comment pins a measurement but not its input, the input is usually recoverable by brute-force sweep
— don't downgrade it to "unverifiable, nit". Run the analyzed binary through a child process (ADR-0021).
