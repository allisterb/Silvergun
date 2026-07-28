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
