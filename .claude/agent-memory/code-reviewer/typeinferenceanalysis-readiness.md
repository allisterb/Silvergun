---
name: typeinferenceanalysis-readiness
description: Status of the effort to make Backend.Analyses.TypeInferenceAnalysis safe to turn on for Silvergun's dataflow/points-to track.
metadata:
  type: project
---

`Backend.Analyses.TypeInferenceAnalysis` (in `ext/analysis-net`) is **not reachable from any
Silvergun `src/` code path today** — `AssemblyDisassembler.cs` only drives
`Backend.Transformations.Disassembler` + `Backend.Analyses.ControlFlowAnalysis`. It's being
incrementally hardened in preparation for a future dataflow/points-to track, one prerequisite defect
at a time, each landed as a standalone measured fix:

1. `platformtypes-comparison-audit.md` (2026-07-27) — found 174 `PlatformTypes.X` equality
   comparisons (`Model/Types/TypeHelper.cs` 162, `Backend/Analyses/TypeInferenceAnalysis.cs` 12) that
   are assembly-name-pinned to `"mscorlib"` and silently wrong on modern TFMs (4.1% divergence
   overall, 18.5% for the `bool`-return-type predicate). The audit's own Phase D recommended a
   shared `PlatformTypes.Matches` helper at ~180 call sites (Option 2/"A" in the follow-up task).
   **Fixed differently in `platformtypes-comparison-fix.md` (2026-07-27)**: the task doc re-opened
   "Option B" — widen `BasicType.Equals` itself (`Model/Types/Types.cs`) to unify two `IBasicType`s
   when both `ContainingAssembly`s are known core libraries (new `Model/Types/CoreLibraryNames.cs`,
   shared with `Disassembler.IsVoidReturn`, which lost its own duplicate allowlist and now reduces to
   `type.Equals(PlatformTypes.Void)`). Chosen over the helper because `BasicType.GetHashCode()` was
   independently confirmed to already hash on `Name` only (ignoring `ContainingAssembly`), so widening
   `Equals` doesn't weaken the hash/equals contract, and `IBasicType` was independently confirmed to
   have exactly one implementer (`BasicType`), bounding the blast radius. Reviewed and verified by
   rebuilding the scratchpad `typediv`/`realinfer`/capmap harnesses (not just re-reading the numbers):
   divergence 4.14%/18.49% → exactly 0% both, TAC failures 1,140 → 1,140 row-for-row identical,
   capability findings 5,128 → 5,128 byte-identical (only a BOM sort-order artifact in the diff),
   reverting `Equals` alone reproduces exactly "5 red / 9 green" on the new 14-test suite. Two small,
   honestly-reported side effects, both in the still-unreachable-from-`src/` `TypeInferenceAnalysis`
   path: fixed-point non-termination 20→21 methods and completion 65011/65031→65010/65031 (−1 method) —
   plausible read is more comparisons now correctly resolve, pushing one borderline method over the
   harness's timeout; not root-caused, consistent with the pre-existing 9→14→20 rising trend. **Gap**:
   no `docs/agent/measurements/*.md` was written up for this task despite its acceptance criteria
   requiring the gate numbers be reported — they were reconstructed and verified by the reviewer
   directly from the scratch `results/{baseline,afterfix}` dirs, not from a committed doc.
2. `dereference-type-nre-fix.md` (2026-07-27) — fixed `Dereference.Type`'s unguarded
   `(Reference.Type as PointerType).TargetType` (100% of 12,248 sites had `Reference.Type == null`,
   because `Disassembler`'s `TemporalVariable`s are typed lazily by `TypeInferenceAnalysis`'s own
   fixed-point pass). Fixed by returning `null` instead of `PlatformTypes.Unknown` — verified this
   preserves the fixed point's self-healing retry (0 `null`/`Unknown` residue in completed methods,
   both before and after). **This surfaced two more, structurally identical, pre-existing sibling
   defects, not yet fixed**: `ArrayElementAccess.Type` (`Operands.cs:805`, same unguarded-cast shape,
   now the dominant blocker) and `TypeHelper.BinarySignedNumericOperationType`/
   `BinaryLogicalOperationType` (`TypeHelper.cs:579`/`533`, missing null-guard on `left`/`right`).
   Also surfaced an apparent fixed-point non-termination on a small number of methods (9→14 after this
   fix, 5s harness timeout), not root-caused.
3. `typeinference-nullguard-fixes.md` (2026-07-27) — fixed both siblings named above:
   `ArrayElementAccess.Type` (same unguarded-`as`-cast shape as `Dereference.Type`, returns `null`)
   and `TypeHelper.BinarySignedNumericOperationType`/`BinaryLogicalOperationType` (missing null-guard
   on `left`/`right` parameters, also returns `null`). Also had to guard `TypeHelper.UnsignedEquivalent`
   — not named in the original task, but discovered by tracing what `BinaryNumericOperationType` does
   with `BinarySignedNumericOperationType`'s now-possibly-null return value; leaving it unguarded would
   have just moved the crash one call deeper for every unsigned Add/Sub/Mul/Div/Rem. See that doc for
   the updated NRE-by-origin table, completion rate, and the new dominant residual failure.

**Why this matters for review:** any future fix in this family should be expected to surface the
*next* sibling in the same unguarded-cast/missing-null-guard pattern — that's not a regression, it's
the masking effect of the fix before it. Check whether a newly-reported "residual NRE" is really new
or just newly-reachable. Also check *within* the fixed function for other internal callees that just
received a newly-possible `null` argument they weren't guarding either (as happened with
`UnsignedEquivalent` above) — the task naming two sites doesn't guarantee the whole call chain is safe.

**How to apply:** when reviewing a change touching `ext/analysis-net/Model` or `Backend/Analyses`,
check this list for whether the touched code is one of the still-open items (`TypeHelper.cs`
comparisons, the non-termination question) before treating it as
untested/low-priority — and confirm via `grep -rn "TypeInferenceAnalysis\|Backend\.Analyses"
src/**/*.cs` that it's still unreached from `src/` before waiving the "no regression test" question,
since that reachability status is exactly what changes when the track gets wired up.

**Item 3 reviewed and confirmed clean (2026-07-27).** Verified, not just re-read: the scratchpad
`Probe`/`corpus`/`results` from the interrupted measurement task were still present in *this same
session's* scratchpad (session-scoped dirs do sometimes survive within one session even across
sub-tasks); rebuilt `Probe` fresh against the current diff, reran `realinfer` on two assemblies
(`Microsoft.AspNetCore.Mvc.NewtonsoftJson`, the net45 control) and reproduced the doc's "after" numbers
exactly, including deterministic timeout method names. Then `git stash`'d the fix, rebuilt, reran the
same assembly, reproduced the "before" row (157/161 completed, 4 NRE = 3 Dereference + 1
ArrayElementAccess) exactly too — confirms causation, not just correlation. Stash popped and confirmed
empty afterward. Also independently confirmed via code+grep (not just the doc's claim): `UnsignedEquivalent`
really does have exactly one outer-fork caller (`BinaryNumericOperationType`); `Visit(BinaryInstruction)`
in `TypeInferenceAnalysis.cs` assigns the three guarded `TypeHelper` methods' results straight to
`instruction.Result.Type` with no further dereference, so it tolerates the now-possible `null` the same
way `Visit(LoadInstruction)`/`Visit(StoreInstruction)`/`Visit(ReturnInstruction)` already do;
`ArrayElementAccess`'s root cause matches `Dereference`'s exactly (`this.Array`/`this.Reference` are both
`stack.Pop()` temporaries in `Disassembler.cs`, typed lazily by `TypeInferenceAnalysis` itself, not by the
Disassembler).

**New observation for the still-open non-termination question (9→20 methods, not yet root-caused):**
`TypeInferenceAnalysis.SameTypes` (`Backend/Analyses/TypeInferenceAnalysis.cs:400`) treats `oldType ==
null || newType == null` as "changed" unconditionally — even when both are `null` (i.e. genuinely
unchanged). Combined with these five guards now letting more variables sit at `null` across iterations
instead of crashing immediately, this is a second plausible non-termination mechanism (a variable that
never gets a type from any producer instruction forces `changed = true` forever, since two `null`s are
never treated as "the same") — additional to the existing suspected-cause (fresh-object-identity in
`SameTypes`'s `!oldType.Equals(newType)` on newly-constructed `ArrayType`/`PointerType`). Not confirmed as
the actual cause (no timeout method's variables were traced), but worth handing to whoever picks up the
follow-up spike alongside the existing hypothesis.
