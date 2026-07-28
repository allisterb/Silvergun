---
name: project-platformtypes-void-fix
description: Status of the ext/analysis-net PlatformTypes.Void mismatch fix and its known-unfixed corollary in TypeInferenceAnalysis/TypeHelper
metadata:
  type: project
---

Reviewed and verified clean (2026-07-27): `ext/analysis-net/Backend/Transformations/Disassembler.cs`
gained a private `IsVoidReturn(IType)` helper (+20/-3, one file) replacing three
`.Equals(PlatformTypes.Void)` call sites (`ProcessReturn`, direct `call`/`callvirt`, `calli` via
`IndirectMethodCallInstruction`). Root cause: `PlatformTypes.Void` is hard-coded to assembly
`"mscorlib"` (`Model/Types/Types.cs:44`) and `BasicType.Equals` compares `ContainingAssembly`, so it
never matched modern IL's `System.Void` (stamped `System.Runtime`/`System.Private.CoreLib`). Backed by
`docs/agent/measurements/tac-platformtypes-spike.md` (corpus failures 15,308 → 1,140, 92.6% reduction).
Regression tests: `tests/Silvergun.CodeAnalysis.IL.Tests.VoidReturnFixture` (net472;net10.0 fixture,
identical source) + 34 xUnit tests in `VoidReturnLiftingRegressionTests.cs`, all independently
confirmed by reverting the `ext/` fix (20/34 red, 14 green — matches the claimed split exactly) and
restoring it.

**Superseded (2026-07-27, `platformtypes-comparison-fix.md`)**: the residual below was tightened, not
left as "not fixed" — `IsVoidReturn`'s local namespace+name fallback (assembly-agnostic) was replaced
by the general `BasicType.Equals` corlib-unification fix (`Model/Types/CoreLibraryNames.cs`'s
known-corlib-name allowlist), exactly the direction this memory previously flagged as worth doing. See
[[typeinferenceanalysis-readiness]] for the full verification. The **spoofable-by-name** residual
(an assembly that just calls itself `mscorlib`) is *not* closed — `IAssemblyReference` still has no
public key token/version — and is now pinned by an explicit xUnit test
(`Equals_AssemblyNamedMscorlibButNotTheRealOne_IsAcceptedKnownLimitationNotABug`) rather than only a
code comment.

**Deliberately out of scope, not yet addressed**: ~150 more `.Equals(PlatformTypes.X)` comparisons
(`Boolean`, `Int32`, `Object`, etc., not just `Void`) in `Backend/Analyses/TypeInferenceAnalysis.cs`
and `Model/Types/TypeHelper.cs` are now **implicitly fixed too**, since they all go through the same
widened `BasicType.Equals` — but both files remain unreachable from `src/` today (unchanged
conclusion), so this is dormant, not live. `TypeInferenceAnalysis` sits directly on top of TAC and is
a likely next step for any dataflow/points-to work — see [[project-analysisnet-workflow]].
