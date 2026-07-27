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

**Known, accepted residual risk**: `IsVoidReturn`'s fallback path matches on namespace+name only,
ignoring `ContainingAssembly` — a hostile assembly declaring its own non-corlib `System.Void` type
(legal at the IL level, illegal only in C#) would false-positive-match and desync the operand stack.
The spike itself flagged this and judged it low-priority for the current threat model (most-likely
manifests as a later Pop/Push exception, not silent misclassification). Not fixed as of this review —
worth tightening to a known-corlib-assembly-name allowlist if a future spike targets adversarial IL
specifically, since Silvergun's stated purpose is analyzing *hostile* packages.

**Deliberately out of scope, not yet addressed**: ~150 more `.Equals(PlatformTypes.X)` comparisons
(`Boolean`, `Int32`, `Object`, etc., not just `Void`) in `Backend/Analyses/TypeInferenceAnalysis.cs`
and `Model/Types/TypeHelper.cs`, same mscorlib-pinned mismatch, but they run on already-lifted TAC
(post-`Disassembler`), not reached during lifting — confirmed by grep, no `PlatformTypes.Void`
comparison exists in `Backend/` outside `Disassembler.cs`'s own new helper. This is flagged as a
plausible next spike, especially since `TypeInferenceAnalysis` sits directly on top of TAC and is a
likely next step for any dataflow/points-to work — see [[project-analysisnet-workflow]].
