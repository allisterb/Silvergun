---
name: canonical-name-parity
description: The CciNames/ModelNames cross-layer parity contract, how to empirically re-verify it with a scratchpad probe, and which divergences are closed vs accepted (re-verified 2026-07-25)
metadata:
  type: project
---

`CanonicalName` + `CciNames`/`ModelNames` (src/Silvergun.CodeAnalysis.IL) must render
byte-identical strings for the same method from raw CCI and from analysis-net `Model`.
Task spec: `docs/agent/tasks/canonical-method-names.md`.

**Why:** parity is the component's entire reason to exist — if the layers diverge,
capability classification (ADR 0019) and call-graph nodes (ADR 0020) silently disagree.

**State after the 2026-07-25 re-review (measured, not assumed):**
- The 64-link truncation asymmetry I found in the first review is **closed** — both walks
  now funnel into `CanonicalName.Truncated(chain)` (empty namespace, `<unknown>` prepended,
  arity forced to 0). Arity *must* stay dropped: CCI sums the links it walked while
  `Model`'s `GenericParameterCount` is cumulative over the whole chain
  (`ext/analysis-net/CCIProvider/TypeExtractor.cs:355-361`), so carrying it re-breaks parity.
- **One accepted divergence remains:** past 64 levels of *generic* nesting the positional
  index differs (`Mix(!0,!64)` from CCI vs `Mix(!0,!69)` from Model), because CCIProvider's
  `TotalGenericParameterCount` (`TypeExtractor.cs:268`) is an unbounded `while` and ours is
  bounded. It touches `NodeId` only — `ClassificationKey` sets stay equal — and such keys
  already carry the `<unknown>` truncation marker. Do not "fix" it by removing our bound.

**How to apply:** when reviewing any change to the adapters, (1) check that every name
decoration (arity, `[]`, `*`, `&`, `<>`, `<unknown>`, the namespace join) is produced only by
`CanonicalName` — a name-building string literal inside an adapter is a finding; (2) check
both adapters still mirror `TypeExtractor` (cumulative nested arity, re-based type-parameter
indices, by-ref carried on `IMethodParameterReference.Kind`, and the quirk that only an
*instantiated* nesting link contributes generic arguments) — matching the quirks is what
preserves parity, "fixing" them breaks it; (3) remember the >64-deep path is **not** covered
by any xUnit test (adding a 70-deep type to the shared fixture would trip the parity suite's
"no `<unknown>` anywhere" anti-vacuity guard), so verify it with the probe below.

**Probe recipe (reusable, no repo writes):** build a throwaway console app in the scratchpad
that `<Reference>`s the DLLs in `tests/Silvergun.CodeAnalysis.IL.Tests/bin/Debug/net10.0`
(plus an `AfterTargets="Build"` copy of that whole folder into `$(OutDir)` so it runs),
defines the hard shapes (nested generic instantiations in signature position,
`ref`/`in`/`out`/pointer/function-pointer parameters, a 70-deep plain chain *and* a 70-deep
generic chain), loads its own assembly through `AssemblyAnalyzer` **and**
`AssemblyDisassembler`, and prints the symmetric difference of both key sets for definitions
and call sites. Deep chains are easiest generated with a shell loop into a `.cs` file.
