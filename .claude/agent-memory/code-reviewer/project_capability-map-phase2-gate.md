---
name: capability-map-phase2-gate
description: Capability-map phase 2 landed 2026-07-31 — the recipe that actually verified its 5,131 -> 7,958 finding delta, reusable for any future detection-seam switch.
metadata:
  type: project
---

Phase 2 (wiring `CapabilityAnalysis.Match` onto `CapabilityMap.Default`) **landed and reviewed clean
2026-07-31**. The over-match concern this memory used to track was resolved deliberately: 417
`Marshalling.*`, 58 exception/sibling and 3 `Marshal*` attribute/exception findings accepted as FP
removals, 2 state-machine `..ctor` accepted, 99 `System.IO.FileSystem` restored by one new map entry.

**Why this is still worth keeping:** the verification recipe generalises to any future matcher swap,
and it is far stronger than reading the implementer's classification table.

**How to apply** — with `capmap-before.tsv` / `capmap-after.tsv` / `capmap-keys.tsv` in
`docs/agent/measurements/` (gitignored), all in PowerShell, no repo edits:

1. Key each finding on `(assembly, Kind, CallerType, CallerMethod, CalledApi)` and diff — do not
   trust the reported lost/new/changed counts, recompute them.
2. **Re-derive every after-finding's capability from `capabilities.cm` independently**, implementing
   the map's own precedence (exact type+method > exact type > longest `.*` prefix, generics stripped
   from `CalledApi`). 0 mismatches over all 7,958 findings is what actually proves the wiring, not a
   green suite.
3. Cross-check the Step-1 divergence file the same way: for every differing
   `TypeName` vs `ClassificationKey` pair, confirm the *map verdict* is unchanged. 0 differences
   means no entry silently stops matching.
4. Re-measure numbers pinned in source comments rather than believing them. Both of phase 2's
   ("144,192 call sites", "`IsElementTypeConstruction` fires 0 times") were independently confirmed
   with a scratch console that walks each corpus assembly in its own child process.

Corpus was 6 assemblies: the netstandard2.0 Fixture, MatrixFixture net472+net10.0, BenchmarkDotNet
0.15.8/net8.0, and System.Net.Sockets + System.Private.CoreLib from
`microsoft.netcore.app.runtime.win-x64` 9.0.11. Related:
[[canonical-name-parity]], [[feedback_isolate-failfast-child-process]],
[[verify-measurement-harnesses]].
