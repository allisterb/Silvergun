---
name: cci-reader-unmaintained
description: CCI's PE metadata reader has no upstream maintainer — Microsoft stopped and the only active fork (asnarnd) works exclusively on the AST/codegen half; we own reader robustness
metadata:
  type: project
---

**There is no upstream for CCI's PE metadata reader. Do not plan around "wait for an
upstream fix" or "pull the latest CCI" as a mitigation for reader bugs.**

**Why:** measured 2026-07-26. The user merged all ~50 commits from the
[asnarnd/cci](https://github.com/asnarnd/cci) fork (the only active continuation of
Microsoft's abandoned CCI) into our `ext/analysis-net/cci` submodule. Result:

- **Their entire PE-reader delta is a 3-line empty XML doc comment**
  (`PEReaderAndWriter/PEReader/AliasForTypeExtensions.cs`).
  `PEFileToObjectModel.cs` and `PEFileStructures.cs` are **untouched**.
- The known `TypedReference*` process-kill (see [[analysisnet-disassembler-gaps]] and
  ADR-0021) is **not** fixed; the `Debug.Assert`/`Debug.Fail` count went **up**, 194 → 195.
- Their ~50 commits are all AST/source-model/codegen (`AstsProjectedAsCodeModel`,
  `SourceModel`, `CodeModel`, a new `Microsoft.Cci.Ast` project, source emitters) plus
  build modernization (~25 csproj files, `Common/Default.props`, dropping `project.json`).

This follows from who they are: **ASNA builds AS/400–RPG → .NET migration tooling**, so
they use CCI to *generate* code from an AST. We use it to *read* untrusted PE files.
Opposite ends of the library — their maintenance will not drift toward our failure mode.

**Good news worth keeping:** the merge caused **zero regressions** — IL 402 /
PackageAnalysis 344 / CLI 105 all green, build clean. The three files they changed that we
transitively consume (`MetadataHelper/TypeHelper.cs`, `MetadataHelper/Members.cs`,
`MetadataHelper/Core.cs`) are additive or off our code paths. So merging their work is
safe; it just does not help us.

**How to apply:** when scoping any CCI reader defect, price in that **we own the fix**.
That raises the value of containment strategies that are indifferent to the specific bug
(process isolation, ADR-0021 Tier 2) over per-construct patches, and it means a survey of
reader gaps has lasting value because nobody else will publish one. Also relevant if
loader replacement (Cecil, `System.Reflection.Metadata`) is ever reconsidered — the
"CCI is maintained" argument is no longer available for the reader half.
