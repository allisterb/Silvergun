---
name: metadata-seam-calledapi-contract
description: The "owner!entryPoint" CalledApi contract for CapabilityAnalysis metadata seams is attacker-controlled and arity-blind — measured weaknesses to re-check whenever a new seam is added.
metadata:
  type: project
---

`CapabilityAnalysis.ScanInteropDeclarations` emits `ApiCallFinding.CalledApi` as `owner!entryPoint`
(`module!entryPoint` for `NativeImport`, `<managed>!entryPoint` for `NativeExport`). Two properties of
that contract are **measured, not theoretical**, and neither is defended in code:

1. **The `!` separator is attacker-controlled.** Both sides come straight from metadata strings.
   `[UnmanagedCallersOnly(EntryPoint = "evil!injected")]` yields `<managed>!evil!injected`, and
   `[DllImport("evil!mod.dll")]` yields `evil!mod.dll!fn` — i.e. the "exactly one `!`" shape that the
   XML doc and `ModernInteropDeclarationTests` 2d assert is violable by any hostile package. No
   production consumer splits on `!` today (all renderers print `CalledApi` verbatim through
   `ReportTheme.Esc`), so it is latent. Angle brackets are safe: Spectre markup is `[`/`]` only, and
   `Markup.Escape` covers those.
2. **Seam findings are arity-blind and then deduplicated.** Both seams use bare `method.Name.Value`, so
   two `[UnmanagedCallersOnly]` (or two `[DllImport]`) overloads with the same entry point produce
   byte-identical finding tuples that `findings.Distinct()` in `Analyze()` collapses to one. Verified:
   `Overloaded(int)` + `Overloaded(long)` → a single finding. The repo already has arity-aware naming
   (`CciNames`/`CanonicalName`, see [[canonical-name-parity]]) that would fix it.

**Why:** a static analyzer that under-reports or mis-renders on crafted metadata fails exactly on the
input it exists for, and the fixture-only tests that pin the contract use benign strings, so they give
false assurance.

**How to apply:** when reviewing any new metadata/attribute seam (`[ComImport]` type scanning is the
deferred next one, per `docs/agent/tasks/interop-detection-gaps.md`), re-check both properties against a
*hostile* probe, not the fixture — and require the shape test to use `Split('!', 2)` semantics or a
sanitized separator rather than asserting a segment count. Reusable hostile-probe recipe: the scratchpad
console app described in [[canonical-name-parity]], with an assembly that applies the attribute with
`!`, markup characters, newlines, an empty value, and a same-simple-name decoy attribute in another
namespace.
