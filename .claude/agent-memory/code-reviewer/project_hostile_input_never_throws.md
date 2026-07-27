---
name: project-hostile-input-never-throws
description: Silvergun ingests malicious assemblies; public read/analyze entrypoints must be total (never throw). Recurring review checkpoint.
metadata:
  type: project
---

Silvergun ingests untrusted/malicious .NET assemblies and NuGet packages. Public
entrypoints that parse those inputs (`AssemblyMetadata.Read`, `CapabilityAnalysis.Analyze`,
etc.) are contractually **total**: they must return a failure/partial `Result`, never throw
and never hang, on crafted/corrupt input.

**Why:** the threat model (ADR 0005/0006) is that a hostile PE/package is the primary input.
An unhandled throw or infinite recursion is a denial-of-service / crash surface, not just a bug.

**How to apply:** when reviewing any reader/analyzer, trace every operation that touches
input-derived CCI/analysis-net objects (property getters, lazy enumerations like
`body.Instructions`, casts like `(IBasicType)ContainingType`, directory walks). Each must be
inside a try/catch or otherwise provably non-throwing. A per-item try/catch (e.g.
per-instruction) is good for resilience but does NOT cover the enclosing enumeration/setup —
verify the method-level and top-level loop are also guarded, and that XML docs claiming
"never throws" / "skipped when scan throws" actually match the code. Watch for pathological
recursion on directory probes — prefer `TopDirectoryOnly` over `AllDirectories` on
attacker-influenced paths.
