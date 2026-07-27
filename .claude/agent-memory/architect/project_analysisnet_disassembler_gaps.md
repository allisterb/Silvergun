---
name: analysisnet-disassembler-gaps
description: analysis-net gotchas — TAC lifter fails on modern IL (mscorlib-pinned PlatformTypes), and the CCI reader can FailFast-kill the process uncatchably; scan bytecode-level calls, never trust never-throws guards
metadata:
  type: project
---

analysis-net's **Disassembler** (`ext/analysis-net/Backend/Transformations/Disassembler.cs`) — the
stage that lifts bytecode → three-address code (TAC) — throws on real-world EH-heavy IL. Diagnosed
2026-07-16 scanning `Microsoft.AspNetCore.Mvc.NewtonsoftJson` from the NuGet cache: **49 methods
skipped, 0 findings** (near-total failure on that assembly).

**⚠️ ROOT CAUSE CORRECTED 2026-07-25 by measurement (the EH story below was wrong/secondary).**
The **dominant** cause is trivial, not deep: `PlatformTypes.Void` is hard-coded to assembly
`mscorlib` (`ext/analysis-net/Model/Types/Types.cs:44`), but modern IL returns
`[System.Runtime]System.Void`, and `BasicType.Equals` compares `ContainingAssembly`. So
`InstructionTranslator.ProcessReturn` (`Disassembler.cs:430`) takes the non-void branch and pops
an **empty stack** for *every void-returning method on any .NET Core / .NET 5+ assembly* — a
4-instruction, 0-EH-region property setter fails. That is **60–97%** of all failures across 6 real
assemblies. **Corollary (bigger than the lifter): analysis-net's whole `PlatformTypes` table is
pinned to `mscorlib`, so anything in `ext/` that compares against platform types is unreliable on
modern assemblies.** Also: "TAC succeeded" ≠ "TAC is correct". Implication — fixing TAC for the
parked dataflow/taint track may be far cheaper than assumed (retarget `PlatformTypes` to the
running/reference platform), so re-cost that work before writing it off.
**Secondary (real, smaller):** the EH stack-model defect — the lifter simulates operand-stack depth
across the CFG (`Disassembler.cs:1013-1053`, `Push`/`Pop` throw at 81/87) and never models the
runtime's exception-object push at handler entry, so handlers underflow / cross-edge depths diverge
("Basic block with different stack size at entry!").
**Measured failure rates** (bodied methods): mvc-newtonsoftjson 5.0.0 **51/161 = 31.7%**, Kestrel
35.5%, Newtonsoft.Json 13.0.4 29.1%, CodeAnalysis.CSharp 17.3%, our own IL.dll 24.4%, ImageSharp
32.0%. The older "49 of 49 methods skipped" figure **does not reproduce** — don't cite it.
**IL/metadata format is NOT the problem** — CCI reads it fine; every call target is present in the
bytecode model.

**Cecil does NOT fix this:** Cecil is a metadata/IL *reader* (same layer as CCI/CCIProvider); the
failure is one layer up in TAC lifting. Porting to Cecil is a separate loader-modernization
question, not this fix.

## ⚠️ SECOND, INDEPENDENT DEFECT CLASS (found 2026-07-26) — the CCI *reader* can kill the process

Separate from the TAC lifter, and more dangerous. **`ext/analysis-net`'s CCI reader terminates the
whole process on some inputs, uncatchably** — so **no `try/catch` "never throws" guard in `src/`
actually holds**, including `CciNames.Guard`, `CapabilityAnalysis`, and `ObfuscationAnalysis`.
Full analysis: **ADR-0021** (`docs/agent/decisions/0021-uncatchable-cci-failfast-containment.md`).

- **Mechanism:** `Debug.Fail`/`Debug.Assert` in CCI → .NET's default `DebugProvider` →
  **`Environment.FailFast`** (exit 35), *not* a managed exception. `DEBUG` **is** defined in our
  Debug build of `Microsoft.Cci.NET6.csproj` (the SDK appends it after the csproj's literal
  `<DefineConstants>`; verify with `dotnet build -getProperty:DefineConstants`).
- **Confirmed trigger:** `GetTypeReference()` has no `ElementType.TypedReference` (0x16) case;
  the `Pointer` arm recurses without the top-level peek, so **`TypedReference*` hits `Debug.Fail`**.
  Reproducible from **plain `unsafe` C#** (`static unsafe void Consume(TypedReference* p) {}`) —
  no crafted metadata, so any hostile package can carry it.
- **Systemic, not a one-off: 194 `Debug.Assert`/`Debug.Fail` sites across 41 files** in
  `ext/analysis-net/cci`. A per-byte patch is an arms race; only a **process boundary** is robust.
- **Release degrades instead of dying** for this construct (`?? Dummy.TypeReference`), so check
  which configuration ships before judging urgency.

**How to apply:**
- **Never call `CciNames.Of(IMethodReference)` just to get a classification key.** It eagerly reads
  `method.Parameters` (the crash path). `CanonicalName.ClassificationKey(MethodIdentity)` is
  signature-free, so use `ClassificationKey(CciNames.Of(callee.ContainingType)) + "." + name`
  instead — same string, no parsing. This kept the crash off the `scan-package` path.
- Before pointing any new analysis at untrusted assemblies, ask **"does this read `.Parameters`,
  or otherwise drive signature parsing?"** If yes, it needs the ADR-0021 containment first.
- **This class of bug is invisible to in-process xUnit** — `Assert.Throws`/`Record.Exception`
  cannot observe a `FailFast`. Regression tests must spawn a child process and assert its exit code.
- Ties to [[project-hostile-input-threat-model]]: a package that kills the scanner is a targeted
  DoS on CI, and an attacker can aim it at their own package specifically.

**How to apply:**
- **Fixing it unlocks two tracks, not one (author's thesis, `reference/papers/tesis_n6970_Zoppi.pdf`):**
  analysis-net's IR ladder is CIL → *simplified bytecode* (~20 instr kinds; this is `Model.Bytecode`,
  the rung we consume, produced with NO stack simulation) → *TAC* (the IR "used by most of the
  analyses") → SSA. The `Disassembler` IS the simplified-bytecode→TAC stage. Every richer analysis —
  including the **flow-sensitive points-to analysis that builds a more precise call graph than CHA**,
  and any taint/dataflow work — sits on TAC and is therefore blocked by this defect. So the cheap
  `PlatformTypes` fix would unlock BOTH the parked taint track AND the call-graph precision lever.
  Also: analysis-net is explicitly modelled on **Soot**, so JCapsLock's SootUp design transfers by
  intent, not coincidence.
- Mitigation (planned): decouple capability detection from TAC — scan the CCI-produced *bytecode*
  body's calls directly (`Model.Bytecode.Instructions.MethodCallInstruction.Method` +
  `CreateObjectInstruction.Constructor`, `Model/Bytecode/Instructions.cs:335,313`), skipping
  `DisassembleMethod`. Restores coverage; TAC/CFG reserved for dataflow analyses that need it.
- Fixing the EH stack simulation itself is real compiler work (ECMA-335 stack model); do it in the
  analysis-net *fork* (silver branch) when taint/reachability need TAC — not in ext/ (read-only).
- **Blast radius includes the CHA call-graph builder (found 2026-07-24):**
  `Backend/Analyses/ClassHierarchyAnalysis.cs` is TAC-coupled — it reads `Model.ThreeAddressCode`
  call instructions and its `DefaultReachableMethodFound` runs `new Disassembler(method).Execute()`,
  so it inherits this bug. **But** `Backend/Model/ClassHierarchy.cs`, `Backend/Model/CallGraph.cs`
  and `Backend/Utils/Helper.FindMethodImplementation` are TAC-free and reusable as-is. So a call
  graph is reachable without TAC: write our own CHA driver over the CCI *bytecode* call sites and
  reuse those three. Details + design: `docs/agent/research/capslock-capability-analysis.md`.
- Always smoke against real cache packages; green synthetic fixtures don't prove disassembler
  robustness. Ties to [[project-hostile-input-threat-model]]: "failed to lift" ≠ "no capabilities"
  — reports must surface analysis coverage (methods scanned vs skipped).
