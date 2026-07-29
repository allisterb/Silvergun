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

## ✅ FIXED 2026-07-27 — the cheap fix worked, and it was bigger than diagnosed

Spike: `docs/agent/measurements/tac-platformtypes-spike.md`. **Corpus-wide TAC failures
15,308 → 1,140 = 92.6% reduction.** Six of seven real assemblies went from 17–36% failure to
**0.0–0.6%**. Change is ~20 lines in `ext/analysis-net/Backend/Transformations/Disassembler.cs`,
all 855 tests still green.

**The diagnosis was right but UNDERCOUNTED: there were THREE `.Equals(PlatformTypes.Void)`
sites, not one.** `ProcessReturn` was the obvious one; the other two (a direct `call`/`callvirt`
and an indirect `calli`) **push a phantom result for every call to a void method**, which
surfaces later as a `Push()` capacity overflow far from the real cause. That is why the biggest
failure bucket was the message-less `Operation is not valid due to the current state of the
object.` (68.3%) rather than something obviously void-related. **Generalisable lesson: fix the
predicate, then grep for every other use of that same predicate before measuring.**

**The decisive experiment was a control pair, not a bigger corpus:** the *same* `Newtonsoft.Json`
13.0.4 package, `net45` build vs `net6.0` build — **0.07% vs 29.1% failure**, ~400× — plus a
purpose-built identical-source fixture at net472 (0/7) vs net10.0 (4/7). TFM isolated as the sole
variable. Use that pattern for any "is this a modern-IL problem?" question.

**What this changes:** TAC lifting is now broadly viable on modern assemblies, so **the parked
taint/dataflow track and the points-to analysis (call graph more precise than CHA) are
un-blocked** — re-cost them rather than treating TAC as broken.

**Still broken, and now the dominant residual:** the EH/CFG stack-depth-consistency defect at
`Disassembler.cs:1067` — 2.7% residual on `Microsoft.CodeAnalysis.CSharp`, near-zero elsewhere.
Untouched by this fix; a genuinely harder compiler problem.

**The corollary elsewhere — NOW MEASURED (2026-07-27):**
`docs/agent/measurements/platformtypes-comparison-audit.md`.

- **174 genuinely-broken comparisons**, not the ~220 a naive `PlatformTypes.` grep suggests —
  of 254 occurrences, 76 are harmless **construction/assignment**. **Always separate
  construction from comparison before quoting a defect count.** (My grep was also wrong in
  both directions: it undercounted `TypeHelper.cs` and missed `CCIProvider`/`Console` entirely.)
- **162 of them are in `TypeHelper.cs`, 12 in `TypeInferenceAnalysis.cs`, and they are one
  repeated `.Equals(PlatformTypes.X)` predicate shape** — not 174 distinct decisions. So a
  single shared helper fixes essentially all of it.
- **None are reachable today.** Stronger than "nothing calls TypeInferenceAnalysis":
  `TypeInferenceAnalysis` is `TypeHelper.cs`'s **only** external caller in the outer fork, so
  those 162 are structurally unreachable, not coincidentally quiet. `CCIProvider` (the live
  path) has 16 `PlatformTypes` refs, **all construction**.
- **Divergence if the dataflow track were on: 4.14%** (37,518/905,446) over six modern
  assemblies, **18.5%** for the highest-stakes predicate
  (`ReturnType.Equals(PlatformTypes.Boolean)`). **Two net472 controls diverged exactly 0.00%**
  — that control is what validates the instrument; always include one.
- **Fix shape: a shared `PlatformTypes.Matches` helper** (generalise the shipped
  `Disassembler.IsVoidReturn`). **Retargeting the static table was assessed and REJECTED with
  evidence:** `AssemblyDisassembler` analyses different TFMs concurrently and would need
  `PlatformTypes.Object` to resolve to different assemblies *simultaneously* — a single static
  table cannot do that under any locking; it would have to become a per-`Host` instance.

## ⛔ 2026-07-28 — `TypeInferenceAnalysis` TERMINATES but is NOT TRUSTWORTHY. Do not build on it.

Termination is fully fixed (`measurements/typeinference-nontermination.md`): 0 NREs, 0 timeouts,
65,028 converge + 17 observably flagged, bound 100 + cycle detection windowed at 20 with an
adversarial worst case of `O(100×20×V)` time / `O(20V)` memory **independent of hash quality**.

**But the audit that followed (`measurements/typehelper-nonmonotonic-audit.md`) found the
answers are frequently WRONG — and wrong *stably*, with no flag:**

- **Commutativity is violated.** `BinarySignedNumericOperationType(left, right)` takes only two
  types and no operator, so it is pure numeric promotion and **must** be commutative. It is
  asymmetric on **~40%** of all `PlatformTypes` pairs (~26% even restricted to the realistic
  14-type numeric subset). Root cause: the float-left branch at `TypeHelper.cs:781-783` returns
  `right` unconditionally. This is a **provable** bug — no oracle needed.
- **18.56% of variables disagree with their declared metadata type** (34,840 / 187,702), *zero
  unexplained*: 97.9% from the Boolean-override guard — including **26.7% where the instance
  receiver `this` is typed `Boolean`** — and 3.5% from Object-narrowing.
- **25.25% of methods are order-dependent** (15,721 / 62,270; 41,511 variable divergences), and
  **both traversal orders report `CONVERGED=True`**. That is the smoking gun: the analysis
  confidently reaches *different* fixed points depending on CFG traversal order.

**Cost to fix (from the audit):** ~days for commutativity (self-contained, testable); **1–2
weeks** to replace the Boolean-override/Object-narrowing guards with real `MergedType` merging
and re-run every gate. Nothing is urgently broken — `TypeInferenceAnalysis` is still unreferenced
from `src/`.

**How to apply:** treat "it converges" as saying nothing about correctness here. Any
points-to/dataflow/taint work must either fix these rules first or not depend on inferred types.
**Re-run the audit's three oracle-free checks as the acceptance test** for any fix:
(1) exhaustive commutativity over `PlatformTypes` pairs, (2) inferred-vs-declared metadata
ground truth, (3) confluence under reversed CFG ordering. That trio is reusable for any
type-inference change and needs no external oracle.

⚠️ **Caveat learned 2026-07-29 while fixing check 1: THE ORACLE IS THE WEAK POINT, NOT THE
CORPUS.** The rewritten promotion passed an exhaustive 2,601-pair commutativity sweep while
still laundering the `PlatformTypes.Unknown` *sentinel* into a confident `PlatformTypes.Object`.
My first diagnosis — "the sentinel wasn't in the operand list" — **was wrong, and `test-engineer`
proved it**: `PlatformTypes.Unknown` is declared `public static readonly UnknownType` and
`UnknownType : IType`, so a reflect-all-`IType`-fields corpus had it all along. The bug survived
because **both operand orders returned the same wrong answer**, and a symmetry-only oracle can
never see that. **Generalisable: enlarging the corpus does not fix an oracle gap. For any
oracle-free symmetry/confluence check, pair it with a value-level assertion on sentinel/bottom
inputs (`Unknown`, `null`, unresolved refs) — "f(a,b) == f(b,a)" must be joined by "and it isn't
a fabricated definite answer".**
Second, smaller: **an exhaustive-looking pair count can hide aliases** — the 37 reflected
`PlatformTypes` fields include `Int8`/`SByte`, `Float64`/`Double`, `ArrayLengthType`/`SizeofType`/
`UInt32`, so ~6 of the 2,601 pairs are duplicates. Pin counts as assertions (so a sweep cannot
silently shrink) but never quote them as *distinct* coverage.

**⚠️ Two caveats on the audit itself:** the original `scratchpad/tac-spike` corpus had been
deleted, so it was rebuilt from the NuGet cache with one version substitution (Kestrel 2.2.0 for
5.0.17) — denominators differ from earlier runs (62,270 vs 65,045 methods), so don't compare
across them. And the "two-outcome, period-2" claim was only *corroborated*, not re-derived,
because the `onIteration` hook was removed at an earlier review — **removing that hook cost us
verification ability later**, worth weighing next time an instrumentation seam is trimmed.

**⚠️ SEPARATE BLOCKER for the dataflow track, found as a byproduct:** a real
`NullReferenceException` in `Dereference.Type` (`Model/ThreeAddressCode/Operands.cs:888`) fires
**13,617 times** on the corpus — including **546 times on the net45 control**, so it is
independent of the `PlatformTypes` defect and TFM-agnostic. It is a normal catchable exception
(not ADR-0021's uncatchable FailFast, which is confined to the `cci` submodule), but it means
**`TypeInferenceAnalysis.Analyze()` would crash on real code on any TFM before the
`PlatformTypes` issue even matters.** Fix this first if the dataflow track proceeds.

## ⚠️ 2026-07-29 — FailFast is NOT the only uncatchable kill: unbounded recursion is a second mechanism

Do not read ADR-0021 as "the uncatchable-kill problem = `Debug.Fail`". A **self-referential enum**
(`E : E`) sends `TypeHelper.StackType` into unbounded recursion ⇒ **`StackOverflowException`**,
which .NET also cannot catch. Measured (7,405 frames). **The defect exists independently in BOTH
halves of the fork** — `Model/Types/TypeHelper.cs:290` (not reachable from `src/`) and
`cci/CoreObjectModel/MetadataHelper/TypeHelper.cs:2091`, whose caller `StackTypesAreEquivalent`
is documented as being for **signature matching**, so it may be on the live path. Reachability
spike + fix specced at `tasks/self-referential-enum-stack-overflow.md`, not yet run.

**How to apply:** when auditing `ext/` for hostile-input safety, grep for **unbounded recursion
over attacker-controlled metadata graphs** (enum underlying types, pointer/array element types,
generic argument nesting, base-type chains), not just for `Debug.Assert`. A `try/catch` catches
neither mechanism. Depth-bound overloads are the cheap fix — legitimate depth is ~1.

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
