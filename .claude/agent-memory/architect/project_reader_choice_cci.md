---
name: reader-choice-cci
description: DECIDED 2026-07-30 — keep the CCI reader; ILSpy and Cecil were measured against it across 4 phases and neither wins. Use SRM/ILSpy as reference implementations, not replacements.
metadata:
  type: project
---

**Decision: Silvergun keeps the `ext/analysis-net/cci` reader.** ILSpy 10.1.1 and Mono.Cecil 0.11.6
were evaluated against it over four measurement phases. Full data:
`docs/agent/measurements/ilspy-provider-spike.md` §0–§2 (ILSpy) and §C (Cecil).
**Do not re-open this without evidence of a kind those phases did not produce.**

**Why:** hostile-input robustness ranked **CCI > ILSpy > Cecil**, which inverted everyone's
expectation including mine. Correctness and coverage were a three-way tie (live-seam naming
0/604,136, findings hash-equal, coverage delta 0/140,441), so equivalence — not superiority — was the
result, and equivalence does not justify a 3.5–5 day port.

**⚠️ THE PRIOR WORTH CARRYING (confirmed 4× in one session): a library's scale of adoption tells you
about accuracy on VALID input, not robustness on HOSTILE input.** Cecil is the most widely deployed
of the three (Fody, Unity, Mono, ILSpy's own test suite) and was the *worst* on crafted input: it
**clamps** a bad `CodeSize` to 0 and reports a destroyed method as cleanly analysed (silent false
negative); a two-byte `FE 99` edit hid **8 of 9 findings** (CCI 9, ILSpy 9, Cecil 1); `HasBody`
ignores RVA so it fabricates **+17 phantom bodies**; and `Write()` on a cyclic enum is an
**uncatchable stack overflow (exit 127)**. Generalise: **any library whose primary users feed it
their own build output inherits a trusted-input assumption** — CCI (2010 MSR, compilers/rewriters)
and Cecil (weavers) both do. ILSpy is the exception because hostile binaries *are* its use case.

**The load-bearing conclusion — this is the reusable one:** **our hostile-input robustness lives in
the six files of `src/Silvergun.CodeAnalysis.IL/`, not in the reader underneath.** Every defect fixed
on 2026-07-29/30 (per-method body-read granularity, a name read inside a catch handler,
`TypedReference*`, ADR-0024 completeness reporting) was in *our* layer. Swapping readers would have
moved none of them. **When robustness is the goal, invest in our layer, not the dependency.**

**How to apply going forward (user's framing):** use **SRM and ILSpy as reference implementations**
when diagnosing a CCI defect — ILSpy 10.1.1 source is at `reference/projects/ILSpy-10.1.1` and is the
exact match for the `ICSharpCode.Decompiler` 10.1.1.8388 package reference on
`Silvergun.CodeAnalysis.IL`. Read them for *how a hardened reader handles X*, then fix our layer.
Both `ICSharpCode.Decompiler` and `Mono.Cecil` 0.11.6 are referenced but **not on the scan path**.

**Cecil's one earned niche:** round-trip instrumentation *works* (646 bodies given a prepended `nop`,
re-read by all three readers findings-hash-equal, CLR loaded and JITted every method). So a
`CecilInstrumenter` for the dynamic-analysis track is viable — **isolated, never on the scan path**,
~1–1.5 days. Caveats: writing needs the full dependency closure, **refuses ReadyToRun images**
(`NotSupportedException: mixed-mode`), and is where the stack overflow lives. Also: **always pass a
scoped `AssemblyResolver`** — `DefaultAssemblyResolver` bound an isolated assembly's refs to files in
the analyzer's own output directory and the live shared framework (attacker-influenced file-open).

See [[analysisnet-disassembler-gaps]], [[hostile-input-threat-model]], [[measure-before-designing]].
