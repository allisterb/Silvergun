---
name: feedback-ext-signature-decoder-review
description: How to verify correctness of ECMA-335 signature-decoder arms in CCI's ext/ fork against byte-consumption and grammar position
metadata:
  type: feedback
---

For changes to `ext/analysis-net/cci/PEReaderAndWriter/PEReader/PEFileToObjectModel.cs`
(`SignatureConverter.GetTypeReference()` and friends), verification cannot stop at "does it
return the right `ITypeReference`" — two more checks matter as much or more:

1. **Byte consumption.** Cross-check the ECMA-335 grammar for the element type (does it take
   an operand, e.g. compressed-uint token, or none, e.g. `TYPEDBYREF`/void-like primitives).
   A correct return value with wrong consumption silently corrupts every subsequent type in
   the same signature — worse than the crash being fixed, and won't show up in a happy-path
   test.
2. **Grammar position / reachability.** Some element types (`Pinned` 0x45, `Sentinel` 0x41)
   are only valid at specific positions in ECMA-335 II.23.2.x (`Pinned` only as a `LocalVarSig`
   constraint; `Sentinel` only inside a param list between fixed and vararg params) — never
   inside the recursive `Type` production `GetTypeReference()` implements. Before treating a
   missing arm as a gap, grep every call site of the helper that strips it (here,
   `GetCustomModifiers(out isPinned)`) and confirm it runs ahead of every context where the
   grammar allows that byte. If it does, a switch arm for it inside `GetTypeReference()` truly
   is dead code, not a gap — don't flag its absence as a Critical finding just because SRM's
   `DecodeType` has an arm for it (SRM's decoder is one generic recursive function reused
   everywhere, so it needs the arm; CCI strips these bytes at each grammar entry point instead
   — different architecture, same correctness).

**Why:** verified against `reference/projects/dotnet-runtime/.../SignatureDecoder.cs` (the
authoritative comparison point named in ADR-0022) and by grepping all
`GetCustomModifiers`/`GetTypeReference` call sites in `PEFileToObjectModel.cs` +
`ILReader.cs`'s `LocalVariableSignatureConverter.GetLocalVariable` — every reachable Pinned/
Sentinel position was already handled outside the switch. The implementer's stated reasoning
for omitting those two arms held up under this check.

**How to apply:** on any future arm added/removed in this switch, redo both checks (grammar
operand size, grammar position) rather than trusting the PR description's claim — this is
exactly the kind of "verify, don't accept" item CLAUDE.md calls out, and it's cheap to check
by grep + reading the reference decoder.
