---
name: detection-calibration
description: Measured 2026-07-31 — capability PRESENCE doesn't discriminate malicious from benign (96% of benign packages trip --strict); composition on a reachable path + call target does. Blocks any risk-scoring model.
metadata:
  type: project
---

**Two independent measurements taken for different reasons reached the same conclusion: capability
*presence* is not a discriminator. Composition on a reachable path, plus the target of the call, is.**

1. **Benign corpus** (`docs/agent/measurements/benign-corpus-2026-07-31.md`, 25 pinned packages,
   deterministic): **`--strict` fails 24 of 25 (96%)**. Per-capability share of benign packages —
   DynamicCodeLoading **80%**, ReflectionInvocation **72%**, EnvironmentProbe 60%, RuntimeControl 40%,
   FileSystem 36%, UnsafeMemory 24%, Crypto/Network 20%, NativeInterop 12%, **ProcessExecution 8%,
   Registry 4%**.
2. **TTP seam mapping** (`docs/agent/research/ttp-seam-mapping.md`, 364 ReversingLabs policies):
   the capability seam is **3 of 364 rows, all `partial`**. RL phrases TTPs as **conjunctions**
   ("collect *and* exfiltrate") and **specific targets** ("the startup sequence"); we have
   presence-not-reachability and unclassified call arguments, so **we can express neither half**.

**How to apply:** **do not design a risk/scoring model on finding counts** — it would be calibrated
against noise. The blocker is architectural (reachability + argument classification), not data. This
is the strongest argument yet for the parked points-to track, and it reframes what `--strict` should
gate on. See [[analysisnet-disassembler-gaps]] for why TAC/points-to is now viable.

⚠️ **Corollary — a corpus of the wrong population produces confident nonsense.** Capability-map
phase 2 reported `UnsafeMemory` at 2,132 findings; on real packages it is **47 (24% share)**. That
corpus included `System.Private.CoreLib` and `System.Net.Sockets` — *the platform*, not packages.
The before/after **delta** was sound (same corpus both sides); the **absolutes** were never
representative, and I quoted them as if they were. **Always state the population a statistic is over.**

**Detection reality, same document:** of 364 policies — covered **4 (1.1%)**, partial 25, absent
**298 (81.9%)**, out-of-scope 37. Threat-hunting: **2 covered of 152**. The engine is deep and
well-tested; coverage is early. The ranked gap list is the roadmap, cheapest first: `ldstr` → URL/IOC
classification (reach ≈50, extraction already exists), then NuGet-native script rules.

**UPDATE 2026-08-22 — the YARA cell is no longer blank, and the gate is no longer noisy.**
`docs/agent/measurements/yara-corpus-top100-2026-08-22.md`: with the in-process backend finally
working (ADR-0028), YARA prevalence on the benign top-100 is **0/100 findings over 2,277 files**, and
under ADR-0027's narrowed `--strict` the same corpus now fails **0/100** (was 72/100). Cost ≈800 ms
fixed + ≈4 ms/file. Crucially the zero was validated with a **synthetic positive control** (the engine
does match a rule when fed one) — three earlier runs reported zero because the backend was silently
dead. **A zero from a detector is worthless without a positive control in the same run.**

**Reusable evaluation shape:** benign corpus gives false-positive rates per capability; a TTP-derived
fixture suite gives detection rates per behaviour; together they are a confusion matrix. **Fixtures
must be derived from an external taxonomy and their outcome predicted before measuring — a suite that
scores 100% was written from our own catalog.** See [[measure-before-designing]].
