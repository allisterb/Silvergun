---
name: project_yara-compiler-poisoning-review
description: ADR-0028 (YARA compiler poisoning) review, 2026-08-21 — libyara.NET ownership facts, which quoted timings the TSV supports, and the round-2 test-suite hazards (UB thread in the test host, multi-TFM test parallelism knob).
metadata:
  type: project
---

Review of the `LibYaraScanner` two-pass-compile + startup-canary fix (ADR-0028, 2026-08-21). Facts
established by reading `reference/projects/libyara.NET/*.h` and
`docs/agent/measurements/yara-inprocess-timing-2026-08-21.tsv` — recorded so they need not be
re-derived.

**libyara.NET ownership (from the headers, the only copy we have — there is no libyara C source under
`reference/`):**
- No C++/CLI wrapper declares a finalizer (`!Compiler()`, `!Rules()`, `!YaraContext()` all absent).
  So an *undisposed* wrapper leaks its native object for the process lifetime, and — usefully — an
  abandoned native thread can never have its `YR_RULES` freed behind its back by the GC.
- `Compiler.h`'s own `CompileRulesFile` / `CompileRulesString` helpers declare `Compiler c;` with
  **stack semantics** (destructor runs at scope exit) and return `c.GetRules()`. That is decisive:
  the returned `Rules` does **not** depend on the compiler staying alive, so a "must not dispose the
  compiler because the Rules outlive it" rationale is wrong.
- `Scanner` has no destructor (not `IDisposable`); `Scanner::ScanFile` throws `FileNotFoundException`
  on an unopenable handle, and `ErrorUtility::ThrowOnError` throws `YaraException` for *any* non-zero
  libyara error code — so per-file native throws are routine, not exotic.
- `Scanner.h`'s `TimeoutSeconds = 10000` really is a private const with a `// TODO make parameter`.

**Measurement-TSV facts (re-measure before trusting a comment):** `RuleFilesFound = 310`,
`attempted=310; skipped=1` → **309 compiled**, the skip being `ReversingLabs.virus.Linux.Virus.Vit.yara`.
The hang threshold rows are `E3 zeros-2 / 2 B / poisoned → 6 ms` and `E3 zeros-4 / 4 B / poisoned →
timeout`. The frequently-quoted "healthy full-ruleset scan of 1 MB is 15 ms" is really
`E3 zeros-1048576` at **RuleFiles=128**, not the full ruleset; and there is **no** 4-byte clean-ruleset
row, so "> 120,000 ms on a 4-byte input versus 5 ms for the identical input" pairs two different
experiments.

**Why:** the class doc comment was rewritten in this change specifically because the previous
explanation ("combinatorial cost from matching hundreds of rules' patterns together") was disproved;
a replacement that quotes unsupported pairings repeats the original failure in a subtler form.

**More TSV facts re-derived in round 2 (2026-08-21):** `E4 first302` = 26,653 B / 302 rule files /
**5 ms** (the only clean-ruleset "5 ms" row). `E2` Newtonsoft `.dll` rows are **7–12 ms** over
524,200–723,368 B at **RuleFiles=128** — a comment saying "8–11 ms" trims the measured tails. `E3`
1 MB rows: 15 ms all-zero / 18 ms random, also RuleFiles=128. Note the column is `RuleFiles`, so
"128-rule subset" is really *128 rule files*. There is still **no** clean-ruleset row at 4 B or 64 KiB.

**Round-2 (test-suite) hazards worth re-checking on any change here:**
- `LibYaraScannerPoisoningTests` deliberately builds a poisoned ruleset and scans it in-process; the
  5 s canary bound abandons a thread that then executes **undefined behaviour inside the test host for
  the rest of the run**. An AV there kills all ~429 tests with an exit code and no failing test — same
  class of hazard as ADR-0021's CCI FailFast. Isolation would need a child process.
- libyara.NET's `YaraContext.h` says *all* yara operations must happen inside a `YaraContext` scope;
  tests that reach `CompilesCleanly`/`new Compiler()` without one rely on undocumented tolerance and on
  xUnit's (unspecified) intra-class ordering.
- Multi-TFM `dotnet test` really does run the two TFMs' hosts **concurrently**: verified in SDK 10.0.101
  `Microsoft.TestPlatform.CrossTargeting.targets` → `DispatchToInnerBuildsWithVSTestTarget`, which uses
  `_TestTfmsInParallel = ValueOrDefault(TestTfmsInParallel, BuildInParallel)`. So `TestTfmsInParallel`
  is the purpose-built knob; `BuildInParallel=false` works but also serializes ProjectReference builds.
  (The inner dispatch passes `VSTestNoBuild=true`, so this is a test-host collision, not CS2012.)

**How to apply:** re-check these on any future `LibYaraScanner` / ADR-0016 / ADR-0028 change before
accepting a disposal rationale or a quoted timing. Related:
[[task-wait-timeout-fault-path]], [[verify-measurement-harnesses]],
[[feedback_isolate-failfast-child-process]].
