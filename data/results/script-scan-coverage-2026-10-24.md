# Measurement: script-scan coverage on the benign corpus (S0), 2026-10-24

**Task:** `tasks/script-scan-coverage.md`, S0.
**Corpus:** `C:\Temp\silvergun-corpus\` (100 `.nupkg`, as for ADR-0033 T6).
**Method:** the real `NuGetPackage.Open` + `ScriptRuleScanner`, run from a snapshot of `src/` (`C:\Temp\sg-s0`,
removed afterwards), 3 runs. Raw data: the scratchpad's `s0-*.tsv`/`s0-summary.md`. Benign inputs only.

## Results

- **Coverage:** 100/100 packages opened. 46 have at least one script.
  - 87 scripts (77 `.targets`, 7 `.props`, 3 `.ps1`) plus 100 nuspecs = 187 files, **all scanned**.
  - 50 findings, on 47 files. The outcomes were identical across 3 runs.
- **Failure paths F1–F7: 0 packages, 0 files.** Gating `--strict` on `ScriptScanStatus.Unavailable` would fail
  **0/100** benign packages.
- **Size:** max 18,507 B (the AWSSDK `.ps1` files), p99 18,487, p95 5,900, p50 1,352. The 5 MiB cap is 283× the
  benign max.
- **Scan time (read + redact + engine):** 738 ms for all 187 files on the first pass.
  - **Corrected by S3:** the S0 "slowest" figure, 68 ms for `coverlet.collector.targets`, was first-use regex
    compilation (regexes are built lazily on first match), not content. Warm, that file takes 4.8 ms.
  - **The real warm slowest** are the 18 KB AWSSDK `.ps1` files, at about 20–22 ms (about 1.1 ms/KiB); the
    warm per-file median is about 1.7 ms.
  - At about 1.1 ms/KiB, a 5 MiB file would take roughly 6 s. That is unmeasured.

## RulesEngine 1.10.2 has no regex match timeout (read from source at the shipped commits; confirmed at runtime)

The shipped commits are RulesEngine/Common `1.10.2+331cf113a7` and OAT `1.2.95+f9d206dda7`.
- `regex`/`regexword` patterns become `OatRegexWithIndexClause`; `AppInspector.Common/Utils.cs:23,33` calls
  `new Regex(built, options)` with **no timeout**.
- NonBacktracking applies only when a rule has the `"nb"` modifier (`Utils.cs:117-121`). None of our embedded rules
  use it.
- Nothing catches while matching: `OatRegexWithIndexOperation.GetMatches` (L163-183), the OAT `Analyzer` capture
  path, and `RuleProcessor.AnalyzeFile`/`AnalyzeTextContainer`.
- **Runtime check:** all 31 compiled regexes have an infinite `MatchTimeout`, none NonBacktracking, and the
  `REGEX_DEFAULT_MATCH_TIMEOUT` AppContext value is null.
- **Consequence:** pathological input would make the script scan **hang**, unbounded CPU in-process. If a timeout
  were ever in force, `RegexMatchTimeoutException` would propagate out of `AnalyzeFile`, so our catch would mark
  the whole file unscanned (F5) and drop the matches already found in that file.
- **Not measured adversarially** (out of scope for agent work; see the task file).
