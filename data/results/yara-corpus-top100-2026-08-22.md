# YARA at scale — ADR-0028 validation and the first real prevalence row (top-100, 2026-08-22)

Raw data: `yara-corpus-top100-2026-08-22.tsv` (100 rows, 21 columns).
Spec: `docs/agent/tasks/yara-corpus-validation-run.md`. Commit under test: **`cc8e6da`**.
Companion: `scan-package-prevalence-top100-2026-08-21.md` (M2 — same corpus, YARA backend broken).

## What this run settles

1. **ADR-0028 holds at n=100, not just n=1.** 100/100 packages report
   `YaraScanStatus = Completed`; **zero** `YARA scan TIMED OUT`; **zero** `YARA scanning UNAVAILABLE`;
   300/300 child processes exited inside {0, 3} with a report written; zero kills, zero missing reports.
   Every YARA-on child logged `Compiled 309 embedded YARA rule file(s)` (200/200) and
   `Dropped 1 … virus.Linux.Virus.Vit.yara` — the documented ELF-module gap, and no other compile count
   anywhere. The `--no-yara` arm logged **no** compile line at all, so the baseline arm is a real baseline.
2. **The YARA prevalence row, measured for the first time: `0 / 100`.** Zero findings over
   **2,277 scanned files**. Three previous attempts had to record "not measured" — first the AnyCPU
   load failure, then the poisoned compiler.
3. **The zero is real, not a fourth silent failure.** A synthetic positive control (inert byte
   patterns satisfying `Win32_Trojan_TrickBot`'s condition, packed into a `.nupkg`, scanned with **the
   same binary**) returned `Completed` with **1 finding, `RuleName = Win32_Trojan_TrickBot`**. This
   distinction is the whole point: a feature that has silently reported zero twice does not get to
   report zero a third time without proof it can report non-zero.
4. **Cost of YARA: ≈ 800 ms fixed + ≈ 4 ms/file.**

## Cost — and why the obvious table is wrong

The naive per-package delta (`yara-on` − `yara-off`) gives median 597 ms / max 8,918 ms, with **27 of
100 packages negative**. It is noise. The two *identical* YARA-on passes differ by median 222 ms /
max 8,282 ms — the same magnitude, with no YARA component whatsoever. Pass ordering (cold → warm disk
cache) and OSV network variance dominate. Re-aggregated independently by the architect from the TSV:
`on1−off` median 596, min −6,594, max 8,918; `on1−on2` median 220, min −3,279, max 8,282. Confirmed.

The interpretable number comes from an interleaved A/B (same binary, `--no-vulns`, 5 iterations per
arm alternating so cache warmth cannot bias one arm), 6 packages spanning 7–253 files:

| Package | files | median Δ ms |
| --- | ---: | ---: |
| xunit | 7 | 834 |
| Moq | 11 | 745 |
| StackExchange.Redis | 21 | 1,004 |
| Newtonsoft.Json | 24 | 976 |
| coverlet.collector | 160 | 1,339 |
| Microsoft.Extensions.ApiDescription.Server | 253 | 1,915 |

All six positive and tight ⇒ **≈800 ms fixed + ≈4 ms/file**. The fixed part is corroborated from the
children's own log timestamps: the ADR-0028 two-pass validation took 0 s in 14, 1 s in 80 and 2 s in 6
of the 100 pass-1 children, matching the ADR's stated ~1 s once per process.

**Lesson worth carrying:** the pass-to-pass noise floor was as large as the effect. Any future A/B on
this corpus must interleave arms; sequential passes cannot resolve anything under ~8 s.

## Determinism

Zero differences across 19 non-timing fields × 100 packages between the two YARA-on passes — including
the vulnerability columns, which were *allowed* to differ (OSV is point-in-time, ADR-0017) and did not.
The comparator was mutation-checked: pointed at the `--no-yara` arm instead, the same code reports
100/100 packages differing on `YaraScanStatus`. So "0 diffs" is falsifiable, not vacuous.

## Comparability with M2, and one exit-code change that is not a regression

Every non-YARA column reproduces M2 exactly: capability 67/100, obfuscation 29/100, `Source=Script`
25/100, `Source=PackageMetadata` 1/100 (`Microsoft.Extensions.Hosting`, same package), gating
indicators 0/100, vulnerabilities 0/100 with 100/100 `Completed`, same 19 zero-assembly packages.

Exit codes are **95 × 0, 5 × 3** (no code 2), where M2 saw 24 / 72 / 4. That is ADR-0027 narrowing
`--strict`, not new breakage. The fifth exit-3 package, `Microsoft.Extensions.ApiDescription.Server`,
was already incomplete in M2 (`1 of 232 file(s) could not be analysed: tools/net10.0/GetDocument.Insider.exe`);
M2 reported it as 2 because the old broad gate outranked the incompleteness code. With the gate
narrowed, the pre-existing incompleteness surfaces. **Under the narrowed gate, this corpus produces a
0 % benign failure rate** — against 72 % before.

## What this does NOT establish

The corpus is **benign**. This measures the **false-positive rate (0/100)** and the **cost**. It says
nothing about **detection rate**, which needs a malicious corpus (parked initiative). Together with
the positive control it establishes that the engine *can* match and is *quiet on benign input* — one
column of a confusion matrix, not the matrix. `0/100` is a licence to keep YARA as a `--strict` gating
source, not evidence that it catches anything real.

## Gap this run exposed → routed

**No automated test asserts the in-process engine can produce a match.** `LibYaraScannerPoisoningTests`
covers ruleset validation, engine build, canary health and scan timing; `YaraScannerTests` can only
pin `Available == false`. The single check that would have caught *both* historical failures early —
feed the engine something a rule matches, assert a finding — exists only as the ad-hoc positive control
above. This is the [[inert-guard-defect-class]] pattern again: a suite that is green whether or not the
feature works. Routed as a follow-up test task.

## Provenance

`FilesScanned` = file entries in the `.nupkg` archive (the report exposes no scanned-file count). Exact
for this corpus: no package contains a nested archive (checked for `.zip/.nupkg/.tar/.gz/.tgz/.7z/.rar/
.jar/.cab/.msi/.vsix`), so RecursiveExtractor produced no extra files. Median 18, max 253, total 2,277.
Build: `dotnet build src/Silvergun.CLI/Silvergun.CLI.csproj -c Release -f net10.0-windows -r win-x64`,
run from `bin/Release/net10.0-windows/win-x64/` — **per-RID, as ADR-0016 requires**; an AnyCPU build
silently disables the backend. Corpus: the 100 `(Id, Version)` pairs from
`scan-package-prevalence-top100-2026-08-21.tsv`, all present in the warm cache, **zero downloads**.
1.2 s between packages; no 429, no 403, no network degradation on any child's stderr.
