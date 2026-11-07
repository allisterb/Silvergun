# D-measure: does the ADR-0032 d9 coverage sentinel flip benign packages? (top-100, Linux CLI backend, 2026-10-19)

Raw data: `yara-cli-coverage-sentinel-2026-10-19.tsv` (100 rows). Spec: `docs/agent/tasks/yara-partial-findings.md`,
Round D, "D-measure". ADR: `0032-yara-findings-survive-an-incomplete-scan.md` d9. The previous run being repeated:
`yara-cli-stderr-errors-2026-10-19.{md,tsv}` ("pre-D", Round C tree, no d9). Same method, corpus, environment and
command line.

**What d9 changed.** The batch `yara -r` pass now carries a `condition: true` rule,
`SilvergunCoverageSentinel_<32 hex>`, with a fresh random suffix per ruleset. yara prints one sentinel line for every
file it actually scanned. Any attributable file without one is "uncovered":
- It is logged (`YaraCliScanner.cs:502`) and re-scanned on its own (`:554`).
- If more than `MaxIndividualScans` = 64 are uncovered, or the 65 s recovery budget runs out, the package is
  `Unavailable`, and every hit found is carried.

## Headline

**0 `YaraStatus` changes out of 100, and 0 packages with any uncovered file.** All 100 are `Completed` with 0 findings
and exit 3, both pre-D and now.
- The batch pass printed a sentinel line for every attributable file of every package.
- No package entered the individual pass.
- The largest package, `Microsoft.Extensions.ApiDescription.Server` (253 files), had 0 uncovered.

**The sentinel path fires in this exact build.** Two positive controls, both below:
- The real CLI with an unreadable file: uncovered 1 → re-scan fails → `Unavailable`, hit kept, `--strict` → 2.
- The real `YaraCliScanner` over real yara pushed past its global deadline: uncovered 8–178. The result was either full
  recovery (`Completed`, 20/20 hits) or `incomplete` with hits carried. It was never `Completed` with hits missing.

| | Count |
| --- | ---: |
| Packages run / pre-D rows | 100 / 100 |
| `YaraStatus` changes (all `Completed` → `Completed`) | **0** |
| `YaraFindingCount` changes (all 0 → 0) | 0 |
| Exit-code changes (all 3 → 3) | 0 |
| Packages with uncovered files (`printed no coverage line for N of M`) | **0** (sum 0) |
| Packages that entered the individual pass (`… were not covered by the recursive pass`) | 0 (0 re-scans) |
| d7 stderr `error` lines / d17 unattributable-hit guard | 0 / 0 |
| Sentinel name in any report JSON, stdout or stderr | 0 |
| Timeouts (300 s), crashes, missing reports | 0 |
| Backend proven `YaraCliScanner`, `Compiled 310 … with yarac` logged exactly once | 100 |

Rule of three: 0/100 bounds the benign flip rate below about 3% at 95% confidence. That is a population bound, not a
per-package proof.

**Why "0 uncovered" is not vacuous.** These three checks together rule out a missing or disabled sentinel:
1. If the sentinel were missing or never printed, *every* attributable file would be uncovered and logged. That is
   2,277 files, not 0.
2. After the run, every one of the 100 `/tmp/silvergun-yara-*` rulesets the corpus children created was inspected.
   Each held exactly one `rule SilvergunCoverageSentinel_<32 hex> { condition: true }`, with 100 distinct names.
3. The driver's regex for the uncovered warning matches the CLI's real `[WRN]` output. Positive control 1 shows it
   matching through the same CLI build, same flags, same capture.
"Compiled … with yarac" logged exactly once per child also confirms no child prepared the plain (individual-pass)
ruleset.

## Changes explained

None. The TSV `Note` column is empty on all 100 rows, and `Uncovered` and `IndividualRescans` are 0 on all 100. The
only stderr lines in the whole run were the expected completeness caveats, identical to pre-D:
- 95 × `the known-vulnerability check did not run`, a consequence of `--no-vulns`;
- 5 × the same caveat plus the 7 known native files that cannot be analysed (the SqlClient SNI packages and
  `GetDocument.Insider.exe`).

Why this result is expected:
- A benign NuGet tree is read in well under the 60 s global deadline. The slowest whole-package child took 10.6 s,
  including IL analysis and rule compilation. Raw `yara -r` over the 253-file package takes about 0.44 s (see Timing).
- Extracted files are readable by construction, so yara examines every file and prints its sentinel line.
- Benign packages contain no links, control-character names or echo collisions here (0 entered the individual pass),
  so nothing is deferred or refused.

## Positive controls

### 1. Real CLI, chmod-000 (re-run of the C-measure d7 control). Now also exercises d9

This uses the same construction as C-measure (`SgProbe.D7Control 1.0.0`, built with Python `zipfile`):
- `content/payload.bin`: 625 bytes, `MZ` plus `$corrupt_physical_drive` from the embedded `Win32_Trojan_HermeticWiper`
  rule, read at run time. Same derivation as `tests/…/HermeticWiperSample.cs`.
- `content/locked.txt`: benign text.
- `lib/net6.0/Newtonsoft.Json.dll`, copied from the corpus.

A poller ran `chmod 000` on `locked.txt` inside the CLI's own `/tmp/silvergun/pkg-*` extraction, 476 ms and 629 ms
after launch. It then re-opened the file and got `PermissionError` (uid 1000, not root-equivalent). Same CLI binary,
env and command line as the corpus.

| Run | Exit | `YaraScanStatus` | `YaraFindings` | d7 error line | d9 uncovered | Individual re-scans |
| --- | ---: | --- | --- | --- | --- | --- |
| NC: no chmod | 3 | `Completed` | 1: `Win32_Trojan_HermeticWiper` @ `content/payload.bin` | none | none | 0 |
| PC: `locked.txt` mode 000 | 3 | **`Unavailable`** | 1: same hit, **kept** | 1 | **1 of 4** | 1, failed (yara exit 1) |
| PC + `--strict` | **2** | `Unavailable` | 1: same hit | 1 | 1 of 4 | 1, failed |

The PC log lines, as the CLI printed them (paths already escaped by `YaraPathSafety`; package path shortened here):

```
[WRN] YARA: the recursive pass over /tmp/silvergun/pkg-dp52wxx19ojz exited 0 but reported 1 error line(s), so at least one file under it was not scanned. Line(s), control characters escaped: 'error scanning /tmp/silvergun/pkg-dp52wxx19ojz/SgProbe.D7Control.1.0.0.nupkg/content/locked.txt: could not open file'
[WRN] YARA: the recursive pass over /tmp/silvergun/pkg-dp52wxx19ojz exited 0 but printed no coverage line for 1 of 4 file(s), so it did not scan them (its --timeout is one deadline for the whole run, and files still queued when it passes are skipped silently); they are re-scanned individually. Path(s), control characters escaped: 'SgProbe.D7Control.1.0.0.nupkg/content/locked.txt'
[WRN] YARA scan of /tmp/silvergun/pkg-dp52wxx19ojz/SgProbe.D7Control.1.0.0.nupkg/content/locked.txt failed: yara exited with code 1: 'error scanning …/content/locked.txt: could not open file'
[WRN] YARA scan INCOMPLETE for SgProbe.D7Control: YARA could not scan 1 of 1 file(s) that its recursive pass did not cover (…) Path(s), control characters escaped: 'SgProbe.D7Control.1.0.0.nupkg/content/locked.txt'. YARA's recursive pass … reported 1 error line(s) … 1 match(es) found in the files that were scanned are reported; …
```

What this shows:
- **The d7 path still works.** The error line was seen, and the package became `Unavailable` with the hit kept.
- **d9 sees the same file independently:** no sentinel line, one bounded single-file re-scan, which fails closed on yara
  exit 1.
- In the PC runs, `Compiled 310 … with yarac` is logged twice: the batch ruleset, then the plain one for the individual
  pass. In the NC run it is logged once.
- The sentinel name appears in no output.
- stderr carried the ADR-0032 advisory (`YARA malware-signature scanning did NOT complete; 1 match(es) were found …`)
  and the caveat `the YARA malware-signature scan did not complete`. NC printed neither.

### 2. Global-deadline drop (the d9 case proper). Harness route, real yara

**Option A was not reachable.** The CLI exposes no YARA timeout knob: `YaraScannerFactory` constructs
`new YaraCliScanner()`, which uses `DefaultScanTimeoutMs` = 60 000, i.e. yara `--timeout=60`. To make a real package
hit that deadline, the batch pass would need more than 60 s of yara work:
- Measured with the run's own compiled batch ruleset and production flags, 16 MiB of each of 15 fills (random, zeros,
  `MZ`, `http://`, UTF-16, `%`, `\`, …) scans at **75–390 MiB/s per thread** on 8 CPUs.
- `yarac` reports no slow-scanning strings in the embedded rules.
- At that rate 60 s means tens of GB. The extractor caps a package at 2 GiB and a 200× deflate ratio.
- A synthetic-package driver was prepared (`dm_pc_d9.py`) but not run, for that reason.

So, as the dispatch allows, the fallback is a harness hosting the real `YaraCliScanner` with a short timeout, over real
`/usr/bin/yara` 4.1.3 and `yarac`. Both harnesses were built from the **same WSL copy** as the CLI:
- **FakeYaraProbe `--scan-directory … --timeout-ms 1000`**, built from the copy's `tests/` snapshot. That snapshot
  predates the test-engineer adding `partial=`/`partialhits=` output, so it reports outcome and message only.
- **The D-impl demo harness** (scratchpad `dharness/Program.cs`, outside the repo, built against the copy's
  `src/Silvergun.PackageAnalysis.NuGet`). It prints the scanner's warnings and the carried `PartialFindings`. The counts
  below come from it.

Tree: N × 4 MiB random `content/bulkNNNN.bin` plus 20 payloads `content/pNN.bin`, each the 625-byte HermeticWiper
sample. `--timeout-ms 1000` gives yara `--timeout=1`, which in `-r` mode is one whole-second global deadline.

| Tree (files) | Timeout | Outcome | Hits returned / carried | Uncovered (of M) | Individual targets | Unrecovered | stderr `error` lines |
| --- | --- | --- | ---: | --- | ---: | --- | ---: |
| 220 | 60 s (negative control) | completed | 20 | — | 0 | — | 0 |
| 220 | 1 s, t0 | **incomplete** | 9 | **178** of 220 | 178 | 114 (64 re-scanned) | 0 |
| 220 | 1 s, t1 | **incomplete** | 10 | **158** of 220 | 158 | 94 (64 re-scanned) | 0 |
| 220 | 1 s, t2 | **incomplete** | 16 | **111** of 220 | 111 | 47 (64 re-scanned) | 0 |
| 140 | 60 s (negative control) | completed | 20 | — | 0 | — | 0 |
| 140 | 1 s, t0 | **incomplete** | 14 | **101** of 140 | 101 | 37 (64 re-scanned) | 0 |
| 140 | 1 s, t1 | **completed (recovered)** | **20** | **8** of 140 | 8 | 0 | 0 |
| 140 | 1 s, t2 | **incomplete** | 15 | **99** of 140 | 99 | 35 (64 re-scanned) | 0 |
| 80 | 60 s / 1 s × 3 | completed | 20 | — (deadline not reached) | 0 | — | 0 |

- **Invariant held 16/16 (dharness) and 8/8 (FakeYaraProbe):** never `completed` with fewer than 20 hits. Every
  carried hit is `Win32_Trojan_HermeticWiper`, and 0 sentinel records appear among hits or partial findings.
- **Both outcomes the spec names were observed:**
  - recovery to `Completed` with every hit (8 uncovered, all re-scanned);
  - `Unavailable`-equivalent (`YaraScanIncompleteException`) with the found hits carried, when the uncovered count
    exceeded `MaxIndividualScans` = 64. Exactly 64 were re-scanned each time; the rest were counted unrecovered.
- FakeYaraProbe, same 140-file shape:
  - 1 s trials: `incomplete` "could not scan 17 of 81" and "8 of 72" (64 re-scanned each), and one `completed hits=20`;
  - the 60-file tree and both default runs: `completed hits=20`.
- **0 stderr `error` lines in every deadline run.** That is ADR-0032 d9's premise reproduced: the d7 check alone sees
  nothing here, and the sentinel is what catches it.

## Timing

**Per-package wall time vs pre-D** (same corpus, machine, CLI flags; `ElapsedMs` vs `PreDElapsedMs` in the TSV):

| | D (now) | Pre-D |
| --- | ---: | ---: |
| Median per package | 2,883 ms | 3,424 ms |
| Min | 1,628 ms | 1,675 ms |
| Max | 10,635 ms | 11,355 ms |
| Sum of children | 365 s | 422 s |
| Driver wall clock | 368 s | 428 s |

Per-package ratio now/pre-D:
- median **0.86×** (p10 0.63, p90 1.15, range 0.40–1.64);
- 77 faster, 23 slower; 8 above 1.2×, 3 above 1.5×.

The slowest-relative packages are small: `Grpc.Net.Common`, 21 files, 1.64×; `OpenTelemetry`, 27 files, 1.57×;
`Serilog.AspNetCore`, 19 files, 1.55×. The five packages with ≥40 files have a median of 0.92×, and the largest
(253 files) took 10,371 vs 11,234 ms.

So the variation tracks machine load, not file count. The 1-minute load average before each child had a median of 1.9
(range 1.4–3.6), and a concurrent test-engineer was using the machine. **No regression is attributable to d9.**

**The sentinel's own cost, isolated.** Raw `yara -r -s -g -C -N --timeout=60` was run over extracted corpus trees, 7
alternating reps each. The rulesets were the run's batch ruleset and the same source with only the sentinel rule
removed, both freshly compiled with `yarac`:

| Package (files) | Plain median | Sentinel median | Sentinel lines / files |
| --- | ---: | ---: | --- |
| `Microsoft.Extensions.ApiDescription.Server` (253) | 419 ms | 439 ms | 253 / 253 |
| `coverlet.collector` (160) | 232 ms | 234 ms | 160 / 160 |
| `Microsoft.Data.SqlClient` (67) | 149 ms | 152 ms | 67 / 67 |

Each sentinel delta (≤20 ms) is inside that pair's own min–max spread (e.g. 370–1,021 ms for plain on the 253-file
package). The batch pass prints one extra stdout line per file, and on benign input that is the whole cost.

## Other observations (none caused by d9; already queued)

- **`/tmp` leak:**
  - The corpus children created 100 new `/tmp/silvergun-yara-*` dirs, one per run, each ~7.5 MB, 750 MB in total.
    Each holds only the batch ruleset; none needed the plain one.
  - With the controls, D-measure added **135** dirs, about 1.0 GB.
  - 715 such dirs already existed before this run (earlier runs and test suites), so 850 are present now.
  - The PC runs confirm the D-impl note: a scanner that enters the individual pass leaks **two** dirs (batch + plain).
- **Cosmetic:** the doubled period (`…could not open file'.. 1 match(es)…`) is still in the `PackageScanner` incomplete
  log line.
- `/tmp/silvergun/pkg-*` extraction dirs: 0 left.

## Provenance

- **Corpus:**
  - `C:\Temp\silvergun-corpus\`: the same 100 `.nupkg` re-acquired for C-measure on 2026-10-19 (see
    `yara-cli-stderr-errors-2026-10-19.md` for fetch provenance, request counts and integrity checks).
  - **Not re-downloaded.** No network access in this run.
  - Read from WSL as `/mnt/c/Temp/silvergun-corpus/`. All 100 were present.
  - Package list and order come from the pre-D TSV.
  - File counts (`Files` = `.nupkg` file entries) equal the 2026-08-22 baseline `FilesScanned` on 100/100; total 2,277,
    max 253.
- **Licence:** the packages are third-party works under their own licences. Nothing from them is committed, and these
  files hold derived counts only.
- **Code under test:**
  - HEAD `f348d51` plus the uncommitted working tree as of **2026-10-19T05:09:48Z**. The fingerprint was taken at
    05:09:48.6Z, and the tar was taken 05:09:49–05:10:05Z.
  - `git diff HEAD --binary` SHA-256 `01dbfc36…8dece` (175,569 bytes); its `src/` part `9f84e76c…bab21` (105,680
    bytes).
  - `git diff --stat HEAD -- src` at copy time: 13 files, +629/−235:

    ```
    src/Silvergun.CLI/Program.cs                       |  12
    src/Silvergun.CLI/Reports/PackageReportRenderer.cs |  21
    src/Silvergun.Intel/Silvergun.Intel.csproj         |   5
    …/PackageModel.cs                                  |   5
    …/PackageScanner.cs                                |  80
    …/Silvergun.PackageAnalysis.NuGet.csproj           |  13
    …/Yara/IYaraScanner.cs                             | 150
    …/Yara/LibYaraScanner.cs                           |  91
    …/Yara/YaraCliScanner.cs                           | 357
    …/Yara/YaraOptions.cs                              |   4
    …/Yara/YaraPathSafety.cs                           |  28
    …/Yara/YaraScanIncompleteException.cs              |  64
    …/Yara/YaraScanStatus.cs                           |  34
    ```
  - This is Round D (d9): `YaraCliScanner.cs` has the sentinel (`:55`, `:412–429`, `:501–503`, `:839–846`).
- **`src/` stability:**
  - **`src/` did not change during the run.** The SHA-256 of all 15 `Yara/*.cs` files plus `PackageScanner.cs` is
    identical at copy time and at end (2026-10-19T05:26:52Z). Examples: `YaraCliScanner.cs` `8436cdf3…a89af2`,
    `PackageScanner.cs` `2b9cd53a…78bd5`.
  - The `src/` aggregate over 125 files was `9e4cc4c7…edb` for the live tree at copy time, for the WSL copy, and for
    the live tree at the end.
  - A byte-compare of copy vs live at the end shows `src/`: 0 differences; `ext/analysis-net`: 0.
  - `tests/` differs, as expected from the concurrent test-engineer: 6 files changed and 4 new
    `…CoverageSentinel…Tests.cs`. Only the FakeYaraProbe harness build used `tests/`, and only from the copy-time
    snapshot.
- **Build:**
  - The tree was tar-copied (excluding `.git`, `reference`, `bin`, `obj`, `.vs`, `TestResults`) to the new dir
    `~/sg-adr0032-measure-d`. `~/sg-adr0032-measure` was not touched, and nothing was
    built under `/mnt/c`.
  - `dotnet build src/Silvergun.CLI/Silvergun.CLI.csproj -c Release -f net10.0`: 0 errors, 5 warnings (all `ext/` or
    SourceLink).
- **Environment:** WSL2 Ubuntu, kernel 6.18.54.1, 8 CPUs, .NET SDK 10.0.103, `yara`/`yarac` **4.1.3** (`/usr/bin`),
  uid 1000 (not root). `SILVERGUN_YARA_PATH=/usr/bin/yara`; `SILVERGUN_YARAC_PATH` unset (derived).
- **Run:**
  - One child per package from `python3 -I`, with a 300 s process-group kill bound.
  - Command: `scan-package <nupkg> --json --depth 0 --no-vulns --output <file>`.
  - Start 2026-10-19T05:12:18Z, 368 s.
  - Per-package uncovered and individual-pass counts are parsed from the CLI's `[WRN]` lines (`YaraCliScanner.cs:502`,
    `:554`, `:598`).
  - `IndividualRescans` = individual-pass targets minus link refusals when the pass did not overflow. On overflow it
    would be written `<= min(targets, 64)`; that never occurred.
- **Scripts (scratchpad):**
  - `dm_codestate.py`, `dm_wsl_build.ps1`: fingerprint, copy, build.
  - `dm_run.py`, `dm_compare.py`, `dm_timing.py`: corpus run and comparison.
  - `dm_tmpcheck.py`: per-ruleset sentinel check.
  - `dm_slow_probe.py`, `dm_slow_rules.py`: Option-A feasibility.
  - `dm_pc_d7.py`: control 1.
  - `dm_pc_harness.py`, `dm_dharness_build.ps1`, `dm_pc_dharness.py`: control 2.
  - `dm_sentinel_cost.py`: isolated cost.
  - `dm_treediff.py`, `dm_leftovers.py`: stability and cleanup checks.
  - Raw outputs are in `scratchpad/dm_run/`.
- **Git:** `docs/agent/*` is gitignored, so these two files do not show in `git status`.
- **TSV escaping:** the `Note` column would hold `;`-joined escaped log lines (ASCII-only, `\` → `\\`, `;` → `\x3b`,
  other non-printables → `\xNN`/`\uNNNN`). It is empty on all 100 rows.
