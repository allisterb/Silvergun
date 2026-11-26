# Linux gate: the YARA-X worker vs the yara CLI backend, WSL2 (2026-11-24)

Spec: `docs/agent/tasks/yarax-worker-linux.md`, "Phase 3: the Linux gate". Windows counterpart:
`yarax-worker-gate-2026-10-22.md`. Raw per-package data: `yarax-worker-gate-linux-2026-11-24.tsv` (100 rows). Commit
under test: **`a4cd3c4`** (Phase 2, the Linux rules cache). This file reports facts; the decision is the user's.

**Environment.**
- Host: WSL2, kernel 6.18.58.1-microsoft-standard-WSL2, 8 cores.
- CLI: `Silvergun.CLI` built `-c Release -f net10.0` in the WSL mirror (`~/silvergun-wsl`), with YARA-X 1.22.0
  (`libyara_x_capi.so`, Silvergun's CI build).
- Baseline: `yara`/`yarac` 4.1.3.
- Driver: an ad hoc Python script, run once. It gave every CLI run its own `TMPDIR`, and all runs shared one private
  `XDG_CACHE_HOME` that was empty at the start. Total 840 s.

**Configurations.**
- **(a)** `SILVERGUN_YARA_ENGINE=yarax`, `SILVERGUN_YARA_PATH` unset: `YaraXWorkerScanner`. With the engine unset, the
  default backend here is Null, so a `Completed` in (a) can only have come from the worker.
- **(b)** `SILVERGUN_YARA_PATH=/usr/bin/yara`: `YaraCliScanner`, today's Linux default.
- Both ran `scan-package <nupkg> --json --no-vulns --allow-incomplete --debug --output <file>`, with a 300 s bound.

**Corpus.** The same 100 packages as the Windows gate (`C:\Temp\silvergun-corpus\`, from nuget.org; provenance in
`benign-corpus-top100-2026-08-21.md`), in sorted order, with (a) and (b) alternating first.

**Conventions.** Median is `statistics.median`. p90 is nearest rank. Wall time is the whole `scan-package` process,
so it includes IL analysis, extraction and script scanning.

## Headline

| | (a) YARA-X worker | (b) yara CLI 4.1.3 |
| --- | ---: | ---: |
| `YaraScanStatus` = `Completed` | **100 / 100** | **100 / 100** |
| YARA findings | **0** | **0** |
| Exit code | 0 × 100 | 0 × 100 |
| Timeouts, crashes, missing reports | 0 / 0 / 0 | 0 / 0 / 0 |
| Wall time per package, median / p90 | **4,226 / 6,935 ms** | **2,622 / 5,030 ms** |
| Mean / min / max | 4,696 / 3,073 / 11,449 ms | 3,086 / 1,619 / 9,100 ms |
| Sum over 100 packages | 469.6 s | 308.6 s |
| Worker processes alive after any run | 0 (checked after each of the 200 runs) | 0 |

**Per package, (a) − (b):**
- median **+1,505 ms**, p90 +2,056 ms;
- min +1,053 ms, max +3,811 ms;
- (a) was slower on all 100 packages.

Status and rule sets agree on 100/100 packages: all `Completed`, all empty.

## Evidence that the backends ran as configured, and the cache was used

These counts come from the CLI's file log (`bin/Release/net10.0/Silvergun-CLI20261124.log`); the run's log level was Debug.

`--debug` does not reach stderr when `--output` is given: the console sink goes to stdout, which the driver discarded.
So the TSV's `A_WorkerCompiled`, `A_WorkerFromCache`, `A_CacheWarnings` and `*_WrnErrLines` columns are 0 and carry no
information. Read these counts instead.

- **(a)** The relayed worker lines say `ready with 1240 rules (compiled)` **once**, at 20:58:22: the first package's
  probe, into the empty cache. They say `ready with 1240 rules (from the rules cache)` **205** times. That is 199 worker
  starts in G1 (2 per package, less the compile), plus 6 in G2. `YARA-X rules cache` warnings: **0**.
- **(b)** `Compiled 310 embedded YARA rule file(s) with yarac` appears 104 times over 103 runs. The extra one is
  `Gate.Newline`: `YaraCliScanner` compiles a second time for its separate pass over unsafe file names (ADR 0029).
- **The cache entry** was written once, at 20:58:22.88, and never rewritten. Every compile stores a new entry.

## Where the +1.5 s comes from

Each `scan-package` in (a) starts two workers: the availability probe, then the scan. G4 measures one worker's start
to `ready` on the warm cache at a median of **847 ms**, 733 ms more than `--help`. Two worker starts are therefore ~1.5
s, which is the measured difference. (b) pays one `yarac` compile of 310 rule files per package, and on this host that
costs less.

On Windows the same comparison was +458 ms. There the baseline (libyara in-process) also compiled 309 files per
package; on Linux the `yarac` baseline is cheaper than that.

**Pre-registered expectation 3 ("(a) faster than (b) on Linux") was wrong.**

## G2: positives and Linux path names

The sample is the HermeticWiper positive control: an `MZ` prefix plus the rule's `$corrupt_physical_drive` hex string,
with `??` rendered as 0x00 (625 bytes). It is derived from the rule at run time, as
`tests/.../HermeticWiperSample.cs` does. It is inert, not a PE, and was written only under `/tmp`.

| Package | Entry (as zipped; `\u` escaped) | (a) hit, namespace, path | (b) hit, namespace, path |
| --- | --- | --- | --- |
| Gate.Positives | `lib/net8.0/plain.bin` | HermeticWiper, `default`, same | HermeticWiper, none, same |
| | `lib/net8.0/back\slash.bin` | HermeticWiper, `default`, **`lib/net8.0/back/slash.bin`** | same as (a), no namespace |
| | `lib/net8.0/\u00fcn\u00ef\u00e7\u00f8d\u00e9-\u6837\u672c.bin` | HermeticWiper, `default`, same | HermeticWiper, none, same |
| | `content/a/b/c/d/e/f/g/h/deep.bin` | HermeticWiper, `default`, same | HermeticWiper, none, same |
| Gate.Newline | `lib/net8.0/nl\nname.bin` | HermeticWiper, `default`, `lib/net8.0/nl\nname.bin` (escaped) | same as (a), no namespace |
| Gate.Negatives | `mz_only.bin`, `empty.bin` | none | none |
| Gate.Negative2 (re-run) | `flipped-literal.bin`: the first literal pattern byte flipped | none | none |

- **(rule, path) agree on every package.** Every scan was `Completed`, and both backends exited 0.
- **Namespace:** `default` in (a) and none in (b), as on Windows.
- **Backslash:** both backends report `back/slash.bin`. Extraction turned the `\` into a directory separator before
  either scanner saw the file; the Linux worker never receives a backslash name from a package. This is the extractor's
  behaviour and is the same for both backends.
- **Newline:** both backends hit, and the path is escaped in the report (ADR 0031). Pre-registered expectation 4
  allowed for a difference here; there is none.
- **Driver error, corrected:** the first run's `flipped.bin` negative flipped byte 312, which is a `??` wildcard in the
  rule. It was still a valid positive, and both backends hit it. The re-run flipped byte 2, a literal, and both
  backends found nothing.

## G3: large file (worker started directly, protocol v1, `--timeout 30`, warm cache)

| File | Size | Scan ms, runs 1 / 2 / 3 | Status |
| --- | ---: | --- | --- |
| sparse, all zeros | 2,147,483,648 B (2 GiB; memory-mapped) | 5,319 / 4,124 / 4,059 | scanned, 0 hits ×3 |
| sparse, all zeros | 2,147,483,591 B (`Array.MaxLength`; one array) | 7,193 / 5,377 / 4,973 | scanned, 0 hits ×3 |

- All 6 finished well inside the 35 s backstop, and no worker was left afterwards.
- The same limit as Windows applies: the files are sparse zeros, a best case. Both were deleted.

## G4: worker start cost (N = 10, warm cache)

| | median | p90 | min | max |
| --- | ---: | ---: | ---: | ---: |
| start → `ready` | **847 ms** | 979 | 810 | 1,333 |
| `--help` (.NET start baseline) | 114 ms | 115 | 114 | 165 |

Compare Phase 2's measurement with no cache: start → `ready` 2,343 ms (Debug build). The cache saves about 1.5 s per
worker start on Linux. This is the Phase 2 number that had not been measured.

## G5: hygiene and cache state

- **Workers:** 0 alive at the start, after each of the 206 CLI runs, after each G3/G4 worker, and at the end.
- **Cache directory:** `…/xdg/silvergun/yara-x-rules` is 0700, and its created parent `…/xdg/silvergun` is 0700.
  It holds one entry (`rules-1.22.0-52f6ba0e….sgyx`), which is 0600, a regular file, with nlink 1, 2,357,114 bytes.
  There are no `*.tmp` files.
- **Temp:** each run's `TMPDIR` holds exactly one entry afterwards, the empty `silvergun/` parent of the per-package
  `pkg-*` extraction directory (`NuGetPackage.cs`). It is the same in (a) and (b). Every `pkg-*` directory was removed;
  nothing else was left.

## Pre-registered expectations, resolved

1. 100/100 `Completed` and 0 findings in both: **confirmed.**
2. One compile, then everything from the cache: **confirmed.** 1 compile and 205 cache loads; that is 199 in G1, as
   predicted, plus 6 in G2.
3. (a) faster than (b): **wrong.** (a) is +1.5 s per package, explained by two worker starts against one cheap `yarac`
   compile.
4. G2 agreement: **confirmed**, including the newline name.
5. G3 in ~6 s: **confirmed** (4–7 s).
