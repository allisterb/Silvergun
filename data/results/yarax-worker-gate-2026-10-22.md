# T6 gate measurement: YARA-X worker vs in-process libyara, Windows (2026-10-22)

Spec: `docs/agent/tasks/yarax-worker.md`, "T6 — the concrete measurement". ADR: `0033-yara-out-of-process-worker.md`
(FINAL FORM). Raw per-package data: `yarax-worker-gate-2026-10-22.tsv` (100 rows, one per package, both configurations
side by side). This file reports facts only; it makes no recommendation.

Configurations:
- **(a)** `SILVERGUN_YARA_ENGINE=yarax`: `YaraXWorkerScanner`, which runs `Silvergun.CLI __worker yara` children.
- **(b)** the default engine: `LibYaraScanner` (libyara.NET 4.5.5, in-process).

Conventions: **median** = `statistics.median`. **p90** = nearest rank, the ⌈0.9·N⌉-th smallest sample. Wall time is the
whole `scan-package` child process, start to exit, measured by the driver (`time.perf_counter`), so it includes IL
analysis, extraction and script scanning as well as YARA.

## Headline

| | (a) YARA-X worker | (b) libyara in-process |
| --- | ---: | ---: |
| Packages run | 100 | 100 |
| `YaraScanStatus` = `Completed` | **100** | **100** |
| YARA findings (packages with any) | **0** (0) | **0** (0) |
| Exit code (with `--allow-incomplete`) | 0 × 100 | 0 × 100 |
| Timeouts (300 s bound), crashes, non-JSON stdout | 0 / 0 / 0 | 0 / 0 / 0 |
| YARA `[WRN]`/`[ERR]` lines in the CLI log | 0 | 200 (2 per run: the Vit rule file dropped, see below) |
| Wall time per package, **median** | **3,545 ms** | **3,084 ms** |
| Wall time per package, **p90** | **6,616 ms** | **6,013 ms** |
| Mean / min / max | 4,087 / 1,867 / 15,016 ms | 3,611 / 1,409 / 14,969 ms |
| Sum over 100 packages | 408.7 s | 361.1 s |
| First package (AutoMapper; for (a) the cold rules compile into an empty cache) | 9,391 ms | 7,189 ms |
| Median / p90 excluding the first package | 3,543 / 6,616 ms | 3,082 / 6,013 ms |
| `Silvergun.CLI` processes alive after a run (checked after each of the 200 runs) | 0 | 0 |

**Per package, (a) − (b):** median **+458 ms**, p90 +607 ms, min +47 ms, max +2,202 ms (AutoMapper, the cold compile).
Ratio (a)/(b): median 1.16, p90 1.31. (a) was slower than (b) on all 100 packages. Status and rule sets agree on
100/100 packages (all `Completed`, all empty).

The smallest packages show the fixed cost most plainly. The 13 workload/SDK manifest packages ran 1,867–2,023 ms under
(a) and 1,433–1,584 ms under (b), a difference of 395–515 ms each. Under (a), each `scan-package` process starts
two workers, the availability probe and the scan (pinned by
`YaraWorkerVerbWindowsTests.ScanPackage_NeverLoadsTheYaraXDll_InItsOwnProcess`). Under (b), each process compiles
309 rule files in-process.

**Why (a)'s `Completed` can only come from YARA-X.** The (a) binary is a plain (RID-less) build, where the default
libyara engine is `Unavailable`. Measured on that same binary with the default engine (AutoMapper): `YaraScanStatus`
`Unavailable`, log `[WRN] YARA scanning UNAVAILABLE for AutoMapper: Could not load file or assembly
'C:\\Temp\\sg-t6\\cli-plain\\runtimes\\win-x64\\lib\\net8.0\\libyara.NET.dll'. The specified module could not be found.`
(escaped as logged). This is the pre-existing fact recorded in the task file: **libyara is available only in a
`-r win-x64` build**, which is why (b) uses one.

## What else was printed

Identical in (a) and (b), package for package (stderr, escaped):
- 95 × `scan-package: analysis INCOMPLETE - the known-vulnerability check did not run. --allow-incomplete given; exit
  code NOT gated on this.` (a consequence of `--no-vulns`);
- 5 × the same caveat plus the native files IL analysis cannot read: the three SqlClient SNI runtime packages
  (`runtimes/win-*/native/sni.dll`), `Microsoft.Data.SqlClient.SNI.runtime` (3 `Microsoft.Data.SqlClient.SNI.dll`), and
  `Microsoft.Extensions.ApiDescription.Server` (`tools/net10.0/GetDocument.Insider.exe`).

(b) only, on every run: `[WRN] Failed to compile embedded YARA rules
Silvergun.PackageAnalysis.NuGet.Resources.YaraRules.ReversingLabs.virus.Linux.Virus.Vit.yara: Error compiling rules.`
and `[WRN] Dropped 1 embedded YARA rule file(s) that failed validation (ADR 0028) …`. libyara 4.5.5 cannot compile
the Vit rule (`unknown module "elf"`), so (b) scans with 309 rule files. (a) scans with all 310; its worker announced
1,240 rules, 0 rule sources with errors, canary passed (from the harness runs below, which relay the worker's stderr).

## Positives parity (scanner level)

Samples: the YARA-X spike's synthetic positives, from a copy of `scratchpad/yrx/make_positives.py` with the **Vit ELF
sample removed** (Defender flagged it in the spike; it was not built). The signed certificate-blocklist sample was not
built either: it is produced by a separate signing script (`sign_cert.ps1`), not by the generator, and that script
imports a throwaway key into the user's key storage. Each sample is inert bytes rendered from the embedded rule text
inside a minimal non-runnable PE32. Written under `C:\Temp\sg-t6\pos\`, deleted after the run. Defender: **0
detections** recorded since 2026-10-22T10:00Z (`Get-MpThreatDetection`, read-only).

Harness: a scratch console app (ProjectReferences only), net10.0-windows, `win-x64`, Release. It runs
`YaraXWorkerScanner` (production constructor; worker = `Silvergun.CLI.exe` beside it, amendment (o) step 2) and
`LibYaraScanner` over each file (`ScanFile`), then over the directory (`ScanDirectory`).

| Sample | Built to hit | YARA-X worker (`ScanFile` / `ScanDirectory`) | libyara in-process (`ScanFile` / `ScanDirectory`) | Same |
| --- | --- | --- | --- | --- |
| `hermeticwiper.bin` | Win32_Trojan_HermeticWiper | hit / hit | hit / hit | yes |
| `elerad_pe.exe` | Win32_Virus_Elerad | hit / hit | hit / hit | yes |
| `awfull_pe_min.exe` | Win32_Virus_Awfull | hit / hit | hit / hit | yes |
| `awfull_pe_max.exe` | Win32_Virus_Awfull | hit / hit | hit / hit | yes |
| `archiveus_pe.exe` | Win32_Ransomware_Archiveus | hit / hit | hit / hit | yes |
| `domaiq.bin` | Win32_PUA_Domaiq | hit / hit | hit / hit | yes |
| `elerad_pe_offby1_negative.exe` | none | – / – | – / – | yes |
| `cert_blocklist_unsigned.exe` | none | – / – | – / – | yes |
| `empty_negative.bin` | none | – / – | – / – | yes |
| `mz_only_negative.bin` | none | – / – | – / – | yes |
| `manifest.json` (the generator's own) | none | – / – | – / – | yes |

- **Identical rule sets on 11/11 files**, by `ScanFile` and by `ScanDirectory`. No sample hit any rule other than its
  target, in either backend. Every scan was `completed` (no `YaraScanIncompleteException`).
- **Tags** are identical (`tc_detection,malicious` on every hit).
- **Namespace differs:** YARA-X reports `default`; libyara reports none (`YaraMatch.Namespace` is null).
- Times: `Available` 2,561 ms for YARA-X (first probe, cold compile into the harness's empty private cache) vs 583 ms for
  libyara (in-process compile). `ScanFile` 478–533 ms per file for YARA-X (one worker run each) vs 2–7 ms for libyara.
  `ScanDirectory` over all 11 files: 498 ms vs 20 ms.
- Not covered: the Vit ELF rule (`elf` module) and the signed `pe.signatures` blocklist sample, both above.

## Large file (amendment (s))

One sparse file inside an otherwise empty scan root, scanned by `YaraXWorkerScanner`'s production constructor:
engine timeout 30 s (the worker logged `per-file timeout 30 s`), per-record backstop 30 s + 5 s grace = 35 s. Each run
used a fresh scanner, so a fresh probe and a fresh scan worker; the rules came from the harness's warm private cache.

| File size | Worker read path | Run | Probe | `ScanDirectory` | Outcome |
| --- | --- | ---: | ---: | ---: | --- |
| 2,147,483,648 B (exactly 2 GiB) | memory-mapped (above `Array.MaxLength`) | 1 | 495 ms | **5,553 ms** | completed, 0 hits |
| | | 2 | 444 ms | **5,530 ms** | completed, 0 hits |
| | | 3 | 462 ms | **5,570 ms** | completed, 0 hits |
| 2,147,483,591 B (`Array.MaxLength`) | read into one byte array | 1 | 505 ms | **6,676 ms** | completed, 0 hits |
| | | 2 | 461 ms | **5,442 ms** | completed, 0 hits |
| | | 3 | 462 ms | **5,536 ms** | completed, 0 hits |

- All 6 runs **finished**. None reached the engine timeout or the 35 s backstop.
- 0 `Silvergun.CLI` processes after each run.
- **Limit of this result:** the file is sparse, so every byte is zero. Reading it costs no disk I/O, and zeros are a
  best case for pattern matching. A dense 2 GiB file was not measured.
- Both files were deleted afterwards (no disk space was used: sparse).

## Hygiene

- **Orphaned workers:** 0. The driver listed `Silvergun.CLI.exe` processes after every one of the 200 corpus runs
  (always 0), and the harness counted them after each large-file run (always 0). A final process listing after Part B
  held no `Silvergun.CLI`, FakeYaraProbe, YaraXProbe or testhost process.
- **Temp:** `%TEMP%\silvergun-yara-*` (which includes `silvergun-yara-x-*`): 0 before and 0 after the corpus run, the
  positives and the large-file runs. **Delta 0 / 0.** The CLI children's working directory was empty after the run.
- **Rules cache.** The CLI does use the default cache location, `%LOCALAPPDATA%\Silvergun\yara-x-rules`. Every child
  (corpus and harness) ran with a private `USERPROFILE`, so that location resolved to a scratch directory under
  `C:\Temp\sg-t6\`.
  - **The real cache was not touched.** Its one entry (`rules-1.22.0-52f6ba0e…feb6.sgyx`, 2,357,114 B) kept its
    mtime of 2026-10-22 05:27:49 −04:00 from before Part B to after it.
  - The corpus's private cache got one entry, written at 07:23:48 by the first (a) run (the cold compile, AutoMapper,
    9,391 ms). The mtime was unchanged at the end, so the other 99 (a) runs loaded the cache and none rewrote it.

## A discarded first run (environment, not the product)

A first full run was made with both CLI builds under the session scratchpad, which is inside `%TEMP%`. Partway through,
**Windows Storage Sense ran**:
- Its `StoragePoliciesLastTrigger` is 2026-10-22 11:15:28 UTC (07:15:28 −04:00). Storage Sense is enabled, with
  "delete temporary files that apps aren't using" on.
- Six seconds later, 07:15:34, files whose timestamps were older than about two days were deleted from both build
  directories. Copied NuGet assemblies keep their package timestamps.
- **Plain build (a):** lost every package assembly, including `System.CommandLine.dll`, and `runtimes\`. From then on
  71/100 (a) runs died at startup: `Unhandled exception. System.IO.FileNotFoundException: Could not load file or
  assembly 'System.CommandLine, Version=2.0.10.0 …'`, exit 0xE0434352, about 0.1 s.
- **RID build (b):** kept the assemblies the (b) process running at that moment had loaded, and lost the rest
  (satellite resources).
- **Before the deletion:** the 29 (a) runs had all been `Completed` with 0 findings.

That run was discarded whole. Both CLIs were rebuilt from the same source tree into `C:\Temp\sg-t6\` (outside
`%TEMP%`), and all 200 runs were repeated. Every number in this file is from the repeat. The CLI's own extraction
directories are still under `%TEMP%`, as in production. Storage Sense did not trigger again during the repeat (its
trigger time was unchanged at the end).

## Method

- **Corpus:** `C:\Temp\silvergun-corpus\`, 100 `.nupkg`, 87,909,459 B. This is the copy re-acquired on 2026-10-19
  (provenance: `yara-cli-stderr-errors-2026-10-19.md`). **Zero downloads.** With `--no-vulns`, `scan-package` makes no
  network call: OSV and the resolver-lite walk are both gated off.
- **Command:** `Silvergun.CLI.exe scan-package <nupkg> --json --no-vulns --allow-incomplete`. One child process per
  package and configuration, 300 s bound (tree kill on expiry, never needed). The driver ran packages sequentially in
  case-insensitive name order, **interleaved**: (a) then (b) on even indices, (b) then (a) on odd ones (the TSV's `Order`
  column).
- **Child environment:** `USERPROFILE` = a private scratch profile; `NO_COLOR=1`; no `DOTNET_STARTUP_HOOKS`;
  `SILVERGUN_YARA_ENGINE=yarax` for (a) and unset for (b); stdin closed; working directory a private empty scratch
  directory.
- **What was recorded:**
  - from the stdout JSON: `YaraScanStatus` and `YaraFindings`;
  - the exit code, the wall time and stderr;
  - the CLI log lines each run appended (`Silvergun-CLI*.log` beside each binary), filtered to YARA `[WRN]`/`[ERR]`.
  - All of it was escaped to printable ASCII before being written.
- **No test suites ran during Part B.** The Part A gate had finished before Part B started.

## Provenance

- **Source:** commit `860c3f3` (HEAD; the brief named `f348d51`, which is HEAD~1) plus the uncommitted working tree.
  - Modified: `src/Silvergun.CLI/Program.cs`, `src/Silvergun.PackageAnalysis.NuGet/Silvergun.PackageAnalysis.NuGet.csproj`,
    `src/Silvergun.PackageAnalysis.NuGet/Yara/YaraScannerFactory.cs`, `src/Silvergun.Runtime/Runtime.cs`.
  - Untracked: `src/Silvergun.PackageAnalysis.NuGet/Yara/{Worker/, YaraX/, YaraXWorkerScanner.cs}`,
    `src/Silvergun.Runtime/CappedTextWriter.cs`.
  - That is the FR2 tree. The newest `src` mtime is 06:41:03 −04:00, and no source changed during the measurement.
- **Builds:** **Release**, `net10.0-windows`, `dotnet build src/Silvergun.CLI/Silvergun.CLI.csproj -c Release -f
  net10.0-windows -o <dir>`, with `-r win-x64` added for (b). Both are framework-dependent apphosts.

| Build | `Silvergun.CLI.dll` sha256 | Engine file sha256 |
| --- | --- | --- |
| (a) plain, `C:\Temp\sg-t6\cli-plain` | `483d8f26…25be` | `yara_x_capi.dll` `bb5c112b…4848` (the T0 pin) |
| (b) `-r win-x64`, `C:\Temp\sg-t6\cli-rid` | `ba605c18…32a7` | `libyara.NET.dll` `a17293cb…e53b` |

- **Versions:**
  - .NET SDK 10.0.101;
  - YARA-X C API 1.22.0 (`artifacts/tools/yara-x-capi/win-x64/PROVENANCE.txt`: GitHub release asset
    `yara-x-capi-v1.22.0-x86_64-pc-windows-msvc.zip`, digest `40317f65…0e1664`, BSD-3-Clause);
  - `Microsoft.O365.Security.Native.libyara.NET.Core` 4.5.5;
  - rules: the embedded ReversingLabs set (310 files) plus the custom rules.
- **Machine:**
  - Intel i5-10300H, Windows 10 Home build 19045, Balanced power plan;
  - Microsoft Defender real-time protection on (engine 1.1.26100.4, signatures 1.461.137.0);
  - Storage Sense on (see above).

## Not measured

- A dense (non-sparse) ~2 GiB file. Large files under (b).
- The Vit ELF rule and the signed `pe.signatures` sample, under either backend on Windows.
- A reboot-cold first run: every number follows earlier runs on the same boot.
- Run-to-run drift was not re-measured; the 2026-10-20 measurement recorded about 15 % on this laptop. The interleaving
  is what makes the per-package (a) − (b) comparison meaningful within this run.
