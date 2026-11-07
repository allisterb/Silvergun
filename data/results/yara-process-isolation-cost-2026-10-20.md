# Cost of process-isolated YARA scanning on Windows (input to ADR-0033) — 2026-10-20

Spec: `docs/agent/tasks/yara-process-isolation-measurement.md`. Raw samples (one row per measured value, 9,350
data rows): `yara-process-isolation-cost-2026-10-20.tsv`. Probe code:
`tests/Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe/IsolationCost.cs` (new modes `--isolation-cost`,
`--worker`, `--inproc-host`, `--extract`, `--dump-rules`).

Conventions: **median** = `statistics.median` (for even N, the mean of the two middle samples). **p90** = nearest
rank, the ⌈0.9·N⌉-th smallest sample. Times are in ms and memory in MiB. "Warm" means every sample except the first
spawn after a build.

## Headline

| Row | Number (median, p90 in brackets) |
| --- | --- |
| **M1** worker spawn-to-ready, full two-pass build, warm | **915 ms** (972), N=14. Pass 1 is 369 ms, pass 2 is 292 ms, process+runtime+IPC residual is 217 ms |
| M1, pass 1 skipped (known-good list) | **531 ms** (583), N=14. Saves ~385 ms |
| M1, first spawn after a build | 1,354 ms, and 1,225 ms in an earlier run. N=2, not a reboot-cold number |
| **M2** 20 packages, (a) in-process / (b) long-lived worker / (c) worker per package | **4.5 s / 3.9 s / 24.4 s** in the main run. Interleaved re-run of (a) vs (b): **3.77 s vs 3.76 s** |
| M2 (b) IPC overhead | **2.2 ms per 20 packages**, about 0.1 ms per package |
| M2 (c) share that is spawn-to-ready | 19.8 s of 24.4 s (81 %) |
| **M3** `Kill(entireProcessTree: true)` → `HasExited` | **41 ms** (63), N=12. Plain `Kill()`: 10.6 ms (13.6), N=12 |
| M3 orphans | **0 / 24** |
| M3 kill start → replacement worker ready | **1,431 ms** (1,637) with tree kill. 1,161 ms (1,476) with plain kill |
| **M4** ready worker | **50.3 MiB working set / 37.6 MiB private**. After 20 trees: 63.5 / 42.3. After 60 trees: 65.6 / 44.0 |
| M4 in-process engine delta in a bare host | **+30.2 MiB WS / +29.8 MiB private** at ready. After 60 tree scans: +46.2 / +41.6 |
| **M5** (Linux proxy) `yara --version` / `yarac` compile / compiled per-package scan of all 20 | **2.4 ms / 286 ms / 1.34 s total** |

## Method

**Build.** Release, `-r win-x64`, net10.0-windows. The probe builds against the product assembly with a
ProjectReference only. No NuGet changes.

**Engine.** Both `--worker` and `--inproc-host` build the engine in the same way. The code copies the *shape* of
`LibYaraScanner.BuildEngine` and does not call it:
- read the 310 embedded `.yara` resources the same way `YaraRuleResources.ReadAll` does;
- touch a libyara.NET type, which loads the native assembly ("nativeLoad");
- `new YaraContext()`;
- **pass 1**: one throwaway `Compiler` per source, disposed;
- **pass 2**: one fresh `Compiler` over the valid sources, `GetRules()`, disposed;
- `new Scanner()`, then the **canary**: `ScanMemory` of 64 zero bytes on a dedicated thread with a 5 s bound.

Pass 1 drops 1 file (`ReversingLabs.virus.Linux.Virus.Vit.yara`, no ELF module), so 309 files compile. This matches
ADR-0028. It was observed in all 80 worker ready reports that the TSV records (M1pre, M1, M2b, S.M2b), and every
recorded M3 respawn passed its canary (24/24). All libyara-typed calls sit behind
`NoInlining` methods that take and return `object`. That way the native load happens inside the "nativeLoad" timer
and not when a caller is JIT-compiled. Phase times are measured inside the child with `Stopwatch`.

**Worker protocol.**
- The worker prints a single "ready" JSON line, then reads JSON commands from stdin, one per line.
- `scan <root>` walks the tree the same way the product's default `ScanDirectory` does (`Directory.GetFiles`, then
  `File.Exists` and `Scanner.ScanFile` per file). For each file it writes one JSON line (path, bytes, status, ms,
  hits), flushed immediately, and finishes with a "done" line.
- The worker scans **inline**, because in the (W) design the parent's kill is the bound.
- `--inproc-host` scans each file on a **dedicated thread joined with a 30 s bound**, which is the shape of
  `LibYaraScanner.TryRunBounded`, the path the product uses today.

**Timing points.**
- **Spawn-to-ready** is timed by the parent from just before `Process.Start` until the ready line has been read.
- **Round trip** is timed from writing the scan command until the "done" line has been read.
- **IPC overhead** = round trip − the worker's own scan time for that tree.

**Isolation.** The orchestrator never loads libyara. It tracks every child by (PID, creation time), kills only those
children, and checks at the end that none is still alive.

**Corpus (M2).** 20 of the 100 packages in `C:\Temp\silvergun-corpus\` were chosen from a central-directory
inventory, made without extracting anything:
- the 5 smallest by file count;
- the 2 largest by file count (`Microsoft.Extensions.ApiDescription.Server` with 253 files, `coverlet.collector`
  with 160);
- the 4 largest by uncompressed bytes (`Microsoft.Data.SqlClient` 34 MB, `AWSSDK.S3`, `StackExchange.Redis`,
  `System.Drawing.Common`);
- `System.Text.Json`;
- 8 more spread across the middle of the file-count range.

That is 826 files and 186 MB in total. The packages were extracted with .NET 10's
`System.IO.Compression.ZipFile.ExtractToDirectory` (`--extract` mode) to `C:\Temp\sg-iso\trees\`. This is a plain
top-level extraction: nested archives were not expanded, unlike the product's RecursiveExtractor. Nothing was
downloaded. Every scan returned 0 hits and 0 failed files: 0 rows have `failed>0` or `hits>0`.

**Runs** (all sequential, nothing else of ours running):

| Run | When (UTC, 2026-10-21) | What |
| --- | --- | --- |
| pre | 00:17–00:18 | M1 + M1 skip-pass1, first execution after the first build. TSV section `M1pre` |
| main | 00:20:46–00:32:07 | first execution after a rebuild. M1, M1 skip-pass1, M2a (10 hosts × 3 rounds), M2b (10 workers × 3 rounds), M2c (10 rounds × 20 packages), M3 (12 tree kills + 12 plain kills). 298 children, 0 failures, 0 alive at the end |
| supplementary S | ~00:34–00:41 | M2a and M2a-inline **alternating host by host**, then M2b. TSV sections `S.*`. 30 children, 0 failures, 0 alive at the end |
| M5 | after main | WSL, see M5 |

**Run-to-run drift is real.** The warm M1 median was **915 ms** in the main run and **792 ms** in the pre-run 3
minutes earlier (the pre-run is N=14 too). The main run's (a)-vs-(b) gap also went away once the two were
interleaved (see M2). The machine is a laptop on the Balanced power plan. Compare numbers *within* a run, not
across runs.

## M1 — worker spawn-to-ready

Main run, N=14 warm (iterations 2–15):

| Phase | full: median | p90 | min | max | skip pass 1: median | p90 | min | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **spawn-to-ready (parent's view)** | **915** | 972 | 856 | 1030 | **531** | 583 | 507 | 601 |
| read 310 rule resources | 19.1 | 23.6 | 16.2 | 25.0 | 19.2 | 22.4 | 16.6 | 27.8 |
| native assembly load | 11.6 | 14.8 | 10.2 | 16.9 | 11.3 | 13.5 | 9.9 | 23.5 |
| `YaraContext` | 1.0 | 1.5 | 0.9 | 1.5 | 1.1 | 1.4 | 0.9 | 3.2 |
| pass 1 (310 throwaway compilers) / read known-good list | 369 | 392 | 348 | 397 | 7.6 | 9.2 | 6.3 | 16.2 |
| pass 2 (309 files, one compiler) | 292 | 323 | 248 | 353 | 270 | 295 | 252 | 303 |
| canary | 4.0 | 4.7 | 3.5 | 5.0 | 3.8 | 5.4 | 3.3 | 5.6 |
| sum of in-child phases | 693 | 737 | 639 | 781 | 317 | 341 | 296 | 370 |
| residual: process create + runtime start + JIT + ready-line IPC | 217 | 251 | 197 | 284 | 210 | 232 | 198 | 266 |
| worker exit after `exit` command | 12.7 | 14.6 | 11.1 | 15.3 | – | – | – | – |

- The child also reports kernel-clock "process start → Main". Its median is 124 ms. That clock is coarse, so the
  residual row above is the more reliable number.
- **Pass 1 costs more than pass 2.** Pass 1 creates 310 compilers, pass 2 creates one.
- Skipping pass 1 is **information only**: the ADR-0028 poisoning guard depends on pass 1.

**First spawn after a build** (N=2, one per build; not a reboot-cold number, because no reboot was possible):

| | main run | pre-run |
| --- | ---: | ---: |
| spawn-to-ready | 1,354 | 1,225 |
| read rule resources | 367 | 330 |
| pass 1 | 434 | 367 |
| pass 2 | 272 | 281 |
| residual | 265 | 207 |

The first-run penalty is almost entirely in "read rule resources" (~350 ms vs 19 ms warm). That phase is the first
load of the product assembly from disk. The rest is close to warm.

**Other healthy spawn samples** (the same build, taken in other phases of the main run):

| Source | N | median | p90 | min | max |
| --- | ---: | ---: | ---: | ---: | ---: |
| M2b long-lived worker spawns | 10 | 1029 | 1253 | 839 | 1287 |
| M2c per-package worker spawns | 200 | 977 | 1212 | 815 | 1814 |
| M3 respawn immediately after a kill | 24 | 1213 | 1573 | 942 | 1689 |
| S run worker spawns | 10 | 905 | 1007 | 794 | 1924 |
| M2a in-proc host: process start → engine built | 10 | 920 | 1108 | 831 | 1218 |

## M2 — scan cost: in-process vs long-lived worker vs worker per package

**Totals over all 20 packages (826 files, 186 MB), main run:**

| Mode | N | median | p90 | min | max |
| --- | ---: | ---: | ---: | ---: | ---: |
| (a) in-process, dedicated bounded thread per file (host × round) | 30 | 4,502 | 5,507 | 3,585 | 7,361 |
| (b) long-lived worker, round trip (worker × round) | 30 | 3,927 | 4,512 | 3,297 | 5,944 |
| (b) of which worker-internal scan | 30 | 3,923 | 4,510 | 3,295 | 5,935 |
| (b) of which IPC (round trip − internal) | 30 | 2.2 | 9.2 | 1.4 | 43.4 |
| **(c) one worker per package: spawn + ready + scan + exit (per round)** | 10 | **24,428** | 26,854 | 21,835 | 30,416 |
| (c) of which spawn-to-ready | 10 | 19,824 | 21,988 | 17,657 | 25,401 |
| (c) of which scan round trips | 10 | 4,460 | 5,214 | 3,963 | 5,658 |
| (c) of which exit | 10 | 243 | 250 | 215 | 281 |
| one-off: (a) host start → engine built / (b) worker spawn-to-ready | 10 / 10 | 920 / 1,029 | 1,108 / 1,253 | | |

**Supplementary run S, (a) and (a') hosts alternating:**

| Mode | N | median | p90 | min | max |
| --- | ---: | ---: | ---: | ---: | ---: |
| (a) in-process, dedicated bounded thread per file | 30 | 3,766 | 4,076 | 3,456 | 4,618 |
| (a') in-process, inline on the caller's thread (information only) | 30 | 3,492 | 3,736 | 3,203 | 3,973 |
| (b) long-lived worker round trip (ran after the hosts) | 30 | 3,759 | 4,159 | 3,174 | 5,046 |

In the main run, (a) was 13 % slower than (b). That gap **did not reproduce**: with interleaving, (a) and (b) are
equal (3,766 vs 3,759 ms), so the main-run gap was machine drift between the two blocks. In run S, (b) still ran
after the hosts and not interleaved with them. The product's thread per file costs ~7 % over inline scanning
((a) vs (a'), interleaved). That thread is also why (a) grew more working set than (a') after 60 tree scans:
70.2 vs 63.4 MiB.

**Per package, main run** (median / p90 ms; N = 30 for (a) and (b), N = 10 for (c)):

| Package | files | MB | (a) in-proc | (b) worker RT | (b) IPC | (c) total | (c) spawn-to-ready | (c) scan RT | (c) exit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| xunit.2.9.3 | 7 | 0.04 | 11.3 / 15.9 | 8.8 / 20.3 | 0.1 / 6.2 | 1041 / 1487 | 1005 / 1453 | 21.2 / 24.0 | 11.4 / 12.6 |
| Swashbuckle.AspNetCore.10.2.3 | 8 | 0.02 | 11.0 / 16.4 | 8.3 / 11.3 | 0.1 / 0.3 | 933 / 1381 | 905 / 1346 | 20.8 / 29.2 | 11.1 / 12.7 |
| Microsoft.Azure.WebJobs.3.0.47 | 8 | 0.77 | 22.3 / 31.2 | 19.8 / 24.4 | 0.1 / 0.3 | 995 / 1215 | 953 / 1160 | 33.2 / 41.9 | 10.9 / 13.1 |
| Microsoft.NET.Sdk.Android.Manifest-8.0.100.34.0.154 | 9 | 0.04 | 11.5 / 18.0 | 10.6 / 13.5 | 0.1 / 0.2 | 1012 / 1099 | 982 / 1069 | 20.7 / 26.7 | 10.8 / 13.9 |
| Microsoft.NET.Workload.Emscripten.net6.Manifest-8.0.100.8.0.30 | 9 | 0.04 | 11.8 / 17.7 | 10.1 / 13.5 | 0.1 / 0.4 | 1027 / 1118 | 996 / 1083 | 22.4 / 25.2 | 11.6 / 12.3 |
| Moq.4.20.72 | 11 | 1.26 | 26.4 / 36.4 | 23.2 / 28.6 | 0.1 / 0.1 | 988 / 1206 | 945 / 1151 | 33.0 / 40.7 | 11.4 / 12.9 |
| Npgsql.10.0.3 | 13 | 6.53 | 56.9 / 66.2 | 52.6 / 67.7 | 0.1 / 0.1 | 1105 / 1194 | 1033 / 1116 | 62.8 / 70.2 | 10.2 / 12.0 |
| AWSSDK.Core.4.0.101.1 | 15 | 9.26 | 100 / 145 | 86.3 / 120 | 0.1 / 0.2 | 1015 / 1238 | 908 / 1126 | 95.8 / 117 | 11.4 / 12.8 |
| NLog.6.2.0 | 16 | 11.67 | 88.4 / 114 | 81.3 / 98.0 | 0.1 / 0.1 | 1007 / 1137 | 902 / 1039 | 87.9 / 96.5 | 11.2 / 11.7 |
| AWSSDK.S3.4.0.102.2 | 18 | 27.64 | 177 / 221 | 167 / 221 | 0.1 / 0.2 | 1103 / 1319 | 913 / 1072 | 179 / 233 | 11.9 / 15.4 |
| StackExchange.Redis.3.1.13 | 21 | 19.65 | 139 / 177 | 138 / 175 | 0.1 / 0.1 | 1107 / 1375 | 952 / 1174 | 144 / 188 | 11.9 / 13.3 |
| Serilog.4.4.0 | 23 | 3.65 | 52.9 / 87.3 | 44.8 / 59.4 | 0.1 / 0.2 | 1085 / 1170 | 1019 / 1096 | 58.8 / 68.4 | 9.6 / 11.9 |
| Newtonsoft.Json.13.0.4 | 24 | 10.72 | 140 / 175 | 126 / 148 | 0.1 / 0.1 | 1063 / 1325 | 922 / 1152 | 133 / 161 | 11.4 / 12.8 |
| Azure.Core.1.61.0 | 24 | 8.75 | 102 / 150 | 101 / 126 | 0.1 / 0.2 | 1033 / 1148 | 907 / 999 | 115 / 137 | 11.7 / 12.9 |
| OpenTelemetry.1.17.0 | 27 | 3.27 | 59.5 / 89.4 | 51.0 / 69.3 | 0.1 / 0.3 | 1063 / 1230 | 991 / 1139 | 66.7 / 92.1 | 11.5 / 13.5 |
| System.Drawing.Common.10.0.11 | 47 | 18.56 | 214 / 290 | 195 / 248 | 0.1 / 0.2 | 1161 / 1580 | 938 / 1307 | 224 / 265 | 12.0 / 13.5 |
| System.Text.Json.10.0.11 | 66 | 8.11 | 307 / 419 | 282 / 341 | 0.1 / 0.2 | 1368 / 1666 | 1027 / 1310 | 313 / 363 | 12.3 / 13.4 |
| Microsoft.Data.SqlClient.7.0.2 | 67 | 34.23 | 524 / 778 | 463 / 593 | 0.1 / 0.2 | 1580 / 1830 | 1070 / 1231 | 520 / 656 | 12.6 / 14.5 |
| coverlet.collector.10.0.1 | 160 | 10.26 | 766 / 1006 | 677 / 841 | 0.1 / 0.1 | 1774 / 2217 | 989 / 1079 | 773 / 1129 | 13.3 / 18.4 |
| Microsoft.Extensions.ApiDescription.Server.10.0.11 | 253 | 11.60 | 1494 / 2110 | 1306 / 1687 | 0.1 / 0.2 | 2407 / 3316 | 969 / 1212 | 1390 / 1718 | 13.2 / 15.0 |

Scan time follows file count more than bytes. ApiDescription.Server (253 files, 11.6 MB) costs about 3× as much as
SqlClient (67 files, 34 MB). In (c), the small packages pay ~1 s each, almost all of it spawn. A fresh worker's
first scan is also ~10 ms slower than a long-lived worker's on the same tree (xunit: 21 vs 9 ms), which is the
first-call JIT inside the new process.

## M3 — killing a worker hung inside a native scan

**Hang technique.** This is `PoisonCanaryCheck`'s technique. A `--poisoned` worker rebuilds the ADR-0028 defect:
- all 310 sources go into ONE compiler;
- the one `CompilationException` is swallowed;
- `GetRules()` is called on the errored compiler;
- the canary is skipped.

The parent then sends a scan of a directory that holds one 4-byte all-zero file. The worker announces the file
before calling `Scanner.ScanFile`.

**Proof that each worker was hung in the native scan**, not blocked or crashed:
- it announced the file;
- no result line arrived during the hold;
- it was still alive at the end of the hold;
- it burned **0.99 core** (median CPU-seconds per wall-second, range 0.88–1.06) for the whole hold.

The hold was 2 s, except iteration 1, which was held for **30 s**, the product's `scanTimeout`. It was still
spinning at 0.94 core at 30 s. All 24 iterations were classified "hung".

**The kill.** `Process.Kill(...)`, then `WaitForExit` and `HasExited`. Then two orphan checks: the PID is absent
from `Process.GetProcesses()`, and no other process runs the probe exe besides the orchestrator.

| N=12 each | `Kill(entireProcessTree: true)` median | p90 | min | max | plain `Kill()` median | p90 | min | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| time inside the `Kill` call | 40.9 | 62.7 | 32.1 | 65.2 | 0.2 | 0.3 | 0.2 | 0.4 |
| **kill start → `HasExited`** | **40.9** | 62.8 | 32.1 | 65.2 | **10.6** | 13.6 | 8.2 | 18.9 |
| orphan PID present / other probe processes | 0 / 0 | | | | 0 / 0 | | | |
| respawn → ready (healthy worker, canary passed) | 1,384 | 1,573 | 1,131 | 1,586 | 1,137 | 1,457 | 942 | 1,689 |
| **kill start → replacement ready** | **1,431** | 1,637 | 1,176 | 1,641 | **1,161** | 1,476 | 960 | 1,712 |
| replacement's proof scan (xunit, 7 files) round trip | 21.2 | 23.8 | 18.8 | 28.5 | 20.7 | 24.5 | 18.0 | 24.6 |
| poisoned worker spawn-to-ready (no pass 1, no canary) | 708 | 770 | 543 | 821 | 692 | 849 | 525 | 855 |

- Every kill returned exit code −1. No orphan was found in any of the 24 iterations.
- With `entireProcessTree: true`, the whole time is spent **inside the call**, which walks the descendants
  (~30 ms more than plain `Kill`) before terminating. Plain `TerminateProcess` returns in 0.2 ms, and the process is
  observed dead ~10 ms later.
- A respawn right after a kill (median 1.14–1.38 s) was **slower than any other healthy spawn in the same run**
  (0.92–1.03 s). This was not investigated. Untested candidates include the CPU frequency state after a 2 s
  single-core spin, and Defender.

## M4 — footprint

The process measures itself (`Process.WorkingSet64`, `PrivateMemorySize64`, `PeakWorkingSet64`, plus
`GC.GetTotalMemory`). Main run, N=10 workers / hosts (M1 rows: N=15):

| Process / point | working set | private | peak WS | managed heap |
| --- | ---: | ---: | ---: | ---: |
| bare .NET host at `Main` (in-proc host, before anything) | 23.6 | 7.6 | 23.6 | 0.7 |
| in-proc host, engine ready | 53.8 | 37.5 | 53.8 | 10.7 |
| in-proc host, after 20 trees (1 round) | 65.8 | 45.8 | 65.8 | 10.3 |
| in-proc host, after 60 trees (3 rounds) | 69.8 | 49.2 | 73.7 | 9.2 |
| **in-proc engine delta vs bare host: ready** | **+30.2** | **+29.8** | | |
| in-proc engine delta: after 20 / 60 trees | +42.2 / +46.2 | +38.2 / +41.6 | | |
| **worker, ready** (M2b) | **50.3** | **37.6** | 50.3 | 10.4 |
| worker, after 20 trees | 63.5 | 42.3 | 64.0 | 8.2 |
| worker, after 60 trees | 65.6 | 44.0 | 70.4 | 10.7 |
| worker ready, M1 full / skip pass 1 (N=15) | 50.4 / 49.2 | 37.1 / 36.4 | | |

p90 values are within 0.5 MiB of the medians for every row (TSV). The in-proc delta includes loading the product
assembly and the probe's own JIT, not only libyara. A real host (CLI, WPF) already has part of that loaded. The
bare host was a console app, so these deltas describe what this probe added, not what a WPF host would add.

## M5 — Linux `yara`/`yarac` 4.1.3 in WSL (PROXY for stock `yara.exe`; different OS, filesystem and AV)

**Setup.**
- WSL2 Ubuntu 22.04.5 LTS, kernel 6.18.54.1-microsoft-standard-WSL2, 8 vCPU (same i5-10300H).
- `/usr/bin/yara` and `/usr/bin/yarac` 4.1.3.
- The same 310 sources, written by `--dump-rules` with `YaraCliScanner.CompileRules`' framing and without its
  per-run sentinel. That is 3,461,532 chars. On Linux all 310 compile.
- The rules and all 20 trees were **copied to the WSL-native filesystem** (`$HOME`) before timing, because 9P reads
  of `/mnt/c` are not what a Windows binary would see.
- Flags are those of `YaraCliScanner`'s recursive pass: `-r -s -g -N --timeout=30`.
- Each invocation was timed with `perf_counter` around fork/exec/`wait4`. Peak RSS comes from `wait4`'s rusage.
- One untimed warm-up of every command. Source and compiled runs were interleaved per iteration.
- Every invocation returned rc=0 and 0 hits.

| Invocation | N | median | p90 | min | max | peak RSS (MiB, median) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `yara --version` (process start overhead) | 15 | 2.4 | 5.2 | 2.0 | 5.3 | 11.3 |
| `yarac` compile of the 310-file source | 12 | 286 | 355 | 230 | 371 | 19.3 |
| `yara` **source** rules, smallest tree (xunit, 7 files) | 12 | 294 | 396 | 209 | 402 | 22.3 |
| `yara -C` **compiled** rules, smallest tree | 12 | 20.5 | 39.3 | 14.8 | 93.1 | 13.9 |
| `yara` **source** rules, largest tree (ApiDescription.Server, 253 files) | 12 | 643 | 848 | 559 | 871 | 29.7 |
| `yara -C` **compiled** rules, largest tree | 12 | 410 | 506 | 329 | 519 | 21.4 |
| (extra) `yara -C -r` once per package over all 20 trees, **total** per iteration | 10 | 1,337 | 1,411 | 1,259 | 1,466 | – |

Per-package medians for the extra row are in the TSV (section `M5d`). They range from 17 ms (Swashbuckle) to 359 ms
(ApiDescription.Server).

These numbers are **not comparable** to the Windows rows: different kernel, filesystem, no Defender, and a
different libyara version (4.1.3 vs 4.5.5). As a fact, not an explanation: the same 253-file tree took 359–410 ms
under Linux `yara -C` and 1.2–1.5 s under Windows libyara in-process.

## M6 — not done: stock `yara.exe` on Windows

This needs the official VirusTotal Windows release, which the user has not approved downloading. It would add these
rows:

1. **M6.1** `yara.exe --version` process-start overhead on Windows. The Windows analogue of the M5 `--version` row.
   Compare it with M1's ~210–217 ms .NET process+runtime residual.
2. **M6.2** `yarac64.exe` compile time of the same 310-file source on Windows, and whether the ELF-module rule
   compiles in that build (the rule count). The analogue of the M5 `yarac` row. Compare it with M1 pass 1 + pass 2.
3. **M6.3** `yara.exe` per invocation, source vs `-C` compiled, on the smallest and largest of the 20 trees. The
   analogue of M5's source/compiled rows.
4. **M6.4** one `yara.exe -C -r` per package over all 20 trees, per package and total. The analogue of M5d. Compare
   it with M2 (a)/(b)/(c).
5. **M6.5** killing a `yara.exe` hung mid-scan: kill → exit, orphans, and whether yara's own `--timeout` fires
   first. A poisoned ruleset cannot be reproduced here, because `yarac` refuses an errored compile. This row needs a
   different hang or a slow-rule technique.
6. **M6.6** `yara.exe` peak working set / private bytes on the smallest and largest tree. The Windows analogue of
   M5's peak RSS, comparable to M4.
7. **M6.7** first-run cost of the freshly downloaded binary under Defender (cold vs warm invocation).

## What this means

- A (W) worker costs ~0.9 s from `Process.Start` to ready on this machine (0.79–1.03 s across runs). 0.66 s of that
  is the two-pass compile, and pass 1 is the larger half. Skipping pass 1 gives ~0.53 s.
- Over these 20 packages, one worker per package took 24.4 s against 3.8–4.5 s for in-process or a long-lived
  worker. 81 % of the difference is spawn-to-ready, paid once per package regardless of package size.
- A long-lived worker's line-JSON IPC adds ~0.1 ms per package. Interleaved against the product's in-process path,
  its scan time is the same (3.76 vs 3.77 s for 20 packages).
- A worker spinning inside a native `yr_rules_scan` call is gone 41 ms (tree kill) or 11 ms (plain kill) after the
  parent decides to kill it, with no orphans in 24/24. A replacement is ready ~1.2–1.4 s after the kill starts.
- A ready worker is ~50 MiB working set / ~38 MiB private, of which ~24 / ~8 MiB is the bare .NET process. Hosting
  the engine in-process added ~30 MiB to a bare host at ready and ~46 MiB after 60 tree scans.
- The Linux `yara` CLI proxy starts in ~2 ms, compiles the ruleset in ~0.29 s, and scans one package per process
  with compiled rules in 17–360 ms. Whether Windows `yara.exe` behaves similarly is exactly what M6 would measure.

## Machine facts and provenance

| Fact | Value |
| --- | --- |
| CPU | Intel Core i5-10300H @ 2.50 GHz, 4 cores / 8 logical (`Environment.ProcessorCount` = 8) |
| RAM | 63.8 GiB |
| OS | Windows 10 Home 22H2, build 19045.7807 |
| Power plan | Balanced (laptop) |
| Defender real-time protection | on (exclusions not inspected) |
| System disk | NVMe SSD |
| .NET | runtime 10.0.1 (`RuntimeInformation.FrameworkDescription`), SDK 10.0.101 |
| libyara.NET | `Microsoft.O365.Security.Native.libyara.NET.Core` 4.5.5 (native libyara 4.5.x); `libyara.NET.dll` 5,852,744 bytes, no file-version resource |
| yara (M5 only) | `yara` / `yarac` 4.1.3, WSL2 Ubuntu 22.04.5 LTS, kernel 6.18.54.1-microsoft-standard-WSL2 |
| Commit under test | `860c3f3` plus the uncommitted probe changes (`Program.cs` dispatch, new `IsolationCost.cs`) |
| Corpus | `C:\Temp\silvergun-corpus\`: the existing benign corpus (copied there for the 2026-08-22 Linux run), read only, **zero downloads** |
| Scratch | `C:\Temp\sg-iso\` (trees, rule dump, hang file) and WSL `~/sg-iso-m5`. **Both deleted** after the runs |

**TSV schema:** `Section Mode Label Iter Round Metric Value Note`.

| Sections | Contents |
| --- | --- |
| `env` / `envPre` / `envSupp` | per-run facts, command lines, child counts, failure counts |
| `M1`, `M1pre` | M1 |
| `M2a`, `M2b`, `M2c` | M2, plus M4 `mem.*` rows |
| `M3` | Modes `killTree` / `killSingle` |
| `M5`, `M5d` | M5 |
| `S.M2a`, `S.M2aInline`, `S.M2b` | supplementary run S |

Every row is one sample. The summary statistics above were computed from these rows.
