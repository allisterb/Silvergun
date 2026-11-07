# C-measure: does the ADR-0032 d7 stderr predicate flip benign packages? (top-100, Linux CLI backend, 2026-10-19)

Raw data: `yara-cli-stderr-errors-2026-10-19.tsv` (100 rows). Spec: `docs/agent/tasks/yara-partial-findings.md`
section C-measure. Method repeated: `docs/agent/tasks/yara-cli-backend-corpus-wsl.md`. Baseline:
`yara-cli-backend-linux-2026-08-22.{md,tsv}` (commit `cc8e6da`). ADR: `0032-yara-findings-survive-an-incomplete-scan.md`
d7/d7a. (The spec names the output `…-2026-10-18`. The files carry the run date, 2026-10-19, as the dispatch asked.)

**What d7 changed.** After a `yara -r` batch run that exited 0, any stderr line whose trimmed start is `error`
(case-insensitive) now makes the package `YaraScanStatus.Unavailable`. Without `--allow-incomplete` that means exit 3.

> **Scope: this measures Round C, not Round D.**
>
> - **What was built:** the copy taken at 2026-10-19T04:20:36Z. It had d7, d7a and d8, and no d9.
> - **What changed afterwards:** Round D (ADR-0032 **d9**, the coverage sentinel) landed in the live working tree
>   while this run was in progress. Six `src/` files were modified 04:39–04:41Z and were still being edited at
>   04:41:46Z:
>   - `PackageScanner.cs`
>   - `Yara/IYaraScanner.cs`
>   - `Yara/YaraCliScanner.cs`
>   - `Yara/YaraOptions.cs`
>   - `Yara/YaraPathSafety.cs`
>   - `Yara/YaraScanIncompleteException.cs`
>
>   `tests/` and `ext/analysis-net` were byte-identical between the copy and the live tree when checked.
> - **What this means:** d9 changes the batch pass for every package. It adds a sentinel line for every file, and
>   any attributable file without one is re-scanned individually. That also adds a new route to `Unavailable`:
>   uncovered files beyond `MaxIndividualScans` = 64. The largest corpus package has 253 files. **This result says
>   nothing about d9.** The task's **D-measure** (re-run this after D-impl) is still required and is not done here.

## Headline

**0 flips out of 100.** Every package that was `Completed` on 2026-08-22 is still `Completed`. No child printed an
`error…` line from yara. The predicate fired 0 times on the benign corpus.

**The predicate does fire in this exact build and setup.** In the positive control below, one file was made
unreadable inside the CLI's own extraction directory. The package went `Completed` → `Unavailable`, kept its genuine
hit, and `--strict` exited 2.

| | Count |
| --- | ---: |
| Packages run / baseline rows | 100 / 100 |
| `Completed` → `Unavailable` flips | **0** |
| Any other `YaraStatus` change | 0 |
| `YaraFindingCount` differences (all 0 → 0) | 0 |
| Exit-code differences (all 3 → 3) | 0 |
| Children logging the d7 warning (`exited 0 but reported N error line(s)`) | 0 |
| Timeouts (300 s), crashes, missing reports | 0 |
| Backend proven `YaraCliScanner`, 310 rule files compiled with `yarac` | 100 |

Rule of three: 0/100 bounds the benign flip rate below about 3% at 95% confidence. This is a population bound, not a
proof for any one package.

## Flips explained

None to explain. The `StderrErrorLines` column is empty on all 100 rows. The d7 warning
(`YaraCliScanner.cs:426`) and the `PackageScanner` incomplete warning (`PackageScanner.cs:208`) appear in no child's
stdout. No child's stderr has a YARA advisory line.

Why the result is expected, not lucky:
- An extracted NuGet tree is readable by construction: the extractor writes files under the invoking user's umask.
- yara's `could not open file` therefore needs a hostile or racy environment.
- A timeout error line needs the run to reach production's `--timeout=60`. Per ADR-0032 d9's correction, in `-r`
  mode that is **one deadline for the whole run**, and only the file mid-scan at that moment gets an error line.
- The slowest *whole-package child* here took 11.4 s, including IL analysis and rule compilation. So no batch
  run came near the 60 s deadline.
- That also means the d9 failure mode (queued files dropped silently at the deadline, with no line at all) cannot
  have hidden anything in this run.

That is exactly the attacker-driven case d7 exists to fail closed. Benign packages do not reach it.

## Positive control

Same CLI binary, same environment (`SILVERGUN_YARA_PATH=/usr/bin/yara`, uid 1000), same command line
(`scan-package <nupkg> --json --depth 0 --no-vulns --output <file>`). The synthetic package
`SgProbe.D7Control 1.0.0` was built with Python `zipfile` and contains:
- `content/payload.bin`: 625 bytes, `MZ` plus the literal bytes of `$corrupt_physical_drive` (wildcards → `00`) from
  the embedded `Win32_Trojan_HermeticWiper` rule. This is the same derivation as
  `tests/Silvergun.PackageAnalysis.NuGet.Tests/HermeticWiperSample.cs`, read from the rule file at run time.
- `content/locked.txt`: benign text, matches nothing.
- `lib/net6.0/Newtonsoft.Json.dll`: copied from the corpus so that IL analysis gives a time window before YARA.

In the PC runs a poller thread watched for a new `/tmp/silvergun/pkg-*` directory and ran `chmod 000` on
`…/content/locked.txt` inside the CLI's own extraction. It did so 656 ms and 3,370 ms after launch. After each chmod
it re-opened the file and got `PermissionError`, which proves the process is not root-equivalent.

| Run | Exit | `YaraScanStatus` | `YaraFindings` | d7 warning |
| --- | ---: | --- | --- | --- |
| NC: no chmod | 3 | `Completed` | 1: `Win32_Trojan_HermeticWiper` @ `content/payload.bin` | none |
| PC: `locked.txt` mode 000 | 3 | **`Unavailable`** | 1: same hit, **kept** (ADR-0032 d1/d7a) | 1 error line |
| PC + `--strict` | **2** | `Unavailable` | 1: same hit | 1 error line |

The error line yara printed, as logged (already escaped by `YaraPathSafety`):

```
error scanning /tmp/silvergun/pkg-0s424f4yhrg4/SgProbe.D7Control.1.0.0.nupkg/content/locked.txt: could not open file
```

PC stderr carried both advisories:
- the ADR-0032 variant: `YARA malware-signature scanning did NOT complete; 1 match(es) were found in the files that
  were scanned …`
- a completeness caveat that now also names `the YARA malware-signature scan did not complete`.

The NC run printed neither. NC and PC differ only in the file mode, and only the PC runs flipped. So the flip is
caused by the d7 predicate and nothing else. Exit 3 cannot tell NC from PC (see "Exit codes" below); `YaraScanStatus`
and the advisory can, and `--strict` → 2 shows the hit still gates.

## Other differences vs the 2026-08-22 baseline

- **YARA status, findings, rule names, matched files, exit codes:** identical on 100/100. Both runs have 0 findings
  and 0 matched files.
- **Files:**
  - Each package's `.nupkg` file-entry count equals the baseline `FilesScanned` on 100/100 rows. Totals are
    **2,277 = 2,277**.
  - The incompleteness set is unchanged: the same 5 packages, with 7 native files that cannot be analysed.
    - `Microsoft.Data.SqlClient.SNI.runtime`: 3 files
    - `Microsoft.Extensions.ApiDescription.Server`: `GetDocument.Insider.exe`
    - the three `runtime.win-*.…SqlClient.sni`: 1 file each
- **New since the baseline, additive:** `PackagingAnomalies` (ADR-0031) is empty for all 100.
- **Exit codes:** all 100 exit 3, as in the baseline. With `--no-vulns` the vulnerability status is `NotChecked`,
  which is a completeness caveat, so exit 3 is guaranteed whatever YARA does. A flip would have shown up in
  `YaraScanStatus` and in the stderr caveat ("the YARA malware-signature scan did not complete"), not in the exit
  code. Neither appeared.
- **Cost:**

  | | Now | Baseline |
  | --- | ---: | ---: |
  | Median per package | 3,424 ms | 2,469 ms |
  | Min | 1,675 ms | — |
  | Max | 11,355 ms | 7,594 ms |
  | Total wall clock | 428 s | 298 s |

  The per-package ratio is median 1.40× (range 0.60–2.73×). **The cause is not isolated.** Candidates:
  - concurrent Windows-side load (a reviewer's `dotnet` may have been running);
  - a different WSL kernel (6.18.54.1 vs 6.18.33.2);
  - pipeline stages added since `cc8e6da` (ADR-0030/0031);
  - the package bumps.

  The d7 check itself is a split-and-scan of stderr, negligible against a process launch. Treat this as a
  performance observation for a later dedicated timing run, not a regression claim.
- **Package-version bumps:** this is the first Linux run on the bumped versions (NuGet.Packaging/Protocol/Versioning
  7.9.0, Microsoft.CST.ApplicationInspector.RulesEngine 1.10.2, SharpCompress 0.50.5,
  System.Security.Cryptography.Pkcs 8.0.2, confirmed in the built `Silvergun.CLI.deps.json`).
  - All 100 packages opened, extracted to the same file counts and scanned.
  - No YARA-visible difference.
  - Script-rule findings (RulesEngine) were not part of the baseline, so they are not compared here.
- **Temp-dir leak (pre-existing, not caused by d7):**
  - Every `scan-package` run left a `/tmp/silvergun-yara-<guid>/` directory behind: 103 from this run, one per
    invocation.
  - Each holds `silvergun-rules.yara` (3.5 MB) and `silvergun-rules.yarac` (4.0 MB), so about 7.2 MB per run and
    about 740 MB here.
  - `YaraCliScanner.CompileRules` creates the directory and nothing deletes it. Only the staging dir (`:593`) and
    the individual-scan copy (`:646`) are cleaned up.
  - Package extraction dirs (`/tmp/silvergun/pkg-*`) were all removed (0 left).
  - On a Linux CI agent scanning many packages this grows without bound.
- **Cosmetic, not a defect of the measurement:** `PackageScanner.cs:208` (`:212` in the live tree) formats
  `"{1}. {2} match(es)…"` after an exception message that already ends in `.`. The log reads
  `…are reported.. 1 match(es) found…` (seen in the PC run). Log text only, but the message is user-visible.

## Provenance

- **Corpus:**
  - `%LOCALAPPDATA%\Silvergun\benign-corpus` no longer existed, and neither did `C:\Temp\silvergun-corpus`. Both
    were re-acquired on 2026-10-19, 04:18:10–04:29:31 UTC, with the **existing**
    `BenignCorpusHarness`:
    - The prebuilt Release binary from 2026-08-21 was used. The harness source is unchanged in the working tree;
      `PackageCache.cs` has been unchanged since `b9b32ef`.
    - It ran into its default cache, one package per invocation from single-entry manifests in the baseline TSV's
      order, with a ≥3 s pause after each download.
    - The driver was set to stop on any download failure; none occurred.
  - Package list: the baseline TSV, identical to `data/corpus/benign-top.manifest`.
  - Only the 100 baseline packages were fetched. The earlier 173-file cache (which also held other manifests) was
    not reconstructed.
- **Fetches:** nuget.org's documented v3 API via `NuGet.Protocol` (`FindPackageByIdResource`).
  `NUGET_HTTP_CACHE_PATH` pointed at a fresh scratch dir so the requests could be counted exactly: **202**.
  - 1 service index
  - 1 repository-signatures
  - 100 `PackageBaseAddress` version lists
  - 100 `.nupkg`
  - Average 0.30 req/s, bursts of at most 2 requests per package.
  - No 429, no 403, no challenge.
- **Integrity:**
  - 13/100 `.nupkg` match the SHA-512 NuGet recorded in the local global-packages folder (`.nupkg.sha512`), 0
    mismatches. The other 87 are not in that folder.
  - Re-running the harness over the re-acquired packages reproduced
    `benign-corpus-top100-2026-08-21.md`'s per-package status, TFM and IL finding count on **100/100**.
  - File counts match the baseline on 100/100.
- **Corpus copy:** `C:\Temp\silvergun-corpus\`, 100 `.nupkg`, 87,909,459 bytes, outside the repo, read from WSL as
  `/mnt/c/Temp/silvergun-corpus/`.
- **Licence:** the packages are third-party works distributed by nuget.org under their own licences. Nothing from
  them is committed. This file and the TSV hold only derived counts.
- **Code under test:**
  - HEAD `f348d51` plus the uncommitted working tree as of 2026-10-19T04:20:36Z.
  - `git diff HEAD --binary` SHA-256 `c35dc372011210f13ca7d1b689400949f85adb97a9a41935855104c1bb8a92f6` (153,461
    bytes).
  - 8 untracked files (all under `tests/`), aggregate SHA-256 `3e2be7b4…e709`.
  - The d7 predicate is at `YaraCliScanner.cs:419-423` in that snapshot.
  - By 04:41Z the live tree's tracked diff was `2700e61b…f3b9` (159,105 bytes): Round D in progress (see Scope
    above).
- **Build:**
  - The tree was tar-copied (excluding `.git`, `reference`, `bin`, `obj`) to `~/sg-adr0032-measure`,
    so nothing was built under `/mnt/c`.
  - `dotnet build src/Silvergun.CLI/Silvergun.CLI.csproj -c Release -f net10.0`: 0 errors, 5 warnings (all in
    `ext/` or SourceLink).
  - The restore was satisfied from the WSL global packages folder, which already held the bumped versions.
- **Environment:** WSL2 Ubuntu, kernel 6.18.54.1, .NET SDK 10.0.103, `yara`/`yarac` **4.1.3** (`/usr/bin`), run as
  uid 1000 (not root). `SILVERGUN_YARA_PATH=/usr/bin/yara`, `SILVERGUN_YARAC_PATH` unset (derived).
- **Run:**
  - One child per package from `python3 -I` with a 300 s process-group kill bound.
  - Every child logged `Compiled 310 embedded YARA rule file(s) with yarac`, which only `YaraCliScanner` emits.
  - Start 2026-10-19T04:30:30Z.
- **Git:** `docs/agent/*` is gitignored (`.gitignore:431`), so `git status` does not list these two files.
- **TSV escaping:**
  - `StderrErrorLines` holds the quoted list from the d7 log line (already `YaraPathSafety`-escaped), re-rendered
    ASCII-only: `\` → `\\`, `;` → `\x3b`, other non-printables → `\xNN`/`\uNNNN`.
  - Multiple lines would be `;`-joined.
  - The column is empty on all 100 rows.
