# `--strict` gating-source prevalence via `scan-package` (top-100 corpus, 2026-08-21)

Evidence for `docs/agent/tasks/strict-gate-source-prevalence.md` (M2). **A measurement, not a gate change** —
nothing in `src/`, `--strict`, or any exit code was touched to produce this. Companion to
`benign-corpus-top100-2026-08-21.md` (M1, capability-only, harness methodology, n=78).

## ⚠️ Read this before trusting the YARA row

**The in-process YARA backend is SELECTED on this build (`YaraScannerFactory.BackendAvailable == true`,
`net10.0-windows`, `LibYaraScanner`) but its native dependency fails to load on every single scan.** This
is a THIRD failure mode beyond the two the task spec anticipated (live-and-working vs. `NullYaraScanner`):
a backend that reports itself "available" while silently producing zero findings on every file, forever,
regardless of content.

Reproduced directly (outside the corpus run, same binary) on two different packages:

```
[03:25:23 INF] Compiled 12 embedded backdoor ruleset file(s) for script content scanning.
[03:25:24 WRN] YARA scanning failed for Newtonsoft.Json: Could not load file or assembly
  'C:\Projects\Silvergun\src\Silvergun.CLI\bin\Release\net10.0-windows\runtimes\win-x64\lib\net8.0\libyara.NET.dll'.
  The specified module could not be found.
```
(and identically for `AWSSDK.Core`). Root cause, confirmed by inspecting the publish output: three copies
of the **managed** `libyara.NET.dll` wrapper are deployed (`bin\...\net10.0-windows\libyara.NET.dll`,
`runtimes\win-x64\lib\net8.0\libyara.NET.dll`, `runtimes\win-arm64\lib\net8.0\libyara.NET.dll`) but **no
native `libyara`/`yara64` core binary is deployed anywhere in the output tree** — only unrelated native
DLLs (`Ijwhost.dll`, `Microsoft.DiaSymReader.Native.amd64.dll`). The mixed-mode wrapper cannot load without
its native counterpart, `ScanFile`/`ScanDirectory`'s `catch (Exception ex)` (ADR 0016, by design: never
throws) swallows the failure, and `YaraFindings` comes back empty every time. Because a "real" backend was
selected (not `NullYaraScanner`), `Program.cs`'s own advisory check
(`!noYara && !YaraScannerFactory.BackendAvailable`) **never fires** — a user running `scan-package` without
`--debug` gets no indication whatsoever that YARA never ran. (With `--debug`, the `INF`/`WRN` lines above
print to stdout — but WRN is above the default `Information` threshold, so **the same lines print even
without `--debug`**, just possibly missed by output redirection or interleaving with the JSON stream when
`--json` and `--output` are both used, as in this run — the CLI's own JSON+file stdout path does not
persist them anywhere.)

**⇒ YARA prevalence below is reported as "not measured — backend broken", never as "0%".** This is a
genuine defect (native asset not published for the `net10.0-windows` TFM) and should be routed to
`dotnet-implementer`/`debugger`; it is out of scope for this measurement task to fix (`src/`/`ext/` are
off-limits here). It is **not** a `--strict`-relevant finding in itself (nothing in the gate contract
changed) but it means **the YARA gating source has never actually been exercised by this corpus run, or
arguably by any Windows in-process scan since this defect was introduced.**

## Which scanner ran, precisely

- Build: `Silvergun.CLI` published for `net10.0-windows` (`-f net10.0-windows`, self-built Release), so the
  `#if WINDOWS` in-process path (`LibYaraScanner`) is compiled in and selected — not the cross-platform
  `YaraCliScanner` (`SILVERGUN_YARA_PATH` was unset throughout; that path was not exercised at all).
- Selected but non-functional, as above. Every one of the 100 `scan-package` runs used this same static
  build, so the failure is deterministic and machine-wide, not data-dependent — no re-verification per
  package was needed once reproduced twice independently.

## Method

- CLI: `Silvergun.CLI.exe scan-package <nupkg> --json --strict --depth 0 --output <file>`, one child process
  per package (100 total), exit code and stderr captured, 300s timeout per child (none hit).
- `--depth 0` (default): OSV.dev checked for the package itself + its declared direct dependencies at their
  version-range floor — **not** a transitive resolver-lite walk. Pinned and stated here per the task's
  requirement to record the resolver depth used.
- Rate limit: 1.2s sleep between packages (guardrail; OSV.dev issued no 429/403 in either run — see below).
- `.nupkg` source: the same cache used by M1 (`%LOCALAPPDATA%\Silvergun\benign-corpus\packages`),
  already warm from the 2026-08-20/2026-08-21 harness runs — **zero new downloads** for this task.
- Two full runs for determinism: `m2-run1` (2026-08-21T07:07:28Z–07:15:43Z UTC, package-level `AnalyzedAt`
  range) and `m2-run2` (07:16:07Z–07:23:30Z UTC).
- Driver: an ad hoc PowerShell script kept in the session scratchpad (not committed; not part of `tests/`),
  per the spec's preference to drive the shipped CLI verb directly rather than reimplementing it in a
  harness. No harness or `src` file was touched for M2.

## Child-process health

**All 100 children completed**: 0 timeouts, 0 missing/unwritten JSON reports, in both runs. Exit-code
distribution, identical across both runs:

| Exit code | Meaning | Count |
| --- | --- | ---: |
| 0 | Clean (no gating source fired) | 24 |
| 2 | `--strict` gate tripped (>=1 gating source) | 72 |
| 3 | Analysis incomplete (native-only assemblies produced no report) | 4 |

The 4 exit-3 packages are the same shape: at least one inventoried `.dll`, zero of them analysable —
`Microsoft.Data.SqlClient.SNI.runtime` (3 native files) and the three
`runtime.win-{arm64,x64,x86}.runtime.native.System.Data.SqlClient.sni` packages (1 native file each). This
is expected: these packages ship only native SNI binaries; CCI cannot analyse non-.NET modules, so
`CompletenessAssessment.ForPackage` correctly marks the file "not analysed" rather than silently reading
zero findings as clean.

## Determinism

Field-by-field diff of every non-timing column (`ExitCode`, all six `Has*`/count pairs, `IsComplete`,
`VulnStatus`) across `m2-run1` and `m2-run2`, all 100 packages: **zero differences.** This includes the
vulnerability row — but that is a fact about *this pair of runs*, taken minutes apart against the same
live OSV.dev state, **not a guarantee**. OSV results are point-in-time by construction (ADR 0017): a
future re-run could see a different `Vulnerabilities` count as advisories publish, with no code change on
either side. Everything else (capability, obfuscation, script, YARA, gating-indicator) is a pure function
of the `.nupkg`'s bytes and is reproducible by construction, and was in fact byte-identical here.

## ⚠️ Two denominators — do not mix them

- **M1 denominator = 78** (packages contributing IL data under the harness's single-best-TFM rule).
- **M2 denominator = 100** (every manifest package; `scan-package` always produces *some* report — it
  inventories every `.dll`/`.exe` anywhere in the package across every role/TFM, always scans the
  `.nuspec`, and always runs YARA over the whole extraction directory — so nothing is dropped from the
  denominator the way `no-scannable-tfm` drops a package from M1).

**19 of the 100 packages produced zero scanned assemblies under `scan-package`** (`AssembliesScanned == 0`):
`Microsoft.Data.SqlClient.SNI.runtime`, `Microsoft.NET.Sdk.Android.Manifest-8.0.100`,
`Microsoft.NET.Sdk.Aspire.Manifest-8.0.100`, `Microsoft.NET.Sdk.MacCatalyst.Manifest-8.0.100`,
`Microsoft.NET.Sdk.Maui.Manifest-8.0.100`, `Microsoft.NET.Sdk.iOS.Manifest-8.0.100`,
`Microsoft.NET.Sdk.macOS.Manifest-8.0.100`, `Microsoft.NET.Sdk.tvOS.Manifest-8.0.100`,
`Microsoft.NET.Workload.Emscripten.{Current,net6,net7}.Manifest-8.0.100` (3),
`Microsoft.NET.Workload.Mono.ToolChain.{net6,net7}.Manifest-8.0.100` (2), `Swashbuckle.AspNetCore`,
`runtime.win-{arm64,x64,x86}.runtime.native.System.Data.SqlClient.sni` (3), `xunit` — all ship no
managed `.dll` at all (metapackages / native-only / SDK manifests).

**This is 3 fewer than M1's 22 non-contributors**, because `scan-package`'s wider inventory (every role,
not just `lib/<best-tfm>`) picks up assemblies M1's single-TFM rule rejects:

- `Microsoft.Extensions.ApiDescription.Server` — `no-scannable-tfm` under M1 (no `lib/<tfm>`), but
  `scan-package` found and analysed a `tools/`-role assembly, taking 8976ms (exit 2 — findings present).
- `Microsoft.IdentityModel.Clients.ActiveDirectory` — M1 rejected its offered TFMs (`monoandroid81`,
  `net45`, `netstandard1.3`, `uap10.0.17763`, `xamarinios10` — none is the preferred `net<major.minor>` or
  `netstandard2.0`); `scan-package` has no such preference and analysed whichever `lib/<tfm>` assemblies it
  inventoried.
- `coverlet.collector` — `no-scannable-tfm` under M1 (its payload lives under `build/`/other roles, not
  `lib/`); `scan-package` found and analysed it (16458ms — the single longest scan in the corpus).

One package (`Microsoft.NET.Workload.Mono.ToolChain.Current.Manifest-8.0.100`) has **zero scanned
assemblies but still trips the gate** (exit 2) purely on a `Script`-sourced finding — proof that the
"0 assemblies" and "0 contribution" are not the same thing under `scan-package`; a metapackage with no
managed code can still gate on packaged build-script content alone.

## Table A — per-source benign prevalence (denominator = 100)

| Gating source | Packages with >=1 | Share | Notes |
| --- | ---: | ---: | --- |
| Capability findings (`scan-package`'s own `AllFindings`, ALL assemblies/TFMs/roles) | 67/100 | 67.0% | **Not the same measurement as M1** (78-denominator, single best TFM only) — see the callout below. Do not average or directly diff these two capability numbers. |
| Obfuscation | 29/100 | 29.0% | |
| Script — `Source=Script` (**gates**) | 25/100 | 25.0% | Real script/build-content rule hits (`.ps1`, `.targets`, etc.) |
| Script — `Source=PackageMetadata` (advisory, never gates) | 1/100 | 1.0% | Only `Microsoft.Extensions.Hosting` — a `.nuspec`-content rule hit; excluded from `--strict` today per ADR/precedent already shipped |
| YARA | **not measured** (backend broken — see callout) | — | 0 raw hits recorded, but the backend never successfully executed a single scan; this is not evidence of absence |
| Vulnerabilities (OSV.dev, depth 0, dated snapshot 2026-08-21) | 0/100 | 0.0% | 100/100 `VulnerabilitiesStatus=Completed` (OSV reachable every time, no outage); genuinely zero known CVEs at these pinned exact versions + declared direct deps at range floor. Re-running later could differ — not a constant. |
| Gating indicator findings (ADR 0026: `CallbackDomain`/`DynamicDns`/`CredentialPath`) | 0/100 | 0.0% | Consistent with the existing `indicator-prevalence-top100-2026-08-20.md` finding (0/78 there; here recomputed inside `scan-package` itself, still 0/100) |
| **(any source — what `--strict` does today)** | **72/100** | **72.0%** | Equivalently: 72 of 100 exit code 2, 24 exit 0, 4 exit 3 (incomplete, excluded from the "clean" count on principle but not from this denominator) |

## Table B — candidate gate compositions (the table ADR-0027 is written from)

| Candidate policy | Benign failure rate (of 100) |
| --- | ---: |
| Current (all six sources) | 72/100 = 72.0% |
| Drop capability presence | 46/100 = 46.0% |
| Drop capability presence + obfuscation | 25/100 = 25.0% |
| Only YARA + vulnerabilities + gating indicators | 0/100 = 0.0% (YARA not measured — see above; this row is really "vuln + gating indicator only" given the current environment) |
| Only vulnerabilities + gating indicators (YARA excluded entirely, since it is unmeasured here) | 0/100 = 0.0% |
| Only gating indicator alone (ADR-0026's three categories) | 0/100 = 0.0% |
| Only vulnerabilities alone | 0/100 = 0.0% (dated snapshot) |

Reading this table: **every composition that drops capability+obfuscation+script collapses to the YARA/vuln/
indicator floor, and in this dated snapshot with a broken YARA backend, that floor is 0%.** The entire
72% observed failure rate under the current policy is attributable to capability presence (67%),
obfuscation heuristics (29%) and script rule hits (25%), with heavy overlap (only 26 of the 67
capability-positive packages are *purely* capability-positive with no obfuscation/script co-finding; 68/100
trip capability-or-obfuscation alone). **Dropping capability + obfuscation together already reduces the
failure rate to exactly the `Script`-only share (25%)** — script is therefore the next thing worth
scrutinising if the gate is narrowed, not YARA/vuln/indicator (which currently contribute nothing
measurable to `Table B` at all in this corpus).

## ⚠️ Table C — user-would-accept vs. noise-if-common (never summed together)

| Class | Composition | Benign failure rate |
| --- | --- | ---: |
| **User-would-accept** (a real vuln, a YARA name match, a high-precision gating indicator) | YARA (unmeasured) or Vulnerabilities or Gating indicator | **0/100 = 0.0%** — but this reflects a dated OSV snapshot AND a broken YARA backend, not a validated "the signal-only gate is quiet." Only the indicator row (0/100, ADR-0026-vetted, no plausible benign use for its three categories) and the vuln row (dated, but OSV genuinely reachable and genuinely empty) are real zeros here; the YARA component of this row is a non-result, not a zero. |
| **Noise-if-common** (capability presence, obfuscation heuristics, script rule heuristics) | Capability or Obfuscation or Script(`Source=Script`) | **72/100 = 72.0%** — this is effectively the WHOLE observed gate footprint today. Every single one of the 72 packages that fails `--strict` in this corpus fails it on a noise-class source; **none fails purely on a source a user would accept as a real positive.** |

**This is the single most load-bearing number in this measurement**: today, `--strict` on this corpus fails
100% of its 72 failing packages for noise-class reasons and 0% for reasons a user would accept as a genuine
signal. That is the precise inverse of a healthy gate, and it is the strongest evidence yet (stronger than
the n=25 96% capability figure it supersedes, and consistent with ADR-0026's own framing of capability
presence as "measurably useless at 96%") that capability presence, and very likely obfuscation and
undifferentiated script-rule hits, should not gate `--strict` in their current form.

## Honesty checklist

- Both denominators stated throughout (78 for anything drawing on M1's harness data; 100 for every M2 row/table).
- Every one of the 22 M1 non-contributors and all 19 M2 zero-assembly packages named above, with the 3-package
  discrepancy between the two sets explained by mechanism (wider `scan-package` inventory scope), not asserted.
- Determinism: confirmed byte-identical (all non-timing fields) across two independent full runs for
  capability, obfuscation, script, YARA(-non-result), and gating-indicator data. The vulnerability row also
  matched across these two runs, but is stated as non-reproducible by construction, not as a fourth
  deterministic row — a future run is not guaranteed to match either the 2026-08-21 run or a later one.
- No `scan-package` child exited non-zero unexpectedly, timed out, or produced no report — 100/100 completed
  in both runs; the only non-zero codes seen (2, 3) are the CLI's documented, expected policy/incompleteness
  codes, not tooling failures.
- Exact command line: `Silvergun.CLI.exe scan-package <nupkg-path> --json --strict --depth 0 --output <path>`,
  built via `dotnet build src/Silvergun.CLI/Silvergun.CLI.csproj -c Release -f net10.0-windows`. Cache root
  `%LOCALAPPDATA%\Silvergun\benign-corpus` (shared with M1; nothing re-fetched). Dates:
  run1 2026-08-21T07:07–07:15 UTC, run2 07:16–07:23 UTC.
- Per-package raw data: `scan-package-prevalence-top100-2026-08-21.tsv` (this directory) — one row per
  manifest package with every `Has*`/count/status field used to build the tables above.
