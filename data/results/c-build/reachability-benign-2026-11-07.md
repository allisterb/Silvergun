# Reachability R2b - the benign-corpus measurement (2026-11-07)

**A measurement, not a feature** (`docs/agent/tasks/reachability-r2.md`, `reachability-r2b.md`). It changes no CLI,
report, gate or map. The expectations it judges (E1, E2) and their thresholds were pre-registered in the specs before
any corpus run. A reachable capability is possible, not proven; a benign package's label is "overwhelmingly not
malware" by download count, not by audit.

## 1. Parameters

| Parameter | Value |
| --- | --- |
| Manifest | `c-build.manifest` |
| Manifest hash (sha256 of normalized `id,version` list) | `cd9ade3633e1e3eb87e51a887afd08550769a7043e12b8e10ce148e4b74a6af0` |
| Manifest entries | 50 |
| Cache root (read only; no download in this mode) | `%LOCALAPPDATA%\Silvergun\benign-corpus` |
| Harness build: `git describe --always --dirty --abbrev=40`, `-dirty` also when `src/`, `ext/` or `tests/` has untracked files | `3c5da420eb59653311f8138d3e39baf7057d57e8` |
| Harness build: sha256 of the output directory's top-level assemblies | `8d6e3f9e66e8421a31817632f43d6a77bac70cdcd4fe63522348056ca6ccb613` |
| Date (`--date`) | 2026-11-07 |
| Child timeout | 600 s |
| Status: scanned / graph-failed / no-assemblies / crashed / timeout / incomplete / not-cached | 50 / 0 / 0 / 0 / 0 / 0 / 0 |
| Measured packages with a lib TFM (`TfmSelection`) | 2 |
| Unmeasured floor packages (crashed / timeout / incomplete): in P-all / in P-lib (a lib TFM by `TfmSelection` over the `.nupkg`, or unknown) | 0 / 0 |
| **P-lib denominator** (the P-lib folder is one either side read: graph or presence) | **2** |
| **P-all denominator** (some folder is one either side read: graph or presence) | **50** |
| Names cut at 1024 chars (amendment a5; distinct per folder, summed over every folder; per folder in section 12) | **22** (some reported names are bounded, not whole) |
| Signal capabilities | FileSystem, Network, ProcessExecution, Registry, NativeInterop |
| Trigger classes | LoadTime, HostContract, TypeInitializer, Finalizer, NativeEntry |
| Judged in this run (P-lib and P-all, both must pass) | TypeInitializer, Finalizer, NativeEntry |
| Judged by `--combine` only (P-all over C100 and C-build) | LoadTime, HostContract |
| Labels (each (class, label) its own verdict) | ChaOnly, Direct |
| Presence oracle (`--oracle`) | `presence-oracle-2026-11-06.tsv` |
| Judged when presence is at least | 3 packages in the population |
| E1 | per judged signal capability: reach share (ChaOnly) <= 0.5 x presence share |
| E2 | packages with a class profile holding >= 2 distinct signal capabilities (Unseen-inclusive) <= 10% |

**Populations.** P-lib: per package, the folder `lib/<TfmSelection.Choose>` (highest `net<x>.<y>`, else
`netstandard2.0`), the presence baseline's folder. P-all: every folder either side read (a built graph, or a
graph-failed folder presence scanned, which makes its package a floor package); a package counts
for (class, capability) when any of its folders does. A crashed, timed-out or incomplete package is a floor
package with unmeasured presence and reach: in P-all always, in P-lib when its `.nupkg` has a lib TFM (or its file
list is unreadable, so that is unknown), and in no role table. Presence is the raw-CCI `CapabilityAnalysis`, all finding
kinds, over each folder's assemblies, recomputed in the same child. Reach share = packages where a root of the
class reaches the capability at ChaOnly (`CapabilityReach.Roots > 0`); Bound share uses `Bound > 0`; Direct share
uses `Direct > 0`, the roots reaching it with no `Ldftn`, `Ldvirtftn` or `LoadToken` edge (ADR 0037 amendment a2).

### Per package

| Package | Version | Status | Lib TFM | Folders | Loaded folders | Roles | P-lib |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| Microsoft.EntityFrameworkCore.Analyzers | 10.0.14 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.CodeAnalysis.Analyzers | 5.9.0 | scanned | - | 28 | 28 | analyzers | no |
| xunit.analyzers | 2.2.0 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.AspNetCore.Components.Analyzers | 10.0.14 | scanned | - | 1 | 1 | analyzers | no |
| StyleCop.Analyzers | 1.1.118 | scanned | - | 8 | 8 | analyzers | no |
| coverlet.msbuild | 10.1.0 | scanned | - | 7 | 7 | tasks | no |
| Microsoft.AspNetCore.Razor.Design | 2.3.13 | scanned | - | 5 | 5 | tasks, tools | no |
| Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | scanned | - | 3 | 3 | tools | no |
| NUnit.Analyzers | 4.15.0 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.NET.ILLink.Tasks | 10.0.14 | scanned | - | 3 | 3 | analyzers, tools | no |
| Microsoft.AspNetCore.Mvc.Analyzers | 2.3.13 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.Azure.Functions.Analyzers | 1.0.0 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.VisualStudio.Threading.Analyzers | 18.12.1 | scanned | - | 28 | 28 | analyzers | no |
| Microsoft.Build.Tasks.Git | 10.0.403 | scanned | - | 28 | 28 | tools | no |
| StyleCop.Analyzers.Unstable | 1.2.0.556 | scanned | - | 8 | 8 | analyzers | no |
| Microsoft.SourceLink.Common | 10.0.403 | scanned | - | 28 | 28 | tools | no |
| Microsoft.Net.Compilers | 4.2.0 | scanned | - | 14 | 14 | tools | no |
| dotnet-reportgenerator-globaltool | 5.5.12 | scanned | - | 6 | 6 | tools | no |
| SonarAnalyzer.CSharp | 10.35.0.4138 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.Azure.Functions.Worker.Sdk.Generators | 1.4.0 | scanned | - | 1 | 1 | analyzers | no |
| NSwag.MSBuild | 14.7.1 | scanned | - | 4 | 4 | tools | no |
| Microsoft.Azure.Functions.Worker.Sdk.Analyzers | 1.2.2 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.SourceLink.GitHub | 10.0.403 | scanned | - | 28 | 28 | tools | no |
| MessagePackAnalyzer | 3.1.12 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.CodeAnalysis.NetAnalyzers | 10.0.403 | scanned | - | 28 | 28 | analyzers | no |
| SpecFlow.Tools.MsBuild.Generation | 3.9.74 | scanned | - | 4 | 4 | tasks | no |
| MSTest.Analyzers | 4.5.2 | scanned | - | 28 | 28 | analyzers | no |
| dotnet-sonarscanner | 12.1.0 | scanned | - | 1 | 1 | tools | no |
| Microsoft.CodeQuality.Analyzers | 3.3.2 | scanned | - | 28 | 28 | analyzers | no |
| Microsoft.NetCore.Analyzers | 3.3.2 | scanned | - | 28 | 28 | analyzers | no |
| Microsoft.NetFramework.Analyzers | 3.3.2 | scanned | - | 28 | 28 | analyzers | no |
| Roslynator.Analyzers | 5.0.1 | scanned | - | 3 | 3 | analyzers | no |
| ReportGenerator | 5.5.12 | scanned | - | 7 | 7 | tools | no |
| Microsoft.CodeAnalysis.VersionCheckAnalyzer | 3.3.2 | scanned | - | 14 | 14 | analyzers | no |
| Microsoft.Azure.Functions.Worker.Extensions.Http.AspNetCore.Analyzers | 1.0.4 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.CodeAnalysis.BannedApiAnalyzers | 5.6.0 | scanned | - | 28 | 28 | analyzers | no |
| Microsoft.Extensions.ApiDescription.Client | 10.0.14 | scanned | - | 1 | 1 | tasks | no |
| NSubstitute.Analyzers.CSharp | 1.0.17 | scanned | - | 1 | 1 | analyzers | no |
| Riok.Mapperly | 4.3.1 | scanned | netstandard2.0 | 8 | 8 | analyzers, lib | yes |
| Microsoft.Azure.WebJobs.Extensions.DurableTask.Analyzers | 0.5.0 | scanned | - | 1 | 1 | analyzers | no |
| Aspire.Hosting.AppHost | 13.6.4 | scanned | net10.0 | 6 | 6 | analyzers, lib, tools | yes |
| GraphQL.Analyzers | 8.8.5 | scanned | - | 1 | 1 | analyzers | no |
| OpenCover | 4.7.1221 | scanned | - | 6 | 4 | build, tools | no |
| Meziantou.Analyzer | 3.0.321 | scanned | - | 5 | 5 | analyzers | no |
| Reqnroll.Tools.MsBuild.Generation | 3.3.4 | scanned | - | 2 | 2 | build | no |
| Xamarin.Build.Download | 0.11.6 | scanned | - | 2 | 2 | build, buildTransitive | no |
| Xamarin.AndroidX.Migration | 1.0.10 | scanned | - | 2 | 2 | build, buildTransitive | no |
| AsyncFixer | 2.1.0 | scanned | - | 1 | 1 | analyzers | no |
| Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | scanned | - | 35 | 35 | buildTransitive | no |
| Microsoft.SourceLink.AzureRepos.Git | 10.0.403 | scanned | - | 28 | 28 | tools | no |

## 2. Regression oracle (P-lib presence against `presence-oracle-2026-11-06.tsv`)

P-lib presence, every finding kind, over the P-lib folders' `.dll` assemblies (the baseline's rule), against the
presence oracle (`--oracle`; the file's header names the report it was copied from): the denominator, assemblies,
methods analysed, findings, the per-capability package counts and totals, and per package its TFM, assemblies,
methods and findings per capability. R2 used `presence-oracle-2026-08-21.tsv`; R2b's default, on the S2 map, is
`presence-oracle-2026-11-06.tsv`. A crashed, timed-out or
incomplete package in P-lib (a lib TFM, or an unknown one) has no measured presence, so it always makes the oracle
a MISMATCH, and the run then gives no verdict (by design: R2's pre-registered rule, the conservative direction).

**Result: MATCH on the 0 package(s) both hold; totals not applicable** (this manifest's hash is not the oracle's `9e5635c320485af7b86e5656860465e4c1bc5ba753e7771336e7d677ac8838a6`).

No P-lib folder holds a non-`.dll` assembly, so P-lib presence and the oracle's presence are the same set.

**No verdict: not comparable (oracle not applicable: another manifest).** Every E1 and E2 cell and every class verdict below reads so; the shares are shown, but nothing may be concluded from them (spec, "No verdict without a comparable population").

## 3. E1 - trigger reach shares against presence

Judged symmetrically. A floor package has Partial reachability, an assembly only presence saw (graph-failed folders
included), or an assembly only the graph loaded, or its child crashed, timed out or stopped short (presence and
reach unmeasured); it stays in the denominator. A cell **fails** only in its best
case: reach from built graphs, against presence from every scoped folder plus each floor package whose presence
could not be measured. It **passes** only in its worst case: every floor package not already reaching counted as
reaching, against presence from the graph-loaded assemblies only. Otherwise it is **Floor**, not a pass.

**Unmeasured packages and the verdict.** A crashed, timed-out or incomplete package in P-lib (its `.nupkg` has a
lib TFM, or whether it has one is unknown) makes the regression oracle a MISMATCH (section 2), so no verdict is
given at all. Of the unmeasured packages, therefore, only the P-all floors of packages with no lib TFM ever feed a
verdict; the P-lib floor rule is applied, but cannot decide one.

**Labels and populations (R2b).** Each trigger class is judged at two labels, each (class, label) its own verdict:
**ChaOnly**, R2's cell (reach = `CapabilityReach.Roots > 0`), and **Direct** (reach counts only the roots reaching
the capability without a deferred edge (Ldftn, Ldvirtftn, LoadToken), `CapabilityReach.Direct > 0`; E2 counts only the profiles' Direct sets).
TypeInitializer, Finalizer, NativeEntry are judged on this run, in P-lib and P-all: a (class,
label) passes only if it passes in both. LoadTime and HostContract are judged on P-all only, over C100
and C-build as one population, by `--combine` alone: here their cells are data and read "judged by --combine",
never a verdict.

### P-lib (denominator 2; floor packages 0)

#### P-lib - ChaOnly

| Signal capability | Presence | LoadTime reach | LoadTime Bound | LoadTime E1 | HostContract reach | HostContract Bound | HostContract E1 | TypeInitializer reach | TypeInitializer Bound | TypeInitializer E1 | Finalizer reach | Finalizer Bound | Finalizer E1 | NativeEntry reach | NativeEntry Bound | NativeEntry E1 |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | ---: | --- | ---: | ---: | --- | ---: | ---: | --- |
| FileSystem | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |
| Network | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |
| ProcessExecution | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |
| Registry | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |
| NativeInterop | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |

| Class | Roots | E1 |
| --- | ---: | --- |
| LoadTime | 0 | judged by --combine |
| HostContract | 0 | judged by --combine |
| TypeInitializer | 1 | not comparable (oracle not applicable: another manifest) |
| Finalizer | 0 | not comparable (oracle not applicable: another manifest) |
| NativeEntry | 0 | not comparable (oracle not applicable: another manifest) |

#### P-lib - Direct

| Signal capability | Presence | LoadTime Direct reach | LoadTime E1 | HostContract Direct reach | HostContract E1 | TypeInitializer Direct reach | TypeInitializer E1 | Finalizer Direct reach | Finalizer E1 | NativeEntry Direct reach | NativeEntry E1 |
| --- | ---: | ---: | --- | ---: | --- | ---: | --- | ---: | --- | ---: | --- |
| FileSystem | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |
| Network | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |
| ProcessExecution | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |
| Registry | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |
| NativeInterop | 0/2 (0.0%) | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | judged by --combine | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/2 (0.0%) | not comparable (oracle not applicable: another manifest) |

| Class | Roots | E1 |
| --- | ---: | --- |
| LoadTime | 0 | judged by --combine |
| HostContract | 0 | judged by --combine |
| TypeInitializer | 1 | not comparable (oracle not applicable: another manifest) |
| Finalizer | 0 | not comparable (oracle not applicable: another manifest) |
| NativeEntry | 0 | not comparable (oracle not applicable: another manifest) |

### P-all (denominator 50; floor packages 0)

#### P-all - ChaOnly

| Signal capability | Presence | LoadTime reach | LoadTime Bound | LoadTime E1 | HostContract reach | HostContract Bound | HostContract E1 | TypeInitializer reach | TypeInitializer Bound | TypeInitializer E1 | Finalizer reach | Finalizer Bound | Finalizer E1 | NativeEntry reach | NativeEntry Bound | NativeEntry E1 |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | ---: | --- | ---: | ---: | --- | ---: | ---: | --- |
| FileSystem | 28/50 (56.0%) | 0/50 (0.0%) | 0/50 (0.0%) | judged by --combine | 19/50 (38.0%) | 19/50 (38.0%) | judged by --combine | 18/50 (36.0%) | 10/50 (20.0%) | not comparable (oracle not applicable: another manifest) | 10/50 (20.0%) | 5/50 (10.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |
| Network | 11/50 (22.0%) | 0/50 (0.0%) | 0/50 (0.0%) | judged by --combine | 6/50 (12.0%) | 3/50 (6.0%) | judged by --combine | 8/50 (16.0%) | 4/50 (8.0%) | not comparable (oracle not applicable: another manifest) | 6/50 (12.0%) | 1/50 (2.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |
| ProcessExecution | 17/50 (34.0%) | 0/50 (0.0%) | 0/50 (0.0%) | judged by --combine | 9/50 (18.0%) | 7/50 (14.0%) | judged by --combine | 5/50 (10.0%) | 3/50 (6.0%) | not comparable (oracle not applicable: another manifest) | 3/50 (6.0%) | 1/50 (2.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |
| Registry | 4/50 (8.0%) | 0/50 (0.0%) | 0/50 (0.0%) | judged by --combine | 2/50 (4.0%) | 2/50 (4.0%) | judged by --combine | 2/50 (4.0%) | 1/50 (2.0%) | not comparable (oracle not applicable: another manifest) | 2/50 (4.0%) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |
| NativeInterop | 17/50 (34.0%) | 0/50 (0.0%) | 0/50 (0.0%) | judged by --combine | 12/50 (24.0%) | 6/50 (12.0%) | judged by --combine | 14/50 (28.0%) | 8/50 (16.0%) | not comparable (oracle not applicable: another manifest) | 11/50 (22.0%) | 4/50 (8.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |

| Class | Roots | E1 |
| --- | ---: | --- |
| LoadTime | 5 | judged by --combine |
| HostContract | 47510 | judged by --combine |
| TypeInitializer | 25773 | not comparable (oracle not applicable: another manifest) |
| Finalizer | 119 | not comparable (oracle not applicable: another manifest) |
| NativeEntry | 0 | not comparable (oracle not applicable: another manifest) |

#### P-all - Direct

| Signal capability | Presence | LoadTime Direct reach | LoadTime E1 | HostContract Direct reach | HostContract E1 | TypeInitializer Direct reach | TypeInitializer E1 | Finalizer Direct reach | Finalizer E1 | NativeEntry Direct reach | NativeEntry E1 |
| --- | ---: | ---: | --- | ---: | --- | ---: | --- | ---: | --- | ---: | --- |
| FileSystem | 28/50 (56.0%) | 0/50 (0.0%) | judged by --combine | 19/50 (38.0%) | judged by --combine | 16/50 (32.0%) | not comparable (oracle not applicable: another manifest) | 10/50 (20.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |
| Network | 11/50 (22.0%) | 0/50 (0.0%) | judged by --combine | 6/50 (12.0%) | judged by --combine | 8/50 (16.0%) | not comparable (oracle not applicable: another manifest) | 6/50 (12.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |
| ProcessExecution | 17/50 (34.0%) | 0/50 (0.0%) | judged by --combine | 9/50 (18.0%) | judged by --combine | 5/50 (10.0%) | not comparable (oracle not applicable: another manifest) | 3/50 (6.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |
| Registry | 4/50 (8.0%) | 0/50 (0.0%) | judged by --combine | 2/50 (4.0%) | judged by --combine | 2/50 (4.0%) | not comparable (oracle not applicable: another manifest) | 2/50 (4.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |
| NativeInterop | 17/50 (34.0%) | 0/50 (0.0%) | judged by --combine | 12/50 (24.0%) | judged by --combine | 14/50 (28.0%) | not comparable (oracle not applicable: another manifest) | 11/50 (22.0%) | not comparable (oracle not applicable: another manifest) | 0/50 (0.0%) | not comparable (oracle not applicable: another manifest) |

| Class | Roots | E1 |
| --- | ---: | --- |
| LoadTime | 5 | judged by --combine |
| HostContract | 47510 | judged by --combine |
| TypeInitializer | 25773 | not comparable (oracle not applicable: another manifest) |
| Finalizer | 119 | not comparable (oracle not applicable: another manifest) |
| NativeEntry | 0 | not comparable (oracle not applicable: another manifest) |

### Per-class verdict (a fail of E1 or E2 in either population = does not discriminate; any Floor = undecided)

| Class | Label | P-lib E1 | P-lib E2 | P-all E1 | P-all E2 | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| LoadTime | ChaOnly | judged by --combine | judged by --combine | judged by --combine | judged by --combine | judged by --combine |
| LoadTime | Direct | judged by --combine | judged by --combine | judged by --combine | judged by --combine | judged by --combine |
| HostContract | ChaOnly | judged by --combine | judged by --combine | judged by --combine | judged by --combine | judged by --combine |
| HostContract | Direct | judged by --combine | judged by --combine | judged by --combine | judged by --combine | judged by --combine |
| TypeInitializer | ChaOnly | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) |
| TypeInitializer | Direct | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) |
| Finalizer | ChaOnly | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) |
| Finalizer | Direct | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) |
| NativeEntry | ChaOnly | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) |
| NativeEntry | Direct | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) | not comparable (oracle not applicable: another manifest) |

## 4. E2 - trigger compositions

Packages with a profile (`ReachProfile`) of the class holding two or more distinct signal capabilities. The judged
column counts every such profile; the next two split it by whether the profile also reaches Unseen. Floor packages
are those not counted whose class profiles were cut at 64, or whose reaches are a floor; E2 fails when
`10 x counted > denominator`, passes only when `10 x (counted + floor) <= denominator`, and is otherwise Floor. At
Direct a profile counts by its Direct capability set (`ReachProfile.DirectCapabilities`, `DirectUnseen`).

### P-lib (denominator 2)

| Class | Label | Roots | >= 2 signals (Unseen-inclusive, judged) | Without Unseen | With Unseen | Class profiles cut at 64 (packages) | Floor packages | E2 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| LoadTime | ChaOnly | 0 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | judged by --combine |
| LoadTime | Direct | 0 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | judged by --combine |
| HostContract | ChaOnly | 0 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | judged by --combine |
| HostContract | Direct | 0 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | judged by --combine |
| TypeInitializer | ChaOnly | 1 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| TypeInitializer | Direct | 1 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| Finalizer | ChaOnly | 0 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| Finalizer | Direct | 0 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| NativeEntry | ChaOnly | 0 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| NativeEntry | Direct | 0 | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |

### P-all (denominator 50)

| Class | Label | Roots | >= 2 signals (Unseen-inclusive, judged) | Without Unseen | With Unseen | Class profiles cut at 64 (packages) | Floor packages | E2 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| LoadTime | ChaOnly | 5 | 0/50 (0.0%) | 0/50 (0.0%) | 0/50 (0.0%) | 0 | 0 | judged by --combine |
| LoadTime | Direct | 5 | 0/50 (0.0%) | 0/50 (0.0%) | 0/50 (0.0%) | 0 | 0 | judged by --combine |
| HostContract | ChaOnly | 47510 | 14/50 (28.0%) | 13/50 (26.0%) | 4/50 (8.0%) | 0 | 0 | judged by --combine |
| HostContract | Direct | 47510 | 14/50 (28.0%) | 13/50 (26.0%) | 4/50 (8.0%) | 0 | 0 | judged by --combine |
| TypeInitializer | ChaOnly | 25773 | 13/50 (26.0%) | 10/50 (20.0%) | 6/50 (12.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| TypeInitializer | Direct | 25773 | 13/50 (26.0%) | 10/50 (20.0%) | 6/50 (12.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| Finalizer | ChaOnly | 119 | 10/50 (20.0%) | 7/50 (14.0%) | 4/50 (8.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| Finalizer | Direct | 119 | 10/50 (20.0%) | 7/50 (14.0%) | 4/50 (8.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| NativeEntry | ChaOnly | 0 | 0/50 (0.0%) | 0/50 (0.0%) | 0/50 (0.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |
| NativeEntry | Direct | 0 | 0/50 (0.0%) | 0/50 (0.0%) | 0/50 (0.0%) | 0 | 0 | not comparable (oracle not applicable: another manifest) |

## 5. Class x capability reach shares

Cells are `share (packages)` over the stated denominator. Presence has no Unseen column. A role table counts only
that role's folders, over the packages that have one. "Unmeasured" is how many packages of the denominator
crashed, timed out or stopped short: they are counted in it, but contribute no presence or reach. Direct counts
`CapabilityReach.Direct > 0`: a root reaching the sink with no deferred edge (Ldftn, Ldvirtftn, LoadToken).

### P-lib - ChaOnly (denominator 2; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| TypeInitializer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Finalizer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Hidden | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |

### P-lib - Bound (denominator 2; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| TypeInitializer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Finalizer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Hidden | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |

### P-lib - Direct (denominator 2; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| TypeInitializer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Finalizer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Hidden | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |

### P-all - ChaOnly (denominator 50; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 56.0% (28) | 22.0% (11) | 34.0% (17) | 8.0% (4) | 68.0% (34) | 60.0% (30) | 34.0% (17) | 40.0% (20) | 64.0% (32) | 46.0% (23) | 48.0% (24) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 38.0% (19) | 12.0% (6) | 18.0% (9) | 4.0% (2) | 56.0% (28) | 48.0% (24) | 24.0% (12) | 30.0% (15) | 58.0% (29) | 36.0% (18) | 38.0% (19) | 10.0% (5) |
| TypeInitializer | 36.0% (18) | 16.0% (8) | 10.0% (5) | 4.0% (2) | 44.0% (22) | 56.0% (28) | 28.0% (14) | 36.0% (18) | 46.0% (23) | 38.0% (19) | 48.0% (24) | 14.0% (7) |
| Finalizer | 20.0% (10) | 12.0% (6) | 6.0% (3) | 4.0% (2) | 20.0% (10) | 20.0% (10) | 22.0% (11) | 20.0% (10) | 20.0% (10) | 18.0% (9) | 22.0% (11) | 8.0% (4) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 54.0% (27) | 18.0% (9) | 28.0% (14) | 4.0% (2) | 62.0% (31) | 50.0% (25) | 30.0% (15) | 38.0% (19) | 58.0% (29) | 44.0% (22) | 44.0% (22) | 14.0% (7) |
| PublicContract | 42.0% (21) | 20.0% (10) | 28.0% (14) | 4.0% (2) | 60.0% (30) | 56.0% (28) | 34.0% (17) | 40.0% (20) | 52.0% (26) | 42.0% (21) | 48.0% (24) | 14.0% (7) |
| Hidden | 54.0% (27) | 20.0% (10) | 30.0% (15) | 4.0% (2) | 64.0% (32) | 58.0% (29) | 34.0% (17) | 38.0% (19) | 64.0% (32) | 46.0% (23) | 48.0% (24) | 14.0% (7) |

### P-all - Bound (denominator 50; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 56.0% (28) | 22.0% (11) | 34.0% (17) | 8.0% (4) | 68.0% (34) | 60.0% (30) | 34.0% (17) | 40.0% (20) | 64.0% (32) | 46.0% (23) | 48.0% (24) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 38.0% (19) | 6.0% (3) | 14.0% (7) | 4.0% (2) | 50.0% (25) | 28.0% (14) | 12.0% (6) | 18.0% (9) | 46.0% (23) | 12.0% (6) | 24.0% (12) | 4.0% (2) |
| TypeInitializer | 20.0% (10) | 8.0% (4) | 6.0% (3) | 2.0% (1) | 30.0% (15) | 44.0% (22) | 16.0% (8) | 24.0% (12) | 42.0% (21) | 20.0% (10) | 32.0% (16) | 8.0% (4) |
| Finalizer | 10.0% (5) | 2.0% (1) | 2.0% (1) | 0.0% (0) | 6.0% (3) | 2.0% (1) | 8.0% (4) | 0.0% (0) | 0.0% (0) | 6.0% (3) | 8.0% (4) | 2.0% (1) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 54.0% (27) | 16.0% (8) | 28.0% (14) | 4.0% (2) | 60.0% (30) | 44.0% (22) | 28.0% (14) | 38.0% (19) | 58.0% (29) | 38.0% (19) | 42.0% (21) | 14.0% (7) |
| PublicContract | 42.0% (21) | 20.0% (10) | 22.0% (11) | 4.0% (2) | 54.0% (27) | 54.0% (27) | 28.0% (14) | 36.0% (18) | 52.0% (26) | 42.0% (21) | 48.0% (24) | 14.0% (7) |
| Hidden | 54.0% (27) | 20.0% (10) | 30.0% (15) | 4.0% (2) | 62.0% (31) | 58.0% (29) | 34.0% (17) | 38.0% (19) | 64.0% (32) | 46.0% (23) | 48.0% (24) | 14.0% (7) |

### P-all - Direct (denominator 50; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 56.0% (28) | 22.0% (11) | 34.0% (17) | 8.0% (4) | 68.0% (34) | 60.0% (30) | 34.0% (17) | 40.0% (20) | 64.0% (32) | 46.0% (23) | 48.0% (24) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 38.0% (19) | 12.0% (6) | 18.0% (9) | 4.0% (2) | 54.0% (27) | 38.0% (19) | 24.0% (12) | 28.0% (14) | 46.0% (23) | 34.0% (17) | 38.0% (19) | 10.0% (5) |
| TypeInitializer | 32.0% (16) | 16.0% (8) | 10.0% (5) | 4.0% (2) | 42.0% (21) | 46.0% (23) | 28.0% (14) | 36.0% (18) | 42.0% (21) | 38.0% (19) | 44.0% (22) | 14.0% (7) |
| Finalizer | 20.0% (10) | 12.0% (6) | 6.0% (3) | 4.0% (2) | 18.0% (9) | 18.0% (9) | 22.0% (11) | 18.0% (9) | 18.0% (9) | 18.0% (9) | 22.0% (11) | 8.0% (4) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 52.0% (26) | 16.0% (8) | 28.0% (14) | 4.0% (2) | 60.0% (30) | 40.0% (20) | 30.0% (15) | 38.0% (19) | 44.0% (22) | 44.0% (22) | 44.0% (22) | 14.0% (7) |
| PublicContract | 42.0% (21) | 20.0% (10) | 28.0% (14) | 4.0% (2) | 58.0% (29) | 46.0% (23) | 34.0% (17) | 40.0% (20) | 42.0% (21) | 42.0% (21) | 48.0% (24) | 14.0% (7) |
| Hidden | 54.0% (27) | 20.0% (10) | 30.0% (15) | 4.0% (2) | 64.0% (32) | 58.0% (29) | 34.0% (17) | 38.0% (19) | 64.0% (32) | 46.0% (23) | 48.0% (24) | 14.0% (7) |

### P-all, role analyzers - ChaOnly (denominator 31; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 32.3% (10) | 3.2% (1) | 6.5% (2) | 0.0% (0) | 51.6% (16) | 51.6% (16) | 6.5% (2) | 16.1% (5) | 54.8% (17) | 19.4% (6) | 22.6% (7) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 9.7% (3) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 41.9% (13) | 45.2% (14) | 0.0% (0) | 12.9% (4) | 54.8% (17) | 12.9% (4) | 16.1% (5) | 3.2% (1) |
| TypeInitializer | 9.7% (3) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 12.9% (4) | 45.2% (14) | 0.0% (0) | 16.1% (5) | 25.8% (8) | 9.7% (3) | 19.4% (6) | 3.2% (1) |
| Finalizer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 29.0% (9) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 41.9% (13) | 35.5% (11) | 0.0% (0) | 12.9% (4) | 45.2% (14) | 12.9% (4) | 16.1% (5) | 3.2% (1) |
| PublicContract | 12.9% (4) | 0.0% (0) | 6.5% (2) | 0.0% (0) | 38.7% (12) | 41.9% (13) | 6.5% (2) | 16.1% (5) | 35.5% (11) | 12.9% (4) | 19.4% (6) | 3.2% (1) |
| Hidden | 32.3% (10) | 3.2% (1) | 6.5% (2) | 0.0% (0) | 45.2% (14) | 48.4% (15) | 6.5% (2) | 16.1% (5) | 54.8% (17) | 19.4% (6) | 19.4% (6) | 3.2% (1) |

### P-all, role analyzers - Bound (denominator 31; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 32.3% (10) | 3.2% (1) | 6.5% (2) | 0.0% (0) | 51.6% (16) | 51.6% (16) | 6.5% (2) | 16.1% (5) | 54.8% (17) | 19.4% (6) | 22.6% (7) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 9.7% (3) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 38.7% (12) | 29.0% (9) | 0.0% (0) | 3.2% (1) | 51.6% (16) | 3.2% (1) | 12.9% (4) | 0.0% (0) |
| TypeInitializer | 9.7% (3) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 9.7% (3) | 35.5% (11) | 0.0% (0) | 16.1% (5) | 22.6% (7) | 9.7% (3) | 6.5% (2) | 3.2% (1) |
| Finalizer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 29.0% (9) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 38.7% (12) | 25.8% (8) | 0.0% (0) | 12.9% (4) | 45.2% (14) | 6.5% (2) | 12.9% (4) | 3.2% (1) |
| PublicContract | 12.9% (4) | 0.0% (0) | 6.5% (2) | 0.0% (0) | 35.5% (11) | 38.7% (12) | 6.5% (2) | 9.7% (3) | 35.5% (11) | 12.9% (4) | 19.4% (6) | 3.2% (1) |
| Hidden | 32.3% (10) | 3.2% (1) | 6.5% (2) | 0.0% (0) | 38.7% (12) | 48.4% (15) | 6.5% (2) | 16.1% (5) | 54.8% (17) | 19.4% (6) | 19.4% (6) | 3.2% (1) |

### P-all, role analyzers - Direct (denominator 31; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 32.3% (10) | 3.2% (1) | 6.5% (2) | 0.0% (0) | 51.6% (16) | 51.6% (16) | 6.5% (2) | 16.1% (5) | 54.8% (17) | 19.4% (6) | 22.6% (7) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 9.7% (3) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 38.7% (12) | 25.8% (8) | 0.0% (0) | 9.7% (3) | 35.5% (11) | 9.7% (3) | 16.1% (5) | 3.2% (1) |
| TypeInitializer | 3.2% (1) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 9.7% (3) | 29.0% (9) | 0.0% (0) | 16.1% (5) | 19.4% (6) | 9.7% (3) | 12.9% (4) | 3.2% (1) |
| Finalizer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 25.8% (8) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 38.7% (12) | 19.4% (6) | 0.0% (0) | 12.9% (4) | 22.6% (7) | 12.9% (4) | 16.1% (5) | 3.2% (1) |
| PublicContract | 12.9% (4) | 0.0% (0) | 6.5% (2) | 0.0% (0) | 35.5% (11) | 25.8% (8) | 6.5% (2) | 16.1% (5) | 19.4% (6) | 12.9% (4) | 19.4% (6) | 3.2% (1) |
| Hidden | 32.3% (10) | 3.2% (1) | 6.5% (2) | 0.0% (0) | 45.2% (14) | 48.4% (15) | 6.5% (2) | 16.1% (5) | 54.8% (17) | 19.4% (6) | 19.4% (6) | 3.2% (1) |

### P-all, role build - ChaOnly (denominator 4; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 100.0% (4) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 100.0% (4) | 75.0% (3) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) |
| TypeInitializer | 50.0% (2) | 50.0% (2) | 25.0% (1) | 0.0% (0) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 0.0% (0) |
| Finalizer | 50.0% (2) | 50.0% (2) | 25.0% (1) | 0.0% (0) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 25.0% (1) | 50.0% (2) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 100.0% (4) | 75.0% (3) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) |
| PublicContract | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 0.0% (0) |
| Hidden | 75.0% (3) | 50.0% (2) | 75.0% (3) | 0.0% (0) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) |

### P-all, role build - Bound (denominator 4; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 100.0% (4) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 100.0% (4) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 25.0% (1) | 50.0% (2) | 0.0% (0) |
| TypeInitializer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 0.0% (0) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 0.0% (0) |
| Finalizer | 50.0% (2) | 25.0% (1) | 0.0% (0) | 0.0% (0) | 25.0% (1) | 25.0% (1) | 25.0% (1) | 0.0% (0) | 0.0% (0) | 25.0% (1) | 25.0% (1) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 100.0% (4) | 50.0% (2) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) |
| PublicContract | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 0.0% (0) |
| Hidden | 75.0% (3) | 50.0% (2) | 75.0% (3) | 0.0% (0) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) |

### P-all, role build - Direct (denominator 4; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 100.0% (4) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 100.0% (4) | 75.0% (3) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) |
| TypeInitializer | 50.0% (2) | 50.0% (2) | 25.0% (1) | 0.0% (0) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 0.0% (0) |
| Finalizer | 50.0% (2) | 50.0% (2) | 25.0% (1) | 0.0% (0) | 25.0% (1) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 25.0% (1) | 25.0% (1) | 50.0% (2) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 100.0% (4) | 50.0% (2) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) |
| PublicContract | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 0.0% (0) |
| Hidden | 75.0% (3) | 50.0% (2) | 75.0% (3) | 0.0% (0) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 75.0% (3) | 0.0% (0) |

### P-all, role buildTransitive - ChaOnly (denominator 3; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 100.0% (3) | 100.0% (3) | 100.0% (3) | 33.3% (1) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 100.0% (3) | 66.7% (2) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 0.0% (0) |
| TypeInitializer | 66.7% (2) | 33.3% (1) | 0.0% (0) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 0.0% (0) |
| Finalizer | 66.7% (2) | 33.3% (1) | 0.0% (0) | 0.0% (0) | 66.7% (2) | 66.7% (2) | 66.7% (2) | 66.7% (2) | 66.7% (2) | 33.3% (1) | 66.7% (2) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 100.0% (3) | 66.7% (2) | 100.0% (3) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 0.0% (0) |
| PublicContract | 100.0% (3) | 100.0% (3) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 0.0% (0) |
| Hidden | 100.0% (3) | 66.7% (2) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 0.0% (0) |

### P-all, role buildTransitive - Bound (denominator 3; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 100.0% (3) | 100.0% (3) | 100.0% (3) | 33.3% (1) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 100.0% (3) | 33.3% (1) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 66.7% (2) | 33.3% (1) | 100.0% (3) | 66.7% (2) | 66.7% (2) | 66.7% (2) | 0.0% (0) |
| TypeInitializer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 66.7% (2) | 100.0% (3) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 33.3% (1) | 100.0% (3) | 0.0% (0) |
| Finalizer | 66.7% (2) | 33.3% (1) | 0.0% (0) | 0.0% (0) | 33.3% (1) | 0.0% (0) | 33.3% (1) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 100.0% (3) | 33.3% (1) | 100.0% (3) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 0.0% (0) |
| PublicContract | 100.0% (3) | 100.0% (3) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 0.0% (0) |
| Hidden | 100.0% (3) | 66.7% (2) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 0.0% (0) |

### P-all, role buildTransitive - Direct (denominator 3; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 100.0% (3) | 100.0% (3) | 100.0% (3) | 33.3% (1) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 100.0% (3) | 66.7% (2) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 0.0% (0) |
| TypeInitializer | 66.7% (2) | 33.3% (1) | 0.0% (0) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 0.0% (0) |
| Finalizer | 66.7% (2) | 33.3% (1) | 0.0% (0) | 0.0% (0) | 33.3% (1) | 33.3% (1) | 66.7% (2) | 33.3% (1) | 33.3% (1) | 33.3% (1) | 66.7% (2) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 100.0% (3) | 33.3% (1) | 100.0% (3) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 0.0% (0) |
| PublicContract | 100.0% (3) | 100.0% (3) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 0.0% (0) |
| Hidden | 100.0% (3) | 66.7% (2) | 66.7% (2) | 0.0% (0) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 66.7% (2) | 100.0% (3) | 100.0% (3) | 100.0% (3) | 0.0% (0) |

### P-all, role lib - ChaOnly (denominator 2; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| TypeInitializer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Finalizer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Hidden | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |

### P-all, role lib - Bound (denominator 2; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| TypeInitializer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Finalizer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Hidden | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |

### P-all, role lib - Direct (denominator 2; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| TypeInitializer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Finalizer | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicContract | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| Hidden | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |

### P-all, role tasks - ChaOnly (denominator 4; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 75.0% (3) | 25.0% (1) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 25.0% (1) |
| TypeInitializer | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 25.0% (1) |
| Finalizer | 50.0% (2) | 25.0% (1) | 25.0% (1) | 25.0% (1) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 25.0% (1) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 25.0% (1) |
| PublicContract | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 25.0% (1) |
| Hidden | 75.0% (3) | 25.0% (1) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 25.0% (1) |

### P-all, role tasks - Bound (denominator 4; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 75.0% (3) | 25.0% (1) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 25.0% (1) |
| TypeInitializer | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 50.0% (2) | 25.0% (1) |
| Finalizer | 25.0% (1) | 0.0% (0) | 25.0% (1) | 0.0% (0) | 25.0% (1) | 0.0% (0) | 25.0% (1) | 0.0% (0) | 0.0% (0) | 25.0% (1) | 25.0% (1) | 25.0% (1) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 25.0% (1) |
| PublicContract | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 25.0% (1) |
| Hidden | 75.0% (3) | 25.0% (1) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 25.0% (1) |

### P-all, role tasks - Direct (denominator 4; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 75.0% (3) | 25.0% (1) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 25.0% (1) |
| TypeInitializer | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 25.0% (1) |
| Finalizer | 50.0% (2) | 25.0% (1) | 25.0% (1) | 25.0% (1) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 25.0% (1) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 25.0% (1) |
| PublicContract | 75.0% (3) | 25.0% (1) | 50.0% (2) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 50.0% (2) | 25.0% (1) |
| Hidden | 75.0% (3) | 25.0% (1) | 75.0% (3) | 25.0% (1) | 75.0% (3) | 50.0% (2) | 75.0% (3) | 75.0% (3) | 50.0% (2) | 50.0% (2) | 75.0% (3) | 25.0% (1) |

### P-all, role tools - ChaOnly (denominator 14; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 85.7% (12) | 35.7% (5) | 64.3% (9) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 64.3% (9) | 14.3% (2) | 35.7% (5) | 0.0% (0) | 71.4% (10) | 35.7% (5) | 42.9% (6) | 35.7% (5) | 42.9% (6) | 57.1% (8) | 64.3% (9) | 21.4% (3) |
| TypeInitializer | 71.4% (10) | 35.7% (5) | 21.4% (3) | 7.1% (1) | 85.7% (12) | 57.1% (8) | 57.1% (8) | 57.1% (8) | 64.3% (9) | 78.6% (11) | 85.7% (12) | 35.7% (5) |
| Finalizer | 35.7% (5) | 21.4% (3) | 7.1% (1) | 7.1% (1) | 35.7% (5) | 35.7% (5) | 42.9% (6) | 35.7% (5) | 35.7% (5) | 35.7% (5) | 42.9% (6) | 21.4% (3) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 85.7% (12) | 35.7% (5) | 64.3% (9) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | 35.7% (5) |
| PublicContract | 78.6% (11) | 35.7% (5) | 57.1% (8) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | 35.7% (5) |
| Hidden | 78.6% (11) | 35.7% (5) | 57.1% (8) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | 35.7% (5) |

### P-all, role tools - Bound (denominator 14; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 85.7% (12) | 35.7% (5) | 64.3% (9) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 57.1% (8) | 7.1% (1) | 21.4% (3) | 0.0% (0) | 57.1% (8) | 7.1% (1) | 21.4% (3) | 14.3% (2) | 21.4% (3) | 14.3% (2) | 14.3% (2) | 7.1% (1) |
| TypeInitializer | 35.7% (5) | 21.4% (3) | 14.3% (2) | 0.0% (0) | 50.0% (7) | 42.9% (6) | 28.6% (4) | 42.9% (6) | 57.1% (8) | 35.7% (5) | 57.1% (8) | 14.3% (2) |
| Finalizer | 7.1% (1) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 14.3% (2) | 0.0% (0) | 0.0% (0) | 7.1% (1) | 14.3% (2) | 0.0% (0) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 85.7% (12) | 35.7% (5) | 57.1% (8) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 57.1% (8) | 64.3% (9) | 64.3% (9) | 78.6% (11) | 85.7% (12) | 35.7% (5) |
| PublicContract | 78.6% (11) | 35.7% (5) | 35.7% (5) | 7.1% (1) | 71.4% (10) | 64.3% (9) | 50.0% (7) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | 35.7% (5) |
| Hidden | 78.6% (11) | 35.7% (5) | 57.1% (8) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | 35.7% (5) |

### P-all, role tools - Direct (denominator 14; unmeasured 0)

| Row | FileSystem | Network | ProcessExecution | Registry | EnvironmentProbe | DynamicCodeLoading | NativeInterop | Cryptography | ReflectionInvocation | UnsafeMemory | RuntimeControl | Unseen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| presence | 85.7% (12) | 35.7% (5) | 64.3% (9) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | - |
| LoadTime | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| HostContract | 64.3% (9) | 14.3% (2) | 35.7% (5) | 0.0% (0) | 71.4% (10) | 35.7% (5) | 42.9% (6) | 35.7% (5) | 42.9% (6) | 57.1% (8) | 64.3% (9) | 21.4% (3) |
| TypeInitializer | 71.4% (10) | 35.7% (5) | 21.4% (3) | 7.1% (1) | 85.7% (12) | 57.1% (8) | 57.1% (8) | 57.1% (8) | 64.3% (9) | 78.6% (11) | 85.7% (12) | 35.7% (5) |
| Finalizer | 35.7% (5) | 21.4% (3) | 7.1% (1) | 7.1% (1) | 35.7% (5) | 35.7% (5) | 42.9% (6) | 35.7% (5) | 35.7% (5) | 35.7% (5) | 42.9% (6) | 21.4% (3) |
| NativeEntry | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) | 0.0% (0) |
| PublicApi | 85.7% (12) | 35.7% (5) | 64.3% (9) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | 35.7% (5) |
| PublicContract | 78.6% (11) | 35.7% (5) | 57.1% (8) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | 35.7% (5) |
| Hidden | 78.6% (11) | 35.7% (5) | 57.1% (8) | 7.1% (1) | 92.9% (13) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 64.3% (9) | 85.7% (12) | 85.7% (12) | 35.7% (5) |

## 6. Q2 - PublicContract against PublicApi and Hidden

Per package, a class's roots over its own methods (summed over the population's folders); median and p90
(nearest-rank) over the packages with own methods. A method may carry several classes; Hidden carries no other.

### P-lib (denominator 2; unmeasured 0; 142 own methods; 2 PublicContract-only, 12 Hidden)

| Class | Packages | Median share of own methods | p90 |
| --- | ---: | ---: | ---: |
| LoadTime | 1 | 0.0% | 0.0% |
| HostContract | 1 | 0.0% | 0.0% |
| TypeInitializer | 1 | 0.7% | 0.7% |
| Finalizer | 1 | 0.0% | 0.0% |
| NativeEntry | 1 | 0.0% | 0.0% |
| PublicApi | 1 | 89.4% | 89.4% |
| PublicContract | 1 | 1.4% | 1.4% |
| Hidden | 1 | 8.5% | 8.5% |

| Capability | PublicApi reach | PublicContract reach | Hidden reach |
| --- | ---: | ---: | ---: |
| FileSystem | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| Network | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| ProcessExecution | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| Registry | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| EnvironmentProbe | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| DynamicCodeLoading | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| NativeInterop | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| Cryptography | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| ReflectionInvocation | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| UnsafeMemory | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |
| RuntimeControl | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) |

### P-all (denominator 50; unmeasured 0; 944236 own methods; 125266 PublicContract-only, 476742 Hidden)

| Class | Packages | Median share of own methods | p90 |
| --- | ---: | ---: | ---: |
| LoadTime | 50 | 0.0% | 0.0% |
| HostContract | 50 | 10.7% | 39.7% |
| TypeInitializer | 50 | 3.6% | 6.8% |
| Finalizer | 50 | 0.0% | 0.0% |
| NativeEntry | 50 | 0.0% | 0.0% |
| PublicApi | 50 | 25.8% | 48.9% |
| PublicContract | 50 | 10.9% | 21.6% |
| Hidden | 50 | 50.0% | 68.8% |

| Capability | PublicApi reach | PublicContract reach | Hidden reach |
| --- | ---: | ---: | ---: |
| FileSystem | 27/50 (54.0%) | 21/50 (42.0%) | 27/50 (54.0%) |
| Network | 9/50 (18.0%) | 10/50 (20.0%) | 10/50 (20.0%) |
| ProcessExecution | 14/50 (28.0%) | 14/50 (28.0%) | 15/50 (30.0%) |
| Registry | 2/50 (4.0%) | 2/50 (4.0%) | 2/50 (4.0%) |
| EnvironmentProbe | 31/50 (62.0%) | 30/50 (60.0%) | 32/50 (64.0%) |
| DynamicCodeLoading | 25/50 (50.0%) | 28/50 (56.0%) | 29/50 (58.0%) |
| NativeInterop | 15/50 (30.0%) | 17/50 (34.0%) | 17/50 (34.0%) |
| Cryptography | 19/50 (38.0%) | 20/50 (40.0%) | 19/50 (38.0%) |
| ReflectionInvocation | 29/50 (58.0%) | 26/50 (52.0%) | 32/50 (64.0%) |
| UnsafeMemory | 22/50 (44.0%) | 21/50 (42.0%) | 23/50 (46.0%) |
| RuntimeControl | 22/50 (44.0%) | 24/50 (48.0%) | 24/50 (48.0%) |

## 7. Q3 - evidence tiers

Per class, the reached (package, capability) pairs (any capability, ChaOnly), by the strongest tier any of the
package's folders reaches the capability on.

### P-lib (denominator 2)

| Class | Reached pairs | Bound | Instantiated, not Bound | ChaOnly only |
| --- | ---: | ---: | ---: | ---: |
| LoadTime | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |
| HostContract | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |
| TypeInitializer | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |
| Finalizer | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |
| NativeEntry | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |
| PublicApi | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |
| PublicContract | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |
| Hidden | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |

### P-all (denominator 50)

| Class | Reached pairs | Bound | Instantiated, not Bound | ChaOnly only |
| --- | ---: | ---: | ---: | ---: |
| LoadTime | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |
| HostContract | 181 | 126/181 (69.6%) | 55/181 (30.4%) | 0/181 (0.0%) |
| TypeInitializer | 181 | 122/181 (67.4%) | 56/181 (30.9%) | 3/181 (1.7%) |
| Finalizer | 92 | 22/92 (23.9%) | 67/92 (72.8%) | 3/92 (3.3%) |
| NativeEntry | 0 | 0/0 (0.0%) | 0/0 (0.0%) | 0/0 (0.0%) |
| PublicApi | 215 | 205/215 (95.3%) | 10/215 (4.7%) | 0/215 (0.0%) |
| PublicContract | 213 | 201/213 (94.4%) | 12/213 (5.6%) | 0/213 (0.0%) |
| Hidden | 230 | 229/230 (99.6%) | 1/230 (0.4%) | 0/230 (0.0%) |

## 8. Q4 - Unknown

Unknown = packages with a folder whose verdict for the class is `Unknown`. Reasons count the packages with an
Unknown folder giving each reason. `unseen` is split by how the class's Unseen example paths (up to three per
folder) end: at an opacity site (by kind), an own InternalCall, or an external the map marks `unanalyzed`. Load
failures are not in any verdict yet (R3 carry) and are counted separately. A crashed, timed-out or incomplete
package is Unknown for every class, with the reason `unmeasured (crashed/timeout/incomplete)`.

### P-lib (denominator 2)

| Class | Unknown | Reasons (packages) | Unseen example ends (packages) | Packages with load failures |
| --- | ---: | --- | --- | ---: |
| LoadTime | 0/2 (0.0%) | - | - | 0 |
| HostContract | 0/2 (0.0%) | - | - | 0 |
| TypeInitializer | 0/2 (0.0%) | - | - | 0 |
| Finalizer | 0/2 (0.0%) | - | - | 0 |
| NativeEntry | 0/2 (0.0%) | - | - | 0 |
| PublicApi | 0/2 (0.0%) | - | - | 0 |
| PublicContract | 0/2 (0.0%) | - | - | 0 |
| Hidden | 0/2 (0.0%) | - | - | 0 |

Unseen sinks in the population's folders: opacity sites -; InternalCall nodes 0; `unanalyzed` externals 0.

### P-all (denominator 50)

| Class | Unknown | Reasons (packages) | Unseen example ends (packages) | Packages with load failures |
| --- | ---: | --- | --- | ---: |
| LoadTime | 6/50 (12.0%) | index-incomplete 3; module-initializer 2; renamed-implementations 1 | - | 4 |
| HostContract | 6/50 (12.0%) | index-incomplete 3; renamed-implementations 1; unseen 5 | opacity:Ambiguous 4; opacity:Unresolved 1 | 4 |
| TypeInitializer | 7/50 (14.0%) | index-incomplete 3; renamed-implementations 1; unseen 7 | internal-call 1; opacity:Ambiguous 5; opacity:Unresolved 1 | 4 |
| Finalizer | 5/50 (10.0%) | index-incomplete 3; renamed-implementations 1; unseen 4 | opacity:Ambiguous 3; opacity:Unresolved 1 | 4 |
| NativeEntry | 4/50 (8.0%) | index-incomplete 3; renamed-implementations 1 | - | 4 |
| PublicApi | 7/50 (14.0%) | index-incomplete 3; renamed-implementations 1; unseen 7 | internal-call 1; opacity:Ambiguous 5; opacity:Unresolved 1 | 4 |
| PublicContract | 7/50 (14.0%) | index-incomplete 3; renamed-implementations 1; unseen 7 | opacity:Ambiguous 5; opacity:Unresolved 2 | 4 |
| Hidden | 7/50 (14.0%) | index-incomplete 3; renamed-implementations 1; unseen 7 | internal-call 1; opacity:Ambiguous 5; opacity:Unresolved 1 | 4 |

Unseen sinks in the population's folders: opacity sites Ambiguous 1476; Unresolved 21; InternalCall nodes 4; `unanalyzed` externals 0.

## 9. Q5 - presence parity per folder (ADR 0037 decision 9)

The rule of `PresenceParityTests`: distinct (caller, capability, callee) triples of the scanner's Call, Construct,
MethodPointerLoad and NativeImport findings against the graph's capability sink edges and NativeImport facts. A
scanner-only triple is NameShadowed when the graph has a call-site edge from that caller to an own node keyed as
the callee. EXACT = no difference; NAMED = only NameShadowed; DIFFERS = an unexplained difference. Lists keep 50
items; counts are true.

Folders compared: 503; EXACT 477; NAMED 25; DIFFERS 1. Triples matched 27585, NameShadowed 24540, scanner-only 2, graph-only 0.

| Package | Version | Folder | Parity | Matched | NameShadowed | Scanner only | Graph only |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| MessagePackAnalyzer | 3.1.12 | analyzers/roslyn4.3/cs | NAMED | 27 | 66 | 0 | 0 |
| Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/netstandard2.0 | NAMED | 502 | 5 | 0 | 0 |
| Microsoft.Build.Tasks.Git | 10.0.403 | tools/netframework | NAMED | 36 | 214 | 0 | 0 |
| Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | buildTransitive/netstandard2.0 | NAMED | 305 | 877 | 0 | 0 |
| Microsoft.NET.ILLink.Tasks | 10.0.14 | tools/netframework | NAMED | 116 | 231 | 0 | 0 |
| Microsoft.Net.Compilers | 4.2.0 | tools | NAMED | 394 | 230 | 0 | 0 |
| Microsoft.SourceLink.AzureRepos.Git | 10.0.403 | tools/netframework | NAMED | 12 | 214 | 0 | 0 |
| Microsoft.SourceLink.GitHub | 10.0.403 | tools/netframework | NAMED | 11 | 214 | 0 | 0 |
| NSwag.MSBuild | 14.7.1 | tools/Win | NAMED | 1468 | 468 | 0 | 0 |
| OpenCover | 4.7.1221 | tools | NAMED | 708 | 259 | 0 | 0 |
| ReportGenerator | 5.5.12 | tools/net47 | DIFFERS | 493 | 4656 | 2 | 0 |
| Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/net462 | NAMED | 336 | 273 | 0 | 0 |
| Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | NAMED | 478 | 1267 | 0 | 0 |
| SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | NAMED | 1781 | 190 | 0 | 0 |
| SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | NAMED | 1327 | 911 | 0 | 0 |
| SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | NAMED | 1327 | 911 | 0 | 0 |
| SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | NAMED | 1333 | 911 | 0 | 0 |
| Xamarin.Build.Download | 0.11.6 | build | NAMED | 157 | 134 | 0 | 0 |
| Xamarin.Build.Download | 0.11.6 | buildTransitive | NAMED | 157 | 134 | 0 | 0 |
| coverlet.msbuild | 10.1.0 | tasks/net10.0 | NAMED | 946 | 1167 | 0 | 0 |
| coverlet.msbuild | 10.1.0 | tasks/net10.0/runtimes/win/lib/net10.0 | NAMED | 996 | 1227 | 0 | 0 |
| coverlet.msbuild | 10.1.0 | tasks/net8.0 | NAMED | 1378 | 2551 | 0 | 0 |
| coverlet.msbuild | 10.1.0 | tasks/net8.0/runtimes/win/lib/net8.0 | NAMED | 996 | 1224 | 0 | 0 |
| coverlet.msbuild | 10.1.0 | tasks/net9.0 | NAMED | 1327 | 2384 | 0 | 0 |
| coverlet.msbuild | 10.1.0 | tasks/net9.0/runtimes/win/lib/net9.0 | NAMED | 996 | 1227 | 0 | 0 |
| coverlet.msbuild | 10.1.0 | tasks/netstandard2.0 | NAMED | 1048 | 2595 | 0 | 0 |

#### MessagePackAnalyzer 3.1.12 `analyzers/roslyn4.3/cs`

- NameShadowed (66, first 50 listed):
  - MessagePack.SourceGenerator.Transforms.CompositeResolverTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.CompositeResolverTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.CompositeResolverTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.CompositeResolverTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.CompositeResolverTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.CompositeResolverTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_IsWarning
  - MessagePack.SourceGenerator.Transforms.CompositeResolverTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.CompositeResolverTemplateBase.get_Errors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection..ctor
  - MessagePack.SourceGenerator.Transforms.EnumTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.EnumTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.EnumTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.EnumTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.EnumTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.EnumTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_IsWarning
  - MessagePack.SourceGenerator.Transforms.EnumTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.EnumTemplateBase.get_Errors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection..ctor
  - MessagePack.SourceGenerator.Transforms.FormatterTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.FormatterTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.FormatterTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.FormatterTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.FormatterTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.FormatterTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_IsWarning
  - MessagePack.SourceGenerator.Transforms.FormatterTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.FormatterTemplateBase.get_Errors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection..ctor
  - MessagePack.SourceGenerator.Transforms.ResolverTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.ResolverTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.ResolverTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.ResolverTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.ResolverTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.ResolverTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_IsWarning
  - MessagePack.SourceGenerator.Transforms.ResolverTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.ResolverTemplateBase.get_Errors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection..ctor
  - MessagePack.SourceGenerator.Transforms.StringKeyFormatterTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.StringKeyFormatterTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.StringKeyFormatterTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.StringKeyFormatterTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.StringKeyFormatterTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.StringKeyFormatterTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_IsWarning
  - MessagePack.SourceGenerator.Transforms.StringKeyFormatterTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.StringKeyFormatterTemplateBase.get_Errors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection..ctor
  - MessagePack.SourceGenerator.Transforms.UnionTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.UnionTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.UnionTemplateBase.Error -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.UnionTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - MessagePack.SourceGenerator.Transforms.UnionTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_ErrorText
  - MessagePack.SourceGenerator.Transforms.UnionTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_IsWarning
  - MessagePack.SourceGenerator.Transforms.UnionTemplateBase.Warning -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection.Add
  - MessagePack.SourceGenerator.Transforms.UnionTemplateBase.get_Errors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerErrorCollection..ctor
  - System.CodeDom.Compiler.CompilerError..ctor -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError..ctor
  - System.CodeDom.Compiler.CompilerError..ctor -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerError.set_Column

#### Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator 4.0.1 `tools/netstandard2.0`

- NameShadowed (5):
  - Microsoft.CSharp.CSharpCodeProvider..ctor -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeDomProvider..ctor
  - System.CodeDom.Compiler.CodeGenerator.IsValidLanguageIndependentIdentifier -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGenerator.IsValidTypeNameOrIdentifier
  - System.CodeDom.Compiler.CodeGenerator.IsValidTypeNameOrIdentifier -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGenerator.IsSpecialTypeChar
  - System.Xml.Serialization.CodeIdentifier.EscapeKeywords -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeDomProvider.CreateEscapedIdentifier
  - System.Xml.Serialization.Globals.IsValidLanguageIndependentIdentifier -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGenerator.IsValidLanguageIndependentIdentifier

#### Microsoft.Build.Tasks.Git 10.0.403 `tools/netframework`

- NameShadowed (214, first 50 listed):
  - System.Buffers.ArrayMemoryPool.Rent -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.ReadOnlySequence..ctor -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryGetArray

#### Microsoft.Maui.Controls.Build.Tasks 10.0.120 `buildTransitive/netstandard2.0`

- NameShadowed (877, first 50 listed):
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_IndentString
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateComment -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter.InternalOutputTabs
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConditionStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateEvents -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateFields -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateMethods -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNamespaces -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromNamespace
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateProperties -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateSnippetMembers -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateStatements -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromStatement
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTryCatchFinallyStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateType -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_VerbatimOrder
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.IsValidIdentifier -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGenerator.IsValidLanguageIndependentIdentifier
  - Microsoft.CSharp.CSharpCodeGenerator.OutputAttributeArgument -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputExpressionList -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputStartingBrace -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BracingStyle
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation.get_IndentationString
  - Microsoft.CSharp.CSharpCodeGenerator.ResolveReferencedAssemblies -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_ReferencedAssemblies
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_IndentString
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor

#### Microsoft.NET.ILLink.Tasks 10.0.14 `tools/netframework`

- NameShadowed (231, first 50 listed):
  - System.Buffers.ArrayMemoryPool.Rent -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.ReadOnlySequence..ctor -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryGetArray

#### Microsoft.Net.Compilers 4.2.0 `tools`

- NameShadowed (230, first 50 listed):
  - Microsoft.CodeAnalysis.Collections.ImmutableSegmentedDictionary.PrivateInterlocked.InterlockedCompareExchange -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsRef
  - Microsoft.CodeAnalysis.Collections.ImmutableSegmentedDictionary.PrivateInterlocked.InterlockedExchange -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsRef
  - Microsoft.CodeAnalysis.Collections.ImmutableSegmentedDictionary.PrivateInterlocked.VolatileRead -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsRef
  - Microsoft.CodeAnalysis.Collections.ImmutableSegmentedList.PrivateInterlocked.InterlockedCompareExchange -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsRef
  - Microsoft.CodeAnalysis.Collections.ImmutableSegmentedList.PrivateInterlocked.InterlockedExchange -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsRef
  - Microsoft.CodeAnalysis.Collections.ImmutableSegmentedList.PrivateInterlocked.VolatileRead -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsRef
  - Microsoft.CodeAnalysis.Collections.Internal.RoslynUnsafe.IsNullRef -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsPointer
  - Microsoft.CodeAnalysis.Collections.Internal.RoslynUnsafe.NullRef -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsRef
  - Microsoft.CodeAnalysis.Collections.Internal.SegmentedArrayHelper.GetOffsetMask -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - Microsoft.CodeAnalysis.Collections.Internal.SegmentedArrayHelper.GetSegmentShift -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - Microsoft.CodeAnalysis.Collections.Internal.SegmentedArrayHelper.GetSegmentSize -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - Microsoft.CodeAnalysis.Collections.Internal.SegmentedArrayHelper.ReferenceTypeSegmentHelper..cctor -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - Microsoft.CodeAnalysis.Collections.Internal.SegmentedArrayHelper.ValueTypeSegmentHelper..cctor -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - Microsoft.CodeAnalysis.Collections.Internal.SegmentedArraySortUtils.Log2SoftwareFallback -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AddByteOffset
  - Microsoft.CodeAnalysis.Collections.Internal.SegmentedArraySortUtils.Log2SoftwareFallback -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.CodeAnalysis.Collections.SegmentedArray.Copy -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryGetArray
  - Microsoft.CodeAnalysis.Collections.SegmentedArray.IndexOf -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryGetArray
  - System.Buffers.ArrayMemoryPool.Rent -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite

#### Microsoft.SourceLink.AzureRepos.Git 10.0.403 `tools/netframework`

- NameShadowed (214, first 50 listed):
  - System.Buffers.ArrayMemoryPool.Rent -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.ReadOnlySequence..ctor -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryGetArray

#### Microsoft.SourceLink.GitHub 10.0.403 `tools/netframework`

- NameShadowed (214, first 50 listed):
  - System.Buffers.ArrayMemoryPool.Rent -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.ReadOnlySequence..ctor -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryGetArray

#### NSwag.MSBuild 14.7.1 `tools/Win`

- NameShadowed (468, first 50 listed):
  - Fluid.TemplateCache..ctor -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform
  - Microsoft.AspNetCore.Certificates.Generation.CertificateManager.\<>c__DisplayClass24_0.\<ListCertificates>b__5 -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform
  - Microsoft.AspNetCore.Hosting.Internal.WebHost.BuildApplication -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.get_FrameworkDescription
  - Microsoft.AspNetCore.Hosting.Internal.WebHost.BuildApplication -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.get_OSDescription
  - Microsoft.AspNetCore.Hosting.Internal.WebHost.BuildApplication -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.get_ProcessArchitecture
  - Microsoft.AspNetCore.HttpSys.Internal.PathNormalizer.RemoveDotSegments -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.Http1Connection.GetUtf8String -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.HttpParser.ParseHeaders -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.HttpParser.ParseRequestLine -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.HttpRequestHeaders.Append -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.PathNormalizer.RemoveDotSegments -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.PipelineExtensions.GetArray -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryGetArray
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.PipelineExtensions.WriteAsciiMultiWrite -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.PipelineExtensions.WriteAsciiNoValidation -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.PipelineExtensions.WriteNumeric -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure.HttpUtilities.GetAsciiStringNonNullCharacters -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure.HttpUtilities.GetKnownHttpScheme -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure.HttpUtilities.GetKnownMethod -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure.HttpUtilities.GetKnownVersion -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure.StringUtilities.TryGetAsciiString -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsRef
  - Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.Internal.BufferExtensions.GetArray -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryGetArray
  - Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.Internal.SocketConnection..cctor -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform
  - Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.SocketTransport.\<RunAcceptLoopAsync>d__17.MoveNext -\[Network\]-> System.Net.Sockets.SocketTaskExtensions.AcceptAsync
  - Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.SocketTransport.EnableRebinding -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform
  - Microsoft.DotNet.PlatformAbstractions.Native.PlatformApis.GetFreeBSDVersion -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.get_OSDescription
  - Microsoft.Extensions.FileProviders.Physical.PollingWildCardChangeToken.CalculateChanges -\[Cryptography\]-> System.Security.Cryptography.IncrementalHash.CreateHash
  - Microsoft.Extensions.FileProviders.Physical.PollingWildCardChangeToken.CalculateChanges -\[Cryptography\]-> System.Security.Cryptography.IncrementalHash.GetHashAndReset
  - Microsoft.Extensions.FileProviders.Physical.PollingWildCardChangeToken.ComputeHash -\[Cryptography\]-> System.Security.Cryptography.IncrementalHash.AppendData
  - Microsoft.Extensions.Primitives.InplaceStringBuilder.Append -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.CopyBlockUnaligned
  - Microsoft.Extensions.Primitives.StringValues.\<GetStringValue>g__GetStringValueFromArray\|19_0 -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.CopyTo -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.Enumerator..ctor -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.GetArrayValue -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.GetHashCode -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.IndexOf -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.IsNullOrEmpty -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.get_Count -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.get_Item -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - System.Buffers.ArrayMemoryPool.Rent -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read

#### OpenCover 4.7.1221 `tools`

- NameShadowed (259, first 50 listed):
  - Microsoft.Extensions.Primitives.StringValues.\<GetStringValue>g__GetStringValueFromArray\|19_0 -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.CopyTo -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.Enumerator..ctor -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.GetArrayValue -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.GetHashCode -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.IndexOf -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.IsNullOrEmpty -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.get_Count -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - Microsoft.Extensions.Primitives.StringValues.get_Item -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.As
  - System.Buffers.ArrayMemoryPool.Rent -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write

#### ReportGenerator 5.5.12 `tools/net47`

- NameShadowed (4656, first 50 listed):
  - Microsoft.CSharp.RuntimeBinder.Binder.BinaryOperation -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.BinaryOperation -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpBinaryOperationBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.Convert -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.Convert -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpConvertBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.GetIndex -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.GetIndex -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpGetIndexBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.GetMember -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.GetMember -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpGetMemberBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.Invoke -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.Invoke -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpInvokeBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.InvokeConstructor -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.InvokeConstructor -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpInvokeConstructorBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.InvokeMember -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.InvokeMember -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpInvokeMemberBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.IsEvent -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.IsEvent -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpIsEventBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.SetIndex -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.SetIndex -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpSetIndexBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.SetMember -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.SetMember -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpSetMemberBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.Binder.UnaryOperation -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.TryGetExisting
  - Microsoft.CSharp.RuntimeBinder.Binder.UnaryOperation -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpUnaryOperationBinder..ctor
  - Microsoft.CSharp.RuntimeBinder.BinderEquivalence..cctor -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderEquivalence.BinderEqualityComparer..ctor
  - Microsoft.CSharp.RuntimeBinder.BinderEquivalence.BinderEqualityComparer.Equals -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.ICSharpBinder.IsEquivalentTo
  - Microsoft.CSharp.RuntimeBinder.BinderEquivalence.BinderEqualityComparer.GetHashCode -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.ICSharpBinder.GetGetBinderEquivalenceHash
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.AddArgHashes -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.AddArgHashes
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.AddArgHashes -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.get_Flags
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.AddArgHashes -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.get_Name
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.Bind -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.ConvertResult
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.Bind -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.DeduceArgumentRestriction
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.Bind -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.GetTypeForErrorMetaObject
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.Bind -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.IsIncrementOrDecrementActionOnLocal
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.Bind -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.get_LiteralConstant
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.Bind -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.RuntimeBinder.Bind
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.CompareArgInfos -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.CompareArgInfos
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.CompareArgInfos -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.get_Flags
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.CompareArgInfos -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.get_Name
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.ConvertResult -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.Error.BindToVoidMethodButExpectResult
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.ConvertResult -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.ICSharpBinder.get_ReturnType
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.ConvertResult -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.ICSharpInvokeOrInvokeMemberBinder.get_ResultDiscarded
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.CreateCallInfo -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.ToArray
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.CreateCallInfo -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.get_Name
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.CreateCallInfo -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.get_NamedArgument
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.DeduceArgumentRestriction -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.IsDynamicallyTypedRuntimeProxy
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.DeduceArgumentRestriction -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.IsTypeOfStaticCall
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.GetTypeForErrorMetaObject -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.ICSharpBinder.get_ReturnType
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.IsDynamicallyTypedRuntimeProxy -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.IsComObject
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.IsDynamicallyTypedRuntimeProxy -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.BinderHelper.IsTransparentProxy
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.IsDynamicallyTypedRuntimeProxy -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.get_UseCompileTimeType
  - Microsoft.CSharp.RuntimeBinder.BinderHelper.IsTypeOfStaticCall -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.ICSharpInvokeOrInvokeMemberBinder.get_StaticCall
- Scanner only (2):
  - Microsoft.CSharp.RuntimeBinder.Semantics.AggregateType.\<get_TypeHierarchy>d__17.System.Collections.IEnumerable.GetEnumerator -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.Semantics.AggregateType.\<get_TypeHierarchy>d__17.System.Collections.Generic.IEnumerable.GetEnumerator
  - Microsoft.CSharp.RuntimeBinder.Semantics.EXPRExtensions.\<ToEnumerable>d__1.System.Collections.IEnumerable.GetEnumerator -\[DynamicCodeLoading\]-> Microsoft.CSharp.RuntimeBinder.Semantics.EXPRExtensions.\<ToEnumerable>d__1.System.Collections.Generic.IEnumerable.GetEnumerator

#### Reqnroll.Tools.MsBuild.Generation 3.3.4 `build/net462`

- NameShadowed (273, first 50 listed):
  - Microsoft.NET.StringTools.InternableString.ExpensiveConvertToString -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.CopyBlockUnaligned
  - System.Buffers.ArrayMemoryPool.Rent -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.SizeOf
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Read
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryReadUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryRead
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.TryWriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.TryWrite
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write
  - System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.Write

#### Reqnroll.Tools.MsBuild.Generation 3.3.4 `build/netstandard2.0`

- NameShadowed (1267, first 50 listed):
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_IndentString
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateComment -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter.InternalOutputTabs
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConditionStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateEvents -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateFields -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateMethods -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNamespaces -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromNamespace
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateProperties -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateSnippetMembers -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateStatements -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromStatement
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTryCatchFinallyStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateType -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_VerbatimOrder
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.IsValidIdentifier -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGenerator.IsValidLanguageIndependentIdentifier
  - Microsoft.CSharp.CSharpCodeGenerator.OutputAttributeArgument -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputExpressionList -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputStartingBrace -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BracingStyle
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation.get_IndentationString
  - Microsoft.CSharp.CSharpCodeGenerator.ResolveReferencedAssemblies -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_ReferencedAssemblies
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_IndentString
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor

#### SpecFlow.Tools.MsBuild.Generation 3.9.74 `tasks/net461`

- NameShadowed (190, first 50 listed):
  - Microsoft.Build.Evaluation.IntrinsicFunctions.IsOSPlatform -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform
  - Microsoft.Build.Shared.NativeMethodsShared.get_IsBSD -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform
  - Microsoft.Build.Shared.NativeMethodsShared.get_IsLinux -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform
  - Microsoft.Build.Shared.NativeMethodsShared.get_IsOSX -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform
  - Microsoft.Build.Shared.NativeMethodsShared.get_IsWindows -\[EnvironmentProbe\]-> System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform
  - Microsoft.Build.Tasks.Deployment.ManifestUtilities.SecurityUtilities.SignFileInternal -\[Cryptography\]-> System.Security.Cryptography.CngLightup.GetRSAPrivateKey
  - Microsoft.Build.Tasks.DownloadFile.Download -\[Network\]-> System.Net.Http.HttpClient..ctor
  - Microsoft.Build.Tasks.DownloadFile.Download -\[Network\]-> System.Net.Http.HttpClient.GetAsync
  - Microsoft.Build.Tasks.DownloadFile.Download -\[Network\]-> System.Net.Http.HttpClientHandler..ctor
  - System.Deployment.Internal.CodeSigning.SignedCmiManifest2.AuthenticodeSignLicenseDom -\[Cryptography\]-> System.Security.Cryptography.CngLightup.GetRSAPrivateKey
  - System.Net.Http.HttpClient..ctor -\[Network\]-> System.Net.Http.HttpClient..ctor
  - System.Net.Http.HttpClient..ctor -\[Network\]-> System.Net.Http.HttpClientHandler..ctor
  - System.Net.Http.HttpClient..ctor -\[Network\]-> System.Net.Http.HttpMessageInvoker..ctor
  - System.Net.Http.HttpClient.\<FinishSendAsyncBuffered>d__58.MoveNext -\[Network\]-> System.Net.Http.HttpClient.HandleFinishSendAsyncCleanup
  - System.Net.Http.HttpClient.\<FinishSendAsyncBuffered>d__58.MoveNext -\[Network\]-> System.Net.Http.HttpClient.HandleFinishSendAsyncError
  - System.Net.Http.HttpClient.\<FinishSendAsyncUnbuffered>d__59.MoveNext -\[Network\]-> System.Net.Http.HttpClient.HandleFinishSendAsyncCleanup
  - System.Net.Http.HttpClient.\<FinishSendAsyncUnbuffered>d__59.MoveNext -\[Network\]-> System.Net.Http.HttpClient.HandleFinishSendAsyncError
  - System.Net.Http.HttpClient.CancelPendingRequests -\[Network\]-> System.Net.Http.HttpClient.CheckDisposed
  - System.Net.Http.HttpClient.CheckDisposedOrStarted -\[Network\]-> System.Net.Http.HttpClient.CheckDisposed
  - System.Net.Http.HttpClient.DeleteAsync -\[Network\]-> System.Net.Http.HttpClient.CreateUri
  - System.Net.Http.HttpClient.DeleteAsync -\[Network\]-> System.Net.Http.HttpClient.DeleteAsync
  - System.Net.Http.HttpClient.DeleteAsync -\[Network\]-> System.Net.Http.HttpMessageInvoker.SendAsync
  - System.Net.Http.HttpClient.Dispose -\[Network\]-> System.Net.Http.HttpMessageInvoker.Dispose
  - System.Net.Http.HttpClient.GetAsync -\[Network\]-> System.Net.Http.HttpClient.CreateUri
  - System.Net.Http.HttpClient.GetAsync -\[Network\]-> System.Net.Http.HttpClient.GetAsync
  - System.Net.Http.HttpClient.GetAsync -\[Network\]-> System.Net.Http.HttpClient.SendAsync
  - System.Net.Http.HttpClient.GetByteArrayAsync -\[Network\]-> System.Net.Http.HttpClient.CreateUri
  - System.Net.Http.HttpClient.GetByteArrayAsync -\[Network\]-> System.Net.Http.HttpClient.GetAsync
  - System.Net.Http.HttpClient.GetByteArrayAsync -\[Network\]-> System.Net.Http.HttpClient.GetByteArrayAsync
  - System.Net.Http.HttpClient.GetByteArrayAsync -\[Network\]-> System.Net.Http.HttpClient.GetByteArrayAsyncCore
  - System.Net.Http.HttpClient.GetStreamAsync -\[Network\]-> System.Net.Http.HttpClient.CreateUri
  - System.Net.Http.HttpClient.GetStreamAsync -\[Network\]-> System.Net.Http.HttpClient.FinishGetStreamAsync
  - System.Net.Http.HttpClient.GetStreamAsync -\[Network\]-> System.Net.Http.HttpClient.GetAsync
  - System.Net.Http.HttpClient.GetStreamAsync -\[Network\]-> System.Net.Http.HttpClient.GetStreamAsync
  - System.Net.Http.HttpClient.GetStringAsync -\[Network\]-> System.Net.Http.HttpClient.CreateUri
  - System.Net.Http.HttpClient.GetStringAsync -\[Network\]-> System.Net.Http.HttpClient.GetAsync
  - System.Net.Http.HttpClient.GetStringAsync -\[Network\]-> System.Net.Http.HttpClient.GetStringAsync
  - System.Net.Http.HttpClient.GetStringAsync -\[Network\]-> System.Net.Http.HttpClient.GetStringAsyncCore
  - System.Net.Http.HttpClient.PostAsync -\[Network\]-> System.Net.Http.HttpClient.CreateUri
  - System.Net.Http.HttpClient.PostAsync -\[Network\]-> System.Net.Http.HttpClient.PostAsync
  - System.Net.Http.HttpClient.PostAsync -\[Network\]-> System.Net.Http.HttpMessageInvoker.SendAsync
  - System.Net.Http.HttpClient.PutAsync -\[Network\]-> System.Net.Http.HttpClient.CreateUri
  - System.Net.Http.HttpClient.PutAsync -\[Network\]-> System.Net.Http.HttpClient.PutAsync
  - System.Net.Http.HttpClient.PutAsync -\[Network\]-> System.Net.Http.HttpMessageInvoker.SendAsync
  - System.Net.Http.HttpClient.SendAsync -\[Network\]-> System.Net.Http.HttpClient.CheckDisposed
  - System.Net.Http.HttpClient.SendAsync -\[Network\]-> System.Net.Http.HttpClient.CheckRequestMessage
  - System.Net.Http.HttpClient.SendAsync -\[Network\]-> System.Net.Http.HttpClient.FinishSendAsyncBuffered
  - System.Net.Http.HttpClient.SendAsync -\[Network\]-> System.Net.Http.HttpClient.FinishSendAsyncUnbuffered
  - System.Net.Http.HttpClient.SendAsync -\[Network\]-> System.Net.Http.HttpClient.PrepareRequestMessage
  - System.Net.Http.HttpClient.SendAsync -\[Network\]-> System.Net.Http.HttpClient.SendAsync

#### SpecFlow.Tools.MsBuild.Generation 3.9.74 `tasks/net5.0`

- NameShadowed (911, first 50 listed):
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeDomProvider.CreateProvider
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeDomProvider.GenerateCodeFromCompileUnit
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.set_BlankLinesBetweenMembers
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.set_VerbatimOrder
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_IndentString
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateComment -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter.InternalOutputTabs
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConditionStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateEvents -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateFields -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateMethods -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNamespaces -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromNamespace
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateProperties -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateSnippetMembers -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateStatements -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromStatement
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTryCatchFinallyStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateType -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_VerbatimOrder
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.IsValidIdentifier -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGenerator.IsValidLanguageIndependentIdentifier
  - Microsoft.CSharp.CSharpCodeGenerator.OutputAttributeArgument -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputExpressionList -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputStartingBrace -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BracingStyle
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation.get_IndentationString
  - Microsoft.CSharp.CSharpCodeGenerator.ResolveReferencedAssemblies -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_ReferencedAssemblies
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles

#### SpecFlow.Tools.MsBuild.Generation 3.9.74 `tasks/net6.0`

- NameShadowed (911, first 50 listed):
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeDomProvider.CreateProvider
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeDomProvider.GenerateCodeFromCompileUnit
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.set_BlankLinesBetweenMembers
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.set_VerbatimOrder
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_IndentString
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateComment -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter.InternalOutputTabs
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConditionStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateEvents -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateFields -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateMethods -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNamespaces -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromNamespace
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateProperties -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateSnippetMembers -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateStatements -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromStatement
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTryCatchFinallyStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateType -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_VerbatimOrder
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.IsValidIdentifier -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGenerator.IsValidLanguageIndependentIdentifier
  - Microsoft.CSharp.CSharpCodeGenerator.OutputAttributeArgument -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputExpressionList -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputStartingBrace -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BracingStyle
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation.get_IndentationString
  - Microsoft.CSharp.CSharpCodeGenerator.ResolveReferencedAssemblies -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_ReferencedAssemblies
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles

#### SpecFlow.Tools.MsBuild.Generation 3.9.74 `tasks/netcoreapp2.1`

- NameShadowed (911, first 50 listed):
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeDomProvider.CreateProvider
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeDomProvider.GenerateCodeFromCompileUnit
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.set_BlankLinesBetweenMembers
  - Microsoft.Build.Tasks.RoslynCodeTaskFactory.GetSourceCode -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.set_VerbatimOrder
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromCompileUnit
  - Microsoft.CSharp.CSharpCodeGenerator.FromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.FromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.AddExtension
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_IndentString
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateCodeFromMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateComment -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ExposedTabStringIndentedTextWriter.InternalOutputTabs
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConditionStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateEvents -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateFields -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateMethods -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNamespaces -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromNamespace
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateNestedTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateProperties -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateSnippetMembers -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateStatements -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromStatement
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTryCatchFinallyStatement -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_ElseOnClosing
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateType -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_VerbatimOrder
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeConstructors -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypeMember -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BlankLinesBetweenMembers
  - Microsoft.CSharp.CSharpCodeGenerator.GenerateTypes -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromType
  - Microsoft.CSharp.CSharpCodeGenerator.IsValidIdentifier -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGenerator.IsValidLanguageIndependentIdentifier
  - Microsoft.CSharp.CSharpCodeGenerator.OutputAttributeArgument -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputExpressionList -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.ICodeGenerator.GenerateCodeFromExpression
  - Microsoft.CSharp.CSharpCodeGenerator.OutputStartingBrace -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CodeGeneratorOptions.get_BracingStyle
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation..ctor
  - Microsoft.CSharp.CSharpCodeGenerator.QuoteSnippetStringCStyle -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.Indentation.get_IndentationString
  - Microsoft.CSharp.CSharpCodeGenerator.ResolveReferencedAssemblies -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_ReferencedAssemblies
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDom -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromDomBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFile -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromFileBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSource -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.TempFileCollection.SafeDelete
  - Microsoft.CSharp.CSharpCodeGenerator.System.CodeDom.Compiler.ICodeCompiler.CompileAssemblyFromSourceBatch -\[DynamicCodeLoading\]-> System.CodeDom.Compiler.CompilerParameters.get_TempFiles

#### Xamarin.Build.Download 0.11.6 `build`

- NameShadowed (134, first 50 listed):
  - Microsoft.Win32.Registry..cctor -\[Registry\]-> Microsoft.Win32.RegistryKey.OpenBaseKey
  - Microsoft.Win32.Registry.GetBaseKeyFromKeyName -\[Registry\]-> Microsoft.Win32.RegistryKey.get_Name
  - Microsoft.Win32.Registry.GetValue -\[Registry\]-> Microsoft.Win32.Registry.GetBaseKeyFromKeyName
  - Microsoft.Win32.Registry.GetValue -\[Registry\]-> Microsoft.Win32.RegistryKey.GetValue
  - Microsoft.Win32.Registry.GetValue -\[Registry\]-> Microsoft.Win32.RegistryKey.OpenSubKey
  - Microsoft.Win32.Registry.SetValue -\[Registry\]-> Microsoft.Win32.Registry.GetBaseKeyFromKeyName
  - Microsoft.Win32.Registry.SetValue -\[Registry\]-> Microsoft.Win32.Registry.SetValue
  - Microsoft.Win32.Registry.SetValue -\[Registry\]-> Microsoft.Win32.RegistryKey.CreateSubKey
  - Microsoft.Win32.Registry.SetValue -\[Registry\]-> Microsoft.Win32.RegistryKey.SetValue
  - Microsoft.Win32.RegistryKey..ctor -\[Registry\]-> Microsoft.Win32.RegistryKey..ctor
  - Microsoft.Win32.RegistryKey..ctor -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyView
  - Microsoft.Win32.RegistryKey.Close -\[Registry\]-> Microsoft.Win32.RegistryKey.Dispose
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.CreateSubKey
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.CreateSubKeyInternalCore
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.EnsureWriteable
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.FixupName
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.InternalOpenSubKeyWithoutSecurityChecks
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyMode
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyName
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyOptions
  - Microsoft.Win32.RegistryKey.CreateSubKeyInternalCore -\[Registry\]-> Microsoft.Win32.RegistryKey..ctor
  - Microsoft.Win32.RegistryKey.CreateSubKeyInternalCore -\[Registry\]-> Microsoft.Win32.RegistryKey.GetRegistryKeyAccess
  - Microsoft.Win32.RegistryKey.CreateSubKeyInternalCore -\[Registry\]-> Microsoft.Win32.RegistryKey.Win32Error
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKey
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyCore
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.EnsureWriteable
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.FixupName
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.InternalOpenSubKeyWithoutSecurityChecks
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyName
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.get_SubKeyCount
  - Microsoft.Win32.RegistryKey.DeleteSubKeyCore -\[Registry\]-> Microsoft.Win32.RegistryKey.Win32Error
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTree
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTreeCore
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.EnsureWriteable
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.FixupName
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.GetSubKeyNames
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.InternalOpenSubKeyWithoutSecurityChecks
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.IsSystemKey
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyName
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.get_SubKeyCount
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeCore -\[Registry\]-> Microsoft.Win32.RegistryKey.Win32Error
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTreeCore
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.GetSubKeyNames
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.InternalOpenSubKeyWithoutSecurityChecks
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.get_SubKeyCount
  - Microsoft.Win32.RegistryKey.DeleteValue -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteValue
  - Microsoft.Win32.RegistryKey.DeleteValue -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteValueCore
  - Microsoft.Win32.RegistryKey.DeleteValue -\[Registry\]-> Microsoft.Win32.RegistryKey.EnsureWriteable

#### Xamarin.Build.Download 0.11.6 `buildTransitive`

- NameShadowed (134, first 50 listed):
  - Microsoft.Win32.Registry..cctor -\[Registry\]-> Microsoft.Win32.RegistryKey.OpenBaseKey
  - Microsoft.Win32.Registry.GetBaseKeyFromKeyName -\[Registry\]-> Microsoft.Win32.RegistryKey.get_Name
  - Microsoft.Win32.Registry.GetValue -\[Registry\]-> Microsoft.Win32.Registry.GetBaseKeyFromKeyName
  - Microsoft.Win32.Registry.GetValue -\[Registry\]-> Microsoft.Win32.RegistryKey.GetValue
  - Microsoft.Win32.Registry.GetValue -\[Registry\]-> Microsoft.Win32.RegistryKey.OpenSubKey
  - Microsoft.Win32.Registry.SetValue -\[Registry\]-> Microsoft.Win32.Registry.GetBaseKeyFromKeyName
  - Microsoft.Win32.Registry.SetValue -\[Registry\]-> Microsoft.Win32.Registry.SetValue
  - Microsoft.Win32.Registry.SetValue -\[Registry\]-> Microsoft.Win32.RegistryKey.CreateSubKey
  - Microsoft.Win32.Registry.SetValue -\[Registry\]-> Microsoft.Win32.RegistryKey.SetValue
  - Microsoft.Win32.RegistryKey..ctor -\[Registry\]-> Microsoft.Win32.RegistryKey..ctor
  - Microsoft.Win32.RegistryKey..ctor -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyView
  - Microsoft.Win32.RegistryKey.Close -\[Registry\]-> Microsoft.Win32.RegistryKey.Dispose
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.CreateSubKey
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.CreateSubKeyInternalCore
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.EnsureWriteable
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.FixupName
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.InternalOpenSubKeyWithoutSecurityChecks
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyMode
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyName
  - Microsoft.Win32.RegistryKey.CreateSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyOptions
  - Microsoft.Win32.RegistryKey.CreateSubKeyInternalCore -\[Registry\]-> Microsoft.Win32.RegistryKey..ctor
  - Microsoft.Win32.RegistryKey.CreateSubKeyInternalCore -\[Registry\]-> Microsoft.Win32.RegistryKey.GetRegistryKeyAccess
  - Microsoft.Win32.RegistryKey.CreateSubKeyInternalCore -\[Registry\]-> Microsoft.Win32.RegistryKey.Win32Error
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKey
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyCore
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.EnsureWriteable
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.FixupName
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.InternalOpenSubKeyWithoutSecurityChecks
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyName
  - Microsoft.Win32.RegistryKey.DeleteSubKey -\[Registry\]-> Microsoft.Win32.RegistryKey.get_SubKeyCount
  - Microsoft.Win32.RegistryKey.DeleteSubKeyCore -\[Registry\]-> Microsoft.Win32.RegistryKey.Win32Error
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTree
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTreeCore
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.EnsureWriteable
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.FixupName
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.GetSubKeyNames
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.InternalOpenSubKeyWithoutSecurityChecks
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.IsSystemKey
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.ValidateKeyName
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTree -\[Registry\]-> Microsoft.Win32.RegistryKey.get_SubKeyCount
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeCore -\[Registry\]-> Microsoft.Win32.RegistryKey.Win32Error
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTreeCore
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.GetSubKeyNames
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.InternalOpenSubKeyWithoutSecurityChecks
  - Microsoft.Win32.RegistryKey.DeleteSubKeyTreeInternal -\[Registry\]-> Microsoft.Win32.RegistryKey.get_SubKeyCount
  - Microsoft.Win32.RegistryKey.DeleteValue -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteValue
  - Microsoft.Win32.RegistryKey.DeleteValue -\[Registry\]-> Microsoft.Win32.RegistryKey.DeleteValueCore
  - Microsoft.Win32.RegistryKey.DeleteValue -\[Registry\]-> Microsoft.Win32.RegistryKey.EnsureWriteable

#### coverlet.msbuild 10.1.0 `tasks/net10.0`

- NameShadowed (1167, first 50 listed):
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.AlgorithmIdentifierAsn.HasNullEquivalentParameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.set_Parameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.PublicKeyInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifierOrKey..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Xml.X509IssuerSerial..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.CopyContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Item
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetEncodedMessageType -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RSAEncryptionPadding
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RecipientIdentifierType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Pal
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Type
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecryptCore -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Pkcs9AttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyTransPal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_KeyLength
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.PkcsHelpers.BuildAttributes -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject.get_Oid
  - Internal.Cryptography.PkcsHelpers.BuildAttributes -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject.get_Values
  - Internal.Cryptography.PkcsHelpers.BuildAttributes -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectCollection.GetEnumerator
  - Internal.Cryptography.PkcsHelpers.BuildAttributes -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectCollection.get_Count
  - Internal.Cryptography.PkcsHelpers.BuildAttributes -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectEnumerator.MoveNext
  - Internal.Cryptography.PkcsHelpers.BuildAttributes -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectEnumerator.get_Current
  - Internal.Cryptography.PkcsHelpers.CreateBestPkcs9AttributeObjectAvailable -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Pkcs9AttributeObject..ctor
  - Internal.Cryptography.PkcsHelpers.CreateBestPkcs9AttributeObjectAvailable -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Pkcs9ContentType..ctor

#### coverlet.msbuild 10.1.0 `tasks/net10.0/runtimes/win/lib/net10.0`

- NameShadowed (1227, first 50 listed):
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.AlgorithmIdentifierAsn.HasNullEquivalentParameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.set_Parameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.PublicKeyInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifierOrKey..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Xml.X509IssuerSerial..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.CopyContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Item
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetEncodedMessageType -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RSAEncryptionPadding
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RecipientIdentifierType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Pal
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Type
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecryptCore -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Pkcs9AttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyTransPal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_KeyLength
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.CreateRecipientInfos -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.ToRecipientInfosForThisIndex -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.ToRecipientInfosForThisIndex -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Parameters
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType

#### coverlet.msbuild 10.1.0 `tasks/net8.0`

- NameShadowed (2551, first 50 listed):
  - Internal.Cryptography.Helpers.EncodeAsnWriterToPem -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Helpers.EncodeAsnWriterToPem -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.AlgorithmIdentifierAsn.HasNullEquivalentParameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.set_Parameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.PublicKeyInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifierOrKey..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Xml.X509IssuerSerial..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.CopyContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Item
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetEncodedMessageType -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.MLDsa.get_IsSupported
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.SlhDsa.get_IsSupported
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.X509Certificates.X509CertificateKeyAccessors.GetMLDsaPrivateKey
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.X509Certificates.X509CertificateKeyAccessors.GetSlhDsaPrivateKey
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RSAEncryptionPadding
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RecipientIdentifierType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Pal
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Type
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecryptCore -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Pkcs9AttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyTransPal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_KeyLength
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.PkcsHelpers.BuildAttributes -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject.get_Oid

#### coverlet.msbuild 10.1.0 `tasks/net8.0/runtimes/win/lib/net8.0`

- NameShadowed (1224, first 50 listed):
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.AlgorithmIdentifierAsn.HasNullEquivalentParameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.set_Parameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.PublicKeyInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifierOrKey..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Xml.X509IssuerSerial..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.CopyContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Item
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetEncodedMessageType -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RSAEncryptionPadding
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RecipientIdentifierType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Pal
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Type
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecryptCore -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Pkcs9AttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyTransPal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_KeyLength
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.CreateRecipientInfos -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.ToRecipientInfosForThisIndex -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.ToRecipientInfosForThisIndex -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Parameters
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType

#### coverlet.msbuild 10.1.0 `tasks/net9.0`

- NameShadowed (2384, first 50 listed):
  - Internal.Cryptography.Helpers.EncodeAsnWriterToPem -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Helpers.EncodeAsnWriterToPem -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.AlgorithmIdentifierAsn.HasNullEquivalentParameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.set_Parameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.PublicKeyInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifierOrKey..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Xml.X509IssuerSerial..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.CopyContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Item
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetEncodedMessageType -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.MLDsa.get_IsSupported
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.SlhDsa.get_IsSupported
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.X509Certificates.X509CertificateKeyAccessors.GetMLDsaPrivateKey
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.X509Certificates.X509CertificateKeyAccessors.GetSlhDsaPrivateKey
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RSAEncryptionPadding
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RecipientIdentifierType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Pal
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Type
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecryptCore -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Pkcs9AttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyTransPal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_KeyLength
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.PkcsHelpers.BuildAttributes -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject.get_Oid
  - Internal.Cryptography.PkcsHelpers.BuildAttributes -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject.get_Values

#### coverlet.msbuild 10.1.0 `tasks/net9.0/runtimes/win/lib/net9.0`

- NameShadowed (1227, first 50 listed):
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.AlgorithmIdentifierAsn.HasNullEquivalentParameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.set_Parameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.PublicKeyInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifierOrKey..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Xml.X509IssuerSerial..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.CopyContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.DecryptKey -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Item
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetEncodedMessageType -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RSAEncryptionPadding
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RecipientIdentifierType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Pal
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Type
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecryptCore -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Pkcs9AttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyTransPal.get_RecipientIdentifier -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_KeyLength
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.OpenAlgorithm -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.CreateRecipientInfos -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.ToRecipientInfosForThisIndex -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.ToRecipientInfosForThisIndex -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Parameters
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.Windows.DecryptorPalWindows.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType

#### coverlet.msbuild 10.1.0 `tasks/netstandard2.0`

- NameShadowed (2595, first 50 listed):
  - Internal.Cryptography.Helpers.ContainsNull -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.IsNullRef
  - Internal.Cryptography.Helpers.ContainsNull -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Internal.Cryptography.Helpers.EncodeAsnWriterToPem -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Helpers.EncodeAsnWriterToPem -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Helpers.EncodeAsnWriterToPem -\[Cryptography\]-> System.Security.Cryptography.PemEncoding.WriteString
  - Internal.Cryptography.Helpers.GetNonNullPinnableReference -\[UnsafeMemory\]-> System.Runtime.CompilerServices.Unsafe.AsRef
  - Internal.Cryptography.Helpers.GetNonNullPinnableReference -\[UnsafeMemory\]-> System.Runtime.InteropServices.MemoryMarshal.GetReference
  - Internal.Cryptography.Helpers.RngFill -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Helpers.RngFill -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.AlgorithmIdentifierAsn.HasNullEquivalentParameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Decode
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.GetEffectiveKeyBits
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToPresentationObject -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.set_Parameters
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.PublicKeyInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Pkcs.SubjectIdentifierOrKey..ctor
  - Internal.Cryptography.Pal.AnyOS.AsnHelpers.ToSubjectIdentifierOrKey -\[Cryptography\]-> System.Security.Cryptography.Xml.X509IssuerSerial..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.CopyContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyAgreeRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.KeyTransRecipientInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfoCollection..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Decode -\[Cryptography\]-> System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObjectCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.AlgorithmIdentifier.get_Oid
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Asn1.EnvelopedDataAsn.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Count
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipientCollection.get_Item
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.Encrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Asn1.Rc2CbcParameters.Encode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_Content
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.EncryptContent -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo.get_ContentType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetEncodedMessageType -\[Cryptography\]-> System.Security.Cryptography.Asn1.Pkcs7.ContentInfoAsn.Decode
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.MLDsa.get_IsSupported
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.SlhDsa.get_IsSupported
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.X509Certificates.X509CertificateKeyAccessors.GetMLDsaPrivateKey
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.GetPrivateKey -\[Cryptography\]-> System.Security.Cryptography.X509Certificates.X509CertificateKeyAccessors.GetSlhDsaPrivateKey
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_Certificate
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RSAEncryptionPadding
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.MakeKtri -\[Cryptography\]-> System.Security.Cryptography.Pkcs.CmsRecipient.get_RecipientIdentifierType
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.DecryptContent -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Rent
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.DecryptContent -\[Cryptography\]-> System.Security.Cryptography.CryptoPool.Return
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Pal
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecrypt -\[Cryptography\]-> System.Security.Cryptography.Pkcs.RecipientInfo.get_Type
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedDecryptorPal.TryDecryptCore -\[Cryptography\]-> System.Security.Cryptography.Pkcs.ContentInfo..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.CryptographicAttributeObject..ctor
  - Internal.Cryptography.Pal.AnyOS.ManagedPkcsPal.ManagedKeyAgreePal.get_OtherKeyAttribute -\[Cryptography\]-> System.Security.Cryptography.Pkcs.Pkcs9AttributeObject..ctor

## 10. Q6 - cost, crashes, timeouts, not-cached packages and load failures

Analyze and build times and peak working sets are in `reachability-benign-2026-11-07-cost.md`, kept out of this file so that it
stays byte-identical across cold runs.

### Packages not scanned

*None: every manifest entry was scanned.*

### Load failures (16)

| Package | Version | Folder | Assembly | Reason |
| --- | --- | --- | --- | --- |
| Microsoft.Net.Compilers | 4.2.0 | tools | tools/Microsoft.DiaSymReader.Native.amd64.dll | Failed to load assembly tools/Microsoft.DiaSymReader.Native.amd64.dll. |
| Microsoft.Net.Compilers | 4.2.0 | tools | tools/Microsoft.DiaSymReader.Native.x86.dll | Failed to load assembly tools/Microsoft.DiaSymReader.Native.x86.dll. |
| dotnet-reportgenerator-globaltool | 5.5.12 | tools/net10.0/any | tools/net10.0/any/ReportGenerator.exe | Failed to load assembly tools/net10.0/any/ReportGenerator.exe. |
| dotnet-reportgenerator-globaltool | 5.5.12 | tools/net8.0/any | tools/net8.0/any/ReportGenerator.exe | Failed to load assembly tools/net8.0/any/ReportGenerator.exe. |
| dotnet-reportgenerator-globaltool | 5.5.12 | tools/net9.0/any | tools/net9.0/any/ReportGenerator.exe | Failed to load assembly tools/net9.0/any/ReportGenerator.exe. |
| NSwag.MSBuild | 14.7.1 | tools/Net100 | tools/Net100/NSwag.AspNetCore.Launcher.exe | Failed to load assembly tools/Net100/NSwag.AspNetCore.Launcher.exe. |
| NSwag.MSBuild | 14.7.1 | tools/Net100 | tools/Net100/dotnet-nswag.exe | Failed to load assembly tools/Net100/dotnet-nswag.exe. |
| NSwag.MSBuild | 14.7.1 | tools/Net80 | tools/Net80/NSwag.AspNetCore.Launcher.exe | Failed to load assembly tools/Net80/NSwag.AspNetCore.Launcher.exe. |
| NSwag.MSBuild | 14.7.1 | tools/Net80 | tools/Net80/dotnet-nswag.exe | Failed to load assembly tools/Net80/dotnet-nswag.exe. |
| NSwag.MSBuild | 14.7.1 | tools/Net90 | tools/Net90/NSwag.AspNetCore.Launcher.exe | Failed to load assembly tools/Net90/NSwag.AspNetCore.Launcher.exe. |
| NSwag.MSBuild | 14.7.1 | tools/Net90 | tools/Net90/dotnet-nswag.exe | Failed to load assembly tools/Net90/dotnet-nswag.exe. |
| ReportGenerator | 5.5.12 | tools/net10.0 | tools/net10.0/ReportGenerator.exe | Failed to load assembly tools/net10.0/ReportGenerator.exe. |
| ReportGenerator | 5.5.12 | tools/net8.0 | tools/net8.0/ReportGenerator.exe | Failed to load assembly tools/net8.0/ReportGenerator.exe. |
| ReportGenerator | 5.5.12 | tools/net9.0 | tools/net9.0/ReportGenerator.exe | Failed to load assembly tools/net9.0/ReportGenerator.exe. |
| OpenCover | 4.7.1221 | tools/x64 | tools/x64/OpenCover.Profiler.dll | Failed to load assembly tools/x64/OpenCover.Profiler.dll. |
| OpenCover | 4.7.1221 | tools/x86 | tools/x86/OpenCover.Profiler.dll | Failed to load assembly tools/x86/OpenCover.Profiler.dll. |

### Presence scans failed or partial (16)

| Package | Version | Folder | Assembly | Failure | Methods skipped |
| --- | --- | --- | --- | --- | ---: |
| Microsoft.Net.Compilers | 4.2.0 | tools | tools/Microsoft.DiaSymReader.Native.amd64.dll | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\Microsoft.Net.Compilers.4.2.0.nupkg\\tools\\Microsoft.DiaSymReader.Native.amd64.dll' is not a valid CLR module or assembly. | 0 |
| Microsoft.Net.Compilers | 4.2.0 | tools | tools/Microsoft.DiaSymReader.Native.x86.dll | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\Microsoft.Net.Compilers.4.2.0.nupkg\\tools\\Microsoft.DiaSymReader.Native.x86.dll' is not a valid CLR module or assembly. | 0 |
| dotnet-reportgenerator-globaltool | 5.5.12 | tools/net10.0/any | tools/net10.0/any/ReportGenerator.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\dotnet-reportgenerator-globaltool.5.5.12.nupkg\\tools\\net10.0\\any\\ReportGenerator.exe' is not a valid CLR module or assembly. | 0 |
| dotnet-reportgenerator-globaltool | 5.5.12 | tools/net8.0/any | tools/net8.0/any/ReportGenerator.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\dotnet-reportgenerator-globaltool.5.5.12.nupkg\\tools\\net8.0\\any\\ReportGenerator.exe' is not a valid CLR module or assembly. | 0 |
| dotnet-reportgenerator-globaltool | 5.5.12 | tools/net9.0/any | tools/net9.0/any/ReportGenerator.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\dotnet-reportgenerator-globaltool.5.5.12.nupkg\\tools\\net9.0\\any\\ReportGenerator.exe' is not a valid CLR module or assembly. | 0 |
| NSwag.MSBuild | 14.7.1 | tools/Net100 | tools/Net100/NSwag.AspNetCore.Launcher.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\NSwag.MSBuild.14.7.1.nupkg\\tools\\Net100\\NSwag.AspNetCore.Launcher.exe' is not a valid CLR module or assembly. | 0 |
| NSwag.MSBuild | 14.7.1 | tools/Net100 | tools/Net100/dotnet-nswag.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\NSwag.MSBuild.14.7.1.nupkg\\tools\\Net100\\dotnet-nswag.exe' is not a valid CLR module or assembly. | 0 |
| NSwag.MSBuild | 14.7.1 | tools/Net80 | tools/Net80/NSwag.AspNetCore.Launcher.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\NSwag.MSBuild.14.7.1.nupkg\\tools\\Net80\\NSwag.AspNetCore.Launcher.exe' is not a valid CLR module or assembly. | 0 |
| NSwag.MSBuild | 14.7.1 | tools/Net80 | tools/Net80/dotnet-nswag.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\NSwag.MSBuild.14.7.1.nupkg\\tools\\Net80\\dotnet-nswag.exe' is not a valid CLR module or assembly. | 0 |
| NSwag.MSBuild | 14.7.1 | tools/Net90 | tools/Net90/NSwag.AspNetCore.Launcher.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\NSwag.MSBuild.14.7.1.nupkg\\tools\\Net90\\NSwag.AspNetCore.Launcher.exe' is not a valid CLR module or assembly. | 0 |
| NSwag.MSBuild | 14.7.1 | tools/Net90 | tools/Net90/dotnet-nswag.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\NSwag.MSBuild.14.7.1.nupkg\\tools\\Net90\\dotnet-nswag.exe' is not a valid CLR module or assembly. | 0 |
| ReportGenerator | 5.5.12 | tools/net10.0 | tools/net10.0/ReportGenerator.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\ReportGenerator.5.5.12.nupkg\\tools\\net10.0\\ReportGenerator.exe' is not a valid CLR module or assembly. | 0 |
| ReportGenerator | 5.5.12 | tools/net8.0 | tools/net8.0/ReportGenerator.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\ReportGenerator.5.5.12.nupkg\\tools\\net8.0\\ReportGenerator.exe' is not a valid CLR module or assembly. | 0 |
| ReportGenerator | 5.5.12 | tools/net9.0 | tools/net9.0/ReportGenerator.exe | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\ReportGenerator.5.5.12.nupkg\\tools\\net9.0\\ReportGenerator.exe' is not a valid CLR module or assembly. | 0 |
| OpenCover | 4.7.1221 | tools/x64 | tools/x64/OpenCover.Profiler.dll | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\OpenCover.4.7.1221.nupkg\\tools\\x64\\OpenCover.Profiler.dll' is not a valid CLR module or assembly. | 0 |
| OpenCover | 4.7.1221 | tools/x86 | tools/x86/OpenCover.Profiler.dll | load failed\: The file '\<temp>/silvergun\\pkg-\<random>\\OpenCover.4.7.1221.nupkg\\tools\\x86\\OpenCover.Profiler.dll' is not a valid CLR module or assembly. | 0 |

## 11. Trigger-class evidence (257)

Every trigger-class x signal-capability reach of every loaded folder, with its first example path (strongest
tier first, at most 64 hops: the first 62 and the last two). This is the list a human reads to judge each hit.
"Direct path": the example has no deferred edge. "Direct reach": the folder's row counts a Direct root, so the
reach is in the Direct cells. They can differ: the Direct pass is over ChaOnly edges, while the example is the
strongest tier's path (R2b S1, known limit), so a Direct reach can show a delegate path.

| Class | Capability | Package | Version | Folder | P-lib | Root | Evidence | Direct path | Direct reach | Length | Path |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- |
| HostContract | FileSystem | Aspire.Hosting.AppHost | 13.6.4 | tools/net472 | no | Aspire.Hosting.Tasks.ResolveAspireCliBundle.EnumerateDirectories(System.String) | Bound | yes | yes | 2 | Aspire.Hosting.Tasks.ResolveAspireCliBundle.EnumerateDirectories(System.String) -Call-> System.IO.Directory.GetDirectories(System.String) |
| HostContract | FileSystem | Aspire.Hosting.AppHost | 13.6.4 | tools/net8.0 | no | Aspire.Hosting.Tasks.ResolveAspireCliBundle.EnumerateDirectories(System.String) | Bound | yes | yes | 2 | Aspire.Hosting.Tasks.ResolveAspireCliBundle.EnumerateDirectories(System.String) -Call-> System.IO.Directory.GetDirectories(System.String) |
| HostContract | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn4.14/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) | Bound | yes | yes | 2 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| HostContract | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn4.8/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) | Bound | yes | yes | 2 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| HostContract | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn5.0/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) | Bound | yes | yes | 2 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| HostContract | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn5.6/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) | Bound | yes | yes | 2 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| HostContract | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn5.9/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) | Bound | yes | yes | 2 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| HostContract | FileSystem | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/net46 | no | Microsoft.AspNetCore.Razor.Tasks.RazorGenerate.ValidateParameters() | Bound | yes | yes | 2 | Microsoft.AspNetCore.Razor.Tasks.RazorGenerate.ValidateParameters() -Call-> System.IO.Directory.Exists(System.String) |
| HostContract | FileSystem | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/netstandard2.0 | no | Microsoft.AspNetCore.Razor.Tasks.RazorGenerate.ValidateParameters() | Bound | yes | yes | 2 | Microsoft.AspNetCore.Razor.Tasks.RazorGenerate.ValidateParameters() -Call-> System.IO.Directory.Exists(System.String) |
| HostContract | FileSystem | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tools | no | Microsoft.CodeAnalysis.Diagnostics.CSharp.CSharpCompilerDiagnosticAnalyzer.GetSupportedErrorCodes() | Instantiated | yes | yes | 4 | Microsoft.CodeAnalysis.Diagnostics.CSharp.CSharpCompilerDiagnosticAnalyzer.GetSupportedErrorCodes() -Dispatch-> Microsoft.CodeAnalysis.CommandLineParser.\<ExpandFileNamePattern>d__46.MoveNext() -CallVirt-> Microsoft.CodeAnalysis.CommandLineParser.EnumerateFiles(System.String,System.String,System.IO.SearchOption) -Call-> System.IO.Directory.EnumerateFiles(System.String,System.String,System.IO.SearchOption) |
| HostContract | FileSystem | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/net46 | no | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.BuildTasks.RemoveRuntimeDependencies.Execute() | Bound | yes | yes | 2 | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.BuildTasks.RemoveRuntimeDependencies.Execute() -Call-> System.IO.File.Delete(System.String) |
| HostContract | FileSystem | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/netstandard2.0 | no | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.BuildTasks.RemoveRuntimeDependencies.Execute() | Bound | yes | yes | 2 | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.BuildTasks.RemoveRuntimeDependencies.Execute() -Call-> System.IO.File.Delete(System.String) |
| HostContract | FileSystem | Microsoft.Build.Tasks.Git | 10.0.403 | tools/net | no | Microsoft.Build.Tasks.Git.RepositoryTask.GetOrCreateRepositoryInstance() | Bound | yes | yes | 4 | Microsoft.Build.Tasks.Git.RepositoryTask.GetOrCreateRepositoryInstance() -Call-> Microsoft.Build.Tasks.Git.GitRepository.TryFindRepository(System.String,Microsoft.Build.Tasks.Git.GitRepositoryLocation&) -Call-> Microsoft.Build.Tasks.Git.GitRepository.TryGetRepositoryLocationImpl(System.String,Microsoft.Build.Tasks.Git.GitRepositoryLocation&) -Call-> System.IO.Directory.Exists(System.String) |
| HostContract | FileSystem | Microsoft.Build.Tasks.Git | 10.0.403 | tools/netframework | no | Microsoft.Build.Tasks.Git.RepositoryTask.GetOrCreateRepositoryInstance() | Bound | yes | yes | 4 | Microsoft.Build.Tasks.Git.RepositoryTask.GetOrCreateRepositoryInstance() -Call-> Microsoft.Build.Tasks.Git.GitRepository.TryFindRepository(System.String,Microsoft.Build.Tasks.Git.GitRepositoryLocation&) -Call-> Microsoft.Build.Tasks.Git.GitRepository.TryGetRepositoryLocationImpl(System.String,Microsoft.Build.Tasks.Git.GitRepositoryLocation&) -Call-> System.IO.Directory.Exists(System.String) |
| HostContract | FileSystem | Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | buildTransitive/netstandard2.0 | no | Microsoft.Maui.Controls.Build.Tasks.XamlCTask.Execute(System.Collections.Generic.IList\`1\<System.Exception>&) | Bound | yes | yes | 2 | Microsoft.Maui.Controls.Build.Tasks.XamlCTask.Execute(System.Collections.Generic.IList\`1\<System.Exception>&) -Call-> System.IO.File.Exists(System.String) |
| HostContract | FileSystem | Microsoft.NET.ILLink.Tasks | 10.0.14 | tools/net | no | ILLink.Tasks.CreateRuntimeRootILLinkDescriptorFile.Execute() | Bound | yes | yes | 2 | ILLink.Tasks.CreateRuntimeRootILLinkDescriptorFile.Execute() -Call-> System.IO.File.Exists(System.String) |
| HostContract | FileSystem | Microsoft.NET.ILLink.Tasks | 10.0.14 | tools/netframework | no | ILLink.Tasks.CreateRuntimeRootILLinkDescriptorFile.Execute() | Bound | yes | yes | 2 | ILLink.Tasks.CreateRuntimeRootILLinkDescriptorFile.Execute() -Call-> System.IO.File.Exists(System.String) |
| HostContract | FileSystem | Microsoft.Net.Compilers | 4.2.0 | tools | no | Microsoft.CodeAnalysis.BuildTasks.CopyRefAssembly.Copy() | Bound | yes | yes | 2 | Microsoft.CodeAnalysis.BuildTasks.CopyRefAssembly.Copy() -Call-> System.IO.File.Copy(System.String,System.String,System.Boolean) |
| HostContract | FileSystem | Microsoft.SourceLink.Common | 10.0.403 | tools/net | no | Microsoft.SourceLink.Common.GenerateSourceLinkFile.WriteSourceLinkFile(System.String) | Bound | yes | yes | 2 | Microsoft.SourceLink.Common.GenerateSourceLinkFile.WriteSourceLinkFile(System.String) -Call-> System.IO.File.Delete(System.String) |
| HostContract | FileSystem | Microsoft.SourceLink.Common | 10.0.403 | tools/netframework | no | Microsoft.SourceLink.Common.GenerateSourceLinkFile.WriteSourceLinkFile(System.String) | Bound | yes | yes | 2 | Microsoft.SourceLink.Common.GenerateSourceLinkFile.WriteSourceLinkFile(System.String) -Call-> System.IO.File.Delete(System.String) |
| HostContract | FileSystem | OpenCover | 4.7.1221 | build | no | OpenCover.MSBuild.OpenCover.GenerateFullPathToTool() | Bound | yes | yes | 2 | OpenCover.MSBuild.OpenCover.GenerateFullPathToTool() -Call-> System.IO.File.Exists(System.String) |
| HostContract | FileSystem | ReportGenerator | 5.5.12 | tools/net10.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Bound | yes | yes | 3 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> DotNetConfig.Config.Build(System.String) -Call-> System.IO.Directory.Exists(System.String) |
| HostContract | FileSystem | ReportGenerator | 5.5.12 | tools/net47 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Bound | yes | yes | 3 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> DotNetConfig.Config.Build(System.String) -Call-> System.IO.Directory.Exists(System.String) |
| HostContract | FileSystem | ReportGenerator | 5.5.12 | tools/net8.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Bound | yes | yes | 3 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> DotNetConfig.Config.Build(System.String) -Call-> System.IO.Directory.Exists(System.String) |
| HostContract | FileSystem | ReportGenerator | 5.5.12 | tools/net9.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Bound | yes | yes | 3 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> DotNetConfig.Config.Build(System.String) -Call-> System.IO.Directory.Exists(System.String) |
| HostContract | FileSystem | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/net462 | no | Reqnroll.Tools.MsBuild.Generation.ReplaceTokenInFileTask.Execute() | Bound | yes | yes | 2 | Reqnroll.Tools.MsBuild.Generation.ReplaceTokenInFileTask.Execute() -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | Reqnroll.Tools.MsBuild.Generation.ReplaceTokenInFileTask.Execute() | Bound | yes | yes | 2 | Reqnroll.Tools.MsBuild.Generation.ReplaceTokenInFileTask.Execute() -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | Roslynator.Analyzers | 5.0.1 | analyzers/dotnet/roslyn3.8/cs | no | Roslynator.AbstractRequiredConfigOptionNotSetAnalyzer.IsOptionSet(Microsoft.CodeAnalysis.Diagnostics.AnalyzerConfigOptions,Roslynator.ConfigOptionDescriptor) | Bound | yes | yes | 4 | Roslynator.AbstractRequiredConfigOptionNotSetAnalyzer.IsOptionSet(Microsoft.CodeAnalysis.Diagnostics.AnalyzerConfigOptions,Roslynator.ConfigOptionDescriptor) -TypeInitializer-> Roslynator.Configuration.CodeAnalysisConfig..cctor() -NewObj-> Roslynator.Configuration.CodeAnalysisConfig..ctor(Roslynator.Configuration.XmlCodeAnalysisConfig,Roslynator.Configuration.EditorConfigCodeAnalysisConfig,Roslynator.Configuration.VisualStudioCodeAnalysisConfig) -Call-> System.IO.File.Exists(System.String) |
| HostContract | FileSystem | Roslynator.Analyzers | 5.0.1 | analyzers/dotnet/roslyn4.7/cs | no | Roslynator.AbstractRequiredConfigOptionNotSetAnalyzer.IsOptionSet(Microsoft.CodeAnalysis.Diagnostics.AnalyzerConfigOptions,Roslynator.ConfigOptionDescriptor) | Bound | yes | yes | 4 | Roslynator.AbstractRequiredConfigOptionNotSetAnalyzer.IsOptionSet(Microsoft.CodeAnalysis.Diagnostics.AnalyzerConfigOptions,Roslynator.ConfigOptionDescriptor) -TypeInitializer-> Roslynator.Configuration.CodeAnalysisConfig..cctor() -NewObj-> Roslynator.Configuration.CodeAnalysisConfig..ctor(Roslynator.Configuration.XmlCodeAnalysisConfig,Roslynator.Configuration.EditorConfigCodeAnalysisConfig,Roslynator.Configuration.VisualStudioCodeAnalysisConfig) -Call-> System.IO.File.Exists(System.String) |
| HostContract | FileSystem | Roslynator.Analyzers | 5.0.1 | analyzers/dotnet/roslyn5.0/cs | no | Roslynator.AbstractRequiredConfigOptionNotSetAnalyzer.IsOptionSet(Microsoft.CodeAnalysis.Diagnostics.AnalyzerConfigOptions,Roslynator.ConfigOptionDescriptor) | Bound | yes | yes | 4 | Roslynator.AbstractRequiredConfigOptionNotSetAnalyzer.IsOptionSet(Microsoft.CodeAnalysis.Diagnostics.AnalyzerConfigOptions,Roslynator.ConfigOptionDescriptor) -TypeInitializer-> Roslynator.Configuration.CodeAnalysisConfig..cctor() -NewObj-> Roslynator.Configuration.CodeAnalysisConfig..ctor(Roslynator.Configuration.XmlCodeAnalysisConfig,Roslynator.Configuration.EditorConfigCodeAnalysisConfig,Roslynator.Configuration.VisualStudioCodeAnalysisConfig) -Call-> System.IO.File.Exists(System.String) |
| HostContract | FileSystem | SonarAnalyzer.CSharp | 10.35.0.4138 | analyzers | no | SonarAnalyzer.CSharp.Rules.DatabasePasswordsShouldBeSecure.CheckAppSettingJson(SonarAnalyzer.Core.AnalysisContext.SonarCompilationReportingContext,System.String) | Bound | yes | yes | 2 | SonarAnalyzer.CSharp.Rules.DatabasePasswordsShouldBeSecure.CheckAppSettingJson(SonarAnalyzer.Core.AnalysisContext.SonarCompilationReportingContext,System.String) -Call-> System.IO.File.ReadAllText(System.String) |
| HostContract | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Tasks.Copy.CopyFileWithLogging(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.Copy.CopyFileWithLogging(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState) -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.Build.Tasks.Copy.CopyFileWithLogging(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.Copy.CopyFileWithLogging(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState) -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.Build.Tasks.Copy.CopyFileWithLogging(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.Copy.CopyFileWithLogging(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState) -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.Build.Tasks.Copy.CopyFileWithLogging(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.Copy.CopyFileWithLogging(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState) -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | Xamarin.AndroidX.Migration.BuildTasks.CollectAllFiles.Execute() | Bound | yes | yes | 2 | Xamarin.AndroidX.Migration.BuildTasks.CollectAllFiles.Execute() -Call-> System.IO.Directory.EnumerateFiles(System.String,System.String,System.IO.SearchOption) |
| HostContract | FileSystem | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | Xamarin.AndroidX.Migration.BuildTasks.CollectAllFiles.Execute() | Bound | yes | yes | 2 | Xamarin.AndroidX.Migration.BuildTasks.CollectAllFiles.Execute() -Call-> System.IO.Directory.EnumerateFiles(System.String,System.String,System.IO.SearchOption) |
| HostContract | FileSystem | Xamarin.Build.Download | 0.11.6 | build | no | Xamarin.Build.Download.XamarinDownloadArchives.Get7ZipPath(System.String,System.String) | Bound | yes | yes | 2 | Xamarin.Build.Download.XamarinDownloadArchives.Get7ZipPath(System.String,System.String) -Call-> System.IO.File.Exists(System.String) |
| HostContract | FileSystem | Xamarin.Build.Download | 0.11.6 | buildTransitive | no | Xamarin.Build.Download.XamarinDownloadArchives.Get7ZipPath(System.String,System.String) | Bound | yes | yes | 2 | Xamarin.Build.Download.XamarinDownloadArchives.Get7ZipPath(System.String,System.String) -Call-> System.IO.File.Exists(System.String) |
| HostContract | FileSystem | coverlet.msbuild | 10.1.0 | tasks/net10.0 | no | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() | Bound | yes | yes | 2 | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | coverlet.msbuild | 10.1.0 | tasks/net8.0 | no | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() | Bound | yes | yes | 2 | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | coverlet.msbuild | 10.1.0 | tasks/net9.0 | no | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() | Bound | yes | yes | 2 | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | coverlet.msbuild | 10.1.0 | tasks/netstandard2.0 | no | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() | Bound | yes | yes | 2 | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() -Call-> System.IO.Directory.CreateDirectory(System.String) |
| HostContract | FileSystem | dotnet-sonarscanner | 12.1.0 | tools/netcoreapp3.1/any | no | SonarScanner.MSBuild.Tasks.GetAnalyzerSettings.AbsoluteRulesetPath() | Bound | yes | yes | 2 | SonarScanner.MSBuild.Tasks.GetAnalyzerSettings.AbsoluteRulesetPath() -Call-> System.IO.File.Exists(System.String) |
| HostContract | Network | ReportGenerator | 5.5.12 | tools/net10.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Bound | yes | yes | 6 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult) -TypeInitializer-> Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() |
| HostContract | Network | ReportGenerator | 5.5.12 | tools/net47 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Bound | yes | yes | 8 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult) -TypeInitializer-> Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() -NewObj-> System.Net.Http.HttpClientHandler..ctor() -Call-> System.Net.HttpWebRequest.get_DefaultMaximumResponseHeadersLength() |
| HostContract | Network | ReportGenerator | 5.5.12 | tools/net8.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Bound | yes | yes | 6 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult) -TypeInitializer-> Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() |
| HostContract | Network | ReportGenerator | 5.5.12 | tools/net9.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Bound | yes | yes | 6 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult) -TypeInitializer-> Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() |
| HostContract | Network | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/net462 | no | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() | Instantiated | yes | yes | 15 | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTaskExecutor.Execute() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.MSBuildTaskAnalyticsTransmitter.TryTransmitProjectCompilingEventAsync() -StateMachine-> Reqnroll.Tools.MsBuild.Generation.MSBuildTaskAnalyticsTransmitter.\<TryTransmitProjectCompilingEventAsync>d__6.MoveNext() -Call-> Reqnroll.Tools.MsBuild.Generation.MSBuildTaskAnalyticsTransmitter.TransmitProjectCompilingEventAsync() -StateMachine-> Reqnroll.Tools.MsBuild.Generation.MSBuildTaskAnalyticsTransmitter.\<TransmitProjectCompilingEventAsync>d__7.MoveNext() -Dispatch-> Reqnroll.Analytics.AnalyticsTransmitter.TransmitReqnrollProjectCompilingEventAsync(Reqnroll.Analytics.ReqnrollProjectCompilingEvent) -StateMachine-> Reqnroll.Analytics.AnalyticsTransmitter.\<TransmitReqnrollProjectCompilingEventAsync>d__5.MoveNext() -Call-> Reqnroll.Analytics.AnalyticsTransmitter.TransmitEventAsync(Reqnroll.Analytics.IAnalyticsEvent) -StateMachine-> Reqnroll.Analytics.AnalyticsTransmitter.\<TransmitEventAsync>d__8.MoveNext() -Dispatch-> Reqnroll.Analytics.HttpClientAnalyticsTransmitterSink.TransmitEventAsync(Reqnroll.Analytics.IAnalyticsEvent,System.String) -StateMachine-> Reqnroll.Analytics.HttpClientAnalyticsTransmitterSink.\<TransmitEventAsync>d__6.MoveNext() -Call-> Reqnroll.Analytics.HttpClientAnalyticsTransmitterSink.TransmitEventInternalAsync(Reqnroll.Analytics.IAnalyticsEvent,System.String) -StateMachine-> Reqnroll.Analytics.HttpClientAnalyticsTransmitterSink.\<TransmitEventInternalAsync>d__7.MoveNext() -CallVirt-> System.Net.Http.HttpClient.PostAsync(System.Uri,System.Net.Http.HttpContent) |
| HostContract | Network | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() | Instantiated | yes | yes | 15 | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTaskExecutor.Execute() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.MSBuildTaskAnalyticsTransmitter.TryTransmitProjectCompilingEventAsync() -StateMachine-> Reqnroll.Tools.MsBuild.Generation.MSBuildTaskAnalyticsTransmitter.\<TryTransmitProjectCompilingEventAsync>d__6.MoveNext() -Call-> Reqnroll.Tools.MsBuild.Generation.MSBuildTaskAnalyticsTransmitter.TransmitProjectCompilingEventAsync() -StateMachine-> Reqnroll.Tools.MsBuild.Generation.MSBuildTaskAnalyticsTransmitter.\<TransmitProjectCompilingEventAsync>d__7.MoveNext() -Dispatch-> Reqnroll.Analytics.AnalyticsTransmitter.TransmitReqnrollProjectCompilingEventAsync(Reqnroll.Analytics.ReqnrollProjectCompilingEvent) -StateMachine-> Reqnroll.Analytics.AnalyticsTransmitter.\<TransmitReqnrollProjectCompilingEventAsync>d__5.MoveNext() -Call-> Reqnroll.Analytics.AnalyticsTransmitter.TransmitEventAsync(Reqnroll.Analytics.IAnalyticsEvent) -StateMachine-> Reqnroll.Analytics.AnalyticsTransmitter.\<TransmitEventAsync>d__8.MoveNext() -Dispatch-> Reqnroll.Analytics.HttpClientAnalyticsTransmitterSink.TransmitEventAsync(Reqnroll.Analytics.IAnalyticsEvent,System.String) -StateMachine-> Reqnroll.Analytics.HttpClientAnalyticsTransmitterSink.\<TransmitEventAsync>d__6.MoveNext() -Call-> Reqnroll.Analytics.HttpClientAnalyticsTransmitterSink.TransmitEventInternalAsync(Reqnroll.Analytics.IAnalyticsEvent,System.String) -StateMachine-> Reqnroll.Analytics.HttpClientAnalyticsTransmitterSink.\<TransmitEventInternalAsync>d__7.MoveNext() -CallVirt-> System.Net.Http.HttpClient.PostAsync(System.Uri,System.Net.Http.HttpContent) |
| HostContract | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Tasks.DownloadFile.Download(System.Uri) | Bound | yes | yes | 3 | Microsoft.Build.Tasks.DownloadFile.Download(System.Uri) -NewObj-> System.Net.Http.HttpClientHandler..ctor() -Call-> System.Net.HttpWebRequest.get_DefaultMaximumResponseHeadersLength() |
| HostContract | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.Build.Tasks.DownloadFile.Download(System.Uri) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.DownloadFile.Download(System.Uri) -NewObj-> System.Net.Http.HttpClient..ctor(System.Net.Http.HttpMessageHandler,System.Boolean) |
| HostContract | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.Build.Tasks.DownloadFile.Download(System.Uri) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.DownloadFile.Download(System.Uri) -NewObj-> System.Net.Http.HttpClient..ctor(System.Net.Http.HttpMessageHandler,System.Boolean) |
| HostContract | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.Build.Tasks.DownloadFile.Download(System.Uri) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.DownloadFile.Download(System.Uri) -NewObj-> System.Net.Http.HttpClient..ctor(System.Net.Http.HttpMessageHandler,System.Boolean) |
| HostContract | Network | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() | Instantiated | yes | yes | 4 | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() -Dispatch-> Mono.Unix.UnixClient.Dispose() -CallVirt-> Mono.Unix.UnixClient.Dispose(System.Boolean) -CallVirt-> System.Net.Sockets.Socket.Close() |
| HostContract | Network | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() | Instantiated | yes | yes | 4 | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() -Dispatch-> Mono.Unix.UnixClient.Dispose() -CallVirt-> Mono.Unix.UnixClient.Dispose(System.Boolean) -CallVirt-> System.Net.Sockets.Socket.Close() |
| HostContract | Network | Xamarin.Build.Download | 0.11.6 | build | no | Xamarin.Build.Download.XamarinDownloadArchives.MakeSureLibraryIsInPlace(Xamarin.Build.Download.XamarinBuildDownload,System.Threading.CancellationToken) | Bound | yes | yes | 3 | Xamarin.Build.Download.XamarinDownloadArchives.MakeSureLibraryIsInPlace(Xamarin.Build.Download.XamarinBuildDownload,System.Threading.CancellationToken) -StateMachine-> Xamarin.Build.Download.XamarinDownloadArchives.\<MakeSureLibraryIsInPlace>d__33.MoveNext() -NewObj-> System.Net.WebClient..ctor() |
| HostContract | Network | Xamarin.Build.Download | 0.11.6 | buildTransitive | no | Xamarin.Build.Download.XamarinDownloadArchives.MakeSureLibraryIsInPlace(Xamarin.Build.Download.XamarinBuildDownload,System.Threading.CancellationToken) | Bound | yes | yes | 3 | Xamarin.Build.Download.XamarinDownloadArchives.MakeSureLibraryIsInPlace(Xamarin.Build.Download.XamarinBuildDownload,System.Threading.CancellationToken) -StateMachine-> Xamarin.Build.Download.XamarinDownloadArchives.\<MakeSureLibraryIsInPlace>d__33.MoveNext() -NewObj-> System.Net.WebClient..ctor() |
| HostContract | Network | dotnet-sonarscanner | 12.1.0 | tools/netcoreapp3.1/any | no | SonarScanner.MSBuild.Tasks.GetAnalyzerSettings.WriteMergedRuleSet(System.String,System.String,System.String) | Instantiated | yes | yes | 3 | SonarScanner.MSBuild.Tasks.GetAnalyzerSettings.WriteMergedRuleSet(System.String,System.String,System.String) -Dispatch-> SonarScanner.MSBuild.PreProcessor.WebClientDownloader.Dispose() -CallVirt-> System.Net.Http.HttpMessageInvoker.Dispose() |
| HostContract | ProcessExecution | Aspire.Hosting.AppHost | 13.6.4 | tools/net472 | no | Aspire.Hosting.Tasks.ResolveAspireCliInvocation.TryGetLatestSdkVersion(System.String,System.String&) | Bound | yes | yes | 2 | Aspire.Hosting.Tasks.ResolveAspireCliInvocation.TryGetLatestSdkVersion(System.String,System.String&) -CallVirt-> System.Diagnostics.Process.Kill() |
| HostContract | ProcessExecution | Aspire.Hosting.AppHost | 13.6.4 | tools/net8.0 | no | Aspire.Hosting.Tasks.ResolveAspireCliInvocation.TryGetLatestSdkVersion(System.String,System.String&) | Bound | yes | yes | 2 | Aspire.Hosting.Tasks.ResolveAspireCliInvocation.TryGetLatestSdkVersion(System.String,System.String&) -CallVirt-> System.Diagnostics.Process.Kill() |
| HostContract | ProcessExecution | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/net46 | no | Microsoft.AspNetCore.Razor.Tasks.DotNetToolTask.Execute() | Bound | yes | yes | 2 | Microsoft.AspNetCore.Razor.Tasks.DotNetToolTask.Execute() -CallVirt-> System.Diagnostics.Process.get_Id() |
| HostContract | ProcessExecution | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/netstandard2.0 | no | Microsoft.AspNetCore.Razor.Tasks.DotNetToolTask.Execute() | Bound | yes | yes | 2 | Microsoft.AspNetCore.Razor.Tasks.DotNetToolTask.Execute() -CallVirt-> System.Diagnostics.Process.get_Id() |
| HostContract | ProcessExecution | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tools | no | Microsoft.CodeAnalysis.Diagnostics.CSharp.CSharpCompilerDiagnosticAnalyzer.GetSupportedErrorCodes() | Instantiated | yes | yes | 6 | Microsoft.CodeAnalysis.Diagnostics.CSharp.CSharpCompilerDiagnosticAnalyzer.GetSupportedErrorCodes() -Dispatch-> Microsoft.AspNetCore.Razor.Tools.Connection.Dispose() -Dispatch-> Microsoft.AspNetCore.Razor.Tools.ConnectionHost.NamedPipeConnection.Dispose(System.Boolean) -TypeInitializer-> Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() -Call-> Microsoft.AspNetCore.Razor.Tools.ServerLogger.GetCurrentProcessId() -CallVirt-> System.Diagnostics.Process.get_Id() |
| HostContract | ProcessExecution | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/net46 | no | ExtensionsMetadataGenerator.BuildTasks.GenerateFunctionsExtensionsMetadata.Execute() | Bound | yes | yes | 2 | ExtensionsMetadataGenerator.BuildTasks.GenerateFunctionsExtensionsMetadata.Execute() -NewObj-> System.Diagnostics.Process..ctor() |
| HostContract | ProcessExecution | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/netstandard2.0 | no | ExtensionsMetadataGenerator.BuildTasks.GenerateFunctionsExtensionsMetadata.Execute() | Bound | yes | yes | 2 | ExtensionsMetadataGenerator.BuildTasks.GenerateFunctionsExtensionsMetadata.Execute() -NewObj-> System.Diagnostics.Process..ctor() |
| HostContract | ProcessExecution | Microsoft.Net.Compilers | 4.2.0 | tools | no | Microsoft.CodeAnalysis.BuildTasks.ManagedCompiler.ExecuteTool(System.String,System.String,System.String) | Bound | yes | yes | 2 | Microsoft.CodeAnalysis.BuildTasks.ManagedCompiler.ExecuteTool(System.String,System.String,System.String) -CallVirt-> System.Diagnostics.Process.get_Id() |
| HostContract | ProcessExecution | ReportGenerator | 5.5.12 | tools/net10.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Instantiated | yes | yes | 10 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult,Palmmedia.ReportGenerator.Core.Parser.FileReading.IFileReader) -Call-> Palmmedia.ReportGenerator.Core.Reporting.ReportGenerator.CreateReport(System.Boolean,System.Collections.Generic.List\`1\<Palmmedia.ReportGenerator.Core.Parser.Analysis.HistoricCoverage>,System.DateTime,System.String) -Dispatch-> Palmmedia.ReportGenerator.Core.Reporting.Builders.CodeClimateReportBuilder.CreateSummaryReport(Palmmedia.ReportGenerator.Core.Parser.Analysis.SummaryResult) -Call-> Palmmedia.ReportGenerator.Core.Reporting.GitHelper.GetFileHash(System.String) -Call-> Palmmedia.ReportGenerator.Core.Reporting.GitHelper.ExecuteGitCommand(System.String) -NewObj-> System.Diagnostics.Process..ctor() |
| HostContract | ProcessExecution | ReportGenerator | 5.5.12 | tools/net47 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Instantiated | yes | yes | 10 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult,Palmmedia.ReportGenerator.Core.Parser.FileReading.IFileReader) -Call-> Palmmedia.ReportGenerator.Core.Reporting.ReportGenerator.CreateReport(System.Boolean,System.Collections.Generic.List\`1\<Palmmedia.ReportGenerator.Core.Parser.Analysis.HistoricCoverage>,System.DateTime,System.String) -Dispatch-> Palmmedia.ReportGenerator.Core.Reporting.Builders.CodeClimateReportBuilder.CreateSummaryReport(Palmmedia.ReportGenerator.Core.Parser.Analysis.SummaryResult) -Call-> Palmmedia.ReportGenerator.Core.Reporting.GitHelper.GetFileHash(System.String) -Call-> Palmmedia.ReportGenerator.Core.Reporting.GitHelper.ExecuteGitCommand(System.String) -NewObj-> System.Diagnostics.Process..ctor() |
| HostContract | ProcessExecution | ReportGenerator | 5.5.12 | tools/net8.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Instantiated | yes | yes | 10 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult,Palmmedia.ReportGenerator.Core.Parser.FileReading.IFileReader) -Call-> Palmmedia.ReportGenerator.Core.Reporting.ReportGenerator.CreateReport(System.Boolean,System.Collections.Generic.List\`1\<Palmmedia.ReportGenerator.Core.Parser.Analysis.HistoricCoverage>,System.DateTime,System.String) -Dispatch-> Palmmedia.ReportGenerator.Core.Reporting.Builders.CodeClimateReportBuilder.CreateSummaryReport(Palmmedia.ReportGenerator.Core.Parser.Analysis.SummaryResult) -Call-> Palmmedia.ReportGenerator.Core.Reporting.GitHelper.GetFileHash(System.String) -Call-> Palmmedia.ReportGenerator.Core.Reporting.GitHelper.ExecuteGitCommand(System.String) -NewObj-> System.Diagnostics.Process..ctor() |
| HostContract | ProcessExecution | ReportGenerator | 5.5.12 | tools/net9.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Instantiated | yes | yes | 10 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult,Palmmedia.ReportGenerator.Core.Parser.FileReading.IFileReader) -Call-> Palmmedia.ReportGenerator.Core.Reporting.ReportGenerator.CreateReport(System.Boolean,System.Collections.Generic.List\`1\<Palmmedia.ReportGenerator.Core.Parser.Analysis.HistoricCoverage>,System.DateTime,System.String) -Dispatch-> Palmmedia.ReportGenerator.Core.Reporting.Builders.CodeClimateReportBuilder.CreateSummaryReport(Palmmedia.ReportGenerator.Core.Parser.Analysis.SummaryResult) -Call-> Palmmedia.ReportGenerator.Core.Reporting.GitHelper.GetFileHash(System.String) -Call-> Palmmedia.ReportGenerator.Core.Reporting.GitHelper.ExecuteGitCommand(System.String) -NewObj-> System.Diagnostics.Process..ctor() |
| HostContract | ProcessExecution | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/net462 | no | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() | Instantiated | yes | yes | 4 | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTaskExecutor.Execute() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.ProcessInfoDumper.DumpProcessInfo() -CallVirt-> System.Diagnostics.Process.get_Id() |
| HostContract | ProcessExecution | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() | Instantiated | yes | yes | 4 | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTaskExecutor.Execute() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.ProcessInfoDumper.DumpProcessInfo() -CallVirt-> System.Diagnostics.Process.get_Id() |
| HostContract | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Utilities.ToolTask.ExecuteTool(System.String,System.String,System.String) | Bound | yes | yes | 2 | Microsoft.Build.Utilities.ToolTask.ExecuteTool(System.String,System.String,System.String) -NewObj-> System.Diagnostics.Process..ctor() |
| HostContract | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.Build.Tasks.RoslynCodeTaskFactoryCompilerBase..cctor() | Bound | yes | yes | 2 | Microsoft.Build.Tasks.RoslynCodeTaskFactoryCompilerBase..cctor() -CallVirt-> System.Diagnostics.Process.get_MainModule() |
| HostContract | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.Build.Tasks.RoslynCodeTaskFactoryCompilerBase..cctor() | Bound | yes | yes | 2 | Microsoft.Build.Tasks.RoslynCodeTaskFactoryCompilerBase..cctor() -CallVirt-> System.Diagnostics.Process.get_MainModule() |
| HostContract | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.Build.Tasks.RoslynCodeTaskFactoryCompilerBase..cctor() | Bound | yes | yes | 2 | Microsoft.Build.Tasks.RoslynCodeTaskFactoryCompilerBase..cctor() -CallVirt-> System.Diagnostics.Process.get_MainModule() |
| HostContract | ProcessExecution | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() | Bound | yes | yes | 4 | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() -CallVirt-> Xamarin.AndroidX.Migration.Jetifier.Jetify(System.Collections.Generic.IEnumerable\`1\<Xamarin.AndroidX.Migration.MigrationPair>) -Call-> Xamarin.AndroidX.Migration.MigrationTool.ExecuteExternalProcess(System.String,System.String,System.String,System.Threading.CancellationToken) -NewObj-> System.Diagnostics.Process..ctor() |
| HostContract | ProcessExecution | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() | Bound | yes | yes | 4 | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() -CallVirt-> Xamarin.AndroidX.Migration.Jetifier.Jetify(System.Collections.Generic.IEnumerable\`1\<Xamarin.AndroidX.Migration.MigrationPair>) -Call-> Xamarin.AndroidX.Migration.MigrationTool.ExecuteExternalProcess(System.String,System.String,System.String,System.Threading.CancellationToken) -NewObj-> System.Diagnostics.Process..ctor() |
| HostContract | ProcessExecution | Xamarin.Build.Download | 0.11.6 | build | no | Xamarin.Build.Download.XamarinDownloadArchives.CreateExtractionArgs(System.String,System.String,Xamarin.Build.Download.ArchiveKind,System.String,System.Boolean) | Bound | yes | yes | 2 | Xamarin.Build.Download.XamarinDownloadArchives.CreateExtractionArgs(System.String,System.String,Xamarin.Build.Download.ArchiveKind,System.String,System.Boolean) -NewObj-> System.Diagnostics.ProcessStartInfo..ctor(System.String,System.String) |
| HostContract | ProcessExecution | Xamarin.Build.Download | 0.11.6 | buildTransitive | no | Xamarin.Build.Download.XamarinDownloadArchives.CreateExtractionArgs(System.String,System.String,Xamarin.Build.Download.ArchiveKind,System.String,System.Boolean) | Bound | yes | yes | 2 | Xamarin.Build.Download.XamarinDownloadArchives.CreateExtractionArgs(System.String,System.String,Xamarin.Build.Download.ArchiveKind,System.String,System.Boolean) -NewObj-> System.Diagnostics.ProcessStartInfo..ctor(System.String,System.String) |
| HostContract | Registry | OpenCover | 4.7.1221 | build | no | OpenCover.MSBuild.OpenCover.GenerateFullPathToTool() | Bound | yes | yes | 2 | OpenCover.MSBuild.OpenCover.GenerateFullPathToTool() -CallVirt-> Microsoft.Win32.RegistryKey.GetValue(System.String) |
| HostContract | Registry | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Tasks.GenerateResource..cctor() | Bound | yes | yes | 2 | Microsoft.Build.Tasks.GenerateResource..cctor() -Call-> Microsoft.Win32.Registry.GetValue(System.String,System.String,System.Object) |
| HostContract | NativeInterop | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/net46 | no | Microsoft.AspNetCore.Razor.Tasks.DotNetToolTask.TryExecuteOnServer(System.String,System.String,System.String,System.Int32&) | Bound | no | no | 4 | Microsoft.AspNetCore.Razor.Tasks.DotNetToolTask.TryExecuteOnServer(System.String,System.String,System.String,System.Int32&) -Call-> Microsoft.AspNetCore.Razor.Tools.ServerConnection.RunOnServer(System.String,System.Collections.Generic.IList\`1\<System.String>,Microsoft.AspNetCore.Razor.Tools.ServerPaths,System.Threading.CancellationToken,System.String,System.Boolean) -Ldftn-> Microsoft.AspNetCore.Razor.Tools.ServerConnection.TryCreateServerCore(System.String,System.String,System.Nullable\`1\<System.Int32>&,System.Boolean) -Call-> Microsoft.AspNetCore.Razor.Tools.NativeMethods.CloseHandle(System.IntPtr) |
| HostContract | NativeInterop | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/netstandard2.0 | no | Microsoft.AspNetCore.Razor.Tasks.DotNetToolTask.TryExecuteOnServer(System.String,System.String,System.String,System.Int32&) | Bound | no | no | 4 | Microsoft.AspNetCore.Razor.Tasks.DotNetToolTask.TryExecuteOnServer(System.String,System.String,System.String,System.Int32&) -Call-> Microsoft.AspNetCore.Razor.Tools.ServerConnection.RunOnServer(System.String,System.Collections.Generic.IList\`1\<System.String>,Microsoft.AspNetCore.Razor.Tools.ServerPaths,System.Threading.CancellationToken,System.String,System.Boolean) -Ldftn-> Microsoft.AspNetCore.Razor.Tools.ServerConnection.TryCreateServerCore(System.String,System.String,System.Nullable\`1\<System.Int32>&,System.Boolean) -Call-> Microsoft.AspNetCore.Razor.Tools.NativeMethods.CloseHandle(System.IntPtr) |
| HostContract | NativeInterop | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tools | no | Microsoft.CodeAnalysis.Diagnostics.CSharp.CSharpCompilerDiagnosticAnalyzer.GetSupportedErrorCodes() | Instantiated | yes | yes | 5 | Microsoft.CodeAnalysis.Diagnostics.CSharp.CSharpCompilerDiagnosticAnalyzer.GetSupportedErrorCodes() -Dispatch-> Microsoft.DiaSymReader.SymUnmanagedWriterImpl.Dispose() -Call-> Microsoft.DiaSymReader.SymUnmanagedWriterImpl.DisposeImpl() -Call-> Microsoft.DiaSymReader.SymUnmanagedWriterImpl.CloseSymWriter() -CallVirt-> Microsoft.DiaSymReader.ISymUnmanagedWriter5.Close() |
| HostContract | NativeInterop | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/netstandard2.0 | no | Microsoft.Build.Utilities.ToolTask.Execute() | Bound | yes | yes | 3 | Microsoft.Build.Utilities.ToolTask.Execute() -Call-> Microsoft.Build.Shared.EncodingUtilities.get_CurrentSystemOemEncoding() -Call-> Microsoft.Build.Shared.NativeMethodsShared.GetOEMCP() |
| HostContract | NativeInterop | Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | buildTransitive/netstandard2.0 | no | Microsoft.Maui.Controls.Build.Tasks.XamlCTask.Execute(System.Collections.Generic.IList\`1\<System.Exception>&) | Instantiated | yes | yes | 4 | Microsoft.Maui.Controls.Build.Tasks.XamlCTask.Execute(System.Collections.Generic.IList\`1\<System.Exception>&) -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| HostContract | NativeInterop | Microsoft.NET.ILLink.Tasks | 10.0.14 | tools/netframework | no | ILLink.Tasks.CombineLinkerXmlFiles.Execute() | Instantiated | no | yes | 16 | ILLink.Tasks.CombineLinkerXmlFiles.Execute() -Dispatch-> Mono.Cecil.AssemblyDefinition.Dispose() -Call-> Mono.Cecil.AssemblyDefinition.get_Modules() -Ldftn-> Mono.Cecil.AssemblyDefinition.\<>c.\<get_Modules>b__14_0(Mono.Cecil.AssemblyDefinition,Mono.Cecil.MetadataReader) -CallVirt-> Mono.Cecil.MetadataReader.ReadModules() -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(Mono.Disposable\`1\<System.IO.Stream>,System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleReader.CreateModule(Mono.Cecil.PE.Image,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleReader.ReadSymbols(Mono.Cecil.ModuleDefinition,Mono.Cecil.ReaderParameters) -CallVirt-> Mono.Cecil.ModuleDefinition.ReadSymbols(Mono.Cecil.Cil.ISymbolReader,System.Boolean) -Dispatch-> Mono.Cecil.Pdb.NativePdbReader.ProcessDebugHeader(Mono.Cecil.Cil.ImageDebugHeader) -Call-> Microsoft.Cci.Pdb.PdbFile.LoadFunctions(System.IO.Stream) -NewObj-> Microsoft.Cci.Pdb.MsfDirectory..ctor(Microsoft.Cci.Pdb.PdbReader,Microsoft.Cci.Pdb.PdbFileHeader,Microsoft.Cci.Pdb.BitAccess) -CallVirt-> Microsoft.Cci.Pdb.BitAccess.Append(System.IO.Stream,System.Int32) -Dispatch-> System.Reflection.Internal.ReadOnlyUnmanagedMemoryStream.Read(System.Byte\[\],System.Int32,System.Int32) -Call-> System.Runtime.InteropServices.Marshal.Copy(System.IntPtr,System.Byte\[\],System.Int32,System.Int32) |
| HostContract | NativeInterop | Microsoft.Net.Compilers | 4.2.0 | tools | no | Microsoft.CodeAnalysis.BuildTasks.Csc.InitializeHostCompiler(Microsoft.Build.Tasks.Hosting.ICscHostObject) | Bound | yes | yes | 2 | Microsoft.CodeAnalysis.BuildTasks.Csc.InitializeHostCompiler(Microsoft.Build.Tasks.Hosting.ICscHostObject) -CallVirt-> Microsoft.CodeAnalysis.BuildTasks.IAnalyzerConfigFilesHostObject.SetAnalyzerConfigFiles(Microsoft.Build.Framework.ITaskItem\[\]) |
| HostContract | NativeInterop | ReportGenerator | 5.5.12 | tools/net10.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Instantiated | yes | yes | 8 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.ReportConfigurationValidator.Validate(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Dispatch-> Palmmedia.ReportGenerator.Core.Reporting.ReportBuilderFactory.GetAvailableReportTypes() -Dispatch-> Palmmedia.ReportGenerator.Core.Plugin.ReflectionPluginLoader.LoadInstancesOfType\`1() -Call-> Palmmedia.ReportGenerator.Core.Plugin.FileUnblocker.Unblock(System.String) -Call-> Palmmedia.ReportGenerator.Core.Plugin.FileUnblocker.DeleteFile(System.String) |
| HostContract | NativeInterop | ReportGenerator | 5.5.12 | tools/net47 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Bound | yes | yes | 11 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds,Palmmedia.ReportGenerator.Core.Parser.ParserResult) -TypeInitializer-> Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() -Call-> System.Net.Http.HttpClient..ctor(System.Net.Http.HttpMessageHandler) -Call-> System.Net.Http.HttpClient..ctor(System.Net.Http.HttpMessageHandler,System.Boolean) -Call-> System.Net.NetEventSource.Enter(System.Object,System.Object,System.String) -Call-> System.Net.NetEventSource.Format(System.Object) -CallVirt-> System.Runtime.InteropServices.SafeHandle.DangerousGetHandle() |
| HostContract | NativeInterop | ReportGenerator | 5.5.12 | tools/net8.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Instantiated | yes | yes | 8 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.ReportConfigurationValidator.Validate(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Dispatch-> Palmmedia.ReportGenerator.Core.Reporting.ReportBuilderFactory.GetAvailableReportTypes() -Dispatch-> Palmmedia.ReportGenerator.Core.Plugin.ReflectionPluginLoader.LoadInstancesOfType\`1() -Call-> Palmmedia.ReportGenerator.Core.Plugin.FileUnblocker.Unblock(System.String) -Call-> Palmmedia.ReportGenerator.Core.Plugin.FileUnblocker.DeleteFile(System.String) |
| HostContract | NativeInterop | ReportGenerator | 5.5.12 | tools/net9.0 | no | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() | Instantiated | yes | yes | 8 | Palmmedia.ReportGenerator.MSBuild.ReportGenerator.Execute() -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Call-> Palmmedia.ReportGenerator.Core.Generator.GenerateReport(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration,Palmmedia.ReportGenerator.Core.Settings,Palmmedia.ReportGenerator.Core.MinimumCoverageThresholds,Palmmedia.ReportGenerator.Core.CodeAnalysis.RiskHotspotsAnalysisThresholds) -Call-> Palmmedia.ReportGenerator.Core.ReportConfigurationValidator.Validate(Palmmedia.ReportGenerator.Core.Reporting.IReportConfiguration) -Dispatch-> Palmmedia.ReportGenerator.Core.Reporting.ReportBuilderFactory.GetAvailableReportTypes() -Dispatch-> Palmmedia.ReportGenerator.Core.Plugin.ReflectionPluginLoader.LoadInstancesOfType\`1() -Call-> Palmmedia.ReportGenerator.Core.Plugin.FileUnblocker.Unblock(System.String) -Call-> Palmmedia.ReportGenerator.Core.Plugin.FileUnblocker.DeleteFile(System.String) |
| HostContract | NativeInterop | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/net462 | no | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.GetPluginParameters(Microsoft.Build.Framework.ITaskItem) | Instantiated | yes | yes | 14 | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.GetPluginParameters(Microsoft.Build.Framework.ITaskItem) -Dispatch-> Reqnroll.Bindings.StepDefinitionRegexCalculator.\<GetPrefixesToRemove>d__5.MoveNext() -Dispatch-> System.Text.Json.Nodes.JsonNode.ToString() -Call-> System.Text.Json.Nodes.JsonNode.WriteToPooledBuffer(System.Text.Json.JsonSerializerOptions,System.Text.Json.JsonWriterOptions,System.Int32) -Dispatch-> System.Text.Json.Nodes.JsonValuePrimitive\`1.WriteTo(System.Text.Json.Utf8JsonWriter,System.Text.Json.JsonSerializerOptions) -Dispatch-> System.Text.Json.Serialization.Converters.EnumConverter\`1.Write(System.Text.Json.Utf8JsonWriter,\!0,System.Text.Json.JsonSerializerOptions) -Call-> System.Text.Json.JsonEncodedText.Encode(System.String,System.Text.Encodings.Web.JavaScriptEncoder) -Call-> System.Text.Json.JsonEncodedText.Encode(System.ReadOnlySpan\`1\<System.Char>,System.Text.Encodings.Web.JavaScriptEncoder) -Call-> System.Text.Json.JsonEncodedText.TranscodeAndEncode(System.ReadOnlySpan\`1\<System.Char>,System.Text.Encodings.Web.JavaScriptEncoder) -Call-> System.Text.Json.JsonReaderHelper.GetUtf8ByteCount(System.ReadOnlySpan\`1\<System.Char>) -Dispatch-> System.Text.EncodingNLS.GetByteCount(System.Char*,System.Int32) -Dispatch-> System.Text.DBCSCodePageEncoding.GetByteCount(System.Char*,System.Int32,System.Text.EncoderNLS) -Call-> System.Text.BaseCodePageEncoding.CheckMemorySection() -CallVirt-> System.Runtime.InteropServices.SafeHandle.DangerousGetHandle() |
| HostContract | NativeInterop | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() | Instantiated | yes | yes | 3 | Reqnroll.Tools.MsBuild.Generation.GenerateFeatureFileCodeBehindTask.Execute() -Dispatch-> Microsoft.Win32.RegistryKey.Dispose() -CallVirt-> System.Runtime.InteropServices.SafeHandle.Dispose() |
| HostContract | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Tasks.Copy.DoCopyWithRetries(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.CopyFileWithState) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.Copy.DoCopyWithRetries(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.CopyFileWithState) -Call-> System.Runtime.InteropServices.Marshal.GetHRForException(System.Exception) |
| HostContract | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.Build.Tasks.Copy.DoCopyWithRetries(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.CopyFileWithState) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.Copy.DoCopyWithRetries(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.CopyFileWithState) -Call-> System.Runtime.InteropServices.Marshal.GetHRForException(System.Exception) |
| HostContract | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.Build.Tasks.Copy.DoCopyWithRetries(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.CopyFileWithState) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.Copy.DoCopyWithRetries(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.CopyFileWithState) -Call-> System.Runtime.InteropServices.Marshal.GetHRForException(System.Exception) |
| HostContract | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.Build.Tasks.Copy.DoCopyWithRetries(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.CopyFileWithState) | Bound | yes | yes | 2 | Microsoft.Build.Tasks.Copy.DoCopyWithRetries(Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.FileState,Microsoft.Build.Tasks.CopyFileWithState) -Call-> System.Runtime.InteropServices.Marshal.GetHRForException(System.Exception) |
| HostContract | NativeInterop | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() | Instantiated | yes | yes | 4 | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| HostContract | NativeInterop | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() | Instantiated | yes | yes | 4 | Xamarin.AndroidX.Migration.BuildTasks.JetifyFiles.Execute() -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| HostContract | NativeInterop | Xamarin.Build.Download | 0.11.6 | build | no | Xamarin.Build.Download.XamarinDownloadArchives.CreateExtractionArgs(System.String,System.String,Xamarin.Build.Download.ArchiveKind,System.String,System.Boolean) | Bound | yes | yes | 4 | Xamarin.Build.Download.XamarinDownloadArchives.CreateExtractionArgs(System.String,System.String,Xamarin.Build.Download.ArchiveKind,System.String,System.Boolean) -TypeInitializer-> Xamarin.Build.Download.Platform..cctor() -Call-> Xamarin.Build.Download.Platform.IsRunningOnMac() -Call-> System.Runtime.InteropServices.Marshal.PtrToStringAnsi(System.IntPtr) |
| HostContract | NativeInterop | Xamarin.Build.Download | 0.11.6 | buildTransitive | no | Xamarin.Build.Download.XamarinDownloadArchives.CreateExtractionArgs(System.String,System.String,Xamarin.Build.Download.ArchiveKind,System.String,System.Boolean) | Bound | yes | yes | 4 | Xamarin.Build.Download.XamarinDownloadArchives.CreateExtractionArgs(System.String,System.String,Xamarin.Build.Download.ArchiveKind,System.String,System.Boolean) -TypeInitializer-> Xamarin.Build.Download.Platform..cctor() -Call-> Xamarin.Build.Download.Platform.IsRunningOnMac() -Call-> System.Runtime.InteropServices.Marshal.PtrToStringAnsi(System.IntPtr) |
| HostContract | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/net10.0 | no | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() | Instantiated | yes | yes | 4 | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| HostContract | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/net8.0 | no | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() | Instantiated | yes | yes | 4 | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| HostContract | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/net9.0 | no | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() | Instantiated | yes | yes | 4 | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| HostContract | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/netstandard2.0 | no | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() | Instantiated | yes | yes | 3 | Coverlet.MSbuild.Tasks.CoverageResultTask.Execute() -Dispatch-> System.Security.Cryptography.SP800108HmacCounterKdfImplementationCng.Dispose() -CallVirt-> System.Runtime.InteropServices.SafeHandle.Dispose() |
| HostContract | NativeInterop | dotnet-sonarscanner | 12.1.0 | tools/netcoreapp3.1/any | no | SonarScanner.MSBuild.Tasks.WriteProjectInfoFile.CalculateProjectGuid() | Instantiated | no | yes | 13 | SonarScanner.MSBuild.Tasks.WriteProjectInfoFile.CalculateProjectGuid() -Dispatch-> Google.Protobuf.Reflection.FileDescriptor.ToString() -Call-> Google.Protobuf.Reflection.FileDescriptor.get_Name() -CallVirt-> Google.Protobuf.Reflection.FileDescriptorProto.get_Name() -TypeInitializer-> Google.Protobuf.Reflection.FileDescriptorProto..cctor() -Call-> Google.Protobuf.FieldCodec.ForMessage\`1(System.UInt32,Google.Protobuf.MessageParser\`1\<\!\!0>) -Ldftn-> Google.Protobuf.FieldCodec.\<>c__32\`1.\<ForMessage>b__32_3(\!0&,\!0) -Dispatch-> Google.Protobuf.Reflection.EnumOptions.MergeFrom(Google.Protobuf.Reflection.EnumOptions) -Call-> Google.Protobuf.ExtensionSet.MergeFrom\`1(Google.Protobuf.ExtensionSet\`1\<\!\!0>&,Google.Protobuf.ExtensionSet\`1\<\!\!0>) -Dispatch-> Google.Protobuf.RepeatedExtensionValue\`1.MergeFrom(Google.Protobuf.ParseContext&) -CallVirt-> Google.Protobuf.Collections.RepeatedField\`1.AddEntriesFrom(Google.Protobuf.ParseContext&,Google.Protobuf.FieldCodec\`1\<\!0>) -Call-> Google.Protobuf.Collections.RepeatedField\`1.TryGetArrayAsSpanPinnedUnsafe(Google.Protobuf.FieldCodec\`1\<\!0>,System.Span\`1\<System.Byte>&,System.Runtime.InteropServices.GCHandle&) -Call-> System.Runtime.InteropServices.Marshal.SizeOf\`1() |
| TypeInitializer | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn4.14/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() | Bound | no | no | 4 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() -Ldftn-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.\<>c.\<.cctor>b__14_0() -Call-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| TypeInitializer | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn4.8/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() | Bound | no | no | 4 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() -Ldftn-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.\<>c.\<.cctor>b__14_0() -Call-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| TypeInitializer | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn5.0/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() | Bound | no | no | 4 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() -Ldftn-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.\<>c.\<.cctor>b__14_0() -Call-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| TypeInitializer | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn5.6/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() | Bound | no | no | 4 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() -Ldftn-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.\<>c.\<.cctor>b__14_0() -Call-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| TypeInitializer | FileSystem | Meziantou.Analyzer | 3.0.321 | analyzers/dotnet/roslyn5.9/cs | no | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() | Bound | no | no | 4 | Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer..cctor() -Ldftn-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.\<>c.\<.cctor>b__14_0() -Call-> Meziantou.Analyzer.Rules.DotNotUseNameFromBCLAnalyzer.LoadTypes(System.Boolean) -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| TypeInitializer | FileSystem | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/net46 | no | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() | Bound | yes | yes | 2 | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() -Call-> System.IO.Directory.Exists(System.String) |
| TypeInitializer | FileSystem | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/netstandard2.0 | no | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() | Bound | yes | yes | 2 | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() -Call-> System.IO.Directory.Exists(System.String) |
| TypeInitializer | FileSystem | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tools | no | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() | Bound | yes | yes | 2 | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() -Call-> System.IO.Directory.Exists(System.String) |
| TypeInitializer | FileSystem | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/net46 | no | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer..cctor() | Bound | yes | yes | 3 | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer..cctor() -Call-> Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer.TryFindMuxerPath() -Call-> System.IO.DirectoryInfo.get_Parent() |
| TypeInitializer | FileSystem | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/netstandard2.0 | no | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer..cctor() | Bound | yes | yes | 3 | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer..cctor() -Call-> Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer.TryFindMuxerPath() -Call-> System.IO.DirectoryInfo.get_Parent() |
| TypeInitializer | FileSystem | Microsoft.Build.Tasks.Git | 10.0.403 | tools/netframework | no | System.SpanHelpers.PerTypeValues\`1..cctor() | Instantiated | yes | yes | 4 | System.SpanHelpers.PerTypeValues\`1..cctor() -Call-> System.SpanHelpers.IsReferenceOrContainsReferencesCore(System.Type) -Dispatch-> Microsoft.Build.Tasks.Git.GitConfig.Reader.\<EnumerateExistingConfigurationFiles>d__10.MoveNext() -Call-> System.IO.File.Exists(System.String) |
| TypeInitializer | FileSystem | Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | buildTransitive/netstandard2.0 | no | Microsoft.Maui.Controls.Device.Styles..cctor() | Instantiated | yes | yes | 5 | Microsoft.Maui.Controls.Device.Styles..cctor() -CallVirt-> Microsoft.Maui.Controls.Style.set_BaseResourceKey(System.String) -Dispatch-> Mono.Cecil.Mdb.MdbWriter.Dispose() -CallVirt-> Mono.CompilerServices.SymbolWriter.MonoSymbolWriter.WriteSymbolFile(System.Guid) -Call-> System.IO.File.Delete(System.String) |
| TypeInitializer | FileSystem | Microsoft.NET.ILLink.Tasks | 10.0.14 | tools/netframework | no | System.SpanHelpers.PerTypeValues\`1..cctor() | Instantiated | yes | yes | 5 | System.SpanHelpers.PerTypeValues\`1..cctor() -Call-> System.SpanHelpers.IsReferenceOrContainsReferencesCore(System.Type) -Dispatch-> Mono.Cecil.Mdb.MdbWriter.Dispose() -CallVirt-> Mono.CompilerServices.SymbolWriter.MonoSymbolWriter.WriteSymbolFile(System.Guid) -Call-> System.IO.File.Delete(System.String) |
| TypeInitializer | FileSystem | Microsoft.Net.Compilers | 4.2.0 | tools | no | Microsoft.CodeAnalysis.MonoGlobalAssemblyCache..cctor() | Bound | yes | yes | 2 | Microsoft.CodeAnalysis.MonoGlobalAssemblyCache..cctor() -CallVirt-> System.IO.DirectoryInfo.get_Parent() |
| TypeInitializer | FileSystem | NSwag.MSBuild | 14.7.1 | tools/Net100 | no | TimeZoneConverter.TZConvert..cctor() | Bound | yes | yes | 5 | TimeZoneConverter.TZConvert..cctor() -Call-> TimeZoneConverter.DataLoader.Populate(System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.Collections.Generic.IList\`1\<System.String>>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.Collections.Generic.IList\`1\<System.String>>) -Call-> TimeZoneConverter.DataLoader.GetEmbeddedData(System.String) -StateMachine-> TimeZoneConverter.DataLoader.\<GetEmbeddedData>d__1.MoveNext() -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| TypeInitializer | FileSystem | NSwag.MSBuild | 14.7.1 | tools/Net80 | no | TimeZoneConverter.TZConvert..cctor() | Bound | yes | yes | 5 | TimeZoneConverter.TZConvert..cctor() -Call-> TimeZoneConverter.DataLoader.Populate(System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.Collections.Generic.IList\`1\<System.String>>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.Collections.Generic.IList\`1\<System.String>>) -Call-> TimeZoneConverter.DataLoader.GetEmbeddedData(System.String) -StateMachine-> TimeZoneConverter.DataLoader.\<GetEmbeddedData>d__1.MoveNext() -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| TypeInitializer | FileSystem | NSwag.MSBuild | 14.7.1 | tools/Net90 | no | TimeZoneConverter.TZConvert..cctor() | Bound | yes | yes | 5 | TimeZoneConverter.TZConvert..cctor() -Call-> TimeZoneConverter.DataLoader.Populate(System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.Collections.Generic.IList\`1\<System.String>>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.Collections.Generic.IList\`1\<System.String>>) -Call-> TimeZoneConverter.DataLoader.GetEmbeddedData(System.String) -StateMachine-> TimeZoneConverter.DataLoader.\<GetEmbeddedData>d__1.MoveNext() -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| TypeInitializer | FileSystem | NSwag.MSBuild | 14.7.1 | tools/Win | no | TimeZoneConverter.TZConvert..cctor() | Bound | yes | yes | 5 | TimeZoneConverter.TZConvert..cctor() -Call-> TimeZoneConverter.DataLoader.Populate(System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.Collections.Generic.IList\`1\<System.String>>,System.Collections.Generic.IDictionary\`2\<System.String,System.String>,System.Collections.Generic.IDictionary\`2\<System.String,System.Collections.Generic.IList\`1\<System.String>>) -Call-> TimeZoneConverter.DataLoader.GetEmbeddedData(System.String) -StateMachine-> TimeZoneConverter.DataLoader.\<GetEmbeddedData>d__1.MoveNext() -NewObj-> System.IO.StreamReader..ctor(System.IO.Stream) |
| TypeInitializer | FileSystem | OpenCover | 4.7.1221 | tools | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | Instantiated | yes | yes | 3 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> Microsoft.Extensions.FileSystemGlobbing.Abstractions.DirectoryInfoWrapper.\<EnumerateFileSystemInfos>d__4.MoveNext() -CallVirt-> System.IO.DirectoryInfo.EnumerateFileSystemInfos(System.String,System.IO.SearchOption) |
| TypeInitializer | FileSystem | ReportGenerator | 5.5.12 | tools/net10.0 | no | Palmmedia.ReportGenerator.MSBuild.AssemblyResolver..cctor() | Bound | no | no | 4 | Palmmedia.ReportGenerator.MSBuild.AssemblyResolver..cctor() -Ldftn-> Palmmedia.ReportGenerator.MSBuild.AssemblyResolver.CurrentDomain_AssemblyResolve(System.Object,System.ResolveEventArgs) -Call-> Palmmedia.ReportGenerator.MSBuild.AssemblyResolver.Probe(System.String,System.Version,System.Reflection.Assembly&) -Call-> System.IO.File.Exists(System.String) |
| TypeInitializer | FileSystem | ReportGenerator | 5.5.12 | tools/net47 | no | Palmmedia.ReportGenerator.MSBuild.AssemblyResolver..cctor() | Bound | no | yes | 4 | Palmmedia.ReportGenerator.MSBuild.AssemblyResolver..cctor() -Ldftn-> Palmmedia.ReportGenerator.MSBuild.AssemblyResolver.CurrentDomain_AssemblyResolve(System.Object,System.ResolveEventArgs) -Call-> Palmmedia.ReportGenerator.MSBuild.AssemblyResolver.Probe(System.String,System.Version,System.Reflection.Assembly&) -Call-> System.IO.File.Exists(System.String) |
| TypeInitializer | FileSystem | ReportGenerator | 5.5.12 | tools/net8.0 | no | Palmmedia.ReportGenerator.MSBuild.AssemblyResolver..cctor() | Bound | no | yes | 4 | Palmmedia.ReportGenerator.MSBuild.AssemblyResolver..cctor() -Ldftn-> Palmmedia.ReportGenerator.MSBuild.AssemblyResolver.CurrentDomain_AssemblyResolve(System.Object,System.ResolveEventArgs) -Call-> Palmmedia.ReportGenerator.MSBuild.AssemblyResolver.Probe(System.String,System.Version,System.Reflection.Assembly&) -Call-> System.IO.File.Exists(System.String) |
| TypeInitializer | FileSystem | ReportGenerator | 5.5.12 | tools/net9.0 | no | Palmmedia.ReportGenerator.MSBuild.AssemblyResolver..cctor() | Bound | no | yes | 4 | Palmmedia.ReportGenerator.MSBuild.AssemblyResolver..cctor() -Ldftn-> Palmmedia.ReportGenerator.MSBuild.AssemblyResolver.CurrentDomain_AssemblyResolve(System.Object,System.ResolveEventArgs) -Call-> Palmmedia.ReportGenerator.MSBuild.AssemblyResolver.Probe(System.String,System.Version,System.Reflection.Assembly&) -Call-> System.IO.File.Exists(System.String) |
| TypeInitializer | FileSystem | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/net462 | no | System.Reflection.Internal.EncodingHelper..cctor() | Instantiated | yes | yes | 5 | System.Reflection.Internal.EncodingHelper..cctor() -Call-> System.Reflection.Internal.EncodingHelper.LoadGetStringPlatform() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.FeatureFileCodeBehindGenerator.\<GenerateFilesForProject>d__6.MoveNext() -CallVirt-> Reqnroll.Tools.MsBuild.Generation.GeneratedFileWriter.DeleteGeneratedFile(System.String) -Call-> System.IO.File.Delete(System.String) |
| TypeInitializer | FileSystem | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | System.Numerics.Hashing.HashHelpers..cctor() | Instantiated | yes | yes | 5 | System.Numerics.Hashing.HashHelpers..cctor() -Dispatch-> System.Configuration.ConfigurationElement.GetHashCode() -Dispatch-> Reqnroll.Tools.MsBuild.Generation.FeatureFileCodeBehindGenerator.\<GenerateFilesForProject>d__6.MoveNext() -CallVirt-> Reqnroll.Tools.MsBuild.Generation.GeneratedFileWriter.DeleteGeneratedFile(System.String) -Call-> System.IO.File.Delete(System.String) |
| TypeInitializer | FileSystem | Roslynator.Analyzers | 5.0.1 | analyzers/dotnet/roslyn3.8/cs | no | Roslynator.Configuration.CodeAnalysisConfig..cctor() | Bound | yes | yes | 3 | Roslynator.Configuration.CodeAnalysisConfig..cctor() -NewObj-> Roslynator.Configuration.CodeAnalysisConfig..ctor(Roslynator.Configuration.XmlCodeAnalysisConfig,Roslynator.Configuration.EditorConfigCodeAnalysisConfig,Roslynator.Configuration.VisualStudioCodeAnalysisConfig) -Call-> System.IO.File.Exists(System.String) |
| TypeInitializer | FileSystem | Roslynator.Analyzers | 5.0.1 | analyzers/dotnet/roslyn4.7/cs | no | Roslynator.Configuration.CodeAnalysisConfig..cctor() | Bound | yes | yes | 3 | Roslynator.Configuration.CodeAnalysisConfig..cctor() -NewObj-> Roslynator.Configuration.CodeAnalysisConfig..ctor(Roslynator.Configuration.XmlCodeAnalysisConfig,Roslynator.Configuration.EditorConfigCodeAnalysisConfig,Roslynator.Configuration.VisualStudioCodeAnalysisConfig) -Call-> System.IO.File.Exists(System.String) |
| TypeInitializer | FileSystem | Roslynator.Analyzers | 5.0.1 | analyzers/dotnet/roslyn5.0/cs | no | Roslynator.Configuration.CodeAnalysisConfig..cctor() | Bound | yes | yes | 3 | Roslynator.Configuration.CodeAnalysisConfig..cctor() -NewObj-> Roslynator.Configuration.CodeAnalysisConfig..ctor(Roslynator.Configuration.XmlCodeAnalysisConfig,Roslynator.Configuration.EditorConfigCodeAnalysisConfig,Roslynator.Configuration.VisualStudioCodeAnalysisConfig) -Call-> System.IO.File.Exists(System.String) |
| TypeInitializer | FileSystem | SonarAnalyzer.CSharp | 10.35.0.4138 | analyzers | no | SonarAnalyzer.Core.Configuration.ProjectConfigReader..cctor() | Bound | no | no | 5 | SonarAnalyzer.Core.Configuration.ProjectConfigReader..cctor() -NewObj-> SonarAnalyzer.Core.Configuration.ProjectConfigReader..ctor(Microsoft.CodeAnalysis.Text.SourceText) -Ldftn-> SonarAnalyzer.Core.Configuration.ProjectConfigReader.\<.ctor>b__23_1() -NewObj-> SonarAnalyzer.Core.Configuration.AnalysisConfigReader..ctor(System.String) -Call-> System.IO.File.Exists(System.String) |
| TypeInitializer | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder..cctor() | Bound | yes | yes | 3 | Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder..cctor() -Call-> Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder.GetLogPath() -Call-> System.IO.Directory.CreateDirectory(System.String) |
| TypeInitializer | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.Build.Shared.BuildEnvironmentHelper.BuildEnvironmentHelperSingleton..cctor() | Bound | yes | yes | 4 | Microsoft.Build.Shared.BuildEnvironmentHelper.BuildEnvironmentHelperSingleton..cctor() -Call-> Microsoft.Build.Shared.BuildEnvironmentHelper.Initialize() -NewObj-> Microsoft.Build.Shared.BuildEnvironment..ctor(Microsoft.Build.Shared.BuildEnvironmentMode,System.String,System.Boolean,System.Boolean,System.String) -CallVirt-> System.IO.DirectoryInfo.get_Parent() |
| TypeInitializer | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.Build.Shared.BuildEnvironmentHelper.BuildEnvironmentHelperSingleton..cctor() | Bound | yes | yes | 4 | Microsoft.Build.Shared.BuildEnvironmentHelper.BuildEnvironmentHelperSingleton..cctor() -Call-> Microsoft.Build.Shared.BuildEnvironmentHelper.Initialize() -NewObj-> Microsoft.Build.Shared.BuildEnvironment..ctor(Microsoft.Build.Shared.BuildEnvironmentMode,System.String,System.Boolean,System.Boolean,System.String) -CallVirt-> System.IO.DirectoryInfo.get_Parent() |
| TypeInitializer | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.Build.Shared.BuildEnvironmentHelper.BuildEnvironmentHelperSingleton..cctor() | Bound | yes | yes | 4 | Microsoft.Build.Shared.BuildEnvironmentHelper.BuildEnvironmentHelperSingleton..cctor() -Call-> Microsoft.Build.Shared.BuildEnvironmentHelper.Initialize() -NewObj-> Microsoft.Build.Shared.BuildEnvironment..ctor(Microsoft.Build.Shared.BuildEnvironmentMode,System.String,System.Boolean,System.Boolean,System.String) -CallVirt-> System.IO.DirectoryInfo.get_Parent() |
| TypeInitializer | FileSystem | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | Fasterflect.Flags..cctor() | Instantiated | yes | yes | 3 | Fasterflect.Flags..cctor() -Dispatch-> Xamarin.AndroidX.Migration.BuildTasks.ResolveEmbeddedFiles.\<GetExtractedResources>d__35.MoveNext() -Call-> System.IO.Directory.EnumerateFiles(System.String,System.String,System.IO.SearchOption) |
| TypeInitializer | FileSystem | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | Fasterflect.Flags..cctor() | Instantiated | yes | yes | 3 | Fasterflect.Flags..cctor() -Dispatch-> Xamarin.AndroidX.Migration.BuildTasks.ResolveEmbeddedFiles.\<GetExtractedResources>d__35.MoveNext() -Call-> System.IO.Directory.EnumerateFiles(System.String,System.String,System.IO.SearchOption) |
| TypeInitializer | FileSystem | coverlet.msbuild | 10.1.0 | tasks/net10.0 | no | Coverlet.Core.Instrumentation.NetstandardAwareAssemblyResolver..cctor() | Bound | yes | yes | 6 | Coverlet.Core.Instrumentation.NetstandardAwareAssemblyResolver..cctor() -Call-> Mono.Cecil.AssemblyDefinition.ReadAssembly(System.String) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleDefinition.GetFileStream(System.String,System.IO.FileMode,System.IO.FileAccess,System.IO.FileShare) -NewObj-> System.IO.FileStream..ctor(System.String,System.IO.FileMode,System.IO.FileAccess,System.IO.FileShare) |
| TypeInitializer | FileSystem | coverlet.msbuild | 10.1.0 | tasks/net8.0 | no | Coverlet.Core.Instrumentation.NetstandardAwareAssemblyResolver..cctor() | Bound | yes | yes | 6 | Coverlet.Core.Instrumentation.NetstandardAwareAssemblyResolver..cctor() -Call-> Mono.Cecil.AssemblyDefinition.ReadAssembly(System.String) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleDefinition.GetFileStream(System.String,System.IO.FileMode,System.IO.FileAccess,System.IO.FileShare) -NewObj-> System.IO.FileStream..ctor(System.String,System.IO.FileMode,System.IO.FileAccess,System.IO.FileShare) |
| TypeInitializer | FileSystem | coverlet.msbuild | 10.1.0 | tasks/net9.0 | no | Coverlet.Core.Instrumentation.NetstandardAwareAssemblyResolver..cctor() | Bound | yes | yes | 6 | Coverlet.Core.Instrumentation.NetstandardAwareAssemblyResolver..cctor() -Call-> Mono.Cecil.AssemblyDefinition.ReadAssembly(System.String) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleDefinition.GetFileStream(System.String,System.IO.FileMode,System.IO.FileAccess,System.IO.FileShare) -NewObj-> System.IO.FileStream..ctor(System.String,System.IO.FileMode,System.IO.FileAccess,System.IO.FileShare) |
| TypeInitializer | FileSystem | coverlet.msbuild | 10.1.0 | tasks/netstandard2.0 | no | Coverlet.Core.Instrumentation.NetstandardAwareAssemblyResolver..cctor() | Bound | yes | yes | 6 | Coverlet.Core.Instrumentation.NetstandardAwareAssemblyResolver..cctor() -Call-> Mono.Cecil.AssemblyDefinition.ReadAssembly(System.String) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleDefinition.GetFileStream(System.String,System.IO.FileMode,System.IO.FileAccess,System.IO.FileShare) -NewObj-> System.IO.FileStream..ctor(System.String,System.IO.FileMode,System.IO.FileAccess,System.IO.FileShare) |
| TypeInitializer | FileSystem | dotnet-reportgenerator-globaltool | 5.5.12 | tools/net10.0/any | no | Microsoft.Extensions.Primitives.CompositeChangeToken..cctor() | Instantiated | no | no | 4 | Microsoft.Extensions.Primitives.CompositeChangeToken..cctor() -Ldftn-> Microsoft.Extensions.Primitives.CompositeChangeToken.OnChange(System.Object) -Dispatch-> McMaster.NETCore.Plugins.PluginLoader.Dispose() -CallVirt-> System.IO.FileSystemWatcher.remove_Changed(System.IO.FileSystemEventHandler) |
| TypeInitializer | FileSystem | dotnet-reportgenerator-globaltool | 5.5.12 | tools/net8.0/any | no | System.Marvin..cctor() | Instantiated | yes | yes | 4 | System.Marvin..cctor() -Call-> System.Marvin.GenerateSeed() -Dispatch-> McMaster.NETCore.Plugins.PluginLoader.Dispose() -CallVirt-> System.IO.FileSystemWatcher.remove_Changed(System.IO.FileSystemEventHandler) |
| TypeInitializer | FileSystem | dotnet-reportgenerator-globaltool | 5.5.12 | tools/net9.0/any | no | System.Marvin..cctor() | Instantiated | yes | yes | 4 | System.Marvin..cctor() -Call-> System.Marvin.GenerateSeed() -Dispatch-> McMaster.NETCore.Plugins.PluginLoader.Dispose() -CallVirt-> System.IO.FileSystemWatcher.remove_Changed(System.IO.FileSystemEventHandler) |
| TypeInitializer | FileSystem | dotnet-sonarscanner | 12.1.0 | tools/netcoreapp3.1/any | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | Instantiated | yes | yes | 4 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> SonarScanner.MSBuild.Common.MsBuildPathSettings.\<LocalApplicationDataPaths>d__6.MoveNext() -Dispatch-> SonarScanner.MSBuild.Common.DirectoryWrapper.Exists(System.String) -Call-> System.IO.Directory.Exists(System.String) |
| TypeInitializer | Network | NSwag.MSBuild | 14.7.1 | tools/Win | no | System.Net.Http.HttpClientHandler..cctor() | Bound | no | yes | 3 | System.Net.Http.HttpClientHandler..cctor() -Ldftn-> System.Net.Http.HttpClientHandler.OnCancel(System.Object) -CallVirt-> System.Net.WebRequest.Abort() |
| TypeInitializer | Network | OpenCover | 4.7.1221 | tools | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | Instantiated | yes | yes | 3 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> log4net.Appender.TelnetAppender.SocketHandler.Dispose() -CallVirt-> System.Net.Sockets.Socket.Close() |
| TypeInitializer | Network | ReportGenerator | 5.5.12 | tools/net10.0 | no | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() | Bound | yes | yes | 2 | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() |
| TypeInitializer | Network | ReportGenerator | 5.5.12 | tools/net47 | no | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() | Bound | yes | yes | 4 | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() -NewObj-> System.Net.Http.HttpClientHandler..ctor() -Call-> System.Net.HttpWebRequest.get_DefaultMaximumResponseHeadersLength() |
| TypeInitializer | Network | ReportGenerator | 5.5.12 | tools/net8.0 | no | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() | Bound | yes | yes | 2 | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() |
| TypeInitializer | Network | ReportGenerator | 5.5.12 | tools/net9.0 | no | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() | Bound | yes | yes | 2 | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() |
| TypeInitializer | Network | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | System.Numerics.Hashing.HashHelpers..cctor() | ChaOnly | yes | yes | 15 | System.Numerics.Hashing.HashHelpers..cctor() -Dispatch-> System.Configuration.ConfigurationElement.GetHashCode() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__14.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.Evaluate(System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.EvaluateOne(System.String\[\],System.Configuration.SectionInput,System.Boolean,System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionXmlReader(System.String\[\],System.Configuration.SectionInput) -Call-> System.Configuration.BaseConfigurationRecord.FindSection(System.String\[\],System.Configuration.SectionXmlInfo,System.Int32&) -Dispatch-> System.Configuration.ClientConfigurationHost.OpenStreamForRead(System.String) -NewObj-> System.Net.WebClient..ctor() |
| TypeInitializer | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | System.Net.Http.HttpClientHandler..cctor() | Bound | no | no | 3 | System.Net.Http.HttpClientHandler..cctor() -Ldftn-> System.Net.Http.HttpClientHandler.OnCancel(System.Object) -CallVirt-> System.Net.WebRequest.Abort() |
| TypeInitializer | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | ChaOnly | yes | yes | 14 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__15.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.Evaluate(System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.EvaluateOne(System.String\[\],System.Configuration.SectionInput,System.Boolean,System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionXmlReader(System.String\[\],System.Configuration.SectionInput) -Call-> System.Configuration.BaseConfigurationRecord.FindSection(System.String\[\],System.Configuration.SectionXmlInfo,System.Int32&) -Dispatch-> System.Configuration.ClientConfigurationHost.OpenStreamForRead(System.String) -NewObj-> System.Net.WebClient..ctor() |
| TypeInitializer | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | ChaOnly | yes | yes | 14 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__15.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.Evaluate(System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.EvaluateOne(System.String\[\],System.Configuration.SectionInput,System.Boolean,System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionXmlReader(System.String\[\],System.Configuration.SectionInput) -Call-> System.Configuration.BaseConfigurationRecord.FindSection(System.String\[\],System.Configuration.SectionXmlInfo,System.Int32&) -Dispatch-> System.Configuration.ClientConfigurationHost.OpenStreamForRead(System.String) -NewObj-> System.Net.WebClient..ctor() |
| TypeInitializer | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | ChaOnly | yes | yes | 14 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__15.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.Evaluate(System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.EvaluateOne(System.String\[\],System.Configuration.SectionInput,System.Boolean,System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionXmlReader(System.String\[\],System.Configuration.SectionInput) -Call-> System.Configuration.BaseConfigurationRecord.FindSection(System.String\[\],System.Configuration.SectionXmlInfo,System.Int32&) -Dispatch-> System.Configuration.ClientConfigurationHost.OpenStreamForRead(System.String) -NewObj-> System.Net.WebClient..ctor() |
| TypeInitializer | Network | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | Fasterflect.Flags..cctor() | Instantiated | yes | yes | 4 | Fasterflect.Flags..cctor() -Dispatch-> Mono.Unix.UnixClient.Dispose() -CallVirt-> Mono.Unix.UnixClient.Dispose(System.Boolean) -CallVirt-> System.Net.Sockets.Socket.Close() |
| TypeInitializer | Network | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | Fasterflect.Flags..cctor() | Instantiated | yes | yes | 4 | Fasterflect.Flags..cctor() -Dispatch-> Mono.Unix.UnixClient.Dispose() -CallVirt-> Mono.Unix.UnixClient.Dispose(System.Boolean) -CallVirt-> System.Net.Sockets.Socket.Close() |
| TypeInitializer | Network | dotnet-reportgenerator-globaltool | 5.5.12 | tools/net10.0/any | no | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() | Bound | yes | yes | 2 | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() |
| TypeInitializer | Network | dotnet-reportgenerator-globaltool | 5.5.12 | tools/net8.0/any | no | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() | Bound | yes | yes | 2 | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() |
| TypeInitializer | Network | dotnet-reportgenerator-globaltool | 5.5.12 | tools/net9.0/any | no | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() | Bound | yes | yes | 2 | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() |
| TypeInitializer | Network | dotnet-sonarscanner | 12.1.0 | tools/netcoreapp3.1/any | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | Instantiated | yes | yes | 3 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> SonarScanner.MSBuild.PreProcessor.WebClientDownloader.Dispose() -CallVirt-> System.Net.Http.HttpMessageInvoker.Dispose() |
| TypeInitializer | ProcessExecution | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/net46 | no | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() | Bound | yes | yes | 3 | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() -Call-> Microsoft.AspNetCore.Razor.Tools.ServerLogger.GetCurrentProcessId() -CallVirt-> System.Diagnostics.Process.get_Id() |
| TypeInitializer | ProcessExecution | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tasks/netstandard2.0 | no | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() | Bound | yes | yes | 3 | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() -Call-> Microsoft.AspNetCore.Razor.Tools.ServerLogger.GetCurrentProcessId() -CallVirt-> System.Diagnostics.Process.get_Id() |
| TypeInitializer | ProcessExecution | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tools | no | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() | Bound | yes | yes | 3 | Microsoft.AspNetCore.Razor.Tools.ServerLogger..cctor() -Call-> Microsoft.AspNetCore.Razor.Tools.ServerLogger.GetCurrentProcessId() -CallVirt-> System.Diagnostics.Process.get_Id() |
| TypeInitializer | ProcessExecution | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/net46 | no | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer..cctor() | Bound | yes | yes | 3 | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer..cctor() -Call-> Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer.TryFindMuxerPath() -CallVirt-> System.Diagnostics.Process.get_MainModule() |
| TypeInitializer | ProcessExecution | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/netstandard2.0 | no | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer..cctor() | Bound | yes | yes | 3 | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer..cctor() -Call-> Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.DotNetMuxer.TryFindMuxerPath() -CallVirt-> System.Diagnostics.Process.get_MainModule() |
| TypeInitializer | ProcessExecution | OpenCover | 4.7.1221 | tools | no | OpenCover.Console.Program..cctor() | ChaOnly | yes | yes | 23 | OpenCover.Console.Program..cctor() -Call-> log4net.LogManager.GetLogger(System.String) -Call-> log4net.LogManager.GetLogger(System.Reflection.Assembly,System.String) -Call-> log4net.Core.LoggerManager.GetLogger(System.Reflection.Assembly,System.String) -Dispatch-> log4net.Core.DefaultRepositorySelector.GetRepository(System.Reflection.Assembly) -Call-> log4net.Core.DefaultRepositorySelector.CreateRepository(System.Reflection.Assembly,System.Type) -Call-> log4net.Core.DefaultRepositorySelector.CreateRepository(System.Reflection.Assembly,System.Type,System.String,System.Boolean) -Call-> log4net.Core.DefaultRepositorySelector.ConfigureRepository(System.Reflection.Assembly,log4net.Repository.ILoggerRepository) -Call-> log4net.Config.XmlConfigurator.Configure(log4net.Repository.ILoggerRepository,System.Uri) -Call-> log4net.Config.XmlConfigurator.InternalConfigure(log4net.Repository.ILoggerRepository,System.Uri) -Call-> log4net.Config.XmlConfigurator.InternalConfigure(log4net.Repository.ILoggerRepository,System.IO.Stream) -Call-> log4net.Config.XmlConfigurator.InternalConfigureFromXml(log4net.Repository.ILoggerRepository,System.Xml.XmlElement) -Dispatch-> log4net.Repository.Hierarchy.Hierarchy.log4net.Repository.IXmlRepositoryConfigurator.Configure(System.Xml.XmlElement) -Call-> log4net.Repository.Hierarchy.Hierarchy.XmlRepositoryConfigure(System.Xml.XmlElement) -CallVirt-> log4net.Repository.Hierarchy.XmlHierarchyConfigurator.Configure(System.Xml.XmlElement) -Call-> log4net.Repository.Hierarchy.XmlHierarchyConfigurator.SetParameter(System.Xml.XmlElement,System.Object) -Call-> log4net.Util.OptionConverter.ConvertTypeTo(System.Object,System.Type) -Dispatch-> log4net.Util.TypeConverters.PatternStringConverter.ConvertTo(System.Object,System.Type) -CallVirt-> log4net.Util.PatternString.Format() -Call-> log4net.Util.PatternString.Format(System.IO.TextWriter) -CallVirt-> log4net.Util.PatternConverter.Format(System.IO.TextWriter,System.Object) -Dispatch-> log4net.Util.PatternStringConverters.ProcessIdPatternConverter.Convert(System.IO.TextWriter,System.Object) -CallVirt-> System.Diagnostics.Process.get_Id() |
| TypeInitializer | ProcessExecution | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | System.Numerics.Hashing.HashHelpers..cctor() | ChaOnly | yes | yes | 14 | System.Numerics.Hashing.HashHelpers..cctor() -Dispatch-> System.Configuration.ConfigurationElement.GetHashCode() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__14.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Dispatch-> System.Configuration.ClientConfigurationHost.RequireCompleteInit(System.Configuration.Internal.IInternalConfigRecord) -Call-> System.Configuration.ClientConfigurationHost.get_ConfigPaths() -Call-> System.Configuration.ClientConfigPaths.GetPaths(System.String,System.Boolean) -NewObj-> System.Configuration.ClientConfigPaths..ctor(System.String,System.Boolean) -CallVirt-> System.Diagnostics.Process.get_MainModule() |
| TypeInitializer | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Framework.Profiler.EvaluationIdProvider..cctor() | Bound | yes | yes | 2 | Microsoft.Build.Framework.Profiler.EvaluationIdProvider..cctor() -CallVirt-> System.Diagnostics.Process.get_Id() |
| TypeInitializer | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.Build.Framework.Profiler.EvaluationIdProvider..cctor() | Bound | yes | yes | 2 | Microsoft.Build.Framework.Profiler.EvaluationIdProvider..cctor() -CallVirt-> System.Diagnostics.Process.get_Id() |
| TypeInitializer | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.Build.Framework.Profiler.EvaluationIdProvider..cctor() | Bound | yes | yes | 2 | Microsoft.Build.Framework.Profiler.EvaluationIdProvider..cctor() -CallVirt-> System.Diagnostics.Process.get_Id() |
| TypeInitializer | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.Build.Framework.Profiler.EvaluationIdProvider..cctor() | Bound | yes | yes | 2 | Microsoft.Build.Framework.Profiler.EvaluationIdProvider..cctor() -CallVirt-> System.Diagnostics.Process.get_Id() |
| TypeInitializer | Registry | OpenCover | 4.7.1221 | tools | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | Instantiated | yes | yes | 3 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> Sentry.PlatformAbstractions.FrameworkInfo.\<GetInstallations>d__5.MoveNext() -CallVirt-> Microsoft.Win32.RegistryKey.GetSubKeyNames() |
| TypeInitializer | Registry | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Tasks.GenerateResource..cctor() | Bound | yes | yes | 2 | Microsoft.Build.Tasks.GenerateResource..cctor() -Call-> Microsoft.Win32.Registry.GetValue(System.String,System.String,System.Object) |
| TypeInitializer | NativeInterop | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tools | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | Instantiated | yes | yes | 5 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> Microsoft.DiaSymReader.SymUnmanagedWriterImpl.Dispose() -Call-> Microsoft.DiaSymReader.SymUnmanagedWriterImpl.DisposeImpl() -Call-> Microsoft.DiaSymReader.SymUnmanagedWriterImpl.CloseSymWriter() -CallVirt-> Microsoft.DiaSymReader.ISymUnmanagedWriter5.Close() |
| TypeInitializer | NativeInterop | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | tools/netstandard2.0 | no | Microsoft.Build.Shared.FrameworkLocationHelper..cctor() | Bound | yes | yes | 3 | Microsoft.Build.Shared.FrameworkLocationHelper..cctor() -Call-> Microsoft.Build.Shared.FileUtilities.GetFolderPath(Microsoft.Build.Shared.FileUtilities.SpecialFolder) -Call-> Microsoft.Build.Shared.FileUtilities.Win32Native.SHGetFolderPath(System.IntPtr,System.Int32,System.IntPtr,System.Int32,System.Text.StringBuilder) |
| TypeInitializer | NativeInterop | Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | buildTransitive/netstandard2.0 | no | Microsoft.Maui.Controls.Device.Styles..cctor() | Instantiated | yes | yes | 5 | Microsoft.Maui.Controls.Device.Styles..cctor() -CallVirt-> Microsoft.Maui.Controls.Style.set_BaseResourceKey(System.String) -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| TypeInitializer | NativeInterop | Microsoft.NET.ILLink.Tasks | 10.0.14 | tools/netframework | no | System.SpanHelpers.PerTypeValues\`1..cctor() | Instantiated | no | yes | 17 | System.SpanHelpers.PerTypeValues\`1..cctor() -Call-> System.SpanHelpers.IsReferenceOrContainsReferencesCore(System.Type) -Dispatch-> Mono.Cecil.AssemblyDefinition.Dispose() -Call-> Mono.Cecil.AssemblyDefinition.get_Modules() -Ldftn-> Mono.Cecil.AssemblyDefinition.\<>c.\<get_Modules>b__14_0(Mono.Cecil.AssemblyDefinition,Mono.Cecil.MetadataReader) -CallVirt-> Mono.Cecil.MetadataReader.ReadModules() -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(Mono.Disposable\`1\<System.IO.Stream>,System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleReader.CreateModule(Mono.Cecil.PE.Image,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleReader.ReadSymbols(Mono.Cecil.ModuleDefinition,Mono.Cecil.ReaderParameters) -CallVirt-> Mono.Cecil.ModuleDefinition.ReadSymbols(Mono.Cecil.Cil.ISymbolReader,System.Boolean) -Dispatch-> Mono.Cecil.Pdb.NativePdbReader.ProcessDebugHeader(Mono.Cecil.Cil.ImageDebugHeader) -Call-> Microsoft.Cci.Pdb.PdbFile.LoadFunctions(System.IO.Stream) -NewObj-> Microsoft.Cci.Pdb.MsfDirectory..ctor(Microsoft.Cci.Pdb.PdbReader,Microsoft.Cci.Pdb.PdbFileHeader,Microsoft.Cci.Pdb.BitAccess) -CallVirt-> Microsoft.Cci.Pdb.BitAccess.Append(System.IO.Stream,System.Int32) -Dispatch-> System.Reflection.Internal.ReadOnlyUnmanagedMemoryStream.Read(System.Byte\[\],System.Int32,System.Int32) -Call-> System.Runtime.InteropServices.Marshal.Copy(System.IntPtr,System.Byte\[\],System.Int32,System.Int32) |
| TypeInitializer | NativeInterop | Microsoft.Net.Compilers | 4.2.0 | tools | no | Microsoft.CodeAnalysis.Scripting.ScriptMetadataResolver..cctor() | Bound | no | yes | 13 | Microsoft.CodeAnalysis.Scripting.ScriptMetadataResolver..cctor() -Call-> Microsoft.CodeAnalysis.Scripting.Hosting.RuntimeMetadataReferenceResolver.CreateCurrentPlatformResolver(System.Collections.Immutable.ImmutableArray\`1\<System.String>,System.String,System.Func\`3\<System.String,Microsoft.CodeAnalysis.MetadataReferenceProperties,Microsoft.CodeAnalysis.PortableExecutableReference>) -NewObj-> Microsoft.CodeAnalysis.Scripting.Hosting.RuntimeMetadataReferenceResolver..ctor(System.Collections.Immutable.ImmutableArray\`1\<System.String>,System.String,Microsoft.CodeAnalysis.Scripting.Hosting.NuGetPackageResolver,Microsoft.CodeAnalysis.Scripting.Hosting.GacFileResolver,System.Collections.Immutable.ImmutableArray\`1\<System.String>,System.Func\`3\<System.String,Microsoft.CodeAnalysis.MetadataReferenceProperties,Microsoft.CodeAnalysis.PortableExecutableReference>) -Call-> Microsoft.CodeAnalysis.Scripting.Hosting.RuntimeMetadataReferenceResolver..ctor(Microsoft.CodeAnalysis.RelativePathResolver,Microsoft.CodeAnalysis.Scripting.Hosting.NuGetPackageResolver,Microsoft.CodeAnalysis.Scripting.Hosting.GacFileResolver,System.Collections.Immutable.ImmutableDictionary\`2\<System.String,System.String>,System.Func\`3\<System.String,Microsoft.CodeAnalysis.MetadataReferenceProperties,Microsoft.CodeAnalysis.PortableExecutableReference>) -Ldftn-> Microsoft.CodeAnalysis.Scripting.Hosting.RuntimeMetadataReferenceResolver.\<>c.\<.ctor>b__11_0(System.String,Microsoft.CodeAnalysis.MetadataReferenceProperties) -Call-> Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(System.String,Microsoft.CodeAnalysis.MetadataReferenceProperties,Microsoft.CodeAnalysis.DocumentationProvider) -Call-> Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(System.IO.Stream,System.String,Microsoft.CodeAnalysis.MetadataReferenceProperties,Microsoft.CodeAnalysis.DocumentationProvider) -Call-> Microsoft.CodeAnalysis.ModuleMetadata.CreateFromStream(System.IO.Stream,System.Reflection.PortableExecutable.PEStreamOptions) -NewObj-> System.Reflection.PortableExecutable.PEReader..ctor(System.IO.Stream,System.Reflection.PortableExecutable.PEStreamOptions) -Call-> System.Reflection.PortableExecutable.PEReader..ctor(System.IO.Stream,System.Reflection.PortableExecutable.PEStreamOptions,System.Int32) -Call-> System.Reflection.Internal.StreamMemoryBlockProvider.ReadMemoryBlockNoLock(System.IO.Stream,System.Boolean,System.Int64,System.Int32) -Call-> System.Reflection.Internal.FileStreamReadLightUp.TryReadFile(System.IO.Stream,System.Byte*,System.Int64,System.Int32) -Call-> Interop.Kernel32.ReadFile(System.Runtime.InteropServices.SafeHandle,System.Byte*,System.Int32,System.Int32&,System.IntPtr) |
| TypeInitializer | NativeInterop | NSwag.MSBuild | 14.7.1 | tools/Win | no | Microsoft.AspNetCore.HttpSys.Internal.HeapAllocHandle..cctor() | Bound | yes | yes | 2 | Microsoft.AspNetCore.HttpSys.Internal.HeapAllocHandle..cctor() -Call-> Microsoft.AspNetCore.HttpSys.Internal.UnsafeNclNativeMethods.GetProcessHeap() |
| TypeInitializer | NativeInterop | OpenCover | 4.7.1221 | tools | no | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() | Instantiated | yes | yes | 4 | Newtonsoft.Json.Utilities.JavaScriptUtils..cctor() -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| TypeInitializer | NativeInterop | ReportGenerator | 5.5.12 | tools/net47 | no | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() | Bound | yes | yes | 7 | Palmmedia.ReportGenerator.Core.Parser.FileReading.CachingFileReader..cctor() -NewObj-> System.Net.Http.HttpClient..ctor() -Call-> System.Net.Http.HttpClient..ctor(System.Net.Http.HttpMessageHandler) -Call-> System.Net.Http.HttpClient..ctor(System.Net.Http.HttpMessageHandler,System.Boolean) -Call-> System.Net.NetEventSource.Enter(System.Object,System.Object,System.String) -Call-> System.Net.NetEventSource.Format(System.Object) -CallVirt-> System.Runtime.InteropServices.SafeHandle.DangerousGetHandle() |
| TypeInitializer | NativeInterop | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/net462 | no | System.Text.BaseCodePageEncoding..cctor() | Instantiated | yes | yes | 5 | System.Text.BaseCodePageEncoding..cctor() -Call-> System.Text.BaseCodePageEncoding.GetEncodingDataStream(System.String) -Call-> System.Text.BaseCodePageEncoding.ReadCodePageDataFileHeader(System.IO.Stream,System.Byte\[\]) -Dispatch-> System.Reflection.Internal.ReadOnlyUnmanagedMemoryStream.Read(System.Byte\[\],System.Int32,System.Int32) -Call-> System.Runtime.InteropServices.Marshal.Copy(System.IntPtr,System.Byte\[\],System.Int32,System.Int32) |
| TypeInitializer | NativeInterop | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | Reqnroll.VersionInfo..cctor() | Instantiated | yes | yes | 4 | Reqnroll.VersionInfo..cctor() -Dispatch-> System.Configuration.CommaDelimitedStringCollection.ToString() -Dispatch-> Microsoft.Win32.RegistryKey.Dispose() -CallVirt-> System.Runtime.InteropServices.SafeHandle.Dispose() |
| TypeInitializer | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Shared.InprocTrackingNativeMethods.FileTrackerDllStub..cctor() | Bound | yes | yes | 3 | Microsoft.Build.Shared.InprocTrackingNativeMethods.FileTrackerDllStub..cctor() -Call-> Microsoft.Build.Shared.InprocTrackingNativeMethods.FileTrackerDllStub.LoadFileTrackerDll() -Call-> Microsoft.Build.Shared.InprocTrackingNativeMethods.FileTrackerDllStub.LoadLibrary(System.String) |
| TypeInitializer | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.DotNet.PlatformAbstractions.RuntimeEnvironment..cctor() | Bound | yes | yes | 4 | Microsoft.DotNet.PlatformAbstractions.RuntimeEnvironment..cctor() -Call-> Microsoft.DotNet.PlatformAbstractions.Native.PlatformApis.GetOSVersion() -Call-> Microsoft.DotNet.PlatformAbstractions.Native.NativeMethods.Windows.RtlGetVersion() -Call-> Microsoft.DotNet.PlatformAbstractions.Native.NativeMethods.Windows.RtlGetVersion(Microsoft.DotNet.PlatformAbstractions.Native.NativeMethods.Windows.RTL_OSVERSIONINFOEX&) |
| TypeInitializer | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.DotNet.PlatformAbstractions.RuntimeEnvironment..cctor() | Bound | yes | yes | 4 | Microsoft.DotNet.PlatformAbstractions.RuntimeEnvironment..cctor() -Call-> Microsoft.DotNet.PlatformAbstractions.Native.PlatformApis.GetOSVersion() -Call-> Microsoft.DotNet.PlatformAbstractions.Native.NativeMethods.Windows.RtlGetVersion() -Call-> Microsoft.DotNet.PlatformAbstractions.Native.NativeMethods.Windows.RtlGetVersion(Microsoft.DotNet.PlatformAbstractions.Native.NativeMethods.Windows.RTL_OSVERSIONINFOEX&) |
| TypeInitializer | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.DotNet.PlatformAbstractions.RuntimeEnvironment..cctor() | Bound | yes | yes | 4 | Microsoft.DotNet.PlatformAbstractions.RuntimeEnvironment..cctor() -Call-> Microsoft.DotNet.PlatformAbstractions.Native.PlatformApis.GetOSVersion() -Call-> Microsoft.DotNet.PlatformAbstractions.Native.NativeMethods.Windows.RtlGetVersion() -Call-> Microsoft.DotNet.PlatformAbstractions.Native.NativeMethods.Windows.RtlGetVersion(Microsoft.DotNet.PlatformAbstractions.Native.NativeMethods.Windows.RTL_OSVERSIONINFOEX&) |
| TypeInitializer | NativeInterop | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | Mono.Unix.Native.FilePosition..cctor() | Bound | yes | yes | 2 | Mono.Unix.Native.FilePosition..cctor() -Call-> Mono.Unix.Native.Stdlib.DumpFilePosition(System.Text.StringBuilder,System.Runtime.InteropServices.HandleRef,System.Int32) |
| TypeInitializer | NativeInterop | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | Mono.Unix.Native.FilePosition..cctor() | Bound | yes | yes | 2 | Mono.Unix.Native.FilePosition..cctor() -Call-> Mono.Unix.Native.Stdlib.DumpFilePosition(System.Text.StringBuilder,System.Runtime.InteropServices.HandleRef,System.Int32) |
| TypeInitializer | NativeInterop | Xamarin.Build.Download | 0.11.6 | build | no | Xamarin.Build.Download.Platform..cctor() | Bound | yes | yes | 3 | Xamarin.Build.Download.Platform..cctor() -Call-> Xamarin.Build.Download.Platform.IsRunningOnMac() -Call-> System.Runtime.InteropServices.Marshal.PtrToStringAnsi(System.IntPtr) |
| TypeInitializer | NativeInterop | Xamarin.Build.Download | 0.11.6 | buildTransitive | no | Xamarin.Build.Download.Platform..cctor() | Bound | yes | yes | 3 | Xamarin.Build.Download.Platform..cctor() -Call-> Xamarin.Build.Download.Platform.IsRunningOnMac() -Call-> System.Runtime.InteropServices.Marshal.PtrToStringAnsi(System.IntPtr) |
| TypeInitializer | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/net10.0 | no | Coverlet.Core.Instrumentation.ModuleTrackerTemplate..cctor() | Instantiated | yes | yes | 5 | Coverlet.Core.Instrumentation.ModuleTrackerTemplate..cctor() -Dispatch-> ConsoleTables.ConsoleTable.ToString() -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| TypeInitializer | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/net10.0/runtimes/win/lib/net10.0 | no | Microsoft.Win32.SafeHandles.SafeHeapAllocHandle..cctor() | Bound | yes | yes | 2 | Microsoft.Win32.SafeHandles.SafeHeapAllocHandle..cctor() -Call-> Interop.Kernel32.GetProcessHeap() |
| TypeInitializer | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/net8.0 | no | System.Security.Cryptography.MLDsaImplementation..cctor() | Bound | yes | yes | 3 | System.Security.Cryptography.MLDsaImplementation..cctor() -Call-> System.Security.Cryptography.MLDsaImplementation.OpenAlgorithmHandle() -CallVirt-> System.Runtime.InteropServices.SafeHandle.Dispose() |
| TypeInitializer | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/net8.0/runtimes/win/lib/net8.0 | no | Microsoft.Win32.SafeHandles.SafeHeapAllocHandle..cctor() | Bound | yes | yes | 2 | Microsoft.Win32.SafeHandles.SafeHeapAllocHandle..cctor() -Call-> Interop.Kernel32.GetProcessHeap() |
| TypeInitializer | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/net9.0 | no | System.Security.Cryptography.MLDsaImplementation..cctor() | Bound | yes | yes | 3 | System.Security.Cryptography.MLDsaImplementation..cctor() -Call-> System.Security.Cryptography.MLDsaImplementation.OpenAlgorithmHandle() -CallVirt-> System.Runtime.InteropServices.SafeHandle.Dispose() |
| TypeInitializer | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/net9.0/runtimes/win/lib/net9.0 | no | Microsoft.Win32.SafeHandles.SafeHeapAllocHandle..cctor() | Bound | yes | yes | 2 | Microsoft.Win32.SafeHandles.SafeHeapAllocHandle..cctor() -Call-> Interop.Kernel32.GetProcessHeap() |
| TypeInitializer | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/netstandard2.0 | no | System.Security.Cryptography.MLDsaImplementation..cctor() | Bound | yes | yes | 3 | System.Security.Cryptography.MLDsaImplementation..cctor() -Call-> System.Security.Cryptography.MLDsaImplementation.OpenAlgorithmHandle() -Call-> Interop.BCrypt.BCryptOpenAlgorithmProvider(Microsoft.Win32.SafeHandles.SafeBCryptAlgorithmHandle&,System.String,System.String,Interop.BCrypt.BCryptOpenAlgorithmProviderFlags) |
| TypeInitializer | NativeInterop | dotnet-sonarscanner | 12.1.0 | tools/netcoreapp3.1/any | no | Google.Protobuf.Reflection.FeatureSetDescriptor..cctor() | Instantiated | yes | yes | 9 | Google.Protobuf.Reflection.FeatureSetDescriptor..cctor() -Call-> Google.Protobuf.Reflection.FeatureSetDescriptor.BuildEditionDefaults() -CallVirt-> Google.Protobuf.Reflection.FeatureSetDescriptor.\<>c__DisplayClass2_0.\<BuildEditionDefaults>g__MaybeCreateDescriptor\|2(Google.Protobuf.Reflection.Edition) -CallVirt-> Google.Protobuf.Reflection.FeatureSet.MergeFrom(Google.Protobuf.Reflection.FeatureSet) -Call-> Google.Protobuf.ExtensionSet.MergeFrom\`1(Google.Protobuf.ExtensionSet\`1\<\!\!0>&,Google.Protobuf.ExtensionSet\`1\<\!\!0>) -Dispatch-> Google.Protobuf.RepeatedExtensionValue\`1.MergeFrom(Google.Protobuf.ParseContext&) -CallVirt-> Google.Protobuf.Collections.RepeatedField\`1.AddEntriesFrom(Google.Protobuf.ParseContext&,Google.Protobuf.FieldCodec\`1\<\!0>) -Call-> Google.Protobuf.Collections.RepeatedField\`1.TryGetArrayAsSpanPinnedUnsafe(Google.Protobuf.FieldCodec\`1\<\!0>,System.Span\`1\<System.Byte>&,System.Runtime.InteropServices.GCHandle&) -Call-> System.Runtime.InteropServices.Marshal.SizeOf\`1() |
| Finalizer | FileSystem | Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | buildTransitive/netstandard2.0 | no | System.CodeDom.Compiler.TempFileCollection.Finalize() | Bound | yes | yes | 4 | System.CodeDom.Compiler.TempFileCollection.Finalize() -CallVirt-> System.CodeDom.Compiler.TempFileCollection.Dispose(System.Boolean) -Call-> System.CodeDom.Compiler.TempFileCollection.SafeDelete() -Call-> System.IO.Directory.Delete(System.String) |
| Finalizer | FileSystem | Microsoft.NET.ILLink.Tasks | 10.0.14 | tools/netframework | no | System.Reflection.Internal.CriticalDisposableObject.Finalize() | Instantiated | yes | yes | 5 | System.Reflection.Internal.CriticalDisposableObject.Finalize() -Dispatch-> System.Reflection.Internal.MemoryMappedFileBlock.DisposableData.Release() -Dispatch-> Mono.Cecil.Mdb.MdbWriter.Dispose() -CallVirt-> Mono.CompilerServices.SymbolWriter.MonoSymbolWriter.WriteSymbolFile(System.Guid) -Call-> System.IO.File.Delete(System.String) |
| Finalizer | FileSystem | Microsoft.Net.Compilers | 4.2.0 | tools | no | Microsoft.CodeAnalysis.Scripting.Hosting.MetadataShadowCopyProvider.Finalize() | Bound | yes | yes | 3 | Microsoft.CodeAnalysis.Scripting.Hosting.MetadataShadowCopyProvider.Finalize() -Call-> Microsoft.CodeAnalysis.Scripting.Hosting.MetadataShadowCopyProvider.DeleteShadowCopyDirectory() -Call-> System.IO.Directory.Delete(System.String,System.Boolean) |
| Finalizer | FileSystem | NSwag.MSBuild | 14.7.1 | tools/Win | no | System.Reflection.Internal.CriticalDisposableObject.Finalize() | Instantiated | yes | yes | 5 | System.Reflection.Internal.CriticalDisposableObject.Finalize() -Dispatch-> System.Reflection.Internal.MemoryMappedFileBlock.DisposableData.Release() -Dispatch-> Microsoft.Extensions.Configuration.ConfigurationRoot.Dispose() -Dispatch-> Microsoft.Extensions.FileSystemGlobbing.Abstractions.DirectoryInfoWrapper.\<EnumerateFileSystemInfos>d__4.MoveNext() -CallVirt-> System.IO.DirectoryInfo.EnumerateFileSystemInfos(System.String,System.IO.SearchOption) |
| Finalizer | FileSystem | OpenCover | 4.7.1221 | tools | no | log4net.Appender.AppenderSkeleton.Finalize() | Instantiated | yes | yes | 6 | log4net.Appender.AppenderSkeleton.Finalize() -TypeInitializer-> log4net.Util.LogLog..cctor() -Call-> log4net.Util.LogLog.Error(System.Type,System.String,System.Exception) -Dispatch-> Gendarme.Framework.Helpers.MethodPrinter.ToString() -Dispatch-> Microsoft.Extensions.FileSystemGlobbing.Abstractions.DirectoryInfoWrapper.\<EnumerateFileSystemInfos>d__4.MoveNext() -CallVirt-> System.IO.DirectoryInfo.EnumerateFileSystemInfos(System.String,System.IO.SearchOption) |
| Finalizer | FileSystem | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/net462 | no | Reqnroll.Tools.MsBuild.Generation.AssemblyResolveLogger.Finalize() | Bound | no | yes | 4 | Reqnroll.Tools.MsBuild.Generation.AssemblyResolveLogger.Finalize() -Call-> Reqnroll.Tools.MsBuild.Generation.AssemblyResolveLogger.Dispose(System.Boolean) -Ldftn-> Reqnroll.Tools.MsBuild.Generation.AssemblyResolveLogger.CurrentDomain_AssemblyResolve(System.Object,System.ResolveEventArgs) -Call-> System.IO.File.Exists(System.String) |
| Finalizer | FileSystem | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | System.CodeDom.Compiler.TempFileCollection.Finalize() | Bound | yes | yes | 4 | System.CodeDom.Compiler.TempFileCollection.Finalize() -CallVirt-> System.CodeDom.Compiler.TempFileCollection.Dispose(System.Boolean) -Call-> System.CodeDom.Compiler.TempFileCollection.SafeDelete() -Call-> System.IO.Directory.Delete(System.String) |
| Finalizer | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | System.Reflection.Metadata.Ecma335.BlobStreamReader.VirtualHeapBlobTable.Finalize() | Instantiated | yes | yes | 4 | System.Reflection.Metadata.Ecma335.BlobStreamReader.VirtualHeapBlobTable.Finalize() -Dispatch-> BoDi.ObjectContainer.Dispose() -Dispatch-> Microsoft.Build.Tasks.NativeMethods.AssemblyCacheEnum.\<GetEnumerator>d__8.MoveNext() -Call-> System.IO.Directory.EnumerateDirectories(System.String) |
| Finalizer | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | System.CodeDom.Compiler.TempFileCollection.Finalize() | Bound | yes | yes | 5 | System.CodeDom.Compiler.TempFileCollection.Finalize() -CallVirt-> System.CodeDom.Compiler.TempFileCollection.Dispose(System.Boolean) -Call-> System.CodeDom.Compiler.TempFileCollection.SafeDelete() -Call-> System.CodeDom.Compiler.TempFileCollection.Delete(System.String) -Call-> System.IO.File.Delete(System.String) |
| Finalizer | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | System.CodeDom.Compiler.TempFileCollection.Finalize() | Bound | yes | yes | 5 | System.CodeDom.Compiler.TempFileCollection.Finalize() -CallVirt-> System.CodeDom.Compiler.TempFileCollection.Dispose(System.Boolean) -Call-> System.CodeDom.Compiler.TempFileCollection.SafeDelete() -Call-> System.CodeDom.Compiler.TempFileCollection.Delete(System.String) -Call-> System.IO.File.Delete(System.String) |
| Finalizer | FileSystem | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | System.CodeDom.Compiler.TempFileCollection.Finalize() | Bound | yes | yes | 5 | System.CodeDom.Compiler.TempFileCollection.Finalize() -CallVirt-> System.CodeDom.Compiler.TempFileCollection.Dispose(System.Boolean) -Call-> System.CodeDom.Compiler.TempFileCollection.SafeDelete() -Call-> System.CodeDom.Compiler.TempFileCollection.Delete(System.String) -Call-> System.IO.File.Delete(System.String) |
| Finalizer | FileSystem | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | ILRepacking.Steps.SourceServerData.PdbStr.Finalize() | Bound | yes | yes | 3 | ILRepacking.Steps.SourceServerData.PdbStr.Finalize() -Call-> ILRepacking.Steps.SourceServerData.PdbStr.SafeDeleteFile(System.String) -Call-> System.IO.File.Delete(System.String) |
| Finalizer | FileSystem | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | ILRepacking.Steps.SourceServerData.PdbStr.Finalize() | Bound | yes | yes | 3 | ILRepacking.Steps.SourceServerData.PdbStr.Finalize() -Call-> ILRepacking.Steps.SourceServerData.PdbStr.SafeDeleteFile(System.String) -Call-> System.IO.File.Delete(System.String) |
| Finalizer | FileSystem | coverlet.msbuild | 10.1.0 | tasks/netstandard2.0 | no | System.Reflection.Internal.CriticalDisposableObject.Finalize() | Instantiated | yes | yes | 5 | System.Reflection.Internal.CriticalDisposableObject.Finalize() -Dispatch-> System.Reflection.Internal.MemoryMappedFileBlock.DisposableData.Release() -Dispatch-> Mono.Cecil.Mdb.MdbWriter.Dispose() -CallVirt-> Mono.CompilerServices.SymbolWriter.MonoSymbolWriter.WriteSymbolFile(System.Guid) -Call-> System.IO.File.Delete(System.String) |
| Finalizer | FileSystem | dotnet-sonarscanner | 12.1.0 | tools/netcoreapp3.1/any | no | ICSharpCode.SharpZipLib.BZip2.BZip2OutputStream.Finalize() | Instantiated | yes | yes | 14 | ICSharpCode.SharpZipLib.BZip2.BZip2OutputStream.Finalize() -Dispatch-> ICSharpCode.SharpZipLib.Zip.Compression.Streams.DeflaterOutputStream.Dispose(System.Boolean) -Dispatch-> Newtonsoft.Json.JsonWriter.System.IDisposable.Dispose() -CallVirt-> Newtonsoft.Json.JsonWriter.Dispose(System.Boolean) -CallVirt-> Newtonsoft.Json.JsonWriter.Close() -Call-> Newtonsoft.Json.JsonWriter.AutoCompleteAll() -CallVirt-> Newtonsoft.Json.JsonWriter.WriteEnd() -Call-> Newtonsoft.Json.JsonWriter.WriteEnd(Newtonsoft.Json.JsonContainerType) -Dispatch-> Google.Protobuf.FieldMaskTree.ToString() -Call-> Google.Protobuf.FieldMaskTree.ToFieldMask() -CallVirt-> Google.Protobuf.Collections.RepeatedField\`1.AddRange(System.Collections.Generic.IEnumerable\`1\<\!0>) -Dispatch-> SonarScanner.MSBuild.Common.MsBuildPathSettings.\<LocalApplicationDataPaths>d__6.MoveNext() -Dispatch-> SonarScanner.MSBuild.Common.DirectoryWrapper.Exists(System.String) -Call-> System.IO.Directory.Exists(System.String) |
| Finalizer | Network | NSwag.MSBuild | 14.7.1 | tools/Win | no | System.Reflection.Internal.CriticalDisposableObject.Finalize() | Instantiated | yes | yes | 4 | System.Reflection.Internal.CriticalDisposableObject.Finalize() -Dispatch-> System.Reflection.Internal.MemoryMappedFileBlock.DisposableData.Release() -Dispatch-> Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.Internal.SocketReceiver.Dispose() -CallVirt-> System.Net.Sockets.SocketAsyncEventArgs.Dispose() |
| Finalizer | Network | OpenCover | 4.7.1221 | tools | no | log4net.Appender.AppenderSkeleton.Finalize() | Instantiated | yes | yes | 4 | log4net.Appender.AppenderSkeleton.Finalize() -Call-> log4net.Appender.AppenderSkeleton.Close() -Dispatch-> log4net.Appender.UdpAppender.OnClose() -CallVirt-> System.Net.Sockets.UdpClient.Close() |
| Finalizer | Network | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | Microsoft.NET.StringTools.WeakStringCache.Finalize() | ChaOnly | yes | yes | 15 | Microsoft.NET.StringTools.WeakStringCache.Finalize() -Call-> Microsoft.NET.StringTools.WeakStringCache.DisposeImpl() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__14.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.Evaluate(System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.EvaluateOne(System.String\[\],System.Configuration.SectionInput,System.Boolean,System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionXmlReader(System.String\[\],System.Configuration.SectionInput) -Call-> System.Configuration.BaseConfigurationRecord.FindSection(System.String\[\],System.Configuration.SectionXmlInfo,System.Int32&) -Dispatch-> System.Configuration.ClientConfigurationHost.OpenStreamForRead(System.String) -NewObj-> System.Net.WebClient..ctor() |
| Finalizer | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | System.Reflection.Metadata.Ecma335.BlobStreamReader.VirtualHeapBlobTable.Finalize() | Instantiated | no | no | 9 | System.Reflection.Metadata.Ecma335.BlobStreamReader.VirtualHeapBlobTable.Finalize() -Dispatch-> BoDi.ObjectContainer.Dispose() -Dispatch-> Microsoft.VisualStudio.Threading.AsyncReaderWriterLock.AwaiterMetadata.\<get_Categories>d__10.MoveNext() -Dispatch-> System.Net.Http.Headers.CacheControlHeaderValue.ToString() -TypeInitializer-> System.Net.Http.Headers.CacheControlHeaderValue..cctor() -TypeInitializer-> System.Net.Http.Headers.GenericHeaderParser..cctor() -Ldftn-> System.Net.Http.Headers.GenericHeaderParser.ParseMailAddress(System.String,System.Int32,System.Object&) -Call-> System.Net.Http.Headers.HeaderUtilities.IsValidEmailAddress(System.String) -Call-> System.Net.Mail.MailAddressParser.ParseAddress(System.String) |
| Finalizer | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() | ChaOnly | yes | yes | 16 | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() -Call-> Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Dispose(System.Boolean) -Dispatch-> BoDi.ObjectContainer.Dispose() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__15.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.Evaluate(System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.EvaluateOne(System.String\[\],System.Configuration.SectionInput,System.Boolean,System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionXmlReader(System.String\[\],System.Configuration.SectionInput) -Call-> System.Configuration.BaseConfigurationRecord.FindSection(System.String\[\],System.Configuration.SectionXmlInfo,System.Int32&) -Dispatch-> System.Configuration.ClientConfigurationHost.OpenStreamForRead(System.String) -NewObj-> System.Net.WebClient..ctor() |
| Finalizer | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() | ChaOnly | yes | yes | 16 | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() -Call-> Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Dispose(System.Boolean) -Dispatch-> BoDi.ObjectContainer.Dispose() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__15.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.Evaluate(System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.EvaluateOne(System.String\[\],System.Configuration.SectionInput,System.Boolean,System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionXmlReader(System.String\[\],System.Configuration.SectionInput) -Call-> System.Configuration.BaseConfigurationRecord.FindSection(System.String\[\],System.Configuration.SectionXmlInfo,System.Int32&) -Dispatch-> System.Configuration.ClientConfigurationHost.OpenStreamForRead(System.String) -NewObj-> System.Net.WebClient..ctor() |
| Finalizer | Network | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() | ChaOnly | yes | yes | 16 | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() -Call-> Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Dispose(System.Boolean) -Dispatch-> BoDi.ObjectContainer.Dispose() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__15.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.Evaluate(System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object,System.Boolean,System.Boolean,System.Object&,System.Object&) -Call-> System.Configuration.BaseConfigurationRecord.EvaluateOne(System.String\[\],System.Configuration.SectionInput,System.Boolean,System.Configuration.FactoryRecord,System.Configuration.SectionRecord,System.Object) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionXmlReader(System.String\[\],System.Configuration.SectionInput) -Call-> System.Configuration.BaseConfigurationRecord.FindSection(System.String\[\],System.Configuration.SectionXmlInfo,System.Int32&) -Dispatch-> System.Configuration.ClientConfigurationHost.OpenStreamForRead(System.String) -NewObj-> System.Net.WebClient..ctor() |
| Finalizer | Network | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | Mono.Unix.UnixClient.Finalize() | Bound | yes | yes | 3 | Mono.Unix.UnixClient.Finalize() -CallVirt-> Mono.Unix.UnixClient.Dispose(System.Boolean) -CallVirt-> System.Net.Sockets.Socket.Close() |
| Finalizer | Network | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | Mono.Unix.UnixClient.Finalize() | Bound | yes | yes | 3 | Mono.Unix.UnixClient.Finalize() -CallVirt-> Mono.Unix.UnixClient.Dispose(System.Boolean) -CallVirt-> System.Net.Sockets.Socket.Close() |
| Finalizer | Network | dotnet-sonarscanner | 12.1.0 | tools/netcoreapp3.1/any | no | ICSharpCode.SharpZipLib.BZip2.BZip2OutputStream.Finalize() | Instantiated | yes | yes | 4 | ICSharpCode.SharpZipLib.BZip2.BZip2OutputStream.Finalize() -Dispatch-> ICSharpCode.SharpZipLib.Zip.Compression.Streams.DeflaterOutputStream.Dispose(System.Boolean) -Dispatch-> SonarScanner.MSBuild.PreProcessor.WebClientDownloader.Dispose() -CallVirt-> System.Net.Http.HttpMessageInvoker.Dispose() |
| Finalizer | ProcessExecution | OpenCover | 4.7.1221 | tools | no | log4net.Appender.AppenderSkeleton.Finalize() | ChaOnly | yes | yes | 10 | log4net.Appender.AppenderSkeleton.Finalize() -Call-> log4net.Appender.AppenderSkeleton.Close() -Dispatch-> log4net.Appender.BufferingAppenderSkeleton.OnClose() -CallVirt-> log4net.Appender.BufferingAppenderSkeleton.Flush(System.Boolean) -Dispatch-> log4net.Appender.SmtpAppender.SendBuffer(log4net.Core.LoggingEvent\[\]) -Call-> log4net.Appender.AppenderSkeleton.RenderLoggingEvent(System.IO.TextWriter,log4net.Core.LoggingEvent) -Dispatch-> log4net.Layout.PatternLayout.Format(System.IO.TextWriter,log4net.Core.LoggingEvent) -CallVirt-> log4net.Util.PatternConverter.Format(System.IO.TextWriter,System.Object) -Dispatch-> log4net.Util.PatternStringConverters.ProcessIdPatternConverter.Convert(System.IO.TextWriter,System.Object) -CallVirt-> System.Diagnostics.Process.get_Id() |
| Finalizer | ProcessExecution | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | Microsoft.NET.StringTools.WeakStringCache.Finalize() | ChaOnly | yes | yes | 14 | Microsoft.NET.StringTools.WeakStringCache.Finalize() -Call-> Microsoft.NET.StringTools.WeakStringCache.DisposeImpl() -Dispatch-> System.Configuration.ConfigurationSectionCollection.\<GetEnumerator>d__14.MoveNext() -Call-> System.Configuration.ConfigurationSectionCollection.get_Item(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.Int32) -Call-> System.Configuration.ConfigurationSectionCollection.Get(System.String) -CallVirt-> System.Configuration.BaseConfigurationRecord.GetSection(System.String) -Call-> System.Configuration.BaseConfigurationRecord.GetSection(System.String,System.Boolean,System.Boolean) -Call-> System.Configuration.BaseConfigurationRecord.GetSectionRecursive(System.String,System.Boolean,System.Boolean,System.Boolean,System.Boolean,System.Object&,System.Object&) -Dispatch-> System.Configuration.ClientConfigurationHost.RequireCompleteInit(System.Configuration.Internal.IInternalConfigRecord) -Call-> System.Configuration.ClientConfigurationHost.get_ConfigPaths() -Call-> System.Configuration.ClientConfigPaths.GetPaths(System.String,System.Boolean) -NewObj-> System.Configuration.ClientConfigPaths..ctor(System.String,System.Boolean) -CallVirt-> System.Diagnostics.Process.get_MainModule() |
| Finalizer | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Execution.BuildManager.Finalize() | Instantiated | yes | yes | 8 | Microsoft.Build.Execution.BuildManager.Finalize() -Call-> Microsoft.Build.Execution.BuildManager.Dispose(System.Boolean) -Call-> Microsoft.Build.BackEnd.BuildComponentFactoryCollection.ShutdownComponents() -CallVirt-> Microsoft.Build.BackEnd.BuildComponentFactoryCollection.BuildComponentEntry.ShutdownSingletonInstance() -Dispatch-> Microsoft.Build.BackEnd.Scheduler.ShutdownComponent() -Call-> Microsoft.Build.BackEnd.Scheduler.Reset() -Call-> Microsoft.Build.BackEnd.Scheduler.DumpConfigurations() -CallVirt-> System.Diagnostics.Process.get_Id() |
| Finalizer | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.Build.BackEnd.Components.Caching.RegisteredTaskObjectCache.Finalize() | Bound | yes | yes | 8 | Microsoft.Build.BackEnd.Components.Caching.RegisteredTaskObjectCache.Finalize() -CallVirt-> Microsoft.Build.BackEnd.Components.Caching.RegisteredTaskObjectCache.Dispose(System.Boolean) -Call-> Microsoft.Build.Shared.ErrorUtilities.VerifyThrow(System.Boolean,System.String) -Call-> Microsoft.Build.Shared.ErrorUtilities.ThrowInternalError(System.String,System.Exception,System.Object\[\]) -NewObj-> Microsoft.Build.Shared.InternalErrorException..ctor(System.String,System.Exception) -Call-> Microsoft.Build.Shared.InternalErrorException.ConsiderDebuggerLaunch(System.String,System.Exception) -Call-> Microsoft.Build.Shared.InternalErrorException.LaunchDebugger(System.String,System.String) -CallVirt-> System.Diagnostics.Process.get_Id() |
| Finalizer | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.Build.BackEnd.Components.Caching.RegisteredTaskObjectCache.Finalize() | Bound | yes | yes | 8 | Microsoft.Build.BackEnd.Components.Caching.RegisteredTaskObjectCache.Finalize() -CallVirt-> Microsoft.Build.BackEnd.Components.Caching.RegisteredTaskObjectCache.Dispose(System.Boolean) -Call-> Microsoft.Build.Shared.ErrorUtilities.VerifyThrow(System.Boolean,System.String) -Call-> Microsoft.Build.Shared.ErrorUtilities.ThrowInternalError(System.String,System.Exception,System.Object\[\]) -NewObj-> Microsoft.Build.Shared.InternalErrorException..ctor(System.String,System.Exception) -Call-> Microsoft.Build.Shared.InternalErrorException.ConsiderDebuggerLaunch(System.String,System.Exception) -Call-> Microsoft.Build.Shared.InternalErrorException.LaunchDebugger(System.String,System.String) -CallVirt-> System.Diagnostics.Process.get_Id() |
| Finalizer | ProcessExecution | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.Build.BackEnd.Components.Caching.RegisteredTaskObjectCache.Finalize() | Bound | yes | yes | 8 | Microsoft.Build.BackEnd.Components.Caching.RegisteredTaskObjectCache.Finalize() -CallVirt-> Microsoft.Build.BackEnd.Components.Caching.RegisteredTaskObjectCache.Dispose(System.Boolean) -Call-> Microsoft.Build.Shared.ErrorUtilities.VerifyThrow(System.Boolean,System.String) -Call-> Microsoft.Build.Shared.ErrorUtilities.ThrowInternalError(System.String,System.Exception,System.Object\[\]) -NewObj-> Microsoft.Build.Shared.InternalErrorException..ctor(System.String,System.Exception) -Call-> Microsoft.Build.Shared.InternalErrorException.ConsiderDebuggerLaunch(System.String,System.Exception) -Call-> Microsoft.Build.Shared.InternalErrorException.LaunchDebugger(System.String,System.String) -CallVirt-> System.Diagnostics.Process.get_Id() |
| Finalizer | Registry | OpenCover | 4.7.1221 | tools | no | log4net.Appender.AppenderSkeleton.Finalize() | Instantiated | yes | yes | 6 | log4net.Appender.AppenderSkeleton.Finalize() -TypeInitializer-> log4net.Util.LogLog..cctor() -Call-> log4net.Util.LogLog.Error(System.Type,System.String,System.Exception) -Dispatch-> Gendarme.Framework.Helpers.MethodPrinter.ToString() -Dispatch-> Sentry.PlatformAbstractions.FrameworkInfo.\<GetInstallations>d__5.MoveNext() -CallVirt-> Microsoft.Win32.RegistryKey.GetSubKeyNames() |
| Finalizer | Registry | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | System.Reflection.Metadata.Ecma335.BlobStreamReader.VirtualHeapBlobTable.Finalize() | Instantiated | yes | yes | 4 | System.Reflection.Metadata.Ecma335.BlobStreamReader.VirtualHeapBlobTable.Finalize() -Dispatch-> Microsoft.Build.Internal.RegistryKeyWrapper.Dispose() -Call-> Microsoft.Build.Internal.RegistryKeyWrapper.Dispose(System.Boolean) -CallVirt-> Microsoft.Win32.RegistryKey.Dispose() |
| Finalizer | NativeInterop | Microsoft.AspNetCore.Razor.Design | 2.3.13 | tools | no | Microsoft.DiaSymReader.SymUnmanagedWriterImpl.Finalize() | Bound | yes | yes | 4 | Microsoft.DiaSymReader.SymUnmanagedWriterImpl.Finalize() -Call-> Microsoft.DiaSymReader.SymUnmanagedWriterImpl.DisposeImpl() -Call-> Microsoft.DiaSymReader.SymUnmanagedWriterImpl.CloseSymWriter() -CallVirt-> Microsoft.DiaSymReader.ISymUnmanagedWriter5.Close() |
| Finalizer | NativeInterop | Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | buildTransitive/netstandard2.0 | no | Microsoft.Maui.Controls.GradientBrush.Finalize() | Instantiated | yes | yes | 4 | Microsoft.Maui.Controls.GradientBrush.Finalize() -Dispatch-> Mono.Cecil.Pdb.NativePdbWriter.Dispose() -CallVirt-> Mono.Cecil.Pdb.SymWriter.Close() -CallVirt-> Mono.Cecil.Pdb.ISymUnmanagedWriter2.Close() |
| Finalizer | NativeInterop | Microsoft.NET.ILLink.Tasks | 10.0.14 | tools/netframework | no | System.Reflection.Internal.CriticalDisposableObject.Finalize() | Instantiated | no | yes | 17 | System.Reflection.Internal.CriticalDisposableObject.Finalize() -Dispatch-> System.Reflection.Internal.MemoryMappedFileBlock.DisposableData.Release() -Dispatch-> Mono.Cecil.AssemblyDefinition.Dispose() -Call-> Mono.Cecil.AssemblyDefinition.get_Modules() -Ldftn-> Mono.Cecil.AssemblyDefinition.\<>c.\<get_Modules>b__14_0(Mono.Cecil.AssemblyDefinition,Mono.Cecil.MetadataReader) -CallVirt-> Mono.Cecil.MetadataReader.ReadModules() -Call-> Mono.Cecil.ModuleDefinition.ReadModule(System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleDefinition.ReadModule(Mono.Disposable\`1\<System.IO.Stream>,System.String,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleReader.CreateModule(Mono.Cecil.PE.Image,Mono.Cecil.ReaderParameters) -Call-> Mono.Cecil.ModuleReader.ReadSymbols(Mono.Cecil.ModuleDefinition,Mono.Cecil.ReaderParameters) -CallVirt-> Mono.Cecil.ModuleDefinition.ReadSymbols(Mono.Cecil.Cil.ISymbolReader,System.Boolean) -Dispatch-> Mono.Cecil.Pdb.NativePdbReader.ProcessDebugHeader(Mono.Cecil.Cil.ImageDebugHeader) -Call-> Microsoft.Cci.Pdb.PdbFile.LoadFunctions(System.IO.Stream) -NewObj-> Microsoft.Cci.Pdb.MsfDirectory..ctor(Microsoft.Cci.Pdb.PdbReader,Microsoft.Cci.Pdb.PdbFileHeader,Microsoft.Cci.Pdb.BitAccess) -CallVirt-> Microsoft.Cci.Pdb.BitAccess.Append(System.IO.Stream,System.Int32) -Dispatch-> System.Reflection.Internal.ReadOnlyUnmanagedMemoryStream.Read(System.Byte\[\],System.Int32,System.Int32) -Call-> System.Runtime.InteropServices.Marshal.Copy(System.IntPtr,System.Byte\[\],System.Int32,System.Int32) |
| Finalizer | NativeInterop | Microsoft.Net.Compilers | 4.2.0 | tools | no | Microsoft.CodeAnalysis.BuildTasks.RCWForCurrentContext\`1.Finalize() | Bound | yes | yes | 3 | Microsoft.CodeAnalysis.BuildTasks.RCWForCurrentContext\`1.Finalize() -Call-> Microsoft.CodeAnalysis.BuildTasks.RCWForCurrentContext\`1.CleanupComObject() -Call-> System.Runtime.InteropServices.Marshal.IsComObject(System.Object) |
| Finalizer | NativeInterop | NSwag.MSBuild | 14.7.1 | tools/Win | no | System.Reflection.Internal.CriticalDisposableObject.Finalize() | Instantiated | yes | yes | 9 | System.Reflection.Internal.CriticalDisposableObject.Finalize() -Dispatch-> System.Reflection.Internal.MemoryMappedFileBlock.DisposableData.Release() -Dispatch-> Microsoft.Extensions.DependencyInjection.ServiceLookup.ServiceProviderEngineScope.Dispose() -Call-> Microsoft.Extensions.DependencyInjection.ServiceLookup.ServiceProviderEngineScope.BeginDispose() -Dispatch-> System.HashCode.GetHashCode() -TypeInitializer-> System.HashCode..cctor() -Call-> System.HashCode.GenerateGlobalSeed() -Call-> Interop.GetRandomBytes(System.Byte*,System.Int32) -Call-> System.Runtime.InteropServices.Marshal.Copy(System.Byte\[\],System.Int32,System.IntPtr,System.Int32) |
| Finalizer | NativeInterop | OpenCover | 4.7.1221 | tools | no | log4net.Appender.AppenderSkeleton.Finalize() | Instantiated | yes | yes | 4 | log4net.Appender.AppenderSkeleton.Finalize() -Call-> log4net.Appender.AppenderSkeleton.Close() -Dispatch-> log4net.Appender.LocalSyslogAppender.OnClose() -Call-> log4net.Appender.LocalSyslogAppender.closelog() |
| Finalizer | NativeInterop | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/net462 | no | Microsoft.NET.StringTools.WeakStringCache.Finalize() | Instantiated | yes | yes | 15 | Microsoft.NET.StringTools.WeakStringCache.Finalize() -Call-> Microsoft.NET.StringTools.WeakStringCache.DisposeImpl() -Dispatch-> Reqnroll.Bindings.StepDefinitionRegexCalculator.\<GetPrefixesToRemove>d__5.MoveNext() -Dispatch-> System.Text.Json.Nodes.JsonNode.ToString() -Call-> System.Text.Json.Nodes.JsonNode.WriteToPooledBuffer(System.Text.Json.JsonSerializerOptions,System.Text.Json.JsonWriterOptions,System.Int32) -Dispatch-> System.Text.Json.Nodes.JsonValuePrimitive\`1.WriteTo(System.Text.Json.Utf8JsonWriter,System.Text.Json.JsonSerializerOptions) -Dispatch-> System.Text.Json.Serialization.Converters.EnumConverter\`1.Write(System.Text.Json.Utf8JsonWriter,\!0,System.Text.Json.JsonSerializerOptions) -Call-> System.Text.Json.JsonEncodedText.Encode(System.String,System.Text.Encodings.Web.JavaScriptEncoder) -Call-> System.Text.Json.JsonEncodedText.Encode(System.ReadOnlySpan\`1\<System.Char>,System.Text.Encodings.Web.JavaScriptEncoder) -Call-> System.Text.Json.JsonEncodedText.TranscodeAndEncode(System.ReadOnlySpan\`1\<System.Char>,System.Text.Encodings.Web.JavaScriptEncoder) -Call-> System.Text.Json.JsonReaderHelper.GetUtf8ByteCount(System.ReadOnlySpan\`1\<System.Char>) -Dispatch-> System.Text.EncodingNLS.GetByteCount(System.Char*,System.Int32) -Dispatch-> System.Text.DBCSCodePageEncoding.GetByteCount(System.Char*,System.Int32,System.Text.EncoderNLS) -Call-> System.Text.BaseCodePageEncoding.CheckMemorySection() -CallVirt-> System.Runtime.InteropServices.SafeHandle.DangerousGetHandle() |
| Finalizer | NativeInterop | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | build/netstandard2.0 | no | Microsoft.NET.StringTools.WeakStringCache.Finalize() | Instantiated | yes | yes | 4 | Microsoft.NET.StringTools.WeakStringCache.Finalize() -Call-> Microsoft.NET.StringTools.WeakStringCache.DisposeImpl() -Dispatch-> Microsoft.Win32.RegistryKey.Dispose() -CallVirt-> System.Runtime.InteropServices.SafeHandle.Dispose() |
| Finalizer | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | no | Microsoft.Build.Tasks.InteropUtilities.RCWForCurrentContext\`1.Finalize() | Bound | yes | yes | 3 | Microsoft.Build.Tasks.InteropUtilities.RCWForCurrentContext\`1.Finalize() -Call-> Microsoft.Build.Tasks.InteropUtilities.RCWForCurrentContext\`1.CleanupComObject() -Call-> System.Runtime.InteropServices.Marshal.IsComObject(System.Object) |
| Finalizer | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net5.0 | no | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() | Instantiated | yes | yes | 9 | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() -Call-> Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Dispose(System.Boolean) -Dispatch-> BoDi.ObjectContainer.Dispose() -Dispatch-> Microsoft.Build.Evaluation.Expander.ItemExpander.IntrinsicItemFunctions.\<ItemSpecModifierFunction>d__5\`3.MoveNext() -Call-> Microsoft.Build.Shared.FileUtilities.ItemSpecModifiers.GetItemSpecModifier(System.String,System.String,System.String,System.String) -Call-> Microsoft.Build.Shared.FileUtilities.ItemSpecModifiers.GetItemSpecModifier(System.String,System.String,System.String,System.String,System.String&) -Dispatch-> Microsoft.Build.Shared.FileSystem.WindowsFileSystem.FileExists(System.String) -Call-> Microsoft.Build.Shared.NativeMethodsShared.FileExistsWindows(System.String) -Call-> Microsoft.Build.Shared.NativeMethodsShared.GetFileAttributesEx(System.String,System.Int32,Microsoft.Build.Shared.NativeMethodsShared.WIN32_FILE_ATTRIBUTE_DATA&) |
| Finalizer | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net6.0 | no | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() | Instantiated | yes | yes | 9 | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() -Call-> Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Dispose(System.Boolean) -Dispatch-> BoDi.ObjectContainer.Dispose() -Dispatch-> Microsoft.Build.Evaluation.Expander.ItemExpander.IntrinsicItemFunctions.\<ItemSpecModifierFunction>d__5\`3.MoveNext() -Call-> Microsoft.Build.Shared.FileUtilities.ItemSpecModifiers.GetItemSpecModifier(System.String,System.String,System.String,System.String) -Call-> Microsoft.Build.Shared.FileUtilities.ItemSpecModifiers.GetItemSpecModifier(System.String,System.String,System.String,System.String,System.String&) -Dispatch-> Microsoft.Build.Shared.FileSystem.WindowsFileSystem.FileExists(System.String) -Call-> Microsoft.Build.Shared.NativeMethodsShared.FileExistsWindows(System.String) -Call-> Microsoft.Build.Shared.NativeMethodsShared.GetFileAttributesEx(System.String,System.Int32,Microsoft.Build.Shared.NativeMethodsShared.WIN32_FILE_ATTRIBUTE_DATA&) |
| Finalizer | NativeInterop | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/netcoreapp2.1 | no | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() | Instantiated | yes | yes | 9 | Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Finalize() -Call-> Microsoft.Build.Collections.ItemDictionary.Enumerator\`1.Dispose(System.Boolean) -Dispatch-> BoDi.ObjectContainer.Dispose() -Dispatch-> Microsoft.Build.Evaluation.Expander.ItemExpander.IntrinsicItemFunctions.\<ItemSpecModifierFunction>d__5\`3.MoveNext() -Call-> Microsoft.Build.Shared.FileUtilities.ItemSpecModifiers.GetItemSpecModifier(System.String,System.String,System.String,System.String) -Call-> Microsoft.Build.Shared.FileUtilities.ItemSpecModifiers.GetItemSpecModifier(System.String,System.String,System.String,System.String,System.String&) -Dispatch-> Microsoft.Build.Shared.FileSystem.WindowsFileSystem.FileExists(System.String) -Call-> Microsoft.Build.Shared.NativeMethodsShared.FileExistsWindows(System.String) -Call-> Microsoft.Build.Shared.NativeMethodsShared.GetFileAttributesEx(System.String,System.Int32,Microsoft.Build.Shared.NativeMethodsShared.WIN32_FILE_ATTRIBUTE_DATA&) |
| Finalizer | NativeInterop | Xamarin.AndroidX.Migration | 1.0.10 | build/monoandroid120 | no | Mono.Unix.Native.FilePosition.Finalize() | Bound | yes | yes | 3 | Mono.Unix.Native.FilePosition.Finalize() -Call-> Mono.Unix.Native.FilePosition.Cleanup() -Call-> Mono.Unix.Native.Stdlib.free(System.IntPtr) |
| Finalizer | NativeInterop | Xamarin.AndroidX.Migration | 1.0.10 | buildTransitive/monoandroid120 | no | Mono.Unix.Native.FilePosition.Finalize() | Bound | yes | yes | 3 | Mono.Unix.Native.FilePosition.Finalize() -Call-> Mono.Unix.Native.FilePosition.Cleanup() -Call-> Mono.Unix.Native.Stdlib.free(System.IntPtr) |
| Finalizer | NativeInterop | coverlet.msbuild | 10.1.0 | tasks/netstandard2.0 | no | System.Reflection.Internal.CriticalDisposableObject.Finalize() | Instantiated | yes | yes | 4 | System.Reflection.Internal.CriticalDisposableObject.Finalize() -Dispatch-> System.Reflection.Internal.MemoryMappedFileBlock.DisposableData.Release() -Dispatch-> System.Security.Cryptography.SP800108HmacCounterKdfImplementationCng.Dispose() -CallVirt-> System.Runtime.InteropServices.SafeHandle.Dispose() |
| Finalizer | NativeInterop | dotnet-sonarscanner | 12.1.0 | tools/netcoreapp3.1/any | no | ICSharpCode.SharpZipLib.BZip2.BZip2OutputStream.Finalize() | Instantiated | no | yes | 20 | ICSharpCode.SharpZipLib.BZip2.BZip2OutputStream.Finalize() -Dispatch-> ICSharpCode.SharpZipLib.Zip.Compression.Streams.DeflaterOutputStream.Dispose(System.Boolean) -Dispatch-> Newtonsoft.Json.JsonWriter.System.IDisposable.Dispose() -CallVirt-> Newtonsoft.Json.JsonWriter.Dispose(System.Boolean) -CallVirt-> Newtonsoft.Json.JsonWriter.Close() -Call-> Newtonsoft.Json.JsonWriter.AutoCompleteAll() -CallVirt-> Newtonsoft.Json.JsonWriter.WriteEnd() -Call-> Newtonsoft.Json.JsonWriter.WriteEnd(Newtonsoft.Json.JsonContainerType) -Dispatch-> Google.Protobuf.Reflection.FileDescriptor.ToString() -Call-> Google.Protobuf.Reflection.FileDescriptor.get_Name() -CallVirt-> Google.Protobuf.Reflection.FileDescriptorProto.get_Name() -TypeInitializer-> Google.Protobuf.Reflection.FileDescriptorProto..cctor() -Call-> Google.Protobuf.FieldCodec.ForMessage\`1(System.UInt32,Google.Protobuf.MessageParser\`1\<\!\!0>) -Ldftn-> Google.Protobuf.FieldCodec.\<>c__32\`1.\<ForMessage>b__32_3(\!0&,\!0) -Dispatch-> Google.Protobuf.Reflection.EnumOptions.MergeFrom(Google.Protobuf.Reflection.EnumOptions) -Call-> Google.Protobuf.ExtensionSet.MergeFrom\`1(Google.Protobuf.ExtensionSet\`1\<\!\!0>&,Google.Protobuf.ExtensionSet\`1\<\!\!0>) -Dispatch-> Google.Protobuf.RepeatedExtensionValue\`1.MergeFrom(Google.Protobuf.ParseContext&) -CallVirt-> Google.Protobuf.Collections.RepeatedField\`1.AddEntriesFrom(Google.Protobuf.ParseContext&,Google.Protobuf.FieldCodec\`1\<\!0>) -Call-> Google.Protobuf.Collections.RepeatedField\`1.TryGetArrayAsSpanPinnedUnsafe(Google.Protobuf.FieldCodec\`1\<\!0>,System.Span\`1\<System.Byte>&,System.Runtime.InteropServices.GCHandle&) -Call-> System.Runtime.InteropServices.Marshal.SizeOf\`1() |

## 12. Coverage honesty (ADR-0024)

Every package or folder whose numbers above are a floor, not a total, and why. Unknown verdicts are already
counted in section 8 and are not repeated here.

| Package | Version | Folder | Why |
| --- | --- | --- | --- |
| Microsoft.Net.Compilers | 4.2.0 | tools | 2 assembl(ies) not loaded; presence scan failed for 2 assembl(ies); 2 name(s) cut at 1024 chars (amendment a5)\: reported names bounded, counts whole |
| dotnet-reportgenerator-globaltool | 5.5.12 | tools/net10.0/any | 1 assembl(ies) not loaded; presence scan failed for 1 assembl(ies) |
| dotnet-reportgenerator-globaltool | 5.5.12 | tools/net8.0/any | 1 assembl(ies) not loaded; presence scan failed for 1 assembl(ies) |
| dotnet-reportgenerator-globaltool | 5.5.12 | tools/net9.0/any | 1 assembl(ies) not loaded; presence scan failed for 1 assembl(ies) |
| NSwag.MSBuild | 14.7.1 | tools/Net100 | 2 assembl(ies) not loaded; presence scan failed for 2 assembl(ies) |
| NSwag.MSBuild | 14.7.1 | tools/Net80 | 2 assembl(ies) not loaded; presence scan failed for 2 assembl(ies) |
| NSwag.MSBuild | 14.7.1 | tools/Net90 | 2 assembl(ies) not loaded; presence scan failed for 2 assembl(ies) |
| NSwag.MSBuild | 14.7.1 | tools/Win | member index incomplete (assemblies 0, types 0, methods 0, forwarders 0, supertypes 0) |
| Microsoft.CodeAnalysis.NetAnalyzers | 10.0.403 | analyzers/dotnet/cs | 4 name(s) cut at 1024 chars (amendment a5)\: reported names bounded, counts whole |
| Microsoft.CodeAnalysis.NetAnalyzers | 10.0.403 | analyzers/dotnet/vb | 4 name(s) cut at 1024 chars (amendment a5)\: reported names bounded, counts whole |
| SpecFlow.Tools.MsBuild.Generation | 3.9.74 | tasks/net461 | member index incomplete (assemblies 0, types 0, methods 0, forwarders 0, supertypes 0) |
| Microsoft.CodeQuality.Analyzers | 3.3.2 | analyzers/dotnet/cs | 3 name(s) cut at 1024 chars (amendment a5)\: reported names bounded, counts whole |
| Microsoft.CodeQuality.Analyzers | 3.3.2 | analyzers/dotnet/vb | 3 name(s) cut at 1024 chars (amendment a5)\: reported names bounded, counts whole |
| Microsoft.NetCore.Analyzers | 3.3.2 | analyzers/dotnet/cs | 3 name(s) cut at 1024 chars (amendment a5)\: reported names bounded, counts whole |
| Microsoft.NetCore.Analyzers | 3.3.2 | analyzers/dotnet/vb | 3 name(s) cut at 1024 chars (amendment a5)\: reported names bounded, counts whole |
| ReportGenerator | 5.5.12 | tools/net10.0 | 1 assembl(ies) not loaded; presence scan failed for 1 assembl(ies) |
| ReportGenerator | 5.5.12 | tools/net47 | member index incomplete (assemblies 0, types 0, methods 0, forwarders 0, supertypes 0) |
| ReportGenerator | 5.5.12 | tools/net8.0 | 1 assembl(ies) not loaded; presence scan failed for 1 assembl(ies) |
| ReportGenerator | 5.5.12 | tools/net9.0 | 1 assembl(ies) not loaded; presence scan failed for 1 assembl(ies) |
| OpenCover | 4.7.1221 | tools/x64 | no assembly of the folder loaded\: no graph; 1 assembl(ies) not loaded; presence scan failed for 1 assembl(ies) |
| OpenCover | 4.7.1221 | tools/x86 | no assembly of the folder loaded\: no graph; 1 assembl(ies) not loaded; presence scan failed for 1 assembl(ies) |

Names cut at 1024 chars (amendment a5), over every folder: **22** (some reported names are bounded, not whole). A folder that cut
any is listed above with its count; a cut changes the names reported, never a count.
