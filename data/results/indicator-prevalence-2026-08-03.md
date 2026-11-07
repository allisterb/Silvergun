# Benign corpus - indicator prevalence (2026-08-03)

**A measurement, not a gate.** These are ordinary, widely-used NuGet packages; their label is
"overwhelmingly not malware" by download count, not by audit (ADR-0021: benign by assumption is not
benign by proof). The question answered here is *precision*: which `IndicatorCategory` values are so
common in benign code that they carry no gating signal on their own. Nothing in `--strict`, the
`IndicatorAnalysis` classifier, or any threshold was changed to produce these numbers - the gating
decision (if any) is a separate ADR, written from this data.

**Filename note.** This file is named `indicator-prevalence-2026-08-03.md` to match
`docs/agent/tasks/indicator-benign-prevalence.md` ("specced 2026-08-03"), the task it answers. The measurement
was actually **executed 2026-08-20** (see "Run date" below) - the harness's own default file-naming (today's
date) was overridden by copying its output to this name rather than changing the harness's date-stamping
behaviour for one run. Every number in this file is from that 2026-08-20 execution, not from 2026-08-03.

| Parameter | Value |
| --- | --- |
| Run date (wall clock) | 2026-08-20 |
| Command line | `Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.exe` (default options: `--manifest benign-corpus.manifest --take 25 --cache %LOCALAPPDATA%\Silvergun\benign-corpus --timeout 300`) |
| Manifest | `benign-corpus.manifest` |
| Manifest hash (sha256 of normalized `id,version` list) | `03034edd2f8f62abf50b938ff8e0543c60cdcfb6f9e214c98cbc9203b12ce75b` |
| Packages in manifest (after `--take`) | 25 |
| Packages contributing to prevalence | 25 |
| Assemblies scanned | 26 |
| Methods analysed | 51035 |
| Methods skipped | 0 |
| Total indicator findings (raw occurrences) | 767 |
| Distinct-indicator cap (10,000/assembly) hit anywhere | no |
| Cache root (outside the repo; no `.nupkg` is ever written into it) | `%LOCALAPPDATA%\Silvergun\benign-corpus` |
| Classified indicator findings | `indicator-prevalence-2026-08-03.tsv` |

## Method

- **TFM selection.** Per package, among `lib/<tfm>/` folders holding at least one `.dll`: the highest
  `net<major>.<minor>` (no platform suffix), else exactly `netstandard2.0`, else the package is reported
  as `no-scannable-tfm` and contributes nothing. The chosen TFM is recorded on every row below, because
  comparing a `net10.0` surface against a `netstandard2.0` one silently would make the corpus
  incomparable with itself.
- **Process isolation.** One child process per assembly, exit code checked (ADR-0021). A child that
  exits non-zero, times out, or exits 0 without printing `DONE` is reported below, never silently lost.
- **Denominator.** Shares are over the packages that contributed data, listed as `scanned` or
  `scanned-partial`. Median and p90 are over that same set *including packages with zero findings*;
  p90 is nearest-rank.
- **Occurrence counting.** `IndicatorAnalysis` aggregates per (Category, Value, CallerType,
  CallerMethod) with an `Occurrences` count (constraint 5 of the classifier spec); "total findings",
  and the per-package median/p90 below, sum `Occurrences`, so they count raw `ldstr` hits, not
  aggregated rows. "Distinct values" counts the aggregated rows' distinct `Value`s instead - the size
  of the corpus-wide value set for that category.
- **Truncation.** `IndicatorReport.Truncated` (the 10,000-distinct-indicator-per-assembly cap) is
  checked per assembly; if it fired anywhere, every number below for the affected package is a
  **floor, not a total** - see Truncation below.

## Regression oracle (checked first, per the task spec)

Before this measurement was produced, the capability half of the harness was re-run unmodified and diffed
byte-for-byte (after normalising the embedded run date) against `benign-corpus-2026-07-31.md` /
`.tsv`: **identical**. Manifest hash, 25/25 packages contributing, 26 assemblies, 51035 methods analysed, 0
skipped, 1706 total capability findings, and the 24/25 = 96.0% "(any capability)" row all reproduced exactly.
The `AssemblyAnalyzer.StringConstants()` seam added since 2026-07-31 did not move the capability numbers. The
harness was then run twice more (with `IndicatorAnalysis` wired into the same child scan) into a scratch
output directory; the two runs' capability and indicator `.md`/`.tsv` outputs were byte-identical pairwise.

## Indicator prevalence - the calibration answer

Share = packages with at least one finding of that category, out of the 25 that
contributed data. A category with a high share cannot gate anything on its own.

| Category | Packages with >=1 | Share of corpus | Total findings | Distinct values | Median/pkg | p90/pkg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ReflectionTypeName | 23 | 92.0% | 686 | 327 | 5.0 | 81 |
| GenericUrl | 7 | 28.0% | 68 | 8 | 0.0 | 8 |
| PublicIpLiteral | 4 | 16.0% | 11 | 4 | 0.0 | 1 |
| PrivateIpLiteral | 1 | 4.0% | 2 | 2 | 0.0 | 0 |
| AutorunRegistry | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| CallbackDomain | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| CredentialPath | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| DynamicDns | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| ExfilSink | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| RawCodeHost | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| **(any indicator)** | **23** | **92.0%** | **767** | **341** | **5.0** | **102** |

## Top 10 most widespread distinct values, per category

Ranked by number of DISTINCT counted packages carrying the value (not raw occurrences); ties broken by
total occurrences, then the value itself. This is the table that makes the shares above interpretable -
without it a high share is just a number.

| Category | Value | Packages | Total occurrences |
| --- | --- | ---: | ---: |
| GenericUrl | www.w3.org | 4 | 44 |
| GenericUrl | james.newtonking.com | 1 | 15 |
| GenericUrl | emptylink | 1 | 2 |
| GenericUrl | microsoft.com | 1 | 2 |
| GenericUrl | nlog-project.org | 1 | 2 |
| GenericUrl | docs.automapper.org | 1 | 1 |
| GenericUrl | github.com | 1 | 1 |
| GenericUrl | schemas.xmlsoap.org | 1 | 1 |
| PrivateIpLiteral | 127.0.0.1 | 1 | 1 |
| PrivateIpLiteral | ::1 | 1 | 1 |
| PublicIpLiteral | :: | 3 | 3 |
| PublicIpLiteral | 1.3.6.1 | 1 | 4 |
| PublicIpLiteral | 0.0.0.0 | 1 | 2 |
| PublicIpLiteral | 4.1.188.7 | 1 | 2 |
| ReflectionTypeName | System.Resources.UseSystemResourceKeys | 4 | 4 |
| ReflectionTypeName | System.ValueTuple | 3 | 11 |
| ReflectionTypeName | Microsoft.FSharp.Collections.ListModule | 3 | 3 |
| ReflectionTypeName | System.Data.Linq.Binary | 2 | 9 |
| ReflectionTypeName | System.Collections.Immutable.ImmutableDictionary | 2 | 8 |
| ReflectionTypeName | System.Collections.Immutable.ImmutableHashSet | 2 | 8 |
| ReflectionTypeName | System.Collections.Immutable.ImmutableList | 2 | 8 |
| ReflectionTypeName | System.Collections.Immutable.ImmutableQueue | 2 | 8 |
| ReflectionTypeName | System.Collections.Immutable.ImmutableStack | 2 | 8 |
| ReflectionTypeName | System.Collections.Immutable.ImmutableArray | 2 | 6 |

## Per package

| Package | Version | TFM | Status | Assemblies | Indicator findings | Truncated | Cap-hit |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| Newtonsoft.Json | 13.0.3 | net6.0 | scanned | 1 | 102 | no | yes |
| Serilog | 4.2.0 | net9.0 | scanned | 1 | 2 | no | yes |
| NLog | 5.3.4 | netstandard2.0 | scanned | 1 | 102 | no | yes |
| AutoMapper | 13.0.1 | net6.0 | scanned | 1 | 4 | no | yes |
| FluentValidation | 11.11.0 | net8.0 | scanned | 1 | 3 | no | yes |
| Polly | 8.5.0 | net6.0 | scanned | 1 | 2 | no | yes |
| Dapper | 2.1.35 | net7.0 | scanned | 1 | 12 | no | yes |
| CsvHelper | 33.0.1 | net8.0 | scanned | 1 | 7 | no | yes |
| HtmlAgilityPack | 1.11.71 | netstandard2.0 | scanned | 1 | 2 | no | yes |
| RestSharp | 112.1.0 | net8.0 | scanned | 1 | 2 | no | yes |
| MediatR | 12.4.1 | net6.0 | scanned | 1 | 0 | no | yes |
| Humanizer.Core | 2.14.1 | net6.0 | scanned | 1 | 2 | no | yes |
| Castle.Core | 5.1.1 | net6.0 | scanned | 1 | 48 | no | yes |
| Moq | 4.20.72 | net6.0 | scanned | 1 | 9 | no | yes |
| NUnit | 4.2.2 | net6.0 | scanned | 2 | 308 | no | yes |
| System.Text.Json | 9.0.0 | net9.0 | scanned | 1 | 76 | no | yes |
| Microsoft.Extensions.Logging.Abstractions | 9.0.0 | net9.0 | scanned | 1 | 1 | no | yes |
| Microsoft.Extensions.DependencyInjection | 9.0.0 | net9.0 | scanned | 1 | 5 | no | yes |
| Microsoft.Extensions.Configuration | 9.0.0 | net9.0 | scanned | 1 | 1 | no | yes |
| Microsoft.Bcl.AsyncInterfaces | 9.0.0 | netstandard2.0 | scanned | 1 | 0 | no | no |
| protobuf-net | 3.2.30 | net6.0 | scanned | 1 | 34 | no | yes |
| YamlDotNet | 16.2.1 | net8.0 | scanned | 1 | 5 | no | yes |
| SharpZipLib | 1.4.2 | net6.0 | scanned | 1 | 7 | no | yes |
| MimeKit | 4.8.0 | net8.0 | scanned | 1 | 26 | no | yes |
| Spectre.Console | 0.49.1 | net8.0 | scanned | 1 | 7 | no | yes |

## CallbackDomain / ExfilSink / DynamicDns - every hit, individually

A benign package tripping one of these three categories is either a false positive in our domain list
or a genuinely interesting package; either way it must be visible by name, not buried in a count.

*None: no package in the corpus produced a CallbackDomain, ExfilSink, or DynamicDns finding.*

## Truncation

*None: the 10,000-distinct-indicator-per-assembly cap was not reached by any assembly in the corpus - every number above is a total, not a floor.*

## Coverage honesty (ADR-0024)

25 of 25 manifest entries were scanned completely.
Everything below is a package whose numbers above are a **floor, not a total** - or that produced no
numbers at all. A corpus statistic computed over partially-analysed input is a lie unless the
partiality is stated alongside it.

*None: every manifest entry was scanned completely.*
