# Benign corpus - indicator prevalence (2026-08-20)

**A measurement, not a gate.** These are ordinary, widely-used NuGet packages; their label is
"overwhelmingly not malware" by download count, not by audit (ADR-0021: benign by assumption is not
benign by proof). The question answered here is *precision*: which `IndicatorCategory` values are so
common in benign code that they carry no gating signal on their own. Nothing in `--strict`, the
`IndicatorAnalysis` classifier, or any threshold was changed to produce these numbers - the gating
decision (if any) is a separate ADR, written from this data.

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
| Total indicator findings (raw occurrences) | 758 |
| Distinct-indicator cap (10,000/assembly) hit anywhere | no |
| Cache root (outside the repo; no `.nupkg` is ever written into it) | `%LOCALAPPDATA%\Silvergun\benign-corpus` |
| Classified indicator findings | `indicator-prevalence-2026-08-20.tsv` |

## Regression oracle (checked first, per the task spec)

Before this re-run, the capability half of the harness was run unmodified into a scratch directory and
diffed byte-for-byte (after normalising the embedded run date) against
`data/results/benign-corpus-2026-07-31.md` / `.tsv`: **identical**. Manifest hash, 25/25
packages contributing, 26 assemblies, 51035 methods analysed, 0 skipped, 1706 total capability
findings, and the 24/25 = 96.0% "(any capability)" row all reproduced exactly. The two false-positive
fixes to `IndicatorAnalysis.cs` made between the two measurement runs did not move the capability
numbers at all, as expected - they only touch the IP-literal branch of a classifier the capability
scan does not call.

The indicator half of the harness was then run **twice more**, into a scratch output directory, with
the fixed `IndicatorAnalysis.cs` wired into the same child scan as the capability scan: the two runs'
capability and indicator `.md`/`.tsv` outputs were byte-identical pairwise (diff produced no output).

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

## Indicator prevalence - the calibration answer

Share = packages with at least one finding of that category, out of the 25 that
contributed data. A category with a high share cannot gate anything on its own.

| Category | Packages with >=1 | Share of corpus | Total findings | Distinct values | Median/pkg | p90/pkg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ReflectionTypeName | 23 | 92.0% | 686 | 327 | 5.0 | 81 |
| GenericUrl | 7 | 28.0% | 68 | 8 | 0.0 | 8 |
| PrivateIpLiteral | 1 | 4.0% | 4 | 3 | 0.0 | 0 |
| AutorunRegistry | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| CallbackDomain | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| CredentialPath | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| DynamicDns | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| ExfilSink | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| PublicIpLiteral | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| RawCodeHost | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| **(any indicator)** | **23** | **92.0%** | **758** | **338** | **5.0** | **101** |

## DELTA vs `indicator-prevalence-2026-08-03.md` (pre-fix)

This is a re-run of the same 25-package corpus after two named false-positive fixes landed in
`IndicatorAnalysis.cs` between the two measurements:

1. **`IsPartOfLongerDottedRun`** - a dotted-quad match that sits inside a longer dotted-decimal run
   (digit-dot on either side) is no longer sliced out and reported as an IP literal. Targets
   cryptographic OIDs.
2. **`HasHexGroup` + unspecified-address handling** - a colon-only match with no hex digit (e.g. a
   bare `::` matched out of a regex/format-string source literal) is no longer reported as a finding
   at all; `0.0.0.0` and `::` are now classified `PrivateIpLiteral` (non-routable/unspecified) instead
   of `PublicIpLiteral`.

Every number below was independently re-derived from the raw TSVs with `awk` (not hand-summed) to
avoid the exact failure mode a prior measurement in this project hit (bucket sum 477 vs measured 480,
three real rows missing).

### Category-level delta

| Category | Old share | New share | Old total findings | New total findings | Old distinct values | New distinct values | Attribution |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| PublicIpLiteral | 16.0% (4/25) | **0.0% (0/25)** | 11 | **0** | 4 | **0** | -11: 3x bare `::` (FluentValidation, NLog, Serilog - all regex/format-string source literals) rejected outright by fix 2; 4x `1.3.6.1` + 2x `4.1.188.7` (MimeKit, sliced out of the S/MIME OIDs `1.3.6.1.4.1.188.7.1.1.2` and `1.3.6.1.4.1.3029.1.2`) rejected outright by fix 1; 2x `0.0.0.0` (NLog) **reclassified** to PrivateIpLiteral by fix 2, not removed. |
| PrivateIpLiteral | 4.0% (1/25) | 4.0% (1/25) | 2 | **4** | 2 | **3** | +2, +1 distinct value: the reclassified `0.0.0.0` (NLog, `AssemblyVersionLayoutRenderer.ApplyFormatToVersion` and `LocalIpAddressLayoutRenderer.IsLoopbackAddressValue`) moved in from PublicIpLiteral. Share unchanged because it was already the same one package (NLog) carrying `127.0.0.1`/`::1`. |
| ReflectionTypeName | 92.0% (23/25) | 92.0% (23/25) | 686 | 686 | 327 | 327 | unchanged - neither fix touches this classifier. |
| GenericUrl | 28.0% (7/25) | 28.0% (7/25) | 68 | 68 | 8 | 8 | unchanged. |
| AutorunRegistry / CallbackDomain / CredentialPath / DynamicDns / ExfilSink / RawCodeHost | 0.0% | 0.0% | 0 | 0 | 0 | 0 | unchanged. |
| **(any indicator)** | **92.0% (23/25)** | **92.0% (23/25)** | **767** | **758** | **341** | **338** | -9 findings = the 9 occurrences that vanished outright (3x `::` + 4x `1.3.6.1` + 2x `4.1.188.7`); the 2x `0.0.0.0` occurrences only changed category, so they do not move this total. -3 distinct values = the 3 distinct strings (`::`, `1.3.6.1`, `4.1.188.7`) that vanished outright; `0.0.0.0` is still one distinct value corpus-wide, just counted under a different category now. |

Package-with->=1 count for `(any indicator)` is unchanged at 23/25: every package that lost a
PublicIpLiteral finding (FluentValidation, NLog, Serilog, MimeKit) still has other indicator findings
(ReflectionTypeName and/or GenericUrl), so none of them dropped out of the "any indicator" set.

### Package-level delta (only the four packages that moved; the other 21 are byte-identical)

| Package | Old indicator findings | New indicator findings | Delta | Cause |
| --- | ---: | ---: | ---: | --- |
| Serilog | 2 | 1 | -1 | `::` matched out of the regex literal `^(?<shortTypeName>[^:]+)::(?<memberName>...)` in `SettingValueConversions..cctor` - no longer a finding (fix 2). |
| NLog | 102 | 101 | -1 | `::` matched out of `LocalIpAddressLayoutRenderer.IsLoopbackAddressValue` - no longer a finding (fix 2). The package's 2x `0.0.0.0` are still counted (now PrivateIpLiteral instead of PublicIpLiteral), so NLog's total only drops by the one `::` occurrence. |
| FluentValidation | 3 | 2 | -1 | `::` matched out of the format-string literal `{([^{}:]+)(?::([^{}]+))?}` in `MessageFormatter..cctor` - no longer a finding (fix 2). |
| MimeKit | 26 | 20 | -6 | `1.3.6.1`x4 + `4.1.188.7`x2 sliced out of the S/MIME OIDs `1.3.6.1.4.1.188.7.1.1.2` (x3 call sites) and `1.3.6.1.4.1.3029.1.2` (x1, contributing 2 occurrences via its `.cctor`) in `BouncyCastleSecureMimeContext`/`SecureMimeContext` - no longer sliced at all (fix 1). |
| all other 21 packages | - | - | 0 | byte-identical row-for-row; unaffected by either fix. |

Sum of the four deltas: -1 -1 -1 -6 = **-9**, exactly matching the corpus-wide total findings delta
(767 -> 758). **Every non-zero delta at both the category level and the package level is attributed to
one of the two named fixes; nothing here is unattributed.**

### What `PublicIpLiteral` is now, and whether any genuine IP literal remains

`PublicIpLiteral` is now **0 packages, 0 findings, 0 distinct values** across the entire 25-package
corpus - not "reduced", *empty*. Cross-checking against the raw pre-fix TSV: **all four** of the
previously-reported `PublicIpLiteral` packages (FluentValidation, MimeKit, NLog, Serilog) owed their
finding entirely to one of the two named mechanisms (regex/format-string `::`, or an OID digit-run).
**There was no genuine routable public IP literal in this corpus before the fix either** - the prior
report's own caveat ("at most one genuine IP literal... re-measure after the fix") turns out to have
been optimistic: the true count was zero, not one. The only IP-shaped literals remaining anywhere in
the corpus are the three PrivateIpLiteral values in NLog (`0.0.0.0`, `127.0.0.1`, `::1`), all from
loopback/unspecified-address detection code, none genuinely identifying a remote host.

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
| PrivateIpLiteral | 0.0.0.0 | 1 | 2 |
| PrivateIpLiteral | 127.0.0.1 | 1 | 1 |
| PrivateIpLiteral | ::1 | 1 | 1 |
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
| Serilog | 4.2.0 | net9.0 | scanned | 1 | 1 | no | yes |
| NLog | 5.3.4 | netstandard2.0 | scanned | 1 | 101 | no | yes |
| AutoMapper | 13.0.1 | net6.0 | scanned | 1 | 4 | no | yes |
| FluentValidation | 11.11.0 | net8.0 | scanned | 1 | 2 | no | yes |
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
| MimeKit | 4.8.0 | net8.0 | scanned | 1 | 20 | no | yes |
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
