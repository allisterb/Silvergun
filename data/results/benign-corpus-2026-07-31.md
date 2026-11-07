# Benign corpus - capability density (2026-07-31)

**A measurement, not a gate.** These are ordinary, widely-used NuGet packages; their label is
"overwhelmingly not malware" by download count, not by audit (ADR-0021: benign by assumption is not
benign by proof). The question answered here is *precision*: which capabilities are so common in benign
code that they cannot gate anything. Nothing in `--strict`, the `Catalog`, `capabilities.cm` or any
scoring was changed to produce these numbers.

| Parameter | Value |
| --- | --- |
| Manifest | `benign-corpus.manifest` |
| Manifest hash (sha256 of normalized `id,version` list) | `03034edd2f8f62abf50b938ff8e0543c60cdcfb6f9e214c98cbc9203b12ce75b` |
| Packages in manifest (after `--take`) | 25 |
| Packages contributing to density | 25 |
| Assemblies scanned | 26 |
| Methods analysed | 51035 |
| Methods skipped | 0 |
| Total findings | 1706 |
| Cache root (outside the repo; no `.nupkg` is ever written into it) | `%LOCALAPPDATA%\Silvergun\benign-corpus` |
| Classified findings | `benign-corpus-2026-07-31.tsv` |

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

## Capability density - the calibration answer

Share = packages with at least one finding of that capability, out of the 25 that
contributed data. A capability with a high share cannot gate anything on its own.

| Capability | Packages with >=1 | Share of corpus | Total findings | Median/pkg | p90/pkg |
| --- | ---: | ---: | ---: | ---: | ---: |
| DynamicCodeLoading | 20 | 80.0% | 482 | 5.0 | 47 |
| ReflectionInvocation | 18 | 72.0% | 206 | 3.0 | 30 |
| EnvironmentProbe | 15 | 60.0% | 156 | 1.0 | 19 |
| RuntimeControl | 10 | 40.0% | 69 | 0.0 | 8 |
| FileSystem | 9 | 36.0% | 296 | 0.0 | 54 |
| UnsafeMemory | 6 | 24.0% | 47 | 0.0 | 5 |
| Cryptography | 5 | 20.0% | 218 | 0.0 | 13 |
| Network | 5 | 20.0% | 209 | 0.0 | 22 |
| NativeInterop | 3 | 12.0% | 12 | 0.0 | 4 |
| ProcessExecution | 2 | 8.0% | 7 | 0.0 | 0 |
| Registry | 1 | 4.0% | 4 | 0.0 | 0 |
| **(any capability - what `--strict` gates on today)** | **24** | **96.0%** | **1706** | **33.0** | **198** |

## Per package

| Package | Version | TFM | Status | Assemblies | Methods analysed | Methods skipped | Findings |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| Newtonsoft.Json | 13.0.3 | net6.0 | scanned | 1 | 4087 | 0 | 78 |
| Serilog | 4.2.0 | net9.0 | scanned | 1 | 1056 | 0 | 15 |
| NLog | 5.3.4 | netstandard2.0 | scanned | 1 | 6245 | 0 | 325 |
| AutoMapper | 13.0.1 | net6.0 | scanned | 1 | 2047 | 0 | 33 |
| FluentValidation | 11.11.0 | net8.0 | scanned | 1 | 1291 | 0 | 3 |
| Polly | 8.5.0 | net6.0 | scanned | 1 | 2164 | 0 | 2 |
| Dapper | 2.1.35 | net7.0 | scanned | 1 | 1080 | 0 | 56 |
| CsvHelper | 33.0.1 | net8.0 | scanned | 1 | 1385 | 0 | 15 |
| HtmlAgilityPack | 1.11.71 | netstandard2.0 | scanned | 1 | 820 | 0 | 50 |
| RestSharp | 112.1.0 | net8.0 | scanned | 1 | 1577 | 0 | 47 |
| MediatR | 12.4.1 | net6.0 | scanned | 1 | 369 | 0 | 8 |
| Humanizer.Core | 2.14.1 | net6.0 | scanned | 1 | 2189 | 0 | 10 |
| Castle.Core | 5.1.1 | net6.0 | scanned | 1 | 3312 | 0 | 198 |
| Moq | 4.20.72 | net6.0 | scanned | 1 | 1670 | 0 | 64 |
| NUnit | 4.2.2 | net6.0 | scanned | 2 | 4173 | 0 | 104 |
| System.Text.Json | 9.0.0 | net9.0 | scanned | 1 | 3787 | 0 | 79 |
| Microsoft.Extensions.Logging.Abstractions | 9.0.0 | net9.0 | scanned | 1 | 385 | 0 | 6 |
| Microsoft.Extensions.DependencyInjection | 9.0.0 | net9.0 | scanned | 1 | 413 | 0 | 28 |
| Microsoft.Extensions.Configuration | 9.0.0 | net9.0 | scanned | 1 | 216 | 0 | 5 |
| Microsoft.Bcl.AsyncInterfaces | 9.0.0 | netstandard2.0 | scanned | 1 | 77 | 0 | 0 |
| protobuf-net | 3.2.30 | net6.0 | scanned | 1 | 1426 | 0 | 125 |
| YamlDotNet | 16.2.1 | net8.0 | scanned | 1 | 2125 | 0 | 23 |
| SharpZipLib | 1.4.2 | net6.0 | scanned | 1 | 1555 | 0 | 127 |
| MimeKit | 4.8.0 | net8.0 | scanned | 1 | 4322 | 0 | 277 |
| Spectre.Console | 0.49.1 | net8.0 | scanned | 1 | 3264 | 0 | 28 |

## Findings by capability, per package

Columns are the first four letters of each capability: `Cryp` = Cryptography, `Dyna` = DynamicCodeLoading, `Envi` = EnvironmentProbe, `File` = FileSystem, `Nati` = NativeInterop, `Netw` = Network, `Proc` = ProcessExecution, `Refl` = ReflectionInvocation, `Regi` = Registry, `Runt` = RuntimeControl, `Unsa` = UnsafeMemory.

| Package | Cryp | Dyna | Envi | File | Nati | Netw | Proc | Refl | Regi | Runt | Unsa |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Newtonsoft.Json | 0 | 35 | 6 | 0 | 0 | 0 | 0 | 30 | 0 | 7 | 0 |
| Serilog | 0 | 5 | 2 | 0 | 0 | 0 | 0 | 7 | 0 | 0 | 1 |
| NLog | 2 | 28 | 36 | 96 | 0 | 119 | 5 | 15 | 0 | 24 | 0 |
| AutoMapper | 0 | 28 | 0 | 0 | 0 | 0 | 0 | 5 | 0 | 0 | 0 |
| FluentValidation | 0 | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Polly | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| Dapper | 0 | 47 | 0 | 0 | 0 | 0 | 0 | 7 | 0 | 2 | 0 |
| CsvHelper | 0 | 8 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| HtmlAgilityPack | 0 | 2 | 2 | 23 | 0 | 22 | 0 | 1 | 0 | 0 | 0 |
| RestSharp | 13 | 3 | 0 | 4 | 0 | 21 | 0 | 1 | 0 | 1 | 4 |
| MediatR | 0 | 6 | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| Humanizer.Core | 0 | 0 | 8 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| Castle.Core | 0 | 135 | 17 | 13 | 4 | 11 | 0 | 10 | 0 | 8 | 0 |
| Moq | 0 | 19 | 36 | 0 | 0 | 0 | 0 | 9 | 0 | 0 | 0 |
| NUnit | 1 | 2 | 19 | 17 | 4 | 0 | 2 | 48 | 4 | 7 | 0 |
| System.Text.Json | 0 | 37 | 1 | 0 | 0 | 0 | 0 | 15 | 0 | 0 | 26 |
| Microsoft.Extensions.Logging.Abstractions | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 6 |
| Microsoft.Extensions.DependencyInjection | 0 | 20 | 0 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 5 |
| Microsoft.Extensions.Configuration | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| Microsoft.Bcl.AsyncInterfaces | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| protobuf-net | 0 | 91 | 0 | 2 | 0 | 0 | 0 | 32 | 0 | 0 | 0 |
| YamlDotNet | 0 | 10 | 1 | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 |
| SharpZipLib | 38 | 1 | 2 | 84 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| MimeKit | 164 | 2 | 4 | 54 | 0 | 36 | 0 | 5 | 0 | 12 | 0 |
| Spectre.Console | 0 | 1 | 18 | 3 | 4 | 0 | 0 | 2 | 0 | 0 | 0 |

## Coverage honesty (ADR-0024)

25 of 25 manifest entries were scanned completely.
Everything below is a package whose numbers above are a **floor, not a total** - or that produced no
numbers at all. A corpus statistic computed over partially-analysed input is a lie unless the
partiality is stated alongside it.

*None: every manifest entry was scanned completely.*
