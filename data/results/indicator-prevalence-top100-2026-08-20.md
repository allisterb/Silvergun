# Benign corpus - indicator prevalence (2026-08-20)

**A measurement, not a gate.** These are ordinary, widely-used NuGet packages; their label is
"overwhelmingly not malware" by download count, not by audit (ADR-0021: benign by assumption is not
benign by proof). The question answered here is *precision*: which `IndicatorCategory` values are so
common in benign code that they carry no gating signal on their own. Nothing in `--strict`, the
`IndicatorAnalysis` classifier, or any threshold was changed to produce these numbers - the gating
decision (if any) is a separate ADR, written from this data.

| Parameter | Value |
| --- | --- |
| Manifest | `benign-top.manifest` |
| Manifest hash (sha256 of normalized `id,version` list) | `9e5635c320485af7b86e5656860465e4c1bc5ba753e7771336e7d677ac8838a6` |
| Packages in manifest (after `--take`) | 100 |
| Packages contributing to prevalence | 78 |
| Assemblies scanned | 81 |
| Methods analysed | 148990 |
| Methods skipped | 0 |
| Total indicator findings (raw occurrences) | 3610 |
| Distinct-indicator cap (10,000/assembly) hit anywhere | no |
| Cache root (outside the repo; no `.nupkg` is ever written into it) | `%LOCALAPPDATA%\Silvergun\benign-corpus` |
| Classified indicator findings | `indicator-prevalence-2026-08-20.tsv` |

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

Share = packages with at least one finding of that category, out of the 78 that
contributed data. A category with a high share cannot gate anything on its own.

| Category | Packages with >=1 | Share of corpus | Total findings | Distinct values | Median/pkg | p90/pkg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ReflectionTypeName | 60 | 76.9% | 3161 | 1037 | 2.0 | 115 |
| GenericUrl | 19 | 24.4% | 378 | 43 | 0.0 | 6 |
| PrivateIpLiteral | 7 | 9.0% | 18 | 7 | 0.0 | 0 |
| PublicIpLiteral | 7 | 9.0% | 53 | 21 | 0.0 | 0 |
| AutorunRegistry | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| CallbackDomain | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| CredentialPath | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| DynamicDns | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| ExfilSink | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| RawCodeHost | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| **(any indicator)** | **60** | **76.9%** | **3610** | **1108** | **4.5** | **131** |

## Top 10 most widespread distinct values, per category

Ranked by number of DISTINCT counted packages carrying the value (not raw occurrences); ties broken by
total occurrences, then the value itself. This is the table that makes the shares above interpretable -
without it a high share is just a number.

| Category | Value | Packages | Total occurrences |
| --- | --- | ---: | ---: |
| GenericUrl | aka.ms | 6 | 108 |
| GenericUrl | www.w3.org | 5 | 76 |
| GenericUrl | opentelemetry.io | 4 | 4 |
| GenericUrl | login.microsoftonline.com | 3 | 9 |
| GenericUrl | localhost | 3 | 7 |
| GenericUrl | learn.microsoft.com | 2 | 7 |
| GenericUrl | storage.azure.com | 2 | 4 |
| GenericUrl | login.chinacloudapi.cn | 2 | 3 |
| GenericUrl | login.microsoftonline.de | 2 | 3 |
| GenericUrl | login.microsoftonline.us | 2 | 3 |
| PrivateIpLiteral | 127.0.0.1 | 4 | 6 |
| PrivateIpLiteral | 169.254.169.254 | 4 | 6 |
| PrivateIpLiteral | 169.254.170.2 | 1 | 2 |
| PrivateIpLiteral | 0.0.0.0 | 1 | 1 |
| PrivateIpLiteral | 169.254.170.23 | 1 | 1 |
| PrivateIpLiteral | fd00:ec2::23 | 1 | 1 |
| PrivateIpLiteral | fd00:ec2::254 | 1 | 1 |
| PublicIpLiteral | 1.0.0.0 | 2 | 4 |
| PublicIpLiteral | 2.5.29.14 | 2 | 4 |
| PublicIpLiteral | 2.5.29.15 | 2 | 4 |
| PublicIpLiteral | 2.5.29.17 | 2 | 3 |
| PublicIpLiteral | 2.5.29.19 | 2 | 3 |
| PublicIpLiteral | 2.5.29.20 | 2 | 3 |
| PublicIpLiteral | 2.5.29.35 | 2 | 3 |
| PublicIpLiteral | 2.5.4.10 | 2 | 3 |
| PublicIpLiteral | 2.5.4.11 | 2 | 3 |
| PublicIpLiteral | 2.5.4.3 | 2 | 3 |
| ReflectionTypeName | System.Resources.UseSystemResourceKeys | 19 | 19 |
| ReflectionTypeName | DateTimeKind.Utc | 5 | 7 |
| ReflectionTypeName | IEnumerable.Reset | 5 | 5 |
| ReflectionTypeName | System.ValueTuple | 4 | 12 |
| ReflectionTypeName | DateTime.SpecifyKind | 4 | 6 |
| ReflectionTypeName | Azure.Core.AzureResourceProviderNamespaceAttribute | 4 | 4 |
| ReflectionTypeName | Azure.Experimental.EnableActivitySource | 4 | 4 |
| ReflectionTypeName | System.Byte | 3 | 6 |
| ReflectionTypeName | Mono.Runtime | 3 | 4 |
| ReflectionTypeName | System.Object | 3 | 3 |

## Per package

| Package | Version | TFM | Status | Assemblies | Indicator findings | Truncated | Cap-hit |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| AWSSDK.Core | 4.0.101.1 | net8.0 | scanned | 1 | 127 | no | yes |
| AWSSDK.S3 | 4.0.102.2 | net8.0 | scanned | 1 | 391 | no | yes |
| AutoMapper | 16.2.0 | net10.0 | scanned | 1 | 11 | no | yes |
| Azure.Core | 1.61.0 | net10.0 | scanned | 1 | 133 | no | yes |
| Azure.Identity | 1.21.0 | net10.0 | scanned | 1 | 0 | no | no |
| Azure.Security.KeyVault.Secrets | 4.11.0 | net10.0 | scanned | 1 | 31 | no | yes |
| Azure.Storage.Blobs | 12.29.1 | net10.0 | scanned | 1 | 134 | no | yes |
| Azure.Storage.Common | 12.28.0 | net10.0 | scanned | 1 | 10 | no | yes |
| Castle.Core | 5.2.1 | net6.0 | scanned | 1 | 47 | no | yes |
| CsvHelper | 33.1.0 | net9.0 | scanned | 1 | 7 | no | yes |
| Dapper | 2.1.79 | net10.0 | scanned | 1 | 12 | no | yes |
| FluentAssertions | 8.10.0 | net6.0 | scanned | 1 | 22 | no | yes |
| FluentValidation | 12.1.1 | net8.0 | scanned | 1 | 2 | no | yes |
| Google.Protobuf | 3.35.1 | net5.0 | scanned | 1 | 5 | no | yes |
| Grpc.Core.Api | 2.83.0 | netstandard2.0 | scanned | 1 | 0 | no | yes |
| Grpc.Net.Client | 2.83.0 | net10.0 | scanned | 1 | 33 | no | yes |
| Grpc.Net.Common | 2.83.0 | net10.0 | scanned | 1 | 0 | no | no |
| Humanizer.Core | 3.0.10 | net10.0 | scanned | 1 | 2 | no | yes |
| Microsoft.ApplicationInsights | 3.1.2 | net10.0 | scanned | 1 | 8 | no | yes |
| Microsoft.AspNetCore.Mvc.NewtonsoftJson | 10.0.11 | net10.0 | scanned | 1 | 0 | no | yes |
| Microsoft.Azure.Amqp | 2.7.4 | net8.0 | scanned | 1 | 6 | no | yes |
| Microsoft.Azure.WebJobs | 3.0.47 | netstandard2.0 | scanned | 1 | 26 | no | yes |
| Microsoft.Bcl.AsyncInterfaces | 10.0.11 | netstandard2.0 | scanned | 1 | 0 | no | no |
| Microsoft.Data.SqlClient | 7.0.2 | net9.0 | scanned | 1 | 1150 | no | no |
| Microsoft.Data.SqlClient.SNI.runtime | 6.0.3 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.EntityFrameworkCore | 10.0.11 | net10.0 | scanned | 1 | 131 | no | yes |
| Microsoft.Extensions.ApiDescription.Server | 10.0.11 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.Extensions.DependencyInjection | 10.0.11 | net10.0 | scanned | 1 | 5 | no | yes |
| Microsoft.Extensions.Diagnostics | 10.0.11 | net10.0 | scanned | 1 | 1 | no | yes |
| Microsoft.Extensions.Diagnostics.Abstractions | 10.0.11 | net10.0 | scanned | 1 | 1 | no | yes |
| Microsoft.Extensions.Diagnostics.HealthChecks | 10.0.11 | net10.0 | scanned | 1 | 0 | no | no |
| Microsoft.Extensions.Diagnostics.HealthChecks.Abstractions | 10.0.11 | net10.0 | scanned | 1 | 0 | no | no |
| Microsoft.Extensions.Hosting | 10.0.11 | net10.0 | scanned | 1 | 4 | no | yes |
| Microsoft.Extensions.Http | 10.0.11 | net10.0 | scanned | 1 | 5 | no | yes |
| Microsoft.Extensions.Logging | 10.0.11 | net10.0 | scanned | 1 | 2 | no | yes |
| Microsoft.Extensions.Logging.EventLog | 10.0.11 | net10.0 | scanned | 1 | 0 | no | no |
| Microsoft.Identity.Client | 4.87.0 | net8.0 | scanned | 1 | 224 | no | yes |
| Microsoft.Identity.Client.Extensions.Msal | 4.87.0 | net8.0 | scanned | 1 | 6 | no | yes |
| Microsoft.IdentityModel.Abstractions | 8.22.0 | net10.0 | scanned | 1 | 0 | no | no |
| Microsoft.IdentityModel.Clients.ActiveDirectory | 5.3.0 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Sdk.Android.Manifest-8.0.100 | 34.0.154 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Sdk.Aspire.Manifest-8.0.100 | 8.2.2 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Sdk.MacCatalyst.Manifest-8.0.100 | 18.0.8319 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Sdk.Maui.Manifest-8.0.100 | 8.0.100 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Sdk.iOS.Manifest-8.0.100 | 18.0.8319 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Sdk.macOS.Manifest-8.0.100 | 15.0.8319 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Sdk.tvOS.Manifest-8.0.100 | 18.0.8319 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Workload.Emscripten.Current.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Workload.Emscripten.net6.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Workload.Emscripten.net7.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Workload.Mono.ToolChain.Current.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Workload.Mono.ToolChain.net6.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.NET.Workload.Mono.ToolChain.net7.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.OpenApi | 3.10.0 | net8.0 | scanned | 1 | 9 | no | yes |
| Microsoft.SqlServer.Server | 1.0.0 | netstandard2.0 | scanned | 1 | 2 | no | yes |
| Microsoft.Win32.SystemEvents | 10.0.11 | net10.0 | scanned | 1 | 1 | no | yes |
| Moq | 4.20.72 | net6.0 | scanned | 1 | 9 | no | yes |
| NLog | 6.2.0 | netstandard2.0 | scanned | 1 | 167 | no | yes |
| NUnit | 4.6.1 | net8.0 | scanned | 2 | 322 | no | yes |
| Newtonsoft.Json | 13.0.4 | net6.0 | scanned | 1 | 119 | no | yes |
| Newtonsoft.Json.Bson | 1.0.3 | netstandard2.0 | scanned | 1 | 1 | no | yes |
| Npgsql | 10.0.3 | net10.0 | scanned | 1 | 48 | no | yes |
| OpenTelemetry | 1.17.0 | net10.0 | scanned | 1 | 38 | no | yes |
| OpenTelemetry.Api | 1.17.0 | net10.0 | scanned | 1 | 1 | no | yes |
| OpenTelemetry.Api.ProviderBuilderExtensions | 1.17.0 | net10.0 | scanned | 1 | 0 | no | no |
| Pipelines.Sockets.Unofficial | 2.3.1 | net10.0 | scanned | 1 | 5 | no | yes |
| Polly | 8.7.0 | net6.0 | scanned | 1 | 2 | no | yes |
| Polly.Core | 8.7.0 | net8.0 | scanned | 1 | 8 | no | yes |
| Serilog | 4.4.0 | net10.0 | scanned | 1 | 2 | no | yes |
| Serilog.AspNetCore | 10.0.0 | net10.0 | scanned | 1 | 0 | no | no |
| Serilog.Extensions.Hosting | 10.0.0 | net10.0 | scanned | 1 | 0 | no | no |
| Serilog.Extensions.Logging | 10.0.0 | net10.0 | scanned | 1 | 0 | no | no |
| Serilog.Formatting.Compact | 3.0.0 | net8.0 | scanned | 1 | 0 | no | no |
| Serilog.Settings.Configuration | 10.0.1 | net10.0 | scanned | 1 | 17 | no | yes |
| Serilog.Sinks.Console | 6.1.1 | net8.0 | scanned | 1 | 0 | no | yes |
| Serilog.Sinks.Debug | 3.0.0 | net8.0 | scanned | 1 | 0 | no | no |
| Serilog.Sinks.File | 7.0.0 | net9.0 | scanned | 1 | 0 | no | yes |
| StackExchange.Redis | 3.1.13 | net10.0 | scanned | 1 | 38 | no | yes |
| Swashbuckle.AspNetCore | 10.2.3 | - | no-scannable-tfm | 0 | 0 | no | no |
| Swashbuckle.AspNetCore.Swagger | 10.2.3 | net10.0 | scanned | 1 | 0 | no | yes |
| Swashbuckle.AspNetCore.SwaggerGen | 10.2.3 | net10.0 | scanned | 1 | 3 | no | yes |
| Swashbuckle.AspNetCore.SwaggerUI | 10.2.3 | net10.0 | scanned | 1 | 2 | no | yes |
| System.ClientModel | 1.15.0 | net10.0 | scanned | 1 | 8 | no | yes |
| System.CodeDom | 10.0.11 | net10.0 | scanned | 1 | 21 | no | yes |
| System.Diagnostics.EventLog | 10.0.11 | net10.0 | scanned | 1 | 1 | no | yes |
| System.Diagnostics.PerformanceCounter | 10.0.11 | net10.0 | scanned | 1 | 1 | no | yes |
| System.Drawing.Common | 10.0.11 | net10.0 | scanned | 3 | 121 | no | yes |
| System.Formats.Asn1 | 10.0.11 | net10.0 | scanned | 1 | 29 | no | yes |
| System.IO.Hashing | 10.0.11 | net10.0 | scanned | 1 | 1 | no | yes |
| System.Memory.Data | 10.0.11 | net10.0 | scanned | 1 | 1 | no | yes |
| System.Runtime.Caching | 10.0.11 | net10.0 | scanned | 1 | 2 | no | yes |
| System.Security.Cryptography.Pkcs | 10.0.11 | net10.0 | scanned | 1 | 17 | no | yes |
| System.Text.Json | 10.0.11 | net10.0 | scanned | 1 | 76 | no | yes |
| System.Threading.Channels | 10.0.11 | net10.0 | scanned | 1 | 1 | no | no |
| System.Windows.Extensions | 10.0.11 | net10.0 | scanned | 1 | 1 | no | yes |
| coverlet.collector | 10.0.1 | - | no-scannable-tfm | 0 | 0 | no | no |
| runtime.win-arm64.runtime.native.System.Data.SqlClient.sni | 4.4.0 | - | no-scannable-tfm | 0 | 0 | no | no |
| runtime.win-x64.runtime.native.System.Data.SqlClient.sni | 4.4.0 | - | no-scannable-tfm | 0 | 0 | no | no |
| runtime.win-x86.runtime.native.System.Data.SqlClient.sni | 4.4.0 | - | no-scannable-tfm | 0 | 0 | no | no |
| xunit | 2.9.3 | - | no-scannable-tfm | 0 | 0 | no | no |

## CallbackDomain / ExfilSink / DynamicDns - every hit, individually

A benign package tripping one of these three categories is either a false positive in our domain list
or a genuinely interesting package; either way it must be visible by name, not buried in a count.

*None: no package in the corpus produced a CallbackDomain, ExfilSink, or DynamicDns finding.*

## Truncation

*None: the 10,000-distinct-indicator-per-assembly cap was not reached by any assembly in the corpus - every number above is a total, not a floor.*

## Coverage honesty (ADR-0024)

78 of 100 manifest entries were scanned completely.
Everything below is a package whose numbers above are a **floor, not a total** - or that produced no
numbers at all. A corpus statistic computed over partially-analysed input is a lie unless the
partiality is stated alongside it.

| Package | Version | Status | Counted in prevalence | Reason |
| --- | --- | --- | --- | --- |
| Microsoft.Data.SqlClient.SNI.runtime | 6.0.3 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.Extensions.ApiDescription.Server | 10.0.11 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.IdentityModel.Clients.ActiveDirectory | 5.3.0 | no-scannable-tfm | **no** | lib TFMs on offer: monoandroid81, net45, netstandard1.3, uap10.0.17763, xamarinios10 |
| Microsoft.NET.Sdk.Android.Manifest-8.0.100 | 34.0.154 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Sdk.Aspire.Manifest-8.0.100 | 8.2.2 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Sdk.MacCatalyst.Manifest-8.0.100 | 18.0.8319 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Sdk.Maui.Manifest-8.0.100 | 8.0.100 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Sdk.iOS.Manifest-8.0.100 | 18.0.8319 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Sdk.macOS.Manifest-8.0.100 | 15.0.8319 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Sdk.tvOS.Manifest-8.0.100 | 18.0.8319 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Workload.Emscripten.Current.Manifest-8.0.100 | 8.0.30 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Workload.Emscripten.net6.Manifest-8.0.100 | 8.0.30 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Workload.Emscripten.net7.Manifest-8.0.100 | 8.0.30 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Workload.Mono.ToolChain.Current.Manifest-8.0.100 | 8.0.30 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Workload.Mono.ToolChain.net6.Manifest-8.0.100 | 8.0.30 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.NET.Workload.Mono.ToolChain.net7.Manifest-8.0.100 | 8.0.30 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Swashbuckle.AspNetCore | 10.2.3 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| coverlet.collector | 10.0.1 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| runtime.win-arm64.runtime.native.System.Data.SqlClient.sni | 4.4.0 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| runtime.win-x64.runtime.native.System.Data.SqlClient.sni | 4.4.0 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| runtime.win-x86.runtime.native.System.Data.SqlClient.sni | 4.4.0 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| xunit | 2.9.3 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
