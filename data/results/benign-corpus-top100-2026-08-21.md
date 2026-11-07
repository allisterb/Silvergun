# Benign corpus (top-100 scale) - capability density (2026-08-21)

**A measurement, not a gate.** These are ordinary, widely-used NuGet packages; their label is
"overwhelmingly not malware" by download count, not by audit (ADR-0021: benign by assumption is not
benign by proof). The question answered here is *precision*: which capabilities are so common in benign
code that they cannot gate anything. Nothing in `--strict`, the `Catalog`, `capabilities.cm` or any
scoring was changed to produce these numbers.

| Parameter | Value |
| --- | --- |
| Manifest | `benign-top.manifest` |
| Manifest hash (sha256 of normalized `id,version` list) | `9e5635c320485af7b86e5656860465e4c1bc5ba753e7771336e7d677ac8838a6` |
| Packages in manifest (after `--take`) | 100 |
| Packages contributing to density | 78 |
| Assemblies scanned | 81 |
| Methods analysed | 148990 |
| Methods skipped | 0 |
| Total findings | 8193 |
| Cache root (outside the repo; no `.nupkg` is ever written into it) | `%LOCALAPPDATA%\Silvergun\benign-corpus` |
| Classified findings | `benign-corpus-top100-2026-08-21.tsv` |

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

Share = packages with at least one finding of that capability, out of the 78 that
contributed data. A capability with a high share cannot gate anything on its own.

| Capability | Packages with >=1 | Share of corpus | Total findings | Median/pkg | p90/pkg |
| --- | ---: | ---: | ---: | ---: | ---: |
| EnvironmentProbe | 42 | 53.8% | 391 | 1.0 | 17 |
| UnsafeMemory | 35 | 44.9% | 847 | 0.0 | 23 |
| DynamicCodeLoading | 32 | 41.0% | 1460 | 0.0 | 28 |
| ReflectionInvocation | 32 | 41.0% | 341 | 0.0 | 12 |
| RuntimeControl | 29 | 37.2% | 619 | 0.0 | 9 |
| FileSystem | 26 | 33.3% | 407 | 0.0 | 14 |
| Cryptography | 18 | 23.1% | 2336 | 0.0 | 20 |
| NativeInterop | 15 | 19.2% | 1247 | 0.0 | 5 |
| Network | 14 | 17.9% | 399 | 0.0 | 25 |
| ProcessExecution | 12 | 15.4% | 142 | 0.0 | 3 |
| Registry | 1 | 1.3% | 4 | 0.0 | 0 |
| **(any capability - what `--strict` gates on today)** | **63** | **80.8%** | **8193** | **15.0** | **198** |

## Per package

| Package | Version | TFM | Status | Assemblies | Methods analysed | Methods skipped | Findings |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| AWSSDK.Core | 4.0.101.1 | net8.0 | scanned | 1 | 5921 | 0 | 317 |
| AWSSDK.S3 | 4.0.102.2 | net8.0 | scanned | 1 | 10274 | 0 | 56 |
| AutoMapper | 16.2.0 | net10.0 | scanned | 1 | 2180 | 0 | 34 |
| Azure.Core | 1.61.0 | net10.0 | scanned | 1 | 4217 | 0 | 240 |
| Azure.Identity | 1.21.0 | net10.0 | scanned | 1 | 0 | 0 | 0 |
| Azure.Security.KeyVault.Secrets | 4.11.0 | net10.0 | scanned | 1 | 1046 | 0 | 3 |
| Azure.Storage.Blobs | 12.29.1 | net10.0 | scanned | 1 | 6187 | 0 | 67 |
| Azure.Storage.Common | 12.28.0 | net10.0 | scanned | 1 | 987 | 0 | 14 |
| Castle.Core | 5.2.1 | net6.0 | scanned | 1 | 3323 | 0 | 198 |
| CsvHelper | 33.1.0 | net9.0 | scanned | 1 | 1390 | 0 | 15 |
| Dapper | 2.1.79 | net10.0 | scanned | 1 | 1083 | 0 | 56 |
| FluentAssertions | 8.10.0 | net6.0 | scanned | 1 | 4676 | 0 | 59 |
| FluentValidation | 12.1.1 | net8.0 | scanned | 1 | 1312 | 0 | 3 |
| Google.Protobuf | 3.35.1 | net5.0 | scanned | 1 | 3745 | 0 | 51 |
| Grpc.Core.Api | 2.83.0 | netstandard2.0 | scanned | 1 | 424 | 0 | 3 |
| Grpc.Net.Client | 2.83.0 | net10.0 | scanned | 1 | 1442 | 0 | 46 |
| Grpc.Net.Common | 2.83.0 | net10.0 | scanned | 1 | 24 | 0 | 0 |
| Humanizer.Core | 3.0.10 | net10.0 | scanned | 1 | 2695 | 0 | 19 |
| Microsoft.ApplicationInsights | 3.1.2 | net10.0 | scanned | 1 | 567 | 0 | 31 |
| Microsoft.AspNetCore.Mvc.NewtonsoftJson | 10.0.11 | net10.0 | scanned | 1 | 179 | 0 | 9 |
| Microsoft.Azure.Amqp | 2.7.4 | net8.0 | scanned | 1 | 3424 | 0 | 154 |
| Microsoft.Azure.WebJobs | 3.0.47 | netstandard2.0 | scanned | 1 | 3279 | 0 | 91 |
| Microsoft.Bcl.AsyncInterfaces | 10.0.11 | netstandard2.0 | scanned | 1 | 91 | 0 | 0 |
| Microsoft.Data.SqlClient | 7.0.2 | net9.0 | scanned | 1 | 2725 | 0 | 0 |
| Microsoft.Data.SqlClient.SNI.runtime | 6.0.3 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.EntityFrameworkCore | 10.0.11 | net10.0 | scanned | 1 | 15662 | 0 | 99 |
| Microsoft.Extensions.ApiDescription.Server | 10.0.11 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.Extensions.DependencyInjection | 10.0.11 | net10.0 | scanned | 1 | 425 | 0 | 28 |
| Microsoft.Extensions.Diagnostics | 10.0.11 | net10.0 | scanned | 1 | 75 | 0 | 5 |
| Microsoft.Extensions.Diagnostics.Abstractions | 10.0.11 | net10.0 | scanned | 1 | 71 | 0 | 5 |
| Microsoft.Extensions.Diagnostics.HealthChecks | 10.0.11 | net10.0 | scanned | 1 | 141 | 0 | 0 |
| Microsoft.Extensions.Diagnostics.HealthChecks.Abstractions | 10.0.11 | net10.0 | scanned | 1 | 48 | 0 | 0 |
| Microsoft.Extensions.Hosting | 10.0.11 | net10.0 | scanned | 1 | 301 | 0 | 9 |
| Microsoft.Extensions.Http | 10.0.11 | net10.0 | scanned | 1 | 414 | 0 | 35 |
| Microsoft.Extensions.Logging | 10.0.11 | net10.0 | scanned | 1 | 227 | 0 | 5 |
| Microsoft.Extensions.Logging.EventLog | 10.0.11 | net10.0 | scanned | 1 | 51 | 0 | 0 |
| Microsoft.Identity.Client | 4.87.0 | net8.0 | scanned | 1 | 5244 | 0 | 305 |
| Microsoft.Identity.Client.Extensions.Msal | 4.87.0 | net8.0 | scanned | 1 | 150 | 0 | 91 |
| Microsoft.IdentityModel.Abstractions | 8.22.0 | net10.0 | scanned | 1 | 34 | 0 | 0 |
| Microsoft.IdentityModel.Clients.ActiveDirectory | 5.3.0 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Sdk.Android.Manifest-8.0.100 | 34.0.154 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Sdk.Aspire.Manifest-8.0.100 | 8.2.2 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Sdk.MacCatalyst.Manifest-8.0.100 | 18.0.8319 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Sdk.Maui.Manifest-8.0.100 | 8.0.100 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Sdk.iOS.Manifest-8.0.100 | 18.0.8319 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Sdk.macOS.Manifest-8.0.100 | 15.0.8319 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Sdk.tvOS.Manifest-8.0.100 | 18.0.8319 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Workload.Emscripten.Current.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Workload.Emscripten.net6.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Workload.Emscripten.net7.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Workload.Mono.ToolChain.Current.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Workload.Mono.ToolChain.net6.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.NET.Workload.Mono.ToolChain.net7.Manifest-8.0.100 | 8.0.30 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Microsoft.OpenApi | 3.10.0 | net8.0 | scanned | 1 | 4196 | 0 | 19 |
| Microsoft.SqlServer.Server | 1.0.0 | netstandard2.0 | scanned | 1 | 84 | 0 | 1 |
| Microsoft.Win32.SystemEvents | 10.0.11 | net10.0 | scanned | 1 | 69 | 0 | 5 |
| Moq | 4.20.72 | net6.0 | scanned | 1 | 1670 | 0 | 64 |
| NLog | 6.2.0 | netstandard2.0 | scanned | 1 | 5489 | 0 | 186 |
| NUnit | 4.6.1 | net8.0 | scanned | 2 | 5357 | 0 | 117 |
| Newtonsoft.Json | 13.0.4 | net6.0 | scanned | 1 | 4107 | 0 | 78 |
| Newtonsoft.Json.Bson | 1.0.3 | netstandard2.0 | scanned | 1 | 412 | 0 | 2 |
| Npgsql | 10.0.3 | net10.0 | scanned | 1 | 7506 | 0 | 203 |
| OpenTelemetry | 1.17.0 | net10.0 | scanned | 1 | 1558 | 0 | 28 |
| OpenTelemetry.Api | 1.17.0 | net10.0 | scanned | 1 | 413 | 0 | 9 |
| OpenTelemetry.Api.ProviderBuilderExtensions | 1.17.0 | net10.0 | scanned | 1 | 123 | 0 | 0 |
| Pipelines.Sockets.Unofficial | 2.3.1 | net10.0 | scanned | 1 | 977 | 0 | 103 |
| Polly | 8.7.0 | net6.0 | scanned | 1 | 2045 | 0 | 2 |
| Polly.Core | 8.7.0 | net8.0 | scanned | 1 | 1265 | 0 | 3 |
| Serilog | 4.4.0 | net10.0 | scanned | 1 | 1057 | 0 | 15 |
| Serilog.AspNetCore | 10.0.0 | net10.0 | scanned | 1 | 59 | 0 | 0 |
| Serilog.Extensions.Hosting | 10.0.0 | net10.0 | scanned | 1 | 204 | 0 | 0 |
| Serilog.Extensions.Logging | 10.0.0 | net10.0 | scanned | 1 | 121 | 0 | 0 |
| Serilog.Formatting.Compact | 3.0.0 | net8.0 | scanned | 1 | 10 | 0 | 0 |
| Serilog.Settings.Configuration | 10.0.1 | net10.0 | scanned | 1 | 316 | 0 | 22 |
| Serilog.Sinks.Console | 6.1.1 | net8.0 | scanned | 1 | 124 | 0 | 6 |
| Serilog.Sinks.Debug | 3.0.0 | net8.0 | scanned | 1 | 4 | 0 | 0 |
| Serilog.Sinks.File | 7.0.0 | net9.0 | scanned | 1 | 156 | 0 | 15 |
| StackExchange.Redis | 3.1.13 | net10.0 | scanned | 1 | 9531 | 0 | 120 |
| Swashbuckle.AspNetCore | 10.2.3 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| Swashbuckle.AspNetCore.Swagger | 10.2.3 | net10.0 | scanned | 1 | 77 | 0 | 1 |
| Swashbuckle.AspNetCore.SwaggerGen | 10.2.3 | net10.0 | scanned | 1 | 812 | 0 | 3 |
| Swashbuckle.AspNetCore.SwaggerUI | 10.2.3 | net10.0 | scanned | 1 | 463 | 0 | 3 |
| System.ClientModel | 1.15.0 | net10.0 | scanned | 1 | 1644 | 0 | 55 |
| System.CodeDom | 10.0.11 | net10.0 | scanned | 1 | 1373 | 0 | 953 |
| System.Diagnostics.EventLog | 10.0.11 | net10.0 | scanned | 1 | 388 | 0 | 5 |
| System.Diagnostics.PerformanceCounter | 10.0.11 | net10.0 | scanned | 1 | 239 | 0 | 5 |
| System.Drawing.Common | 10.0.11 | net10.0 | scanned | 3 | 6327 | 0 | 2029 |
| System.Formats.Asn1 | 10.0.11 | net10.0 | scanned | 1 | 340 | 0 | 26 |
| System.IO.Hashing | 10.0.11 | net10.0 | scanned | 1 | 218 | 0 | 31 |
| System.Memory.Data | 10.0.11 | net10.0 | scanned | 1 | 96 | 0 | 7 |
| System.Runtime.Caching | 10.0.11 | net10.0 | scanned | 1 | 426 | 0 | 38 |
| System.Security.Cryptography.Pkcs | 10.0.11 | net10.0 | scanned | 1 | 1336 | 0 | 1905 |
| System.Text.Json | 10.0.11 | net10.0 | scanned | 1 | 3975 | 0 | 81 |
| System.Threading.Channels | 10.0.11 | net10.0 | scanned | 1 | 311 | 0 | 0 |
| System.Windows.Extensions | 10.0.11 | net10.0 | scanned | 1 | 78 | 0 | 5 |
| coverlet.collector | 10.0.1 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| runtime.win-arm64.runtime.native.System.Data.SqlClient.sni | 4.4.0 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| runtime.win-x64.runtime.native.System.Data.SqlClient.sni | 4.4.0 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| runtime.win-x86.runtime.native.System.Data.SqlClient.sni | 4.4.0 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |
| xunit | 2.9.3 | - | no-scannable-tfm | 0 | 0 | 0 | 0 |

## Findings by capability, per package

Columns are the first four letters of each capability: `Cryp` = Cryptography, `Dyna` = DynamicCodeLoading, `Envi` = EnvironmentProbe, `File` = FileSystem, `Nati` = NativeInterop, `Netw` = Network, `Proc` = ProcessExecution, `Refl` = ReflectionInvocation, `Regi` = Registry, `Runt` = RuntimeControl, `Unsa` = UnsafeMemory.

| Package | Cryp | Dyna | Envi | File | Nati | Netw | Proc | Refl | Regi | Runt | Unsa |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| AWSSDK.Core | 58 | 9 | 52 | 59 | 10 | 51 | 31 | 12 | 0 | 32 | 3 |
| AWSSDK.S3 | 2 | 0 | 5 | 37 | 0 | 8 | 0 | 0 | 0 | 4 | 0 |
| AutoMapper | 0 | 28 | 1 | 0 | 0 | 0 | 0 | 5 | 0 | 0 | 0 |
| Azure.Core | 42 | 1 | 62 | 11 | 26 | 25 | 54 | 8 | 0 | 6 | 5 |
| Azure.Identity | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Azure.Security.KeyVault.Secrets | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| Azure.Storage.Blobs | 47 | 0 | 4 | 7 | 0 | 0 | 0 | 0 | 0 | 4 | 5 |
| Azure.Storage.Common | 5 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 5 |
| Castle.Core | 0 | 135 | 17 | 13 | 4 | 11 | 0 | 10 | 0 | 8 | 0 |
| CsvHelper | 0 | 8 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| Dapper | 0 | 47 | 0 | 0 | 0 | 0 | 0 | 7 | 0 | 2 | 0 |
| FluentAssertions | 0 | 40 | 0 | 2 | 0 | 0 | 0 | 11 | 0 | 6 | 0 |
| FluentValidation | 0 | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Google.Protobuf | 0 | 9 | 0 | 0 | 5 | 0 | 0 | 14 | 0 | 0 | 23 |
| Grpc.Core.Api | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 2 | 0 | 0 | 0 |
| Grpc.Net.Client | 0 | 0 | 6 | 0 | 3 | 34 | 0 | 0 | 0 | 3 | 0 |
| Grpc.Net.Common | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Humanizer.Core | 0 | 0 | 9 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 6 |
| Microsoft.ApplicationInsights | 0 | 1 | 7 | 8 | 0 | 4 | 2 | 1 | 0 | 8 | 0 |
| Microsoft.AspNetCore.Mvc.NewtonsoftJson | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 5 |
| Microsoft.Azure.Amqp | 5 | 6 | 2 | 0 | 0 | 95 | 1 | 12 | 0 | 3 | 30 |
| Microsoft.Azure.WebJobs | 2 | 15 | 17 | 13 | 2 | 0 | 5 | 29 | 0 | 8 | 0 |
| Microsoft.Bcl.AsyncInterfaces | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Microsoft.Data.SqlClient | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Microsoft.EntityFrameworkCore | 0 | 59 | 0 | 0 | 0 | 0 | 0 | 34 | 0 | 0 | 6 |
| Microsoft.Extensions.DependencyInjection | 0 | 20 | 0 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 5 |
| Microsoft.Extensions.Diagnostics | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| Microsoft.Extensions.Diagnostics.Abstractions | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| Microsoft.Extensions.Diagnostics.HealthChecks | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Microsoft.Extensions.Diagnostics.HealthChecks.Abstractions | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Microsoft.Extensions.Hosting | 0 | 1 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| Microsoft.Extensions.Http | 0 | 0 | 1 | 0 | 0 | 29 | 0 | 0 | 0 | 0 | 5 |
| Microsoft.Extensions.Logging | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| Microsoft.Extensions.Logging.EventLog | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Microsoft.Identity.Client | 175 | 0 | 35 | 7 | 42 | 29 | 16 | 1 | 0 | 0 | 0 |
| Microsoft.Identity.Client.Extensions.Msal | 2 | 0 | 10 | 24 | 50 | 0 | 4 | 1 | 0 | 0 | 0 |
| Microsoft.IdentityModel.Abstractions | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Microsoft.OpenApi | 4 | 1 | 1 | 8 | 0 | 3 | 0 | 2 | 0 | 0 | 0 |
| Microsoft.SqlServer.Server | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Microsoft.Win32.SystemEvents | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| Moq | 0 | 19 | 36 | 0 | 0 | 0 | 0 | 9 | 0 | 0 | 0 |
| NLog | 0 | 25 | 29 | 93 | 0 | 0 | 3 | 12 | 0 | 24 | 0 |
| NUnit | 1 | 2 | 19 | 17 | 5 | 0 | 2 | 55 | 4 | 12 | 0 |
| Newtonsoft.Json | 0 | 35 | 6 | 0 | 0 | 0 | 0 | 30 | 0 | 7 | 0 |
| Newtonsoft.Json.Bson | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Npgsql | 51 | 11 | 22 | 10 | 0 | 35 | 11 | 12 | 0 | 9 | 42 |
| OpenTelemetry | 0 | 0 | 3 | 8 | 1 | 0 | 2 | 0 | 0 | 9 | 5 |
| OpenTelemetry.Api | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 5 |
| OpenTelemetry.Api.ProviderBuilderExtensions | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Pipelines.Sockets.Unofficial | 0 | 3 | 0 | 8 | 5 | 41 | 0 | 4 | 0 | 7 | 35 |
| Polly | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| Polly.Core | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| Serilog | 0 | 5 | 2 | 0 | 0 | 0 | 0 | 7 | 0 | 0 | 1 |
| Serilog.AspNetCore | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Serilog.Extensions.Hosting | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Serilog.Extensions.Logging | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Serilog.Formatting.Compact | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Serilog.Settings.Configuration | 0 | 4 | 1 | 2 | 0 | 0 | 0 | 14 | 0 | 1 | 0 |
| Serilog.Sinks.Console | 0 | 0 | 3 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| Serilog.Sinks.Debug | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Serilog.Sinks.File | 0 | 0 | 1 | 14 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| StackExchange.Redis | 28 | 1 | 7 | 11 | 0 | 22 | 0 | 4 | 0 | 17 | 30 |
| Swashbuckle.AspNetCore.Swagger | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Swashbuckle.AspNetCore.SwaggerGen | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| Swashbuckle.AspNetCore.SwaggerUI | 2 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| System.ClientModel | 1 | 12 | 6 | 2 | 0 | 12 | 0 | 9 | 0 | 7 | 6 |
| System.CodeDom | 0 | 911 | 1 | 21 | 0 | 0 | 11 | 3 | 0 | 1 | 5 |
| System.Diagnostics.EventLog | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| System.Diagnostics.PerformanceCounter | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| System.Drawing.Common | 0 | 9 | 7 | 9 | 1085 | 0 | 0 | 9 | 0 | 418 | 492 |
| System.Formats.Asn1 | 20 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 6 |
| System.IO.Hashing | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 31 |
| System.Memory.Data | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| System.Runtime.Caching | 0 | 0 | 1 | 18 | 5 | 0 | 0 | 0 | 0 | 9 | 5 |
| System.Security.Cryptography.Pkcs | 1889 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 14 |
| System.Text.Json | 2 | 37 | 1 | 0 | 0 | 0 | 0 | 15 | 0 | 0 | 26 |
| System.Threading.Channels | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| System.Windows.Extensions | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |

## Coverage honesty (ADR-0024)

78 of 100 manifest entries were scanned completely.
Everything below is a package whose numbers above are a **floor, not a total** - or that produced no
numbers at all. A corpus statistic computed over partially-analysed input is a lie unless the
partiality is stated alongside it.

| Package | Version | Status | Counted in density | Reason |
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

## Provenance and reproducibility

Produced for `docs/agent/tasks/strict-gate-source-prevalence.md` (M1). The 2026-08-20 falsification-corpus
run (`data/results/indicator-prevalence-top100-2026-08-20.md`) computed this capability half
too but never wrote it to a file; this run recomputes it against the same manifest and cache.

- **Regression oracle, run first:** the harness against the pinned 25-package
  `tests/Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness/benign-corpus.manifest`
  (hash `03034edd2f8f62abf50b938ff8e0543c60cdcfb6f9e214c98cbc9203b12ce75b`) reproduced the pinned figures
  exactly: 25 packages, 26 assemblies, 51035 methods analysed, 0 skipped, 1706 findings, 96.0%
  `(any capability)`. Nothing moved; the run below proceeded.
- **Commands (both runs against the shared, pre-warmed package cache; nothing was re-fetched):**
  ```
  <harness>.exe --manifest tests/Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness/benign-corpus.manifest --take 25 \
      --cache %LOCALAPPDATA%\Silvergun\benign-corpus --out <scratch>/oracle-run1
  <harness>.exe --manifest data/corpus/benign-top.manifest --take 0 \
      --cache %LOCALAPPDATA%\Silvergun\benign-corpus --out <scratch>/top100-run1
  <harness>.exe --manifest data/corpus/benign-top.manifest --take 0 \
      --cache %LOCALAPPDATA%\Silvergun\benign-corpus --out <scratch>/top100-run2
  ```
  `<harness>` = `tests/Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness/bin/Release/net10.0/Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.exe`,
  built via `dotnet build ... -c Release` immediately before this run. Cache root
  `%LOCALAPPDATA%\Silvergun\benign-corpus` (outside the repo, pre-populated by the
  2026-08-20 run; 173 cached `.nupkg`, 136 cached extractions - nothing was downloaded by this task).
  Date: 2026-08-21.
- **Determinism:** `top100-run1` and `top100-run2` produced byte-identical `benign-corpus-2026-08-21.md`
  and `.tsv` (diffed directly; zero-line diff). No harness code was changed to produce this report - the
  two files here are the driver's normal output, copied from the scratch `--out` directory to this path
  and filename (`benign-corpus-top100-2026-08-21.{md,tsv}`) and with only the `Classified findings`
  filename reference and title line edited to match; every number is untouched driver output.
- **No child exited non-zero, timed out, or produced a partial scan.** All 78 contributing packages show
  `scanned` with 0 methods skipped in both runs.
- **Denominator:** 78 of 100 manifest entries contributed IL data (`scanned`); the other 22 are
  `no-scannable-tfm` and are named in the Coverage honesty table above - this is the M1 denominator.
  M2 (below, in the ADR-0027 evidence writeup) uses all 100, since a `no-scannable-tfm` package still
  has a `.nuspec` and may carry script findings.
