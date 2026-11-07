# Benign corpus - indicator prevalence (2026-08-20)

**A measurement, not a gate.** These are ordinary, widely-used NuGet packages; their label is
"overwhelmingly not malware" by download count, not by audit (ADR-0021: benign by assumption is not
benign by proof). The question answered here is *precision*: which `IndicatorCategory` values are so
common in benign code that they carry no gating signal on their own. Nothing in `--strict`, the
`IndicatorAnalysis` classifier, or any threshold was changed to produce these numbers - the gating
decision (if any) is a separate ADR, written from this data.

| Parameter | Value |
| --- | --- |
| Manifest | `benign-adversarial.manifest` |
| Manifest hash (sha256 of normalized `id,version` list) | `b491c907f1a1673664f29d956473c897d57690722326fe2bcc62bce9b00a72dc` |
| Packages in manifest (after `--take`) | 48 |
| Packages contributing to prevalence | 35 |
| Assemblies scanned | 35 |
| Methods analysed | 222589 |
| Methods skipped | 0 |
| Total indicator findings (raw occurrences) | 3065 |
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

Share = packages with at least one finding of that category, out of the 35 that
contributed data. A category with a high share cannot gate anything on its own.

| Category | Packages with >=1 | Share of corpus | Total findings | Distinct values | Median/pkg | p90/pkg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| GenericUrl | 16 | 45.7% | 1466 | 42 | 0.0 | 6 |
| ReflectionTypeName | 13 | 37.1% | 1090 | 714 | 0.0 | 34 |
| PublicIpLiteral | 5 | 14.3% | 477 | 59 | 0.0 | 7 |
| PrivateIpLiteral | 3 | 8.6% | 30 | 8 | 0.0 | 0 |
| ExfilSink | 1 | 2.9% | 1 | 1 | 0.0 | 0 |
| RawCodeHost | 1 | 2.9% | 1 | 1 | 0.0 | 0 |
| AutorunRegistry | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| CallbackDomain | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| CredentialPath | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| DynamicDns | 0 | 0.0% | 0 | 0 | 0.0 | 0 |
| **(any indicator)** | **28** | **80.0%** | **3065** | **825** | **1.0** | **127** |

## Top 10 most widespread distinct values, per category

Ranked by number of DISTINCT counted packages carrying the value (not raw occurrences); ties broken by
total occurrences, then the value itself. This is the table that makes the shares above interpretable -
without it a high share is just a number.

| Category | Value | Packages | Total occurrences |
| --- | --- | ---: | ---: |
| ExfilSink | discord.com | 1 | 1 |
| GenericUrl | www.googleapis.com | 3 | 12 |
| GenericUrl | dns.googleapis.com | 3 | 6 |
| GenericUrl | api.cloudflare.com | 3 | 3 |
| GenericUrl | discord.com | 2 | 6 |
| GenericUrl | localhost | 2 | 4 |
| GenericUrl | api.ngrok.com | 2 | 2 |
| GenericUrl | github.com | 2 | 2 |
| GenericUrl | www.w3.org | 1 | 780 |
| GenericUrl | uri.etsi.org | 1 | 204 |
| GenericUrl | saml.secureblackbox.com | 1 | 93 |
| PrivateIpLiteral | 0.0.0.0 | 2 | 10 |
| PrivateIpLiteral | 127.0.0.1 | 2 | 10 |
| PrivateIpLiteral | ::1 | 1 | 4 |
| PrivateIpLiteral | 169.254.170.2 | 1 | 2 |
| PrivateIpLiteral | 169.254.169.254 | 1 | 1 |
| PrivateIpLiteral | 169.254.170.23 | 1 | 1 |
| PrivateIpLiteral | fd00:ec2::23 | 1 | 1 |
| PrivateIpLiteral | fd00:ec2::254 | 1 | 1 |
| PublicIpLiteral | f:: | 2 | 22 |
| PublicIpLiteral | 2001:4860:4860::8844 | 2 | 2 |
| PublicIpLiteral | 2001:4860:4860::8888 | 2 | 2 |
| PublicIpLiteral | 8.8.4.4 | 2 | 2 |
| PublicIpLiteral | 8.8.8.8 | 2 | 2 |
| PublicIpLiteral | d:: | 1 | 150 |
| PublicIpLiteral | e:: | 1 | 135 |
| PublicIpLiteral | ed:: | 1 | 55 |
| PublicIpLiteral | a:: | 1 | 15 |
| PublicIpLiteral | c:: | 1 | 15 |
| RawCodeHost | raw.githubusercontent.com | 1 | 1 |
| ReflectionTypeName | XAdES.BASELINE | 1 | 33 |
| ReflectionTypeName | AWSSDK.SecurityToken | 1 | 17 |
| ReflectionTypeName | ElPDFSecurityHandler.DecryptObject | 1 | 14 |
| ReflectionTypeName | ElPDFSecurityHandler.EncryptObject | 1 | 14 |
| ReflectionTypeName | Amazon.SecurityToken.AmazonSecurityTokenServiceClient | 1 | 11 |
| ReflectionTypeName | SBUnicode.Unit.Initialize | 1 | 11 |
| ReflectionTypeName | TLSExtensions.CertificateStatus | 1 | 11 |
| ReflectionTypeName | AWSSDK.Core | 1 | 10 |
| ReflectionTypeName | AWSSDK.Extensions.CrtIntegration | 1 | 10 |
| ReflectionTypeName | Cert.KeyMaterial | 1 | 10 |

## Per package

| Package | Version | TFM | Status | Assemblies | Indicator findings | Truncated | Cap-hit |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| ARSoft.Tools.Net | 3.6.1 | net6.0 | scanned | 1 | 41 | no | yes |
| AWSSDK.Core | 4.0.101.1 | net8.0 | scanned | 1 | 127 | no | yes |
| AWSSDK.Extensions.NETCore.Setup | 4.0.100.9 | net8.0 | scanned | 1 | 1 | no | yes |
| AWSSDKCPP-Core | 1.6.25 | - | no-scannable-tfm | 0 | 0 | no | no |
| AWSSDKCPP-Core.redist | 1.6.25 | - | no-scannable-tfm | 0 | 0 | no | no |
| CSharpDiscordWebhook.NET | 2.7.1 | net6.0 | scanned | 1 | 0 | no | yes |
| Carbon | 2.11.0 | - | no-scannable-tfm | 0 | 0 | no | no |
| CloudFlare.Client | 8.0.0 | netstandard2.0 | scanned | 1 | 1 | no | yes |
| CloudPub.Client | 1.5.7 | - | no-scannable-tfm | 0 | 0 | no | no |
| Cloudflare.Net.ZeroTrust | 0.1.4 | net10.0 | scanned | 1 | 1 | no | no |
| Cloudflare.ZeroTrust | 0.1.5 | net10.0 | scanned | 1 | 1 | no | no |
| DNS | 7.0.0 | netstandard2.0 | scanned | 1 | 0 | no | yes |
| DSharpPlus | 5.0.0 | net7.0 | scanned | 1 | 459 | no | yes |
| Devart.Data.Oracle | 11.1.123 | netstandard2.0 | scanned | 1 | 0 | no | yes |
| Discord.Net.Labs.Webhook | 3.6.1 | net6.0 | scanned | 1 | 0 | no | yes |
| Discord.Net.Webhook | 3.20.1 | net10.0 | scanned | 1 | 0 | no | yes |
| Discord.Webhook | 1.0.9 | netstandard2.0 | scanned | 1 | 1 | no | yes |
| DnsClient | 1.8.0 | net8.0 | scanned | 1 | 10 | no | yes |
| Google.Apis.Dns.v1 | 1.75.0.4212 | net6.0 | scanned | 1 | 6 | no | no |
| Google.Apis.Dns.v1beta2 | 1.75.0.4212 | net6.0 | scanned | 1 | 6 | no | no |
| Google.Apis.Dns.v2beta1 | 1.48.0.2044 | netstandard2.0 | scanned | 1 | 6 | no | no |
| IPRangeLookup | 1.0.3 | net5.0 | scanned | 1 | 1 | no | yes |
| ImTryin.WindowsConsoleService | 1.0.8 | - | no-scannable-tfm | 0 | 0 | no | no |
| Kuestenlogik.Bowire.Oast | 2.4.0 | net10.0 | scanned | 1 | 3 | no | yes |
| Meziantou.Framework.Win32.CredentialManager | 3.0.1 | net11.0 | scanned | 1 | 2 | no | yes |
| Microsoft.Azure.Functions.Worker.ProjectTemplates | 4.0.5590 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.Azure.WebJobs.ProjectTemplates | 4.0.5590 | - | no-scannable-tfm | 0 | 0 | no | no |
| Microsoft.VisualStudio.Web.CodeGeneration.Design | 10.0.2 | net10.0 | scanned | 1 | 1 | no | yes |
| Microsoft.VisualStudio.Web.CodeGeneration.Tools | 2.0.4 | - | no-scannable-tfm | 0 | 0 | no | no |
| NJsonSchema.CodeGeneration | 11.6.1 | net8.0 | scanned | 1 | 2 | no | yes |
| NJsonSchema.CodeGeneration.CSharp | 11.6.1 | net8.0 | scanned | 1 | 34 | no | no |
| NJsonSchema.CodeGeneration.TypeScript | 11.6.1 | net8.0 | scanned | 1 | 4 | no | no |
| NVelocity | 1.2.0 | netstandard2.0 | scanned | 1 | 7 | no | yes |
| OwinWindowsService | 1.0.0.1 | - | no-scannable-tfm | 0 | 0 | no | no |
| PanoramicSystems.Templates.WindowsService | 1.0.4 | - | no-scannable-tfm | 0 | 0 | no | no |
| Rebex.Sftp | 8.0.9709 | net10.0 | scanned | 1 | 7 | no | yes |
| Serilog.Sinks.Discord.Lite | 0.2.0 | netstandard2.0 | scanned | 1 | 3 | no | no |
| Soenneker.Fastly.OpenApiClient | 4.0.49 | net10.0 | scanned | 1 | 1 | no | no |
| Soenneker.ngrok.HttpClients | 4.0.87 | net10.0 | scanned | 1 | 1 | no | no |
| Soenneker.ngrok.OpenApiClient | 4.0.29 | net10.0 | scanned | 1 | 1 | no | no |
| Soenneker.ngrok.OpenApiClientUtil | 4.0.109 | net10.0 | scanned | 1 | 0 | no | no |
| Telegram.Bot | 22.10.2.1 | net6.0 | scanned | 1 | 197 | no | yes |
| UWS | 2.0.21 | - | no-scannable-tfm | 0 | 0 | no | no |
| Usa.Tool.ServiceDeploy | 1.3.0 | - | no-scannable-tfm | 0 | 0 | no | no |
| Woof.ServiceInstaller | 9.0.0 | net9.0 | scanned | 1 | 0 | no | yes |
| ZTImage.ServiceController | 1.0.1.3 | - | no-scannable-tfm | 0 | 0 | no | no |
| discord-webhook-client | 4.1.0 | net8.0 | scanned | 1 | 1 | no | yes |
| nsoftware.SecureBlackbox | 24.0.9710 | netstandard2.0 | scanned | 1 | 2140 | no | yes |

## CallbackDomain / ExfilSink / DynamicDns - every hit, individually

A benign package tripping one of these three categories is either a false positive in our domain list
or a genuinely interesting package; either way it must be visible by name, not buried in a count.

| Category | Package | Version | Assembly | Value | CallerType | CallerMethod | Occurrences |
| --- | --- | --- | --- | --- | --- | --- | ---: |
| ExfilSink | Serilog.Sinks.Discord.Lite | 0.2.0 | Serilog.Sinks.Discord.dll | discord.com | Serilog.Sinks.Discord.DiscordSink | SendMessage | 1 |

## Truncation

*None: the 10,000-distinct-indicator-per-assembly cap was not reached by any assembly in the corpus - every number above is a total, not a floor.*

## Coverage honesty (ADR-0024)

35 of 48 manifest entries were scanned completely.
Everything below is a package whose numbers above are a **floor, not a total** - or that produced no
numbers at all. A corpus statistic computed over partially-analysed input is a lie unless the
partiality is stated alongside it.

| Package | Version | Status | Counted in prevalence | Reason |
| --- | --- | --- | --- | --- |
| AWSSDKCPP-Core | 1.6.25 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| AWSSDKCPP-Core.redist | 1.6.25 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Carbon | 2.11.0 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| CloudPub.Client | 1.5.7 | no-scannable-tfm | **no** | lib TFMs on offer: netstandard2.1 |
| ImTryin.WindowsConsoleService | 1.0.8 | no-scannable-tfm | **no** | lib TFMs on offer: net48 |
| Microsoft.Azure.Functions.Worker.ProjectTemplates | 4.0.5590 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.Azure.WebJobs.ProjectTemplates | 4.0.5590 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Microsoft.VisualStudio.Web.CodeGeneration.Tools | 2.0.4 | no-scannable-tfm | **no** | lib TFMs on offer: netcoreapp2.0 |
| OwinWindowsService | 1.0.0.1 | no-scannable-tfm | **no** | lib TFMs on offer: net45 |
| PanoramicSystems.Templates.WindowsService | 1.0.4 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| UWS | 2.0.21 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| Usa.Tool.ServiceDeploy | 1.3.0 | no-scannable-tfm | **no** | package ships no lib/<tfm>/*.dll at all |
| ZTImage.ServiceController | 1.0.1.3 | no-scannable-tfm | **no** | lib TFMs on offer: net45 |
