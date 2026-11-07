# C-build corpus provenance

- **Fetched:** 2026-11-06, by `fetch_cbuild.py` (reachability R2b, S3), in
  `tests/Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness`.
- **Service index:** https://api.nuget.org/v3/index.json
- **Search:** `https://azuresearch-ussc.nuget.org/query?q=<term>&take=1000&prerelease=false&semVerLevel=2.0.0`, terms `analyzers`, `sourcegenerator`, `generator`, `msbuild`.
- **Packages:** `https://api.nuget.org/v3-flatcontainer/<id>/<version>/<id>.<version>.nupkg` (lower-cased).
- **Rule:** union by id; ranked by `totalDownloads` (descending, ties by id); the search result's version (latest stable); C100 ids excluded; kept if a `.dll` sits under `analyzers/`, `build/`, `buildTransitive/`, `tasks/` or `tools/`; stop at 50.
- **Counts:** 3892 distinct ids; 81 examined; 50 kept; 31 rejected.
- **C100:** `data/corpus/benign-top.manifest` (3 of the 3,892 ids are in it; 1 would otherwise have been kept).
- **Per-query cap:** each query returned its first 1,000 hits by the search's own relevance order (total hits:
  `analyzers` 1,949, `sourcegenerator` 1,273, `generator` 12,030, `msbuild` 2,152), and only those were ranked by
  downloads. A highly downloaded package ranked below 1,000 by relevance in every query would be missed.
- **Fetch log:** 0 refusals (no 429, 403 or challenge). Both hosts' `robots.txt` returned 404 (treated as unspecified);
  this is NuGet's documented public V3 API. No credentials; User-Agent `Silvergun-corpus-fetch/1.0`.
- **Correction (2026-11-06, before any run on this corpus):** the first selection was given the harness's 25-package
  `benign-corpus.manifest` as C100 by mistake, so it kept `Microsoft.Extensions.ApiDescription.Server`, which is in
  C100. It was caught by the harness's `CheckedInManifests_C100AndCbuild_ShareNoId` test. The selection was re-run
  with the right manifest from the cached search responses: that package is out and
  `Microsoft.SourceLink.AzureRepos.Git` 10.0.403 (one new download) is in. Nothing else changed.
- **Bundled DLLs:** "Build DLLs" counts every `.dll` under the five folders, including third-party ones a package ships
  in `tools/` or `tasks/` (for example `tools/Newtonsoft.Json.dll`). They are what the package installs.
- **Licence:** each package keeps its own licence (see its .nuspec). Only ids and versions are recorded in the repository; the .nupkg files are cached outside it.
- **Download counts** are as of the fetch date and change daily.

## Kept

| # | Id | Version | Downloads | Query | Build DLLs | First |
|---|---|---|---|---|---|---|
| 1 | Microsoft.EntityFrameworkCore.Analyzers | 10.0.14 | 2425398219 | analyzers | 1 | `analyzers/dotnet/cs/Microsoft.EntityFrameworkCore.Analyzers.dll` |
| 2 | Microsoft.CodeAnalysis.Analyzers | 5.9.0 | 1860416863 | analyzers | 30 | `analyzers/dotnet/cs/Microsoft.CodeAnalysis.Analyzers.dll` |
| 3 | xunit.analyzers | 2.2.0 | 1143011749 | analyzers | 2 | `analyzers/dotnet/cs/xunit.analyzers.dll` |
| 4 | Microsoft.AspNetCore.Components.Analyzers | 10.0.14 | 304788243 | analyzers | 1 | `analyzers/dotnet/cs/Microsoft.AspNetCore.Components.Analyzers.dll` |
| 5 | StyleCop.Analyzers | 1.1.118 | 287612097 | analyzers | 9 | `analyzers/dotnet/cs/StyleCop.Analyzers.CodeFixes.dll` |
| 6 | coverlet.msbuild | 10.1.0 | 274952760 | msbuild | 70 | `tasks/net10.0/Microsoft.Extensions.DependencyInjection.Abstractions.dll` |
| 7 | Microsoft.AspNetCore.Razor.Design | 2.3.13 | 243011440 | msbuild | 10 | `tasks/net46/Microsoft.AspNetCore.Razor.Tasks.dll` |
| 8 | Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | 193536940 | generator | 32 | `tools/net46/Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.dll` |
| 9 | NUnit.Analyzers | 4.15.0 | 182842269 | analyzers | 2 | `analyzers/dotnet/cs/nunit.analyzers.codefixes.dll` |
| 10 | Microsoft.NET.ILLink.Tasks | 10.0.14 | 173006057 | msbuild | 19 | `analyzers/dotnet/cs/ILLink.CodeFixProvider.dll` |
| 11 | Microsoft.AspNetCore.Mvc.Analyzers | 2.3.13 | 168977295 | analyzers | 1 | `analyzers/dotnet/cs/Microsoft.AspNetCore.Mvc.Analyzers.dll` |
| 12 | Microsoft.Azure.Functions.Analyzers | 1.0.0 | 149341527 | analyzers | 1 | `analyzers/dotnet/cs/Microsoft.Azure.Functions.Analyzers.dll` |
| 13 | Microsoft.VisualStudio.Threading.Analyzers | 18.12.1 | 147110890 | analyzers | 32 | `analyzers/cs/Microsoft.VisualStudio.Threading.Analyzers.CSharp.dll` |
| 14 | Microsoft.Build.Tasks.Git | 10.0.403 | 133925054 | msbuild | 34 | `tools/net/Microsoft.Build.Tasks.Git.dll` |
| 15 | StyleCop.Analyzers.Unstable | 1.2.0.556 | 133195003 | analyzers | 9 | `analyzers/dotnet/cs/StyleCop.Analyzers.CodeFixes.dll` |
| 16 | Microsoft.SourceLink.Common | 10.0.403 | 132278923 | msbuild | 28 | `tools/net/Microsoft.SourceLink.Common.dll` |
| 17 | Microsoft.Net.Compilers | 4.2.0 | 129772537 | msbuild | 94 | `tools/Microsoft.Build.Tasks.CodeAnalysis.dll` |
| 18 | dotnet-reportgenerator-globaltool | 5.5.12 | 127446339 | generator | 57 | `tools/net10.0/any/DotNetConfig.dll` |
| 19 | SonarAnalyzer.CSharp | 10.35.0.4138 | 118621055 | analyzers | 1 | `analyzers/SonarAnalyzer.CSharp.dll` |
| 20 | Microsoft.Azure.Functions.Worker.Sdk.Generators | 1.4.0 | 112097696 | generator | 4 | `analyzers/dotnet/cs/Microsoft.Azure.Functions.Worker.Sdk.Generators.dll` |
| 21 | NSwag.MSBuild | 14.7.1 | 109348081 | msbuild | 260 | `tools/Net100/Fluid.dll` |
| 22 | Microsoft.Azure.Functions.Worker.Sdk.Analyzers | 1.2.2 | 109180641 | analyzers | 1 | `analyzers/dotnet/cs/Microsoft.Azure.Functions.Worker.Sdk.Analyzers.dll` |
| 23 | Microsoft.SourceLink.GitHub | 10.0.403 | 101717081 | msbuild | 34 | `tools/net/Microsoft.SourceLink.GitHub.dll` |
| 24 | MessagePackAnalyzer | 3.1.12 | 101465806 | analyzers | 2 | `analyzers/roslyn4.3/cs//MessagePack.Analyzers.CodeFixes.dll` |
| 25 | Microsoft.CodeAnalysis.NetAnalyzers | 10.0.403 | 95556858 | analyzers | 30 | `analyzers/dotnet/cs/Microsoft.CodeAnalysis.CSharp.NetAnalyzers.dll` |
| 26 | SpecFlow.Tools.MsBuild.Generation | 3.9.74 | 93313151 | msbuild | 213 | `tasks/net461/BoDi.dll` |
| 27 | MSTest.Analyzers | 4.5.2 | 84329680 | analyzers | 42 | `analyzers/dotnet/cs/MSTest.Analyzers.CodeFixes.dll` |
| 28 | dotnet-sonarscanner | 12.1.0 | 82835576 | msbuild | 11 | `tools/netcoreapp3.1/any/Google.Protobuf.dll` |
| 29 | Microsoft.CodeQuality.Analyzers | 3.3.2 | 76572084 | analyzers | 32 | `analyzers/dotnet/cs/Humanizer.dll` |
| 30 | Microsoft.NetCore.Analyzers | 3.3.2 | 76152998 | analyzers | 30 | `analyzers/dotnet/cs/Microsoft.NetCore.Analyzers.dll` |
| 31 | Microsoft.NetFramework.Analyzers | 3.3.2 | 74048045 | analyzers | 30 | `analyzers/dotnet/cs/Microsoft.NetFramework.Analyzers.dll` |
| 32 | Roslynator.Analyzers | 5.0.1 | 65986889 | analyzers | 24 | `analyzers/dotnet/roslyn3.8/cs/Roslynator.CSharp.Analyzers.CodeFixes.dll` |
| 33 | ReportGenerator | 5.5.12 | 65777343 | generator | 185 | `tools/net10.0/DotNetConfig.dll` |
| 34 | Microsoft.CodeAnalysis.VersionCheckAnalyzer | 3.3.2 | 62482175 | analyzers | 14 | `analyzers/dotnet/Microsoft.CodeAnalysis.VersionCheckAnalyzer.dll` |
| 35 | Microsoft.Azure.Functions.Worker.Extensions.Http.AspNetCore.Analyzers | 1.0.4 | 59199090 | analyzers | 1 | `analyzers/dotnet/cs/Microsoft.Azure.Functions.Worker.Extensions.Http.AspNetCore.Analyzers.dll` |
| 36 | Microsoft.CodeAnalysis.BannedApiAnalyzers | 5.6.0 | 57637943 | analyzers | 30 | `analyzers/dotnet/cs/Microsoft.CodeAnalysis.BannedApiAnalyzers.dll` |
| 37 | Microsoft.Extensions.ApiDescription.Client | 10.0.14 | 53194014 | msbuild | 1 | `tasks/netstandard2.0/Microsoft.Extensions.ApiDescription.Client.dll` |
| 38 | NSubstitute.Analyzers.CSharp | 1.0.17 | 38757865 | analyzers | 2 | `analyzers/dotnet/cs/NSubstitute.Analyzers.CSharp.dll` |
| 39 | Riok.Mapperly | 4.3.1 | 37693344 | sourcegenerator | 14 | `analyzers/roslyn4.0/dotnet/cs/Riok.Mapperly.Abstractions.dll` |
| 40 | Microsoft.Azure.WebJobs.Extensions.DurableTask.Analyzers | 0.5.0 | 37233462 | analyzers | 1 | `analyzers/dotnet/cs/Microsoft.Azure.WebJobs.Extensions.DurableTask.Analyzers.dll` |
| 41 | Aspire.Hosting.AppHost | 13.6.4 | 36541792 | msbuild | 3 | `analyzers/dotnet/cs/Aspire.Hosting.Analyzers.dll` |
| 42 | GraphQL.Analyzers | 8.8.5 | 33694728 | analyzers | 2 | `analyzers/dotnet/cs/GraphQL.Analyzers.CodeFixes.dll` |
| 43 | OpenCover | 4.7.1221 | 29656387 | generator | 38 | `build/OpenCover.MSBuild.dll` |
| 44 | Meziantou.Analyzer | 3.0.321 | 29114244 | analyzers | 10 | `analyzers/dotnet/roslyn4.14/cs/Meziantou.Analyzer.CodeFixers.dll` |
| 45 | Reqnroll.Tools.MsBuild.Generation | 3.3.4 | 29046586 | msbuild | 74 | `build/net462/Cucumber.HtmlFormatter.dll` |
| 46 | Xamarin.Build.Download | 0.11.6 | 28344434 | msbuild | 6 | `build/Microsoft.Win32.Registry.dll` |
| 47 | Xamarin.AndroidX.Migration | 1.0.10 | 26972572 | msbuild | 16 | `build/monoandroid120/ILRepack.dll` |
| 48 | AsyncFixer | 2.1.0 | 26595588 | analyzers | 1 | `analyzers/dotnet/cs/AsyncFixer.dll` |
| 49 | Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | 24752297 | msbuild | 42 | `buildTransitive/netstandard2.0/Microsoft.Maui.Controls.BindingSourceGen.dll` |
| 50 | Microsoft.SourceLink.AzureRepos.Git | 10.0.403 | 24435763 | msbuild | 34 | `tools/net/Microsoft.SourceLink.AzureRepos.Git.dll` |

## Rejected (examined, in rank order)

| Id | Version | Downloads | Reason |
|---|---|---|---|
| Microsoft.NET.Test.Sdk | 18.11.0 | 2009080596 | no build-time DLL |
| Microsoft.Build.Framework | 18.11.0 | 916544910 | no build-time DLL |
| NJsonSchema | 11.6.1 | 421263428 | no build-time DLL |
| Microsoft.NET.StringTools | 18.11.0 | 415101831 | no build-time DLL |
| Microsoft.Build | 18.11.0 | 345474468 | no build-time DLL |
| Microsoft.CodeAnalysis.Workspaces.MSBuild | 5.9.0 | 333512353 | no build-time DLL |
| Microsoft.Testing.Platform.MSBuild | 2.5.2 | 305531761 | no build-time DLL |
| Microsoft.VisualStudio.Web.CodeGenerators.Mvc | 10.0.2 | 296137684 | no build-time DLL |
| Microsoft.VisualStudio.Web.CodeGeneration | 10.0.2 | 295086001 | no build-time DLL |
| Bogus | 35.6.5 | 291802722 | no build-time DLL |
| Microsoft.Build.Utilities.Core | 18.11.0 | 287653985 | no build-time DLL |
| Microsoft.Build.Tasks.Core | 18.11.0 | 213490770 | no build-time DLL |
| Swashbuckle.AspNetCore.Newtonsoft | 10.3.1 | 210203041 | no build-time DLL |
| Microsoft.Build.Locator | 1.11.2 | 190444258 | no build-time DLL |
| NJsonSchema.Annotations | 11.6.1 | 141999952 | no build-time DLL |
| NJsonSchema.Yaml | 11.6.1 | 134638171 | no build-time DLL |
| Microsoft.CodeAnalysis.AnalyzerUtilities | 5.6.0 | 118702981 | no build-time DLL |
| NJsonSchema.NewtonsoftJson | 11.6.1 | 104833871 | no build-time DLL |
| Selenium.WebDriver.ChromeDriver | 157.0.8103.3800 | 84689336 | no build-time DLL |
| NewId | 4.0.1 | 84285575 | no build-time DLL |
| Microsoft.Build.Runtime | 18.11.0 | 76079210 | no build-time DLL |
| Microsoft.CodeAnalysis.FxCopAnalyzers | 3.3.2 | 74978277 | no build-time DLL |
| RandomDataGenerator.Net | 1.0.19.1 | 63530774 | no build-time DLL |
| Microsoft.VisualStudio.Threading.Only | 18.12.1 | 53984197 | no build-time DLL |
| NJsonSchema.Extensions | 0.2.0 | 43414353 | no build-time DLL |
| Microsoft.TypeScript.MSBuild | 7.0.1 | 42990789 | no build-time DLL |
| NJsonSchema.CodeGeneration | 11.6.1 | 38546589 | no build-time DLL |
| RestEase | 1.6.4 | 38295430 | no build-time DLL |
| xunit.v3.mtp-v1 | 3.2.2 | 37469159 | no build-time DLL |
| NJsonSchema.CodeGeneration.CSharp | 11.6.1 | 30009053 | no build-time DLL |
| AutoBogus | 2.13.1 | 29751203 | no build-time DLL |

## Kept packages, pinned by content

S4 reads these from the harness cache offline. Each `.nupkg` is pinned here by SHA-256 so a changed cache file shows
(S0–S3 review, Nit 5). Hashed 2026-11-06 from `%LOCALAPPDATA%/Silvergun/benign-corpus/packages`.

| Id | Version | SHA-256 of the .nupkg |
|---|---|---|
| Microsoft.EntityFrameworkCore.Analyzers | 10.0.14 | `84978f2cc4d108110b99980c6a260ad460bc9c9ce948338b1cb0eb248865b519` |
| Microsoft.CodeAnalysis.Analyzers | 5.9.0 | `3a1ff7ec1de65781d47c9c60742f7163a4e9ce9c09c701cd8202ded9a20d4995` |
| xunit.analyzers | 2.2.0 | `66d3c3b642e1f1ceaa702c0e1d8901d918268bf177690bc270a34d680b23d225` |
| Microsoft.AspNetCore.Components.Analyzers | 10.0.14 | `90461dc0c187da63d8ad3c2b533930cdd1321d2ec458ea9adb91fb7d81a4b676` |
| StyleCop.Analyzers | 1.1.118 | `0a30b57f9cf4b0fd7917a15e5ea2033ad64b1ea8239904f3a6c22b464c574442` |
| coverlet.msbuild | 10.1.0 | `2dd269f4d93130c21fa55a0898569077c1654313d314d5032407d913e28916b8` |
| Microsoft.AspNetCore.Razor.Design | 2.3.13 | `007db21708d158889485436cbefa0879b91372ca378108bd14ccf150e47a8723` |
| Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator | 4.0.1 | `480ff0c74a4d9f373a6dda61868b73db7ffea3102242865b2fb7c13e8ecaad2c` |
| NUnit.Analyzers | 4.15.0 | `38069d619404ad4c3d54ac3d80f9d1da4481ce1b533ebfa3c7b63e4f4366acaa` |
| Microsoft.NET.ILLink.Tasks | 10.0.14 | `e2a71b32b5c135dc2b0c87ea8fba6c9e677332e00bf959fbcdced239b825b75c` |
| Microsoft.AspNetCore.Mvc.Analyzers | 2.3.13 | `32268c9100f854fbd62ed3844802736bf79daf8025a623f9db9cb0167fc0fd2b` |
| Microsoft.Azure.Functions.Analyzers | 1.0.0 | `3c37f284075c3e71a21d8fc879e8f8bf5d18381564292dbf5ff6cf1ea90fb0d7` |
| Microsoft.VisualStudio.Threading.Analyzers | 18.12.1 | `c39e8dcebc83ead26cd23e8f69608ef789a7af6f9c7f8db1742a9275e1fa7b32` |
| Microsoft.Build.Tasks.Git | 10.0.403 | `9d21a711e9fce96b34e8c02f10069bc66a381d84a2912e65a14dc9c411135e29` |
| StyleCop.Analyzers.Unstable | 1.2.0.556 | `695a29edaf6bf97d91b191138278019b7a903c42223c15a01f389c1924c4ca67` |
| Microsoft.SourceLink.Common | 10.0.403 | `e99d7aea402042d04faa4971709718ebf256406b4c59f700cb1c8a739859c6a2` |
| Microsoft.Net.Compilers | 4.2.0 | `d1a8d866d6806202b2f1f5e21cb77839cef2606de9c0d9e6939a7e1f1baa4244` |
| dotnet-reportgenerator-globaltool | 5.5.12 | `f1ae28d9b8b5d7bc4f958fc5f1cd104298173e1f9dbd395c924a68cdeb972ddd` |
| SonarAnalyzer.CSharp | 10.35.0.4138 | `253e3678f5b33849f6727e7570c0c43bc8603e327df5b0e28967a19b1de3ed04` |
| Microsoft.Azure.Functions.Worker.Sdk.Generators | 1.4.0 | `6d644ddebc9331fc2885294b63822548b8f775e1955be1aa178be1047cecfbe4` |
| NSwag.MSBuild | 14.7.1 | `40a8819827ff7c59ac6a2c9512bf40fbf759c79c5c01d38770eea74aee658e38` |
| Microsoft.Azure.Functions.Worker.Sdk.Analyzers | 1.2.2 | `eab0877cf5ecc228826976004db7277c34ddb66e896a1b2ef0c9530e246190c1` |
| Microsoft.SourceLink.GitHub | 10.0.403 | `9c3252f8cbe1547bf8c12b7c65a7bc28985bab2d598ff97c13e0104c22d80cd5` |
| MessagePackAnalyzer | 3.1.12 | `848c795de5939b79fc9f8ba8573613c81b8f99ea81d52d308825badd6891c62c` |
| Microsoft.CodeAnalysis.NetAnalyzers | 10.0.403 | `17bc3cd141fa7e9c595673f3878927bf5729ace97a8fae8baf7ff33ba1648f88` |
| SpecFlow.Tools.MsBuild.Generation | 3.9.74 | `44d91d14e9d38238c29c176604dcbdc807fbf0112345567abd084de905e4b0c8` |
| MSTest.Analyzers | 4.5.2 | `065e1bb771c179ebcfe3d9f9c98eb9b8a29f9503ae77ca8807d01646cfb4822c` |
| dotnet-sonarscanner | 12.1.0 | `350a5bfbb0400b4516b397dacd72ad5eeb91bc5b7ef2c3c471894ad2507a223c` |
| Microsoft.CodeQuality.Analyzers | 3.3.2 | `b9e08c515b9b8ec224306751c51ef2513d4e4c5f5beb6048a7befc491e96da41` |
| Microsoft.NetCore.Analyzers | 3.3.2 | `d85e32e5d2663f15e1a359d0b50cc07f92cd75e72d8a1b8c661613c363942bc0` |
| Microsoft.NetFramework.Analyzers | 3.3.2 | `0951359fdfc92ddd05f055c4e0b92f379ec1100ba082651e61a7d6c10c735569` |
| Roslynator.Analyzers | 5.0.1 | `c34f0658e9219bcf615a70215be64bb9333ecfbfb6c60dd8cc7ef7be50edf580` |
| ReportGenerator | 5.5.12 | `0585502dee5aebb2d31583072c3f99fbbee94155e090512cde059c54b491496d` |
| Microsoft.CodeAnalysis.VersionCheckAnalyzer | 3.3.2 | `db514edd06be01d35c0a3019b1b35bf6fb899307a5774fcc3f5ee165829daef3` |
| Microsoft.Azure.Functions.Worker.Extensions.Http.AspNetCore.Analyzers | 1.0.4 | `785f04eca484cc16398c79e328a7c6e939643b020431c6e0a15b36f780bf11ff` |
| Microsoft.CodeAnalysis.BannedApiAnalyzers | 5.6.0 | `f2ef6b5cbd7ec027d87293e51a98c91a689fc96761fa803f7a85863f379c638c` |
| Microsoft.Extensions.ApiDescription.Client | 10.0.14 | `679b950d432ea05564b02f90d6c416c0e69b330c66dd373431946107cad90a68` |
| NSubstitute.Analyzers.CSharp | 1.0.17 | `1f23213493337b700b25b97bd69a6b8ee2c2a92f8a2c0fdb39e5f84a783f79be` |
| Riok.Mapperly | 4.3.1 | `77be3205434872d5e96db24dc96540a47fa45753775c442f968dcc1659f5a0a6` |
| Microsoft.Azure.WebJobs.Extensions.DurableTask.Analyzers | 0.5.0 | `c9b10494b4449db9e0c8b4e3c9421e73a012381eca480188db97b3cd2d0c7217` |
| Aspire.Hosting.AppHost | 13.6.4 | `2c58d4e0946e586c30003ec1a5e194b20d490dd274c3ee5c8d752cd59811697b` |
| GraphQL.Analyzers | 8.8.5 | `a37ffbb15ec0d84c7939b27c8ccc6b2934c0a9214d8ddad84f2627cd3b4ae090` |
| OpenCover | 4.7.1221 | `8518295792b5dd98a912e6c1d7865ab489f091431c3a7220fc55fc8f3187d34e` |
| Meziantou.Analyzer | 3.0.321 | `41d7534708262bd0b20dac70e5d95015f3a2ca9426edbcd80029d3c253693b5d` |
| Reqnroll.Tools.MsBuild.Generation | 3.3.4 | `6bd5cadd19065e56ea5ddb5b7da195678d8fe396f7806e90a342b55a3e2dee05` |
| Xamarin.Build.Download | 0.11.6 | `9e8e540f35d3b6beabf320b4de12930fc2b8f7c436cf66abf4604a8e01c37071` |
| Xamarin.AndroidX.Migration | 1.0.10 | `f28aa35bcd52f1956c10ee9e0f8895cb8d5f4c4f137d09b42e4e0f8db987779a` |
| AsyncFixer | 2.1.0 | `e76613665b87c66c7ca191182b71fd7d44f7c6ec014b9a9f8f0f99a7f20ea0e6` |
| Microsoft.Maui.Controls.Build.Tasks | 10.0.120 | `b41ab3a85c263bc74ff75f60f65189e741e8f5d27de28cfac8181dfdab1b044d` |
| Microsoft.SourceLink.AzureRepos.Git | 10.0.403 | `a53cd3b74f8e6a1c0b7c8643e926ff2e36ff985271561f744a21844e793cc2f2` |
