# Hidden payloads 1: benign base rates, c-build.manifest (C-build), Debug, 2026-11-16

Provenance: `data/corpus/c-build.manifest` (50 entries), each scanned from the local benign-corpus package cache
(`%LOCALAPPDATA%\Silvergun\benign-corpus\packages`, fetched earlier from nuget.org; nothing was downloaded for this run)
with `scan-package <nupkg> --json --no-yara --no-vulns --allow-incomplete` (offline), one guarded run per package, on the
working tree after `docs/agent/tasks/hidden-payloads-1.md` review round 4. All 50 exited 0. Package names and file paths
below are third-party data, tab/newline-cleaned and cut; per-finding rows are in the `-findings.tsv` beside this file.
Informational base rates: obfuscation findings never gate. Benign embedded PEs seen here: coverlet's
`coverlet.template.dll` and ILRepack's `pdbstr.exe` (build tooling); substring PNGs are HTML `data:` URIs.

- reports read: 50; unreadable: 0
- packages with any obfuscation finding: 34 (68%)
- packages with any non-image finding (the attention headline): 34 (68%)

| Kind | Source | Packages | % | Findings | DetectedAs |
|---|---|---:|---:|---:|---|
| EncodedArchive | FieldData | 1 | 2% | 1 | gzip (1) |
| EncodedArchive | Resource | 1 | 2% | 16 | gzip (16) |
| EncodedExecutable | Resource | 2 | 4% | 6 | Windows PE (6) |
| EncodedImage | Substring | 3 | 6% | 11 | PNG (11) |
| EncodedImage | Resource | 2 | 4% | 3 | PNG (2), ICO (1) |
| EncodedText | Constant | 2 | 4% | 87 | UTF-8 text (87) |
| EncodedText | Substring | 1 | 2% | 2 | UTF-8 text (2) |
| HighEntropyBlob | Constant | 34 | 68% | 2824 | high-entropy base64 (2824) |
| HighEntropyBlob | Folded | 1 | 2% | 2 | high-entropy base64 (2) |

## Packages per cell

- EncodedArchive/FieldData: dotnet-sonarscanner.12.1.0
- EncodedArchive/Resource: NSwag.MSBuild.14.7.1
- EncodedExecutable/Resource: Xamarin.AndroidX.Migration.1.0.10, coverlet.msbuild.10.1.0
- EncodedImage/Substring: NSwag.MSBuild.14.7.1, ReportGenerator.5.5.12, dotnet-reportgenerator-globaltool.5.5.12
- EncodedImage/Resource: OpenCover.4.7.1221, Reqnroll.Tools.MsBuild.Generation.3.3.4
- EncodedText/Constant: SonarAnalyzer.CSharp.10.35.0.4138, dotnet-sonarscanner.12.1.0
- EncodedText/Substring: Reqnroll.Tools.MsBuild.Generation.3.3.4
- HighEntropyBlob/Constant: AsyncFixer.2.1.0, MSTest.Analyzers.4.5.2, Meziantou.Analyzer.3.0.321, Microsoft.AspNetCore.Razor.Design.2.3.13, Microsoft.Azure.Functions.Worker.Extensions.Http.AspNetCore.Analyzers.1.0.4, Microsoft.Azure.Functions.Worker.Sdk.Generators.1.4.0, Microsoft.Azure.WebJobs.Extensions.DurableTask.Analyzers.0.5.0, Microsoft.Azure.WebJobs.Script.ExtensionsMetadataGenerator.4.0.1, Microsoft.Build.Tasks.Git.10.0.403, Microsoft.CodeAnalysis.Analyzers.5.9.0, Microsoft.CodeAnalysis.BannedApiAnalyzers.5.6.0, Microsoft.CodeAnalysis.NetAnalyzers.10.0.403, Microsoft.CodeQuality.Analyzers.3.3.2, Microsoft.EntityFrameworkCore.Analyzers.10.0.14, Microsoft.Maui.Controls.Build.Tasks.10.0.120, Microsoft.NET.ILLink.Tasks.10.0.14, Microsoft.Net.Compilers.4.2.0, Microsoft.NetCore.Analyzers.3.3.2, Microsoft.NetFramework.Analyzers.3.3.2, Microsoft.VisualStudio.Threading.Analyzers.18.12.1, NSubstitute.Analyzers.CSharp.1.0.17, NSwag.MSBuild.14.7.1, OpenCover.4.7.1221, ReportGenerator.5.5.12, Reqnroll.Tools.MsBuild.Generation.3.3.4, Roslynator.Analyzers.5.0.1, SonarAnalyzer.CSharp.10.35.0.4138, SpecFlow.Tools.MsBuild.Generation.3.9.74, StyleCop.Analyzers.1.1.118, StyleCop.Analyzers.Unstable.1.2.0.556, Xamarin.AndroidX.Migration.1.0.10, coverlet.msbuild.10.1.0, dotnet-reportgenerator-globaltool.5.5.12, dotnet-sonarscanner.12.1.0
- HighEntropyBlob/Folded: dotnet-sonarscanner.12.1.0
