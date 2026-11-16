# Hidden payloads 1: benign base rates, benign-suspect.manifest (C-suspect), Debug, 2026-11-16

Provenance: `data/corpus/benign-suspect.manifest` (68 entries chosen because they should look like something; categories and hypotheses in `data/corpus/corpus-expansion-draft.md`). All 68 exited 0. Embedded executables seen: Cake.Tool (reference assemblies), CliWrap (`Signaler.exe`), Costura.Fody (bundled DLLs), ILRepack (`pdbstr.exe`), Lib.Harmony (native exception helpers, ELF and Mach-O), NuGet.CommandLine (merged satellite resource DLLs). each entry scanned from the local benign-corpus package cache (`%LOCALAPPDATA%\Silvergun\benign-corpus\packages`), downloaded 2026-11-16 from `https://api.nuget.org/v3-flatcontainer/` at 1 request/s with a zip-magic check (163 downloads, 1.67 GB, no refusals; 5 already cached), with `scan-package <nupkg> --json --no-yara --no-vulns --allow-incomplete` (offline), one guarded run per package, on the working tree after `docs/agent/tasks/hidden-payloads-1.md` review round 4. Manifest selection and request counts: `data/corpus/PROVENANCE.md`, "Expansion, 2026-11-16". Each package keeps its own licence; only ids, versions and finding rows are recorded here. Package names, resource names and paths below are third-party data, tab/newline-cleaned and cut; per-finding rows are in the `-findings.tsv` beside this file. Informational base rates: obfuscation findings never gate.

- reports read: 68; unreadable: 0
- packages with any obfuscation finding: 38 (56%)
- packages with any non-image finding (the attention headline): 37 (54%)

| Kind | Source | Packages | % | Findings | DetectedAs |
|---|---|---:|---:|---:|---|
| EncodedArchive | FieldData | 4 | 6% | 40 | zip (24), gzip (16) |
| EncodedArchive | Resource | 6 | 9% | 175 | zip (167), gzip (8) |
| EncodedExecutable | Resource | 7 | 10% | 419 | Windows PE (371), ELF (24), Mach-O (24) |
| EncodedImage | FieldData | 5 | 7% | 25 | PNG (20), JPEG (5) |
| EncodedImage | Resource | 5 | 7% | 1319 | PNG (805), ICO (289), JPEG (225) |
| EncodedText | Constant | 1 | 1% | 1825 | UTF-8 text (1825) |
| HighEntropyBlob | Constant | 30 | 44% | 902 | high-entropy base64 (902) |
| HighEntropyBlob | Folded | 4 | 6% | 14 | high-entropy base64 (14) |

## Packages per cell

- EncodedArchive/FieldData: Aspose.Words.26.11.0, EO.Pdf.26.3.58, FreeSpire.PDF.12.4.0, Spire.PDF.12.11.0
- EncodedArchive/Resource: Aspose.Cells.26.11.0, Aspose.Words.26.11.0, EO.Pdf.26.3.58, FreeSpire.PDF.12.4.0, IronPython.3.4.2, Spire.PDF.12.11.0
- EncodedExecutable/Resource: Cake.Tool.7.0.0, CliWrap.3.10.5, Costura.Fody.6.2.0, ILRepack.2.0.48, ILRepack.Lib.MSBuild.Task.2.0.48, Lib.Harmony.2.4.3, NuGet.CommandLine.8.0.0
- EncodedImage/FieldData: FreeSpire.PDF.12.4.0, PeNet.6.1.2, Spire.PDF.12.11.0, Syncfusion.Pdf.Net.Core.35.1.46, Syncfusion.XlsIO.Net.Core.35.1.46
- EncodedImage/Resource: Aspose.Words.26.11.0, FreeSpire.PDF.12.4.0, Spire.PDF.12.11.0, Syncfusion.Licensing.35.1.46, Syncfusion.XlsIO.Net.Core.35.1.46
- EncodedText/Constant: Syncfusion.Pdf.Net.Core.35.1.46
- HighEntropyBlob/Constant: AsmResolver.PE.6.1.0, Autoupdater.NET.Official.1.9.3, Cake.Tool.7.0.0, Clowd.Squirrel.2.11.1, EntityFramework.6.5.2, Fody.6.9.3, GitVersion.Tool.6.8.2, ILMerge.3.0.41, ILRepack.2.0.48, ILRepack.Lib.MSBuild.Task.2.0.48, IronPython.3.4.2, Jint.4.18.0, Lib.Harmony.2.4.3, Microsoft.Playwright.1.64.1, Microsoft.Web.WebView2.1.0.4314.35, NUnit.ConsoleRunner.3.22.0, Nerdbank.GitVersioning.3.10.94, NuGet.CommandLine.8.0.0, Obfuscar.2.2.50, PeNet.6.1.2, PuppeteerSharp.25.17.1, Selenium.WebDriver.4.52.0, Syncfusion.Pdf.Net.Core.35.1.46, Syncfusion.XlsIO.Net.Core.35.1.46, System.Management.11.0.0, TaskScheduler.2.12.2, dnlib.4.5.0, dotnet-ef.11.0.0, dotnet-script.2.0.1, squirrel.windows.2.0.1
- HighEntropyBlob/Folded: Cake.Tool.7.0.0, Clowd.Squirrel.2.11.1, NuGet.CommandLine.8.0.0, dotnet-script.2.0.1

Note: Aspose.Words and Spire.PDF/FreeSpire.PDF obfuscate type names with control characters, Unicode spaces,
zero-width spaces (Aspose) and single CJK/Hangul characters (Spire). Every character outside printable ASCII
in a name is written here as `\uXXXX`. No embedded instructions were found; these are obfuscated identifiers.
