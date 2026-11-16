# Corpus expansion draft (2026-11-16)

**Fetched 2026-11-16:** `benign-top-ext.manifest` (100) and `benign-suspect.manifest` (68 of 71). Results, the
family-key correction and request counts: `PROVENANCE.md`, "Expansion, 2026-11-16". The text below is the
pre-fetch draft, kept as written.

Two new pinned manifests, in the same `id,version` format as `benign-top.manifest`. Nothing here has been fetched.
Versions are resolved later by `Get-Corpus.ps1` (highest stable from PackageBaseAddress). Ids that do not resolve are
dropped and listed in the provenance file, not replaced by hand. `benign-top.manifest` (C100) stays frozen as the
comparison baseline.

## 1. `benign-top-ext.manifest` (C100+, ~100 packages)

**Rule** (fixed before any fetch; ids cannot be listed yet: the 2026-08-20 search cache is gone, and the C-build cache
holds keyword searches only):

1. `SearchQueryService`, `q=` (empty), `take=100`, `skip=0,100,200,300`, `prerelease=false`, `semVerLevel=2.0.0`. Rank by
   `totalDownloads`, as for C100. 4 requests.
2. Walk ranks in order, skipping ids already in C100, C-build or the adversarial manifest, until 100 are kept.
3. **Skip, recording the reason:**
   - `runtime.*` and `*.runtime.native.*` stubs, `*.Manifest-*` / `Microsoft.NET.Workload.*` SDK manifests, and
     `*.Ref` / reference-assembly-only packages: no managed implementation to scan.
   - **Family cap**: at most 3 new ids per family (the id up to its second dot, e.g. `Microsoft.Extensions`,
     `Serilog.Sinks`, `AWSSDK`). This is the main lever against "more of the same".
4. Pin each kept id to its highest stable version: about 100 to 130 version lookups.

Estimated cost: ~105-135 API requests at 1/s (~2-3 minutes), plus ~100 `.nupkg` downloads at scan time.

## 2. `benign-suspect.manifest` (C-suspect, ~70 packages)

Benign packages chosen **because** they should look like something: embedded executables or archives,
obfuscation, native loaders, code that downloads and runs things, runtime patching, scripting hosts. The question is
not "do they come back clean" but "what does a benign package with this capability look like", for the base rates an
agent will use. Like the adversarial set, a hit is expected, and everything is reported by name.

Hypotheses are recorded here before measurement.

### A. Commercial obfuscated or protected libraries
Hypothesis: heavy `HighEntropyBlob` and `EncodedArchive` (compressed embedded resources), obfuscated names, possibly
encrypted string tables (Folded/FieldData).
- `Aspose.Words`, `Aspose.Cells`, `Aspose.PDF`
- `Syncfusion.Licensing`, `Syncfusion.Pdf.Net.Core`, `Syncfusion.XlsIO.Net.Core`
- `Spire.PDF`, `FreeSpire.PDF`
- `IronPdf`
- `DevExpress.Xpo`
- `Devart.Data.MySql`
- `EO.Pdf`

### B. Licensing and protection SDKs
Hypothesis: embedded public keys (high entropy), machine-fingerprint reads (WMI, registry, MAC), network licence checks.
- `Standard.Licensing`, `Portable.Licensing`, `Cryptolens.Licensing`, `LicenseSpring`
- `SmartAssembly.Attributes`, `Obfuscar`

### C. Embedded or merged assemblies
Hypothesis: `EncodedExecutable` or `EncodedArchive` resources (Costura stores deflated DLLs); real PEs in resources
or `tools/`.
- `Costura.Fody`, `Fody`
- `ILMerge`, `ILRepack`, `ILRepack.Lib.MSBuild.Task`
- `NuGet.CommandLine` (merged nuget.exe)
- `squirrel.windows`, `Clowd.Squirrel`, `Velopack`

### D. Native loaders and wrappers
Hypothesis: native-library loading (`NativeLibrary.Load`, `DllImport` resolution), file writes of extracted natives,
PEs as content files.
- `SkiaSharp`, `SQLitePCLRaw.bundle_e_sqlite3`, `LibGit2Sharp`, `Magick.NET-Q16-AnyCPU`, `OpenCvSharp4`
- `Microsoft.ML.OnnxRuntime`, `Microsoft.Web.WebView2`, `Microsoft.ClearScript`, `Tesseract`

### E. Downloaders and process launchers
Hypothesis: `Process.Start` and HTTP download of executables by design: the clearest "benign download-and-run"
base rate.
- `Microsoft.Playwright`, `PuppeteerSharp` (download a browser, then launch it)
- `Selenium.WebDriver` (ships selenium-manager), `Selenium.WebDriver.ChromeDriver` (ships chromedriver.exe),
  `WebDriverManager`
- `Autoupdater.NET.Official`, `NetSparkleUpdater.SparkleUpdater` (self-updaters)
- `CliWrap`, `Medallion.Shell`, `SimpleExec`

### F. Install-time and tool packages
Hypothesis: legacy `install.ps1` / `init.ps1` scripts, and executables under `tools/`.
- `EntityFramework` (6.x, init/install scripts)
- `xunit.runner.console`, `NUnit.ConsoleRunner`
- `GitVersion.Tool`, `Nerdbank.GitVersioning`
- `dotnet-ef`, `Cake.Tool`, `dotnet-script`

### G. Runtime patching, hooking and PE tooling
Hypothesis: executable-memory writes (`VirtualProtect`, `VirtualAlloc`), detours, IL emission; PE and opcode tables
in field data (FieldData/EncodedExecutable false positives).
- `Lib.Harmony`, `MonoMod.RuntimeDetour`, `Reloaded.Hooks`, `EasyHook`
- `Iced`, `PeNet`, `AsmResolver.PE`, `dnlib`

### H. Scripting and dynamic-code hosts
Hypothesis: dynamic compile-and-execute capability (`Assembly.Load(byte[])`, `CSharpScript`).
- `Microsoft.CodeAnalysis.CSharp.Scripting`, `Jint`, `IronPython`, `NLua`, `Microsoft.PowerShell.SDK`

### I. System management
Hypothesis: WMI, scheduled tasks, services and registry access: autorun-adjacent capability with no malice.
- `System.Management`, `TaskScheduler`, `Topshelf`, `Vanara.PInvoke.Kernel32`

**Count: 71 ids** (A 12, B 6, C 9, D 9, E 10, F 8, G 8, H 5, I 4). Some may not resolve. All are benign by assumption (download counts and publisher), not by proof
(ADR-0021).

### Notes for review
- **Large downloads:** `Microsoft.PowerShell.SDK`, `Microsoft.Playwright`, `Magick.NET-Q16-AnyCPU`,
  `Microsoft.ML.OnnxRuntime` and `IronPdf` are each tens to hundreds of MB. Drop any that the harness's size limits would
  reject anyway.
- **Commercial EULAs (A):** only ids and versions go in the repo, and `.nupkg` files stay in the local cache, as now.
  Whether downloading these for analysis is acceptable is your call.
- **Overlap:** none with C100, C-build or the adversarial manifest; checked by id.

## Network cost of both

About 4 search requests plus ~170-200 version lookups at 1/s (~3-4 minutes), cached, with the 429/403/challenge
hard stops already in `Get-Corpus.ps1`. Then ~160 `.nupkg` downloads at scan time through `PackageCache`.
`Get-Corpus.ps1` needs two new `-Manifest` modes (`top-ext`, `suspect`). The suspect mode takes this fixed id list
and does no search.
