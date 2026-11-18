# Native binary base rates (2026-11-18)

Provenance: fresh `scan-package <nupkg> --json --no-yara --no-vulns --allow-incomplete` reports, offline, one guarded
run per package (`tools/guarded-dotnet.ps1`, Debug, net10.0), built from commit `aa12c87` ("Add NativeBinary finding",
`docs/agent/tasks/native-binaries-1.md`), 2026-11-18. Every package exited 0; no guard kills. Corpora:
`data/corpus/benign-top.manifest` (C100), `benign-top-ext.manifest` (C100+), `c-build.manifest` (C-build),
`benign-suspect.manifest` (C-suspect); selection and fetch provenance in `data/corpus/PROVENANCE.md` and
`c-build.provenance.md`. Top 200 = C100 and C100+ (disjoint). Each package keeps its own licence; only ids, versions,
package-relative paths, sizes and SHA-256 hashes are recorded. Paths are third-party data, escaped to printable ASCII
and cut. Per-binary rows are in the `-findings.tsv` beside this file. The same run reproduces the capability, indicator
and script-rule tables of `capability-base-rates-2026-11-16.md` exactly (no change from adding this pass).

## Reading this

- **Facts, not verdicts.** `NativeBinaries` lists every contained file whose header is PE, ELF or Mach-O, whatever its
  name: native code the CIL analysis cannot see, plus PEs it otherwise would not (ReadyToRun, mixed-mode C++/CLI,
  IL-only under a non-.dll/.exe name). Nothing here gates.
- **Counts are packages** (with the number of binaries in parentheses). Many packages ship one binary per RID, so
  binary counts run high (Grpc.Tools: 12 compilers/plugins across six platforms).
- **Native is rare in popular libraries:** 4% of the top 200 ship any, 2% a native executable; in the suspect corpus
  21% and 10%. ReadyToRun: none in any corpus (runtime packs, where it is common, are not in these corpora).
- **Many "native executables" are .NET apphosts:** `GetDocument.Insider.exe`, `ReportGenerator.exe`, `dotnet-nswag.exe`,
  `dotnet-ef.exe` shims are the native launcher stub that starts a managed tool. They are correctly native PEs; telling
  an apphost from arbitrary native code is a possible refinement.
- **IL-only outside the CIL inventory:** only the two WebView2 `.winmd` files (Windows Runtime metadata, which has no
  code); the pass is quiet on benign data.
- **Mixed-mode:** only EasyHook's `EasyLoad32/64.dll` (C++/CLI loader stubs), each shipped twice (`content/` and
  `contentFiles/`).

- C100: 100 reports; status {'Completed': 100}
- C100+: 100 reports; status {'Completed': 100}
- Top 200: 200 reports; status {'Completed': 200}
- C-build: 50 reports; status {'Completed': 50}
- C-suspect: 68 reports; status {'Completed': 68}

## Packages with at least one (count, % of corpus; binaries in parentheses)

| Measure | C100 | C100+ | Top 200 | C-build | C-suspect |
|---|---:|---:|---:|---:|---:|
| Any listed binary | 5 (5%) (7) | 3 (3%) (40) | 8 (4%) (47) | 5 (10%) (16) | 14 (21%) (145) |
| Native code (Code=Native) | 5 (5%) (7) | 3 (3%) (40) | 8 (4%) (47) | 5 (10%) (16) | 14 (21%) (135) |
| Native executable | 1 (1%) (1) | 2 (2%) (13) | 3 (2%) (14) | 3 (6%) (12) | 7 (10%) (32) |
| Native shared library | 4 (4%) (6) | 1 (1%) (25) | 5 (2%) (31) | 2 (4%) (4) | 10 (15%) (103) |
| ReadyToRun PE | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) |
| Mixed-mode PE (C++/CLI) | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) | 1 (1%) (8) |
| IL-only PE outside CIL inventory | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) | 1 (1%) (2) |
| Malformed header | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) | 0 (0%) (0) |

## Binaries by Format

| Value | C100 | C100+ | Top 200 | C-build | C-suspect |
|---|---:|---:|---:|---:|---:|
| PE | 7 | 8 | 15 | 16 | 86 |
| Elf | 0 | 24 | 24 | 0 | 42 |
| MachO | 0 | 4 | 4 | 0 | 16 |
| MachOUniversal | 0 | 4 | 4 | 0 | 1 |

## Binaries by Role

| Value | C100 | C100+ | Top 200 | C-build | C-suspect |
|---|---:|---:|---:|---:|---:|
| Tools | 1 | 13 | 14 | 16 | 70 |
| Runtimes | 6 | 27 | 33 | 0 | 27 |
| Build | 0 | 0 | 0 | 0 | 18 |
| Content | 0 | 0 | 0 | 0 | 16 |
| Other | 0 | 0 | 0 | 0 | 13 |
| Lib | 0 | 0 | 0 | 0 | 1 |

## Binaries by Architecture (native code only)

| Value | C100 | C100+ | Top 200 | C-build | C-suspect |
|---|---:|---:|---:|---:|---:|
| x64 | 3 | 11 | 14 | 14 | 48 |
| x86 | 2 | 7 | 9 | 2 | 40 |
| arm64 | 2 | 8 | 10 | 0 | 34 |
| arm | 0 | 4 | 4 | 0 | 8 |
| x64+arm64 | 0 | 4 | 4 | 0 | 1 |
| ppc64 | 0 | 1 | 1 | 0 | 4 |
| riscv | 0 | 2 | 2 | 0 | 0 |
| s390x | 0 | 2 | 2 | 0 | 0 |
| mips | 0 | 1 | 1 | 0 | 0 |

## Packages shipping native or IL-only-outside-inventory executables

- **C100** (1 packages)
  - Microsoft.Extensions.ApiDescription.Server.10.0.11 (1): tools/net10.0/GetDocument.Insider.exe
- **C100+** (2 packages)
  - EO.WebBrowser.26.3.58 (1): tools/eowp.exe
  - Grpc.Tools.2.85.0 (12): tools/linux_arm64/grpc_csharp_plugin, tools/linux_arm64/protoc, tools/linux_x64/grpc_csharp_plugin, tools/linux_x64/protoc ...
- **C-build** (3 packages)
  - NSwag.MSBuild.14.7.1 (6): tools/Net100/dotnet-nswag.exe, tools/Net100/NSwag.AspNetCore.Launcher.exe, tools/Net80/dotnet-nswag.exe, tools/Net80/NSwag.AspNetCore.Launcher.exe ...
  - ReportGenerator.5.5.12 (3): tools/net10.0/ReportGenerator.exe, tools/net8.0/ReportGenerator.exe, tools/net9.0/ReportGenerator.exe
  - dotnet-reportgenerator-globaltool.5.5.12 (3): tools/net10.0/any/ReportGenerator.exe, tools/net8.0/any/ReportGenerator.exe, tools/net9.0/any/ReportGenerator.exe
- **C-suspect** (7 packages)
  - Clowd.Squirrel.2.11.1 (8): tools/7z.exe, tools/rcedit.exe, tools/Setup.exe, tools/signtool.exe ...
  - Microsoft.Playwright.1.64.1 (5): .playwright/node/darwin-arm64/node, .playwright/node/darwin-x64/node, .playwright/node/linux-arm64/node, .playwright/node/linux-x64/node ...
  - Selenium.WebDriver.4.52.0 (3): runtimes/linux-arm64/native/selenium-manager, runtimes/osx/native/selenium-manager, runtimes/win/native/selenium-manager.exe
  - Selenium.WebDriver.ChromeDriver.157.0.8103.7800 (4): driver/linux64/chromedriver, driver/mac64/chromedriver, driver/mac64arm/chromedriver, driver/win32/chromedriver.exe
  - dotnet-ef.11.0.0 (4): tools/net10.0/any/ef.exe, tools/net10.0/any/shims/win-arm64/dotnet-ef.exe, tools/net10.0/any/shims/win-x64/dotnet-ef.exe, tools/net10.0/any/shims/win-x86/dotnet-ef.exe
  - squirrel.windows.2.0.1 (7): tools/7z.exe, tools/rcedit.exe, tools/Setup.exe, tools/signtool.exe ...
  - xunit.runner.console.2.9.3 (1): tools/net6.0/xunit.console.exe

## IL-only PEs outside the CIL inventory (all)

- C-suspect / Microsoft.Web.WebView2.1.0.4314.35: `lib/Microsoft.Web.WebView2.Core.winmd` (SharedLibrary, Lib)
- C-suspect / Microsoft.Web.WebView2.1.0.4314.35: `tools/wv2winrt/winrt_winmd.winmd` (SharedLibrary, Tools)
