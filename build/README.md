# build/

Helper scripts. Nothing here is wired into any build.

## fetch-yara.ps1

Fetches a pinned, prebuilt YARA engine and verifies it before anything is installed. Run it with
Windows PowerShell 5.1:

    powershell -NoProfile -ExecutionPolicy Bypass -File build\fetch-yara.ps1 [-Engine Classic|YaraX|YaraXCapi] [-Platform win-x64|linux-x64] [-SkipDownload] [-Force] [-ZipPath <file>]

| Engine / Platform | Asset | Installs into | Cache |
| --- | --- | --- | --- |
| `Classic` / `win-x64` (default) | yara 4.5.5 `yara-4.5.5-2368-win64.zip` | `artifacts/tools/yara/win-x64/` | `artifacts/cache/yara/` |
| `YaraX` / `win-x64` | YARA-X 1.22.0 `yara-x-v1.22.0-x86_64-pc-windows-msvc.zip` | `artifacts/tools/yara-x/win-x64/` | `artifacts/cache/yara-x/` |
| `YaraX` / `linux-x64` | YARA-X 1.22.0 `yara-x-v1.22.0-x86_64-unknown-linux-gnu.tar.gz` | `artifacts/tools/yara-x/linux-x64/` | `artifacts/cache/yara-x/` |
| `YaraXCapi` / `win-x64` (only) | YARA-X 1.22.0 C API `yara-x-capi-v1.22.0-x86_64-pc-windows-msvc.zip` | `artifacts/tools/yara-x-capi/win-x64/` | `artifacts/cache/yara-x-capi/` |

- The outer archive is checked against GitHub's asset size and sha256 digest **before** extraction.
- Only the expected binary (`yara64.exe`/`yarac64.exe`, `yr.exe`, `yr`) and any licence file are
  extracted, to names the script chooses. For `YaraXCapi` the expected files are `yara_x_capi.dll`,
  its import library `yara_x_capi.dll.lib` and the header `yara_x.h`; the zip's static library
  `yara_x_capi.lib` and `yara_x_capi.def` are listed and reported, never extracted. The `.tar.gz` is handled by `%SystemRoot%\System32\tar.exe`
  (bsdtar): first a listing, then one member per extraction into a fresh scratch directory.
- Each binary must match its own pin. **Pins are empty until reviewed**: with an empty pin the
  script refuses to install, prints the observed sha256 and exits 3. Record pins in the script.
- Every run re-verifies the installed copy. Unexpected items in the install directory are an error.
- The script never executes the binaries it fetches, and never loads the C API DLL.
- `-ZipPath` (alias `-ArchivePath`) installs from a local copy, after the same checks.

Exit codes and details are in the script's comment-based help (`Get-Help build\fetch-yara.ps1 -Full`).

## init-yara-x.ps1

Checks out the `ext/yara-x` submodule without upstream's `testdata/` directories (malware samples and
macro dumps for upstream's module tests, which antivirus quarantines; the C API build doesn't use them).
Use it instead of `git submodule update --init` for this submodule:

    powershell -NoProfile -ExecutionPolicy Bypass -File build\init-yara-x.ps1

- **Fresh clone:** blobless clone (`--filter=blob:none`), so excluded files are never downloaded.
  Then a non-cone sparse-checkout (`/*`, `!testdata/`) and checkout of the commit the index records.
- **Existing checkout:** applies the same sparse-checkout in place.
- Sparse-checkout is local git configuration and can't be committed, so each clone of Silvergun has
  to run the script.
