<#
.SYNOPSIS
    Fetch a pinned prebuilt YARA engine, verify it against pinned sha256 hashes, and install it
    under artifacts/tools/. Classic yara 4.5.5 for Windows x64 (the default), YARA-X 1.22.0
    (yr) for Windows x64 or Linux x64, or the YARA-X 1.22.0 C API (DLL, import library, header)
    for Windows x64.

.DESCRIPTION
    Four pinned assets are known, all official VirusTotal releases. -Engine/-Platform pick one:

      -Engine Classic (default; win-x64 only) -> artifacts/tools/yara/win-x64/, cache artifacts/cache/yara/
      https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip
      2,232,629 bytes, sha256 352396c8a3d9b31b157a4820abd3b9347fc934a2314cdda8a4f566a5570163e4

      -Engine YaraX -Platform win-x64 (default platform) -> artifacts/tools/yara-x/win-x64/
      https://github.com/VirusTotal/yara-x/releases/download/v1.22.0/yara-x-v1.22.0-x86_64-pc-windows-msvc.zip
      9,081,400 bytes, sha256 eac36a58699b94d3732a7fe1d8453fe89e0077bb18ac2c99b4c2ee102a431f2e

      -Engine YaraX -Platform linux-x64 -> artifacts/tools/yara-x/linux-x64/
      https://github.com/VirusTotal/yara-x/releases/download/v1.22.0/yara-x-v1.22.0-x86_64-unknown-linux-gnu.tar.gz
      10,347,394 bytes, sha256 7f470770b2c1a0d97f02298fc194978d999074d147d003d33dd62775761439db

      (both YARA-X assets are cached in artifacts/cache/yara-x/)

      -Engine YaraXCapi (win-x64 only) -> artifacts/tools/yara-x-capi/win-x64/, cache artifacts/cache/yara-x-capi/
      https://github.com/VirusTotal/yara-x/releases/download/v1.22.0/yara-x-capi-v1.22.0-x86_64-pc-windows-msvc.zip
      20,798,844 bytes, sha256 40317f65781e3a17bffe31f9837143a51c1c28ce5061eac2b90695fbb30e1664
      The zip is flat: yara_x_capi.dll, yara_x_capi.dll.lib (import library), yara_x.h,
      yara_x_capi.def and yara_x_capi.lib (static library, 64,117,162 bytes). Only the DLL, its
      import library and the header are extracted and installed; every other entry is listed and
      reported, never installed. For this engine only, an entry over the size limit below is listed
      by its declared size (not hashed, never extracted) instead of failing the run.

    Each archive sha256 is GitHub's own asset digest for that release asset, and it is the trust
    anchor. Order of operations:

      1. The archive is downloaded into a fresh, randomly named scratch directory.
      2. Its size and sha256 are checked against the pin BEFORE anything is extracted. On a
         mismatch the file is deleted and the script stops.
      3. Zip: the verified zip is listed (name, size, sha256 of every entry) using .NET's
         System.IO.Compression, not Expand-Archive. Only the expected entries are extracted, to
         file names this script chooses, so an entry's own path is never used as a destination.
         tar.gz: Windows PowerShell 5.1 has no tar API, so Windows' own bsdtar
         (%SystemRoot%\System32\tar.exe, never whatever "tar" is on PATH) is used, and only on
         the verified archive. Members are listed first (tar -tzf / -tvzf) and unexpected ones
         are reported. Each expected member is then extracted on its own (tar -xzf <archive>
         -C <fresh dir> <member>) into a fresh scratch directory, which must then hold exactly
         that one regular file (no links); it is hashed and moved to a name this script chooses.
         Member names are used only if they are plain relative paths with no glob characters.
         No binary data passes through the PowerShell pipeline.
      4. Each extracted binary (yara64.exe, yarac64.exe; yr.exe / yr; or, for the C API, the
         DLL, import library and header, all called "binaries" below) is checked against its
         own pin. A binary whose pin is empty is NOT installed: the script prints the sha256 it
         observed so the pin can be recorded after review, and exits non-zero.
      5. The binaries, any licence file in the archive (the yara 4.5.5 win64 zip holds only
         yara64.exe and yarac64.exe) and a PROVENANCE.txt are copied into the install directory,
         and the installed copies are hashed again.

    Every run re-verifies the installed binaries against the pins, whether or not anything was
    downloaded. A verified archive is kept in the cache directory so that a later run (for example,
    after the inner pins have been recorded) does not fetch it again; a cached archive is
    re-verified against the pin every time it is used. Unexpected entries in the archive, and
    missing expected ones, are reported; unexpected entries are never installed.

    This script never executes yara, yarac or yr, and never loads the YARA-X C API DLL. The only
    program it runs is Windows' tar.exe, and only for the Linux .tar.gz.

    WHY 4.5.5 AND NOT 4.5.8 (ADR-0033, "Engine-version finding"):
    yara 4.5.6, 4.5.7 and 4.5.8 (all published 2026-07-28) fix memory-safety bugs in parsers that
    handle hostile input. The 4.5.7/4.5.8 PE-module fixes are reachable by Silvergun: an undersized
    rich header and MAX_RESOURCES, the pe_parse_exports count overflow and e_lfanew sign, Authenticode
    digest buffers that were not null-terminated, and delayed-import hardening. 16 of Silvergun's
    rule files import "pe" (including certificate/blocklist.yara) and every .NET assembly is a PE.
    VirusTotal published no Windows binaries for 4.5.6-4.5.8; the newest prebuilt win64 zip is
    this 4.5.5 one, so THIS BINARY DOES NOT HAVE THOSE FIXES. It is no worse than the libyara 4.5.5
    that Silvergun runs in-process on Windows today, and running it out of process isolates a
    parser bug to one worker, but it is a stepping stone: a patched Windows engine needs a
    source build.

    Exit codes:
      0  installed copy verified, or freshly installed and verified
      1  unexpected error (including a tar.exe failure), or contradictory parameters
      2  the archive did not match the pinned size/sha256 (deleted; nothing extracted)
      3  an extracted binary has no recorded pin (observed sha256 printed; nothing installed)
      4  the archive lacks an expected binary, has an ambiguous or unusable one, or an extracted
         binary does not match its pin
      5  an installed file failed verification, the install directory holds an unexpected item,
         or a binary is missing and nothing may be fetched

    This script is a spike tool (docs/agent/tasks/yara-native-windows-spike.md and
    docs/agent/tasks/yara-x-spike.md). It is not wired into any build. Its structure (pinned
    hashes, verify on every run, refuse what cannot be verified) follows the ideas of the user's
    reference/scripts/build.ps1; no code was copied.

.PARAMETER SkipDownload
    Never touch the network. The installed copy is still verified, and a mismatch still fails.
    If the binaries are not installed, they are installed from -ZipPath or from the cached archive
    (both verified against the pin first); with neither, the script fails.

.PARAMETER Force
    Ignore the installed copy and the cached archive: fetch the archive again (or re-read
    -ZipPath), verify it, and reinstall. Cannot be combined with -SkipDownload unless -ZipPath
    is given.

.PARAMETER ZipPath
    Use this local file instead of downloading (alias -ArchivePath; it may be the .tar.gz). It is
    copied into the scratch directory and goes through exactly the same checks as a download: a
    file that does not match the pin is rejected before extraction and the scratch copy is
    deleted (the file at -ZipPath itself is left alone). Intended for offline installs from a
    hand-fetched copy, and for testing the rejection path with a deliberately altered archive.

.PARAMETER Engine
    Classic (default): yara 4.5.5, Windows x64 only. YaraX: YARA-X 1.22.0 (yr). YaraXCapi: the
    YARA-X 1.22.0 C API (DLL, import library, header), Windows x64 only.

.PARAMETER Platform
    win-x64 (default) or linux-x64. linux-x64 is only available with -Engine YaraX. The Linux
    binary is stored on NTFS, which keeps no executable bit; it is meant to be copied into
    WSL/Linux by the caller.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File build\fetch-yara.ps1
    Verify the installed copy; fetch, verify and install it if it is missing.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File build\fetch-yara.ps1 -SkipDownload
    Verify the installed copy without touching the network.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File build\fetch-yara.ps1 -Force
    Re-fetch the zip, re-verify everything and reinstall.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File build\fetch-yara.ps1 -ZipPath C:\temp\yara-4.5.5-2368-win64.zip
    Install from a local copy of the zip, after checking it against the pin.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File build\fetch-yara.ps1 -Engine YaraX -Platform linux-x64
    Verify, or fetch, verify and install, the Linux x64 yr into artifacts/tools/yara-x/linux-x64/.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File build\fetch-yara.ps1 -Engine YaraXCapi
    Verify, or fetch, verify and install, the YARA-X C API into artifacts/tools/yara-x-capi/win-x64/.
#>
[CmdletBinding()]
param(
    [switch] $SkipDownload,
    [switch] $Force,
    [Alias('ArchivePath')]
    [string] $ZipPath,
    [ValidateSet('Classic', 'YaraX', 'YaraXCapi')]
    [string] $Engine = 'Classic',
    [ValidateSet('win-x64', 'linux-x64')]
    [string] $Platform = 'win-x64'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Invoke-WebRequest's progress bar makes downloads crawl under Windows PowerShell 5.1.
$ProgressPreference = 'SilentlyContinue'

#region Pins

# --- Classic: yara 4.5.5, Windows x64 (-Engine Classic, the default) ---

$YaraVersion = '4.5.5'
$ZipName     = 'yara-4.5.5-2368-win64.zip'
$ZipUrl      = 'https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip'
$ZipSize     = 2232629
# Trust anchor: GitHub's published asset digest for $ZipUrl.
$ZipSha256   = '352396c8a3d9b31b157a4820abd3b9347fc934a2314cdda8a4f566a5570163e4'

# sha256 of each binary as extracted from the zip above. EMPTY = NOT YET REVIEWED: the script
# refuses to install a binary whose pin is empty and prints the sha256 it observed. When these are
# recorded, note here that they were taken from a zip that matched $ZipSha256 (GitHub's digest),
# who recorded them, and when.
$BinaryPins = [ordered]@{
    'yara64.exe'  = ''
    'yarac64.exe' = ''
}

# --- YARA-X 1.22.0 (-Engine YaraX) ---

$YaraXVersion = '1.22.0'

# Windows x64. Trust anchor: GitHub's published asset digest for $YaraXWinUrl.
$YaraXWinName   = 'yara-x-v1.22.0-x86_64-pc-windows-msvc.zip'
$YaraXWinUrl    = 'https://github.com/VirusTotal/yara-x/releases/download/v1.22.0/yara-x-v1.22.0-x86_64-pc-windows-msvc.zip'
$YaraXWinSize   = 9081400
$YaraXWinSha256 = 'eac36a58699b94d3732a7fe1d8453fe89e0077bb18ac2c99b4c2ee102a431f2e'

# Linux x64 (glibc). Trust anchor: GitHub's published asset digest for $YaraXLinuxUrl.
$YaraXLinuxName   = 'yara-x-v1.22.0-x86_64-unknown-linux-gnu.tar.gz'
$YaraXLinuxUrl    = 'https://github.com/VirusTotal/yara-x/releases/download/v1.22.0/yara-x-v1.22.0-x86_64-unknown-linux-gnu.tar.gz'
$YaraXLinuxSize   = 10347394
$YaraXLinuxSha256 = '7f470770b2c1a0d97f02298fc194978d999074d147d003d33dd62775761439db'

# sha256 of yr as extracted from the archives above. EMPTY = NOT YET REVIEWED, exactly as for
# $BinaryPins: when recorded, note the archive digest they were taken from, who, and when.
$YaraXWinPins = [ordered]@{
    'yr.exe' = ''
}
$YaraXLinuxPins = [ordered]@{
    'yr' = ''
}

# --- YARA-X 1.22.0 C API, Windows x64 (-Engine YaraXCapi) ---

# Trust anchor: GitHub's published asset digest for $YaraXCapiUrl.
$YaraXCapiName   = 'yara-x-capi-v1.22.0-x86_64-pc-windows-msvc.zip'
$YaraXCapiUrl    = 'https://github.com/VirusTotal/yara-x/releases/download/v1.22.0/yara-x-capi-v1.22.0-x86_64-pc-windows-msvc.zip'
$YaraXCapiSize   = 20798844
$YaraXCapiSha256 = '40317f65781e3a17bffe31f9837143a51c1c28ce5061eac2b90695fbb30e1664'

# sha256 of the DLL, its import library and the header as extracted from the zip above. Each key
# is both the zip entry's file name (matched case-insensitively, wherever it sits in the zip) and
# the name it is installed under. EMPTY = NOT YET REVIEWED, exactly as for $BinaryPins.
# Recorded 2026-10-22, APPROVED BY THE USER on 2026-10-22 (docs/agent/tasks/yarax-worker.md, "T0 approved"):
# taken from the v1.22.0 C API zip whose sha256 matches GitHub's asset digest for $YaraXCapiUrl
# ($YaraXCapiSha256, 40317f65...0e1664); the member hashes were computed independently, in memory.
$YaraXCapiPins = [ordered]@{
    'yara_x_capi.dll'     = 'bb5c112bf479d1b1706fbecf85275d3806321ee2912dea4f36750289d0294848'
    'yara_x_capi.dll.lib' = 'f229c490530c812d45d4184679b97322e9c3ab7d467102bb65bdfd5d5efc34c8'
    'yara_x.h'            = '68b6239bc308adeedd56a7c258f0cd384189edb688c34c0a77265de0f5aa76c8'
}

# --- All engines ---

# Licence files copied if present. yara and yara-x are BSD-3-Clause; the yara source tree calls
# it COPYING, the yara-x one LICENSE.
$LicencePattern = '^(COPYING|LICENSE|LICENCE)(\.[A-Za-z0-9]+)?$'

# No legitimate entry in these archives is anywhere near this size; it bounds what gets hashed/extracted.
$MaxEntryBytes = 64MB

# A tar member is only ever named on tar's command line if it is a plain relative path: no
# absolute path or drive, no '.'/'..' segment (an optional leading './' aside), no backslash and
# no glob characters (bsdtar treats member arguments as patterns).
$SafeMemberPattern = '^(\./)?[A-Za-z0-9_][A-Za-z0-9._+-]*(/[A-Za-z0-9_][A-Za-z0-9._+-]*)*$'

#endregion

#region Target

$Targets = @{
    'Classic/win-x64' = @{
        Product = 'yara'; Version = $YaraVersion; Description = 'Windows x64'
        ArchiveName = $ZipName; Url = $ZipUrl; Size = $ZipSize; Sha256 = $ZipSha256; Format = 'zip'
        BinaryPins = $BinaryPins; PinVariable = '$BinaryPins'; FileLabel = 'binary'
        InstallDir = 'artifacts\tools\yara\win-x64'; CacheDir = 'artifacts\cache\yara'
        SkipOversizeEntries = $false; NoLicenceNote = $null
        Notes = @(
            "licence      yara is BSD-3-Clause (COPYING in the yara source tree); the 4.5.5 win64 zip ships no licence file"
            "note         lacks the yara 4.5.6-4.5.8 parser fixes; see ADR-0033 'Engine-version finding'"
        )
    }
    'YaraX/win-x64' = @{
        Product = 'yara-x'; Version = $YaraXVersion; Description = 'Windows x64'
        ArchiveName = $YaraXWinName; Url = $YaraXWinUrl; Size = $YaraXWinSize; Sha256 = $YaraXWinSha256; Format = 'zip'
        BinaryPins = $YaraXWinPins; PinVariable = '$YaraXWinPins'; FileLabel = 'binary'
        InstallDir = 'artifacts\tools\yara-x\win-x64'; CacheDir = 'artifacts\cache\yara-x'
        SkipOversizeEntries = $false; NoLicenceNote = $null
        Notes = @(
            "licence      yara-x is BSD-3-Clause (LICENSE in the yara-x source tree); the v1.22.0 windows-msvc zip ships no licence file"
            "note         spike install (docs/agent/tasks/yara-x-spike.md); never executed by this script"
        )
    }
    'YaraX/linux-x64' = @{
        Product = 'yara-x'; Version = $YaraXVersion; Description = 'Linux x64 (glibc)'
        ArchiveName = $YaraXLinuxName; Url = $YaraXLinuxUrl; Size = $YaraXLinuxSize; Sha256 = $YaraXLinuxSha256; Format = 'tar.gz'
        BinaryPins = $YaraXLinuxPins; PinVariable = '$YaraXLinuxPins'; FileLabel = 'binary'
        InstallDir = 'artifacts\tools\yara-x\linux-x64'; CacheDir = 'artifacts\cache\yara-x'
        SkipOversizeEntries = $false; NoLicenceNote = $null
        Notes = @(
            "licence      yara-x is BSD-3-Clause (LICENSE in the yara-x source tree); the v1.22.0 linux-gnu tar.gz ships no licence file"
            "note         Linux ELF stored on NTFS, which keeps no executable bit; chmod +x after copying into WSL/Linux"
            "note         spike install (docs/agent/tasks/yara-x-spike.md); never executed by this script"
        )
    }
    # The C API zip may also hold a large static library, so entries over $MaxEntryBytes are listed
    # (unhashed) and reported instead of failing the run; none of them is ever extracted.
    'YaraXCapi/win-x64' = @{
        Product = 'yara-x C API'; Version = $YaraXVersion; Description = 'Windows x64'
        ArchiveName = $YaraXCapiName; Url = $YaraXCapiUrl; Size = $YaraXCapiSize; Sha256 = $YaraXCapiSha256; Format = 'zip'
        BinaryPins = $YaraXCapiPins; PinVariable = '$YaraXCapiPins'; FileLabel = 'file'
        InstallDir = 'artifacts\tools\yara-x-capi\win-x64'; CacheDir = 'artifacts\cache\yara-x-capi'
        SkipOversizeEntries = $true
        NoLicenceNote = "licence      yara-x is BSD-3-Clause (LICENSE in the yara-x source tree); the v1.22.0 capi windows-msvc zip ships no licence file"
        Notes = @(
            "note         only the DLL, its import library and the header are installed; the zip's other entries are not"
            "note         C API spike install (docs/agent/tasks/yara-x-spike.md, addendum); never loaded or executed by this script"
        )
    }
}

$T = $Targets["$Engine/$Platform"]
if (-not $T) {
    $why = if ($Engine -eq 'YaraXCapi') { 'the YARA-X C API is published for win-x64 only' } else { 'classic yara is fetched for win-x64 only' }
    Write-Host "error: -Platform $Platform is not available for -Engine $Engine ($why)." -ForegroundColor Red
    exit 1
}
# What the downloaded file is called in messages: 'zip' or 'archive'.
$Noun  = if ($T.Format -eq 'zip') { 'zip' } else { 'archive' }
$ANoun = if ($T.Format -eq 'zip') { 'a zip' } else { 'an archive' }

#endregion

#region Paths

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$InstallDir = Join-Path $RepoRoot $T.InstallDir
$CacheDir   = Join-Path $RepoRoot $T.CacheDir
$CachedZip  = Join-Path $CacheDir $T.ArchiveName
$Provenance = 'PROVENANCE.txt'
# Windows' own bsdtar. Never resolved through PATH, where GNU tar (e.g. Git's) may come first.
$TarExe     = Join-Path $env:SystemRoot 'System32\tar.exe'

#endregion

#region Helpers

$script:FailCode = 1

function Write-Step([string] $Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Info([string] $Message) { Write-Host "    $Message" }
function Write-Warn([string] $Message) { Write-Host "warning: $Message" -ForegroundColor Yellow }

# Records the exit code, then throws; the top level prints the message and exits with the code.
function Stop-Fetch([int] $Code, [string] $Message) {
    $script:FailCode = $Code
    throw $Message
}

function Get-Sha256([string] $Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StreamSha256([IO.Stream] $Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash($Stream) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
}

function Get-LeafName([string] $EntryName) {
    ($EntryName -split '[\\/]' | Where-Object { $_ -ne '' } | Select-Object -Last 1)
}

function New-ScratchDir {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('fetch-yara-' + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $path | Out-Null
    $path
}

#endregion

#region Installed copy

# Returns 'Verified' when every binary is installed and matches its pin, 'Missing' when at least
# one is absent and none is wrong. Stops (exit 5) on a binary that is present but wrong or that
# cannot be verified because its pin is empty.
function Test-Installed {
    $missing = @()
    foreach ($name in $T.BinaryPins.Keys) {
        $path = Join-Path $InstallDir $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $missing += $name; continue }
        $pin = $T.BinaryPins[$name]
        $actual = Get-Sha256 $path
        if (-not $pin) {
            Stop-Fetch 5 ("$path is present but no sha256 pin is recorded for $name, so it cannot be verified.`n" +
                "  observed sha256 $actual`n" +
                "Do not use it. Delete it, or record a reviewed pin in this script.")
        }
        if ($actual -ne $pin) {
            Stop-Fetch 5 ("$path does not match its pin.`n" +
                "  expected sha256 $pin`n" +
                "  actual   sha256 $actual`n" +
                "Do not use it. Delete it and re-run, or re-run with -Force.")
        }
        Write-Info "verified  $name  $actual"
    }

    # Anything else in the directory is unverified, and the application directory is first in the
    # DLL search order, so a stray DLL next to the binary would be loaded by it. Fail rather than warn.
    if (Test-Path -LiteralPath $InstallDir -PathType Container) {
        $known = @($T.BinaryPins.Keys) + @($Provenance)
        $extras = @(Get-ChildItem -LiteralPath $InstallDir -Force |
            Where-Object { $known -notcontains $_.Name -and $_.Name -notmatch $LicencePattern })
        if ($extras.Count -gt 0) {
            Stop-Fetch 5 ("Unexpected item(s) in $InstallDir, not installed by this script: " +
                (($extras | ForEach-Object { $_.Name }) -join ', ') + ".`n" +
                "The directory cannot be verified while they are there. Remove them (this script never deletes files it did not install).")
        }
    }

    if ($missing.Count -gt 0) {
        Write-Info ("not installed: " + ($missing -join ', '))
        return 'Missing'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir $Provenance) -PathType Leaf)) {
        Write-Warn "$Provenance is missing from $InstallDir; re-run with -Force to rewrite it"
    }
    'Verified'
}

#endregion

#region Archive

# Puts a copy of the archive in $Scratch and returns its path plus a description of where it came from.
function Get-Zip([string] $Scratch) {
    $dest = Join-Path $Scratch $T.ArchiveName
    if ($ZipPath) {
        $source = (Resolve-Path -LiteralPath $ZipPath).ProviderPath
        Write-Step "Using local $Noun $source (no download)"
        Copy-Item -LiteralPath $source -Destination $dest
        return @{ Path = $dest; Origin = "local file $source"; Fetched = 'unknown (supplied with -ZipPath)' }
    }
    if (-not $Force -and (Test-Path -LiteralPath $CachedZip -PathType Leaf)) {
        Write-Step "Using cached $Noun $CachedZip (no download)"
        Copy-Item -LiteralPath $CachedZip -Destination $dest
        # Install-Yara stamps the cached archive with the time it was verified and stored.
        $cachedAt = (Get-Item -LiteralPath $CachedZip).LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        return @{ Path = $dest; Origin = "cache $CachedZip"; Fetched = "$cachedAt (when the cached $Noun was verified and stored)" }
    }
    if ($SkipDownload) {
        Stop-Fetch 5 ("$($T.Product) is not installed in $InstallDir, there is no cached $Noun, and -SkipDownload forbids fetching it.`n" +
            "Re-run without -SkipDownload, or pass -ZipPath.")
    }

    Write-Step "Downloading $($T.Url)"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $response = Invoke-WebRequest -Uri $T.Url -OutFile $dest -UseBasicParsing -PassThru
    Write-Info "1 GET issued; HTTP $([int] $response.StatusCode)"
    $final = $null
    if ($response.BaseResponse -and $response.BaseResponse.PSObject.Properties['ResponseUri']) {
        $final = $response.BaseResponse.ResponseUri
    }
    if ($final) {
        # The query string of a redirected GitHub asset URL is a short-lived signature; don't print it.
        $shown = $final.GetLeftPart([UriPartial]::Path)
        if ($final.Host -ne ([Uri] $T.Url).Host) { Write-Info "redirected; final URL $shown" }
        else { Write-Info "final URL $shown" }
        if ($final.Scheme -ne 'https') {
            Remove-Item -LiteralPath $dest -Force
            Stop-Fetch 2 "The download ended on a non-https URL ($shown). Discarded."
        }
    }
    @{ Path = $dest; Origin = $T.Url; Fetched = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
}

# Size and sha256 check against the trust anchor. Deletes the file and stops (exit 2) on mismatch.
# $AlsoDelete names a second copy to remove on mismatch (the cache, when that was the source).
function Assert-ZipPin([string] $Path, [string] $AlsoDelete) {
    $size = (Get-Item -LiteralPath $Path).Length
    $actual = Get-Sha256 $Path
    if ($size -ne $T.Size -or $actual -ne $T.Sha256) {
        Remove-Item -LiteralPath $Path -Force
        if ($AlsoDelete) { Remove-Item -LiteralPath $AlsoDelete -Force -ErrorAction SilentlyContinue }
        $deleted = if ($AlsoDelete) { "$Path and $AlsoDelete" } else { $Path }
        Stop-Fetch 2 ("The $Noun does NOT match the pinned release asset. Nothing was extracted.`n" +
            "  expected $($T.Size) bytes, sha256 $($T.Sha256)`n" +
            "  actual   $size bytes, sha256 $actual`n" +
            "Deleted $deleted. Do not use this file until the mismatch is explained.")
    }
    Write-Info "$Noun verified: $size bytes, sha256 $actual (matches pin)"
}

# Lists every entry with its size and sha256 (hashed from the stream, nothing written to disk;
# an entry over $MaxEntryBytes stops the run, or with SkipOversizeEntries is listed unhashed),
# then extracts only the expected binaries and licence into $OutDir under names chosen here.
# Returns a hashtable: leaf name -> extracted path.
function Expand-Expected([string] $Zip, [string] $OutDir) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    New-Item -ItemType Directory -Path $OutDir | Out-Null

    $archive = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        $entries = @($archive.Entries)
        Write-Step "Zip contents ($($entries.Count) entries)"
        foreach ($entry in $entries) {
            if ($entry.FullName.EndsWith('/')) {
                Write-Info ('{0,10}  {1,-64}  {2}' -f '<dir>', '', $entry.FullName)
                continue
            }
            if ($entry.Length -gt $MaxEntryBytes) {
                if (-not $T.SkipOversizeEntries) { Stop-Fetch 1 "Zip entry $($entry.FullName) is $($entry.Length) bytes; refusing it." }
                Write-Info ('{0,10}  {1,-64}  {2}' -f $entry.Length, '<over the size limit: not hashed, never extracted>', $entry.FullName)
                continue
            }
            $stream = $entry.Open()
            try { $hash = Get-StreamSha256 $stream } finally { $stream.Dispose() }
            Write-Info ('{0,10}  {1}  {2}' -f $entry.Length, $hash, $entry.FullName)
        }

        $files = @($entries | Where-Object { -not $_.FullName.EndsWith('/') })
        $suspicious = @($files | Where-Object { $_.FullName -match '(^|[\\/])\.\.([\\/]|$)' -or $_.FullName -match '^([\\/]|[A-Za-z]:)' })
        foreach ($entry in $suspicious) { Write-Warn "zip entry with an absolute or parent-relative path: $($entry.FullName) (never used as a destination)" }

        $extracted = @{}
        $claimed = @{}
        foreach ($name in $T.BinaryPins.Keys) {
            $matches_ = @($files | Where-Object { (Get-LeafName $_.FullName) -ieq $name })
            if ($matches_.Count -eq 0) { Stop-Fetch 4 "The zip has no $name. Nothing installed." }
            if ($matches_.Count -gt 1) { Stop-Fetch 4 "The zip has $($matches_.Count) entries named $name; refusing to choose. Nothing installed." }
            if ($matches_[0].Length -gt $MaxEntryBytes) { Stop-Fetch 4 "The zip entry for $name is $($matches_[0].Length) bytes, over the size limit; refusing it. Nothing installed." }
            $out = Join-Path $OutDir $name
            [IO.Compression.ZipFileExtensions]::ExtractToFile($matches_[0], $out, $false)
            $extracted[$name] = $out
            $claimed[$matches_[0].FullName] = $true
        }

        $licences = @($files | Where-Object { (Get-LeafName $_.FullName) -match $LicencePattern -and $_.Length -le $MaxEntryBytes })
        if ($licences.Count -eq 0) { Write-Warn 'the zip has no COPYING/LICENSE file; none will be installed' }
        foreach ($entry in $licences) {
            $leaf = Get-LeafName $entry.FullName
            if ($extracted.ContainsKey($leaf)) { Write-Warn "duplicate licence entry $($entry.FullName) ignored"; continue }
            $out = Join-Path $OutDir $leaf
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $out, $false)
            $extracted[$leaf] = $out
            $claimed[$entry.FullName] = $true
        }

        foreach ($entry in $files) {
            if (-not $claimed.ContainsKey($entry.FullName)) {
                Write-Warn "unexpected zip entry, NOT installed: $($entry.FullName)"
            }
        }
        $extracted
    }
    finally { $archive.Dispose() }
}

# Runs Windows' bsdtar and returns its stdout lines (text only: member names, never file data).
# stderr is left on the console; under Windows PowerShell 5.1 redirecting it would turn each line
# into an error record. Any non-zero exit stops the script (exit 1).
function Invoke-Tar([string[]] $Arguments) {
    $out = @(& $TarExe @Arguments)
    if ($LASTEXITCODE -ne 0) { Stop-Fetch 1 "tar.exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE. Nothing installed." }
    $out
}

# Extracts one member of the verified tar.gz into a fresh directory under $OutDir, checks that
# exactly one regular file (no link) appeared where the member name says, and moves it to
# $OutDir\$LeafName. Returns that path.
function Expand-TarMember([string] $Archive, [string] $Member, [string] $OutDir, [string] $LeafName) {
    $stage = Join-Path $OutDir ('tar-' + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $stage | Out-Null
    Invoke-Tar @('-xzf', $Archive, '-C', $stage, $Member) | Out-Null

    $items = @(Get-ChildItem -LiteralPath $stage -Recurse -Force)
    $links = @($items | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 })
    if ($links.Count -gt 0) { Stop-Fetch 4 "Extracting $Member produced a link ($(($links | ForEach-Object { $_.Name }) -join ', ')); refusing it. Nothing installed." }
    $produced = @($items | Where-Object { -not $_.PSIsContainer })
    $expected = [IO.Path]::GetFullPath((Join-Path $stage ($Member -replace '/', '\')))
    if ($produced.Count -ne 1 -or $produced[0].FullName -ne $expected) {
        $got = ($produced | ForEach-Object { $_.FullName.Substring($stage.Length + 1) }) -join ', '
        Stop-Fetch 4 ("Extracting $Member did not produce exactly that one regular file (got $($produced.Count) file(s): $got); refusing it. Nothing installed.")
    }
    if ($produced[0].Length -gt $MaxEntryBytes) { Stop-Fetch 1 "Archive member $Member is $($produced[0].Length) bytes; refusing it." }

    $out = Join-Path $OutDir $LeafName
    Move-Item -LiteralPath $expected -Destination $out
    Remove-Item -LiteralPath $stage -Recurse -Force
    Write-Info ('{0,10}  {1}  {2}  -> {3}' -f (Get-Item -LiteralPath $out).Length, (Get-Sha256 $out), $Member, $LeafName)
    $out
}

# tar.gz counterpart of Expand-Expected. Lists the members, reports unexpected ones, then extracts
# only the expected binaries and licence, one member at a time, under names chosen here.
# Returns a hashtable: leaf name -> extracted path.
function Expand-ExpectedTar([string] $Archive, [string] $OutDir) {
    if (-not (Test-Path -LiteralPath $TarExe -PathType Leaf)) {
        Stop-Fetch 1 "Windows tar.exe was not found at $TarExe (it ships with Windows 10 1803 and later)."
    }
    $version = @(Invoke-Tar @('--version'))
    if (-not (($version -join ' ') -match 'bsdtar')) { Stop-Fetch 1 "$TarExe does not report itself as bsdtar; refusing to use it." }
    Write-Info "using $TarExe ($($version[0]))"
    New-Item -ItemType Directory -Path $OutDir | Out-Null

    $names = @(Invoke-Tar @('-tzf', $Archive))
    $long = @(Invoke-Tar @('-tvzf', $Archive))
    Write-Step "Archive contents ($($names.Count) members; tar -tvzf, nothing extracted yet)"
    foreach ($line in $long) { Write-Info $line }
    if ($long.Count -ne $names.Count) { Write-Warn "tar -tzf listed $($names.Count) members but tar -tvzf $($long.Count) lines" }

    $files = @($names | Where-Object { -not $_.EndsWith('/') })
    foreach ($m in @($files | Where-Object { $_ -notmatch $SafeMemberPattern })) {
        Write-Warn "archive member with an unusual name (never passed to tar, never extracted): $m"
    }

    # Decide everything from the listing before extracting anything.
    $plan = [ordered]@{}
    foreach ($name in $T.BinaryPins.Keys) {
        $hits = @($files | Where-Object { (Get-LeafName $_) -ieq $name })
        if ($hits.Count -eq 0) { Stop-Fetch 4 "The archive has no $name. Nothing installed." }
        if ($hits.Count -gt 1) { Stop-Fetch 4 "The archive has $($hits.Count) members named $name; refusing to choose. Nothing installed." }
        if ($hits[0] -notmatch $SafeMemberPattern) { Stop-Fetch 4 "The archive member for $name has an unusable name ($($hits[0])). Nothing installed." }
        $plan[$name] = $hits[0]
    }
    $licences = @($files | Where-Object { (Get-LeafName $_) -match $LicencePattern -and $_ -match $SafeMemberPattern })
    if ($licences.Count -eq 0) { Write-Warn 'the archive has no COPYING/LICENSE file; none will be installed' }
    foreach ($member in $licences) {
        $leaf = Get-LeafName $member
        if ($plan.Contains($leaf)) { Write-Warn "duplicate licence member $member ignored"; continue }
        $plan[$leaf] = $member
    }
    $claimed = @($plan.Values)
    foreach ($member in $files) {
        if ($claimed -notcontains $member) { Write-Warn "unexpected archive member, NOT extracted or installed: $member" }
    }

    Write-Step "Extracting $($plan.Count) member(s), one at a time, into $OutDir"
    $extracted = @{}
    foreach ($leaf in $plan.Keys) { $extracted[$leaf] = Expand-TarMember $Archive $plan[$leaf] $OutDir $leaf }
    $extracted
}

#endregion

#region Install

function Install-Yara([string] $Scratch) {
    $zip = Get-Zip $Scratch
    Write-Step "Verifying $($T.ArchiveName) against the pinned sha256 (before extraction)"
    $alsoDelete = if ($zip.Origin -like 'cache *') { $CachedZip } else { $null }
    Assert-ZipPin $zip.Path $alsoDelete

    # Only bytes that matched the trust anchor are ever cached.
    if ($zip.Origin -notlike 'cache *') {
        New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
        Copy-Item -LiteralPath $zip.Path -Destination $CachedZip -Force
        (Get-Item -LiteralPath $CachedZip).LastWriteTimeUtc = [DateTime]::UtcNow
        Write-Info "cached verified $Noun at $CachedZip"
    }

    $extractDir = Join-Path $Scratch 'extract'
    $extracted = if ($T.Format -eq 'zip') { Expand-Expected $zip.Path $extractDir } else { Expand-ExpectedTar $zip.Path $extractDir }

    Write-Step 'Verifying extracted binaries against their pins'
    $observed = [ordered]@{}
    $unpinned = @()
    foreach ($name in $T.BinaryPins.Keys) {
        $actual = Get-Sha256 $extracted[$name]
        $observed[$name] = $actual
        $pin = $T.BinaryPins[$name]
        if (-not $pin) { $unpinned += $name; Write-Info "UNPINNED  $name  observed sha256 $actual"; continue }
        if ($actual -ne $pin) {
            Stop-Fetch 4 ("$name from $ANoun that matched the pin does not match its own pin.`n" +
                "  expected sha256 $pin`n" +
                "  actual   sha256 $actual`n" +
                "Nothing installed.")
        }
        Write-Info "verified  $name  $actual"
    }
    if ($unpinned.Count -gt 0) {
        $lines = ($observed.Keys | ForEach-Object { "    '$_' = '$($observed[$_])'" }) -join "`n"
        Stop-Fetch 3 ("REFUSING TO INSTALL: no sha256 pin is recorded for " + ($unpinned -join ', ') + ".`n" +
            "These were extracted from $ANoun that matched GitHub's digest ($($T.Sha256)).`n" +
            "After review, record them in $($T.PinVariable) in this script:`n$lines`n" +
            "Nothing was installed. The verified $Noun is cached, so the next run will not download it again.")
    }

    Write-Step "Installing into $InstallDir"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $licenceLines = @()
    foreach ($name in @($extracted.Keys | Sort-Object)) {
        Copy-Item -LiteralPath $extracted[$name] -Destination (Join-Path $InstallDir $name) -Force
        Write-Info "installed $name"
        if ($name -match $LicencePattern) { $licenceLines += "licence      $name  sha256 $(Get-Sha256 $extracted[$name])" }
    }

    # Re-hash what actually landed on disk, not what was staged.
    foreach ($name in $T.BinaryPins.Keys) {
        $actual = Get-Sha256 (Join-Path $InstallDir $name)
        if ($actual -ne $T.BinaryPins[$name]) {
            Stop-Fetch 5 "Installed $name hashes to $actual, not its pin $($T.BinaryPins[$name]). Do not use it."
        }
    }

    $binaryLines = @($T.BinaryPins.Keys | ForEach-Object { '{0,-13}{1}  sha256 {2}' -f $T.FileLabel, $_, $observed[$_] })
    if ($licenceLines.Count -eq 0 -and $T.NoLicenceNote) { $licenceLines += $T.NoLicenceNote }
    $text = @(
        "$($T.Product) $($T.Version) for $($T.Description), installed by build/fetch-yara.ps1"
        "source       $($T.Url)"
        "obtained     $($zip.Origin)"
        "version      $($T.Version)"
        ('{0,-13}{1}  {2} bytes  sha256 {3} (GitHub asset digest; verified)' -f $Noun, $T.ArchiveName, $T.Size, $T.Sha256)
    ) + $binaryLines + $licenceLines + @(
        "fetched_utc  $($zip.Fetched)"
        "installed_utc $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    ) + $T.Notes
    Set-Content -LiteralPath (Join-Path $InstallDir $Provenance) -Value $text -Encoding Ascii
    Write-Info "wrote $Provenance"
}

#endregion

#region Main

function Invoke-Main {
    if ($Force -and $SkipDownload -and -not $ZipPath) {
        Stop-Fetch 1 '-Force re-fetches and -SkipDownload forbids fetching; pass -ZipPath to reinstall offline.'
    }

    Write-Step "$($T.Product) $($T.Version) ($Platform) -> $InstallDir"
    if ($Force) {
        Write-Info "-Force: ignoring the installed copy and the cached $Noun"
    } else {
        Write-Step 'Verifying installed copy'
        if ((Test-Installed) -eq 'Verified') {
            if ($ZipPath) { Write-Info '-ZipPath not used: the installed copy is verified (add -Force to reinstall from it)' }
            Write-Step 'Done: installed copy verified, nothing fetched'
            return
        }
    }

    $scratch = New-ScratchDir
    Write-Info "scratch directory $scratch"
    try { Install-Yara $scratch }
    finally {
        Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $scratch) { Write-Warn "could not remove scratch directory $scratch" }
        else { Write-Info "removed scratch directory $scratch" }
    }

    Write-Step 'Verifying installed copy'
    if ((Test-Installed) -ne 'Verified') { Stop-Fetch 5 'The installed copy did not verify after installation.' }
    Write-Step 'Done: installed and verified'
}

try {
    Invoke-Main
    exit 0
}
catch {
    Write-Host "error: $($_.Exception.Message)" -ForegroundColor Red
    exit $script:FailCode
}

#endregion
