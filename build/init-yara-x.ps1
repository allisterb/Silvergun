<#
.SYNOPSIS
    Checks out the ext/yara-x submodule without upstream's test data.

.DESCRIPTION
    Upstream keeps malware samples and macro dumps under */testdata/ for its module tests; antivirus
    quarantines some of them on read. Building the C API needs none of them: every reference is in
    #[cfg(test)] modules, tests/ or benches/.

    Fresh clone: initialises the submodule, clones it blobless (--filter=blob:none, so excluded files are
    never downloaded), applies the sparse-checkout below, checks out the commit the superproject's index
    records, then moves the git dir into .git/modules (absorbgitdirs).
    Existing checkout: applies the same sparse-checkout in place, which removes the test data from the
    working tree; it stays in history.

    Sparse-checkout is local configuration (.git/modules/ext/yara-x/info/sparse-checkout) and cannot be
    committed. Run this script, not 'git submodule update --init', for ext/yara-x, because that command
    would check out everything first.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File build\init-yara-x.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$path = 'ext/yara-x'
$dir = Join-Path $root $path
$patterns = "/*`n!testdata/`n"
$gitExe = (Get-Command git -CommandType Application | Select-Object -First 1).Source

function Git {
    & $gitExe @args
    if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed with exit code $LASTEXITCODE" }
}

function Set-Sparse([string] $gitDir) {
    Git -C $dir config core.sparseCheckout true
    Git -C $dir config core.sparseCheckoutCone false
    $info = Join-Path $gitDir 'info'
    New-Item -ItemType Directory -Force -Path $info | Out-Null
    [IO.File]::WriteAllText((Join-Path $info 'sparse-checkout'), $patterns, (New-Object Text.UTF8Encoding $false))
}

Push-Location $root
try {
    $entry = (Git ls-files -s -- $path) -split '\s+'
    if ($entry.Count -lt 2 -or $entry[0] -ne '160000') { throw "$path is not a submodule in the index." }
    $commit = $entry[1]

    if (Test-Path (Join-Path $dir '.git')) {
        Set-Sparse (Git -C $dir rev-parse --absolute-git-dir)
        Git -C $dir sparse-checkout reapply
        Write-Host "Applied sparse-checkout to the existing $path checkout."
    }
    else {
        Git submodule init -- $path
        $url = Git config --get "submodule.$path.url"
        if ((Test-Path $dir) -and (Get-ChildItem -Force $dir | Select-Object -First 1)) { throw "$dir exists and is not empty." }
        Git clone --no-checkout --filter=blob:none --origin upstream $url $dir
        Set-Sparse (Join-Path $dir '.git')
        Git -C $dir checkout --detach $commit
        Git submodule absorbgitdirs -- $path
        Write-Host "Cloned $path at $commit without test data."
    }

    $head = Git -C $dir rev-parse HEAD
    if ($head -ne $commit) { Write-Warning "$path HEAD is $head but the superproject index records $commit." }
    $left = @(Git -C $dir ls-files -t | Where-Object { $_ -match '^H .*/testdata/' })
    if ($left.Count) { throw "$($left.Count) testdata files are still checked out." }
}
finally { Pop-Location }
