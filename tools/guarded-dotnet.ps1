<#
.SYNOPSIS
    Runs `dotnet build|test|run <project>` under a memory and time guard.

.DESCRIPTION
    Written after a test fixture (a 40-rank jagged-array overload) drove the C# compiler server to ~50 GB
    (docs/agent/tasks/capslock-mechanism-fixtures-and-a1.md §2.5). Use it for new or edited fixture projects and for
    agent-driven builds.

    The compiler server (VBCSCompiler) and MSBuild node reuse are turned off, so every compiler process is a
    descendant of the dotnet process this script starts. Every 500 ms the script sums the private bytes of that
    process tree (plus any VBCSCompiler.exe started after the guard, in case one starts anyway - a compiler server
    that was already running, e.g. Visual Studio's, is never counted or killed; one that something else starts
    DURING the run would be) and kills the whole tree when the sum exceeds -LimitMB or the run exceeds
    -TimeoutSec. A process joins the tree only if it started after the guard and after its parent, so a reused
    process id cannot pull an unrelated process into it; every process killed is logged first. A descendant whose
    parent has already exited is no longer linked to the tree, so it is neither counted nor killed. Sampling can miss a process that lives under 500 ms, so the reported peak is a lower bound. If the
    script stops on Ctrl-C or an error, the tree is killed too; if the script itself is hard-killed, its finally
    block does not run and dotnet can outlive it.

    Full stdout/stderr go to -LogDir (default %TEMP%\silvergun-guarded-logs); the last -TailLines of each are echoed.

    Exit codes: the dotnet exit code on a normal finish; 99 = killed by the memory guard; 98 = killed by timeout;
    97 = killed because the guard could no longer sample processes.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\guarded-dotnet.ps1 -Verb build -Project tests\X\X.csproj
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\guarded-dotnet.ps1 -Verb test -Project tests\X\X.csproj -Filter "FullyQualifiedName~MemberIndex"
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\guarded-dotnet.ps1 -Verb run -Project harness\harness.csproj -AppArgs "C:\some\assembly.dll"
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('build', 'test', 'run')][string]$Verb,
    [Parameter(Mandatory = $true)][string]$Project,
    [int]$LimitMB = 4096,
    [int]$TimeoutSec = 900,
    [int]$TailLines = 60,
    # dotnet test --filter expression.
    [string]$Filter = '',
    # Arguments for the program under `run`, whitespace-separated (paths must not contain spaces).
    [string]$AppArgs = '',
    # Build configuration (-c); empty for the project's default (Debug).
    [ValidateSet('', 'Debug', 'Release')][string]$Configuration = '',
    # Target framework (-f) for a multi-targeted project; empty for none.
    [string]$Framework = '',
    [string]$LogDir = (Join-Path ([IO.Path]::GetTempPath()) 'silvergun-guarded-logs')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Project)) { throw "Project not found: $Project" }

$env:MSBUILDDISABLENODEREUSE = '1'
$env:DOTNET_CLI_USE_MSBUILD_SERVER = '0'
$env:UseSharedCompilation = 'false'

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$name = [IO.Path]::GetFileNameWithoutExtension($Project)
$stdout = Join-Path $LogDir "$name-$Verb-$stamp.out.log"
$stderr = Join-Path $LogDir "$name-$Verb-$stamp.err.log"

$arguments = switch ($Verb) {
    'run' { @('run', '--project', $Project, '-p:UseSharedCompilation=false') }
    default { @($Verb, $Project, '-p:UseSharedCompilation=false', '-nodeReuse:false', '-m:1') }
}
if ($Configuration) { $arguments += @('-c', $Configuration) }
if ($Framework) { $arguments += @('-f', $Framework) }
if ($Filter) { $arguments += @('--filter', $Filter) }
if ($AppArgs) { $arguments += @('--') + ($AppArgs -split '\s+' | Where-Object { $_ }) }
# Windows command-line quoting (CommandLineToArgvW rules): backslashes are literal except before a quote.
function ConvertTo-Argument([string]$value) {
    $escaped = [regex]::Replace($value, '(\\*)"', { param($m) $m.Groups[1].Value * 2 + '\"' })
    '"' + [regex]::Replace($escaped, '(\\+)$', { param($m) $m.Groups[1].Value * 2 }) + '"'
}
$quoted = $arguments | ForEach-Object { ConvertTo-Argument $_ }

function Get-Tree([int]$rootId, [datetime]$since) {
    $all = Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, PrivatePageCount, CreationDate
    $children = @{}
    foreach ($p in $all) {
        $key = [int]$p.ParentProcessId
        if (-not $children.ContainsKey($key)) { $children[$key] = New-Object System.Collections.Generic.List[object] }
        $children[$key].Add($p)
    }
    $tree = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[int]
    $root = $all | Where-Object { $_.ProcessId -eq $rootId } | Select-Object -First 1
    if (-not $root) { return $tree }
    $tree.Add($root); $null = $seen.Add($rootId)
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue($root)
    while ($queue.Count -gt 0) {
        $parent = $queue.Dequeue()
        $id = [int]$parent.ProcessId
        if ($children.ContainsKey($id)) {
            foreach ($c in $children[$id]) {
                # Windows keeps a dead parent's id in ParentProcessId and reuses ids, so an unrelated process can
                # name one of ours as its parent. A real descendant starts after the guard and after its parent.
                if ($c.CreationDate -lt $since -or $c.CreationDate -lt $parent.CreationDate) { continue }
                if ($seen.Add([int]$c.ProcessId)) { $tree.Add($c); $queue.Enqueue($c) }
            }
        }
    }
    # A compiler server detaches from its parent; count one only if it started during this run.
    foreach ($p in $all | Where-Object { $_.Name -eq 'VBCSCompiler.exe' -and $_.CreationDate -ge $since }) {
        if ($seen.Add([int]$p.ProcessId)) { $tree.Add($p) }
    }
    $tree
}

# Kills the tree, then the root again by handle in case the CIM query itself fails.
function Stop-Tree([System.Diagnostics.Process]$process, [datetime]$since) {
    try {
        foreach ($p in @(Get-Tree $process.Id $since)) {
            Write-Output ("guarded-dotnet: killing {0} pid {1} (parent {2}, started {3:HH:mm:ss.fff}, {4} MB)" -f `
                $p.Name, $p.ProcessId, $p.ParentProcessId, $p.CreationDate, [math]::Round($p.PrivatePageCount / 1MB))
            Stop-Process -Id ([int]$p.ProcessId) -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        if (-not $process.HasExited) { try { $process.Kill() } catch { } }
    }
}

Write-Output "guarded-dotnet: dotnet $($arguments -join ' ')"
Write-Output "guarded-dotnet: limit $LimitMB MB, timeout $TimeoutSec s, log $stdout"

$since = Get-Date
$proc = Start-Process -FilePath 'dotnet' -ArgumentList $quoted -NoNewWindow -PassThru `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$null = $proc.Handle
$watch = [Diagnostics.Stopwatch]::StartNew()
$peakMB = 0
$peakWho = ''
$verdict = $null
$failedSamples = 0

try {
    while (-not $proc.HasExited) {
        try {
            $tree = @(Get-Tree $proc.Id $since)
            $failedSamples = 0
        }
        catch {
            # A transient CIM failure skips one sample; a persistent one is a guard that can no longer see.
            if (++$failedSamples -ge 10) { $verdict = "GUARD ERROR: process sampling failed 10 times: $_"; break }
            Start-Sleep -Milliseconds 500
            continue
        }
        $totalMB = [math]::Round((($tree | Measure-Object -Property PrivatePageCount -Sum).Sum) / 1MB)
        if ($totalMB -gt $peakMB) {
            $peakMB = $totalMB
            $top = $tree | Sort-Object PrivatePageCount -Descending | Select-Object -First 1
            $peakWho = "$($top.Name) pid $($top.ProcessId) $([math]::Round($top.PrivatePageCount / 1MB)) MB"
        }
        if ($totalMB -gt $LimitMB) { $verdict = "MEMORY GUARD: tree reached $totalMB MB (> $LimitMB MB); largest $peakWho"; break }
        if ($watch.Elapsed.TotalSeconds -gt $TimeoutSec) { $verdict = "TIMEOUT GUARD: exceeded $TimeoutSec s"; break }
        Start-Sleep -Milliseconds 500
    }
}
finally {
    # Runs on a verdict, an error or Ctrl-C alike: dotnet never outlives its guard.
    if (-not $proc.HasExited) {
        Stop-Tree $proc $since
        $proc.WaitForExit(10000) | Out-Null
    }
}

Get-Content -LiteralPath $stdout -Tail $TailLines -ErrorAction SilentlyContinue
Get-Content -LiteralPath $stderr -Tail $TailLines -ErrorAction SilentlyContinue
Write-Output ("guarded-dotnet: elapsed {0:N1} s, peak tree private bytes {1} MB ({2})" -f $watch.Elapsed.TotalSeconds, $peakMB, $peakWho)

if ($verdict) {
    Write-Output $verdict
    if ($verdict.StartsWith('MEMORY')) { exit 99 } elseif ($verdict.StartsWith('TIMEOUT')) { exit 98 } else { exit 97 }
}
Write-Output "guarded-dotnet: dotnet exit code $($proc.ExitCode)"
exit $proc.ExitCode
