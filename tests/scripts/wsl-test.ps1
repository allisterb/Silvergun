<#
.SYNOPSIS
    Run a Silvergun test project inside WSL from a persistent, incrementally built mirror.

.DESCRIPTION
    Spec: docs/agent/tasks/wsl-test-mirror.md. Tiers: docs/agent/testing-tiers.md.

    1. Sync:  rsync -a --delete from the Windows repo root (as seen from WSL, e.g. /mnt/c/Projects/Silvergun/)
              to the fixed mirror ~/silvergun-wsl/. Excludes .git, bin, obj, .vs, TestResults, /reference/,
              /docs/agent/ and scratch*. There is deliberately NO --delete-excluded, so the Linux bin/ and obj/
              in the mirror survive between runs and the build is incremental.
    2. Test:  dotnet test <mirror>/<Project> -f <Framework> [--filter <Filter>] inside WSL. Output is streamed
              and the exit code is propagated.
    3. Report the elapsed time of each step.

    Safety: this script runs rsync --delete. The destination is computed from $HOME inside WSL and must be
    exactly /home/<user>/silvergun-wsl where <user> is the WSL user (Get-MirrorDestinationError). The source
    must be the repo root, i.e. contain src/Silvergun.sln, checked on both sides (Get-MirrorSourceError).
    -SelfTest exercises those guards with fake values and never calls WSL or rsync.

    Windows PowerShell 5.1 only; keep this file ASCII-only.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tests\scripts\wsl-test.ps1 -Project tests/Silvergun.PackageAnalysis.NuGet.Tests/Silvergun.PackageAnalysis.NuGet.Tests.csproj

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tests\scripts\wsl-test.ps1 -Project tests/Silvergun.PackageAnalysis.NuGet.Tests/Silvergun.PackageAnalysis.NuGet.Tests.csproj -Filter "FullyQualifiedName~Yara&Category!=Slow"

.NOTES
    Exit codes: the dotnet test exit code when the test step runs; 2 = argument or safety-guard refusal
    (nothing was synced); 3 = rsync failed (no tests run); 4 = timed out waiting for another run of this
    script. -SelfTest exits 0 when every guard case behaves as expected, 1 otherwise.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [string]$Project,

    [Parameter(ParameterSetName = 'Run')]
    [string]$Framework = 'net10.0',

    [Parameter(ParameterSetName = 'Run')]
    [string]$Filter,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$NoSync,

    [Parameter(ParameterSetName = 'SelfTest', Mandatory = $true)]
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
# Not 'Stop': under Windows PowerShell 5.1 a native command's stderr can surface as NativeCommandError records,
# which 'Stop' would turn into a terminating error mid-run. Every native call checks $LASTEXITCODE explicitly.
$ErrorActionPreference = 'Continue'

$MirrorName = 'silvergun-wsl'
$LockTimeoutMinutes = 20

# Excludes for the sync. Unanchored names match at any depth (e.g. the ext/*/.git submodule files and every
# project's bin/ and obj/); a leading '/' anchors to the repo root. Excluded paths are also protected from
# --delete on the receiving side, which is what keeps the mirror's Linux bin/ and obj/ alive.
$RsyncExcludes = @(
    '.git',
    'bin/',
    'obj/',
    '.vs/',
    'TestResults/',
    '/reference/',
    '/docs/agent/',
    'scratch*'
)

#region Guards (pure: no WSL, no rsync)

function Get-MirrorDestination {
    param([AllowNull()][AllowEmptyString()][string]$WslHome)
    return ([string]$WslHome) + '/' + $MirrorName
}

# Returns $null when $Destination is acceptable as the rsync --delete target, otherwise the reason it is not.
# The only acceptable value is exactly /home/<WslUser>/silvergun-wsl, with $WslHome exactly /home/<WslUser>.
function Get-MirrorDestinationError {
    param(
        [AllowNull()][AllowEmptyString()][string]$Destination,
        [AllowNull()][AllowEmptyString()][string]$WslHome,
        [AllowNull()][AllowEmptyString()][string]$WslUser
    )
    if ([string]::IsNullOrEmpty($Destination)) { return 'destination is empty' }
    # \A...\z, not ^...$: .NET '$' also matches before a trailing newline.
    if ($Destination -cnotmatch '\A[\x21-\x7E]+\z') { return 'destination contains whitespace, control or non-ASCII characters' }
    if ($Destination -ceq '/') { return 'destination is the filesystem root' }
    if (-not $Destination.StartsWith('/')) { return 'destination is not an absolute path' }
    if ($Destination.Contains('..')) { return "destination contains '..'" }
    if ($Destination.Contains('//')) { return "destination contains '//'" }
    if ($Destination.Contains('/./') -or $Destination.EndsWith('/.')) { return "destination contains a '.' segment" }
    if ($Destination.EndsWith('/')) { return 'destination has a trailing slash' }
    if ([string]::IsNullOrEmpty($WslUser) -or $WslUser -cnotmatch '\A[a-z_][a-z0-9_-]{0,31}\z') { return 'WSL user name is empty or not a plain user name' }
    $expectedHome = '/home/' + $WslUser
    if ($WslHome -cne $expectedHome) { return "WSL HOME '$WslHome' is not $expectedHome" }
    $expected = $expectedHome + '/' + $MirrorName
    if ($Destination -cne $expected) { return "destination '$Destination' is not exactly $expected" }
    return $null
}

# Returns $null when the pair (Windows repo root, the same directory as seen from WSL) is acceptable as the
# rsync source, otherwise the reason it is not. The in-WSL existence check is done separately (Test-Wsl).
function Get-MirrorSourceError {
    param(
        [AllowNull()][AllowEmptyString()][string]$WindowsRoot,
        [AllowNull()][AllowEmptyString()][string]$WslSource
    )
    if ([string]::IsNullOrEmpty($WindowsRoot)) { return 'Windows repo root is empty' }
    if (-not (Test-Path -LiteralPath (Join-Path $WindowsRoot 'src\Silvergun.sln') -PathType Leaf)) {
        return "'$WindowsRoot' is not the repo root (no src\Silvergun.sln)"
    }
    if ([string]::IsNullOrEmpty($WslSource)) { return 'WSL source path is empty' }
    if ($WslSource -cnotmatch '\A/mnt/[a-z](/[^/\x00-\x1F\x7F]+)+\z') { return "WSL source '$WslSource' is not a /mnt/<drive>/... path" }
    foreach ($segment in $WslSource.Split('/')) {
        if ($segment -ceq '.' -or $segment -ceq '..') { return "WSL source '$WslSource' contains a '.' or '..' segment" }
    }
    return $null
}

# Returns $null when -Project names a repo-relative .csproj that will exist in the mirror, otherwise the reason.
function Get-ProjectPathError {
    param(
        [AllowNull()][AllowEmptyString()][string]$ProjectPath,
        [AllowNull()][AllowEmptyString()][string]$WindowsRoot
    )
    if ([string]::IsNullOrEmpty($ProjectPath)) { return '-Project is empty' }
    if ($ProjectPath -cnotmatch '\A[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*\.csproj\z') {
        return "-Project '$ProjectPath' is not a repo-relative path to a .csproj (letters, digits, '_', '.', '-', '/' only)"
    }
    $segments = $ProjectPath.Split('/')
    foreach ($segment in $segments) {
        if ($segment -ceq '.' -or $segment -ceq '..') { return "-Project '$ProjectPath' contains a '.' or '..' segment" }
        if (@('.git', 'bin', 'obj', '.vs', 'TestResults') -contains $segment -or $segment -like 'scratch*') {
            return "-Project '$ProjectPath' is under a directory the mirror excludes ('$segment')"
        }
    }
    if ($segments[0] -eq 'reference' -or ($segments.Length -gt 1 -and $segments[0] -eq 'docs' -and $segments[1] -eq 'agent')) {
        return "-Project '$ProjectPath' is under a directory the mirror excludes"
    }
    if (-not [string]::IsNullOrEmpty($WindowsRoot)) {
        if (-not (Test-Path -LiteralPath (Join-Path $WindowsRoot ($ProjectPath.Replace('/', '\'))) -PathType Leaf)) {
            return "-Project '$ProjectPath' does not exist under $WindowsRoot"
        }
    }
    return $null
}

function Get-FrameworkError {
    param([AllowNull()][AllowEmptyString()][string]$Tfm)
    if ([string]::IsNullOrEmpty($Tfm) -or $Tfm -cnotmatch '\Anet[0-9]+(\.[0-9]+)*(-[a-z]+[0-9.]*)?\z') { return "-Framework '$Tfm' is not a target framework moniker" }
    if ($Tfm -clike '*-windows*') { return "-Framework '$Tfm' is Windows-only and cannot run in WSL" }
    return $null
}

# Windows PowerShell 5.1 mangles embedded double quotes and drops empty strings when passing arguments to a
# native command, so a filter that needs them cannot arrive intact: refuse it rather than run something else.
function Get-FilterError {
    param([AllowNull()][AllowEmptyString()][string]$TestFilter)
    if ($null -eq $TestFilter -or $TestFilter -ceq '') { return $null }
    if ($TestFilter -cnotmatch '\A[\x20-\x7E]+\z') { return '-Filter contains control or non-ASCII characters' }
    if ($TestFilter.Contains('"')) { return '-Filter contains a double quote, which Windows PowerShell 5.1 cannot pass intact' }
    if ($TestFilter.Trim() -cne $TestFilter) { return '-Filter has leading or trailing whitespace' }
    if ($TestFilter.EndsWith('\')) { return '-Filter ends with a backslash, which Windows PowerShell 5.1 cannot pass intact' }
    return $null
}

#endregion

#region Helpers

function Write-Step {
    param([string]$Message)
    [Console]::Out.WriteLine('[wsl-test] ' + $Message)
    [Console]::Out.Flush()
}

function Format-Elapsed {
    param([TimeSpan]$Elapsed)
    return ('{0:0.0} s' -f $Elapsed.TotalSeconds)
}

function Format-CommandLine {
    param([string[]]$Arguments)
    return (($Arguments | ForEach-Object { if ($_ -match '[\s&|<>()~*?$;]') { "'" + $_ + "'" } else { $_ } }) -join ' ')
}

# Runs wsl.exe with $Arguments, capturing stdout as lines (stderr discarded). Used for short queries only.
function Get-WslOutput {
    param([string[]]$Arguments)
    $lines = @(& wsl.exe @Arguments 2>$null)
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Lines = $lines }
}

# Runs wsl.exe with $Arguments, streaming both output streams line by line, and returns the exit code.
function Invoke-WslStreaming {
    param([string[]]$Arguments)
    & wsl.exe @Arguments 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { [Console]::Error.WriteLine($_.Exception.Message) }
        else { [Console]::Out.WriteLine([string]$_) }
    }
    return $LASTEXITCODE
}

# A previous run that was killed leaves the mutex abandoned; acquiring it then throws (wrapped by PowerShell in
# a MethodInvocationException), but the caller does own it.
function Wait-MirrorLock {
    param([System.Threading.Mutex]$Mutex, [TimeSpan]$Timeout)
    try { return $Mutex.WaitOne($Timeout) }
    catch {
        $inner = $_.Exception
        while ($null -ne $inner) {
            if ($inner -is [System.Threading.AbandonedMutexException]) { return $true }
            $inner = $inner.InnerException
        }
        throw
    }
}

function Test-Wsl {
    param([string[]]$Arguments)
    $null = & wsl.exe @Arguments 2>$null
    return ($LASTEXITCODE -eq 0)
}

#endregion

#region Self-test

function Invoke-SelfTest {
    # No native calls here, so any error is a bug in the self-test and must not pass silently.
    $ErrorActionPreference = 'Stop'
    $user = 'allisterb'
    $userHome = '/home/' + $user
    $good = $userHome + '/' + $MirrorName
    $nl = [string][char]10
    $failures = 0

    # Each case: description, destination, WSL HOME, WSL user, expect accepted?
    $destinationCases = @(
        @('expected value', $good, $userHome, $user, $true),
        @('empty string', '', $userHome, $user, $false),
        @('null', $null, $userHome, $user, $false),
        @('filesystem root', '/', $userHome, $user, $false),
        @('/home', '/home', $userHome, $user, $false),
        @('the home directory itself', $userHome, $userHome, $user, $false),
        @('home with trailing slash', ($userHome + '/'), $userHome, $user, $false),
        @("'..' back into the mirror", ($userHome + '/../' + $user + '/' + $MirrorName), $userHome, $user, $false),
        @("'..' after the mirror", ($good + '/..'), $userHome, $user, $false),
        @("'..' to the root", ($good + '/../../..'), $userHome, $user, $false),
        @("'.' segment", ($userHome + '/./' + $MirrorName), $userHome, $user, $false),
        @('double slash', ($userHome + '//' + $MirrorName), $userHome, $user, $false),
        @('trailing slash', ($good + '/'), $userHome, $user, $false),
        @('trailing newline', ($good + $nl), $userHome, $user, $false),
        @('trailing space', ($good + ' '), $userHome, $user, $false),
        @('tilde form', ('~/' + $MirrorName), $userHome, $user, $false),
        @('relative path', $MirrorName, $userHome, $user, $false),
        @('subdirectory of the mirror', ($good + '/src'), $userHome, $user, $false),
        @('another user', ('/home/someoneelse/' + $MirrorName), $userHome, $user, $false),
        @('/root', ('/root/' + $MirrorName), '/root', 'root', $false),
        @('/tmp', ('/tmp/' + $MirrorName), $userHome, $user, $false),
        @('the Windows repo', '/mnt/c/Projects/Silvergun', $userHome, $user, $false),
        @('computed from empty HOME', (Get-MirrorDestination ''), '', $user, $false),
        @('computed from HOME=/', (Get-MirrorDestination '/'), '/', $user, $false),
        @('computed from HOME=/home', (Get-MirrorDestination '/home'), '/home', $user, $false),
        @('HOME does not match user', $good, '/home/someoneelse', $user, $false),
        @('empty user', $good, $userHome, '', $false),
        @("user '..'", '/home/../silvergun-wsl', '/home/..', '..', $false),
        @('computed from the expected HOME', (Get-MirrorDestination $userHome), $userHome, $user, $true)
    )

    Write-Step 'Self-test: Get-MirrorDestinationError (rsync --delete target guard)'
    foreach ($case in $destinationCases) {
        $reason = Get-MirrorDestinationError -Destination $case[1] -WslHome $case[2] -WslUser $case[3]
        $accepted = ($null -eq $reason)
        $ok = ($accepted -eq $case[4])
        if (-not $ok) { $failures++ }
        $shown = if ($null -eq $case[1]) { '<null>' } else { ([string]$case[1]).Replace($nl, '\n') }
        $outcome = if ($accepted) { 'ACCEPTED' } else { 'REFUSED (' + $reason.Replace($nl, '\n') + ')' }
        $mark = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Step ('  {0}  {1,-34} "{2}" -> {3}' -f $mark, $case[0], $shown, $outcome)
    }

    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
    $notRepo = $PSScriptRoot
    $sourceCases = @(
        @('expected value', $repoRoot, '/mnt/c/Projects/Silvergun', $true),
        @('path with a space', $repoRoot, '/mnt/c/Projects/Silver gun', $true),
        @('empty Windows root', '', '/mnt/c/Projects/Silvergun', $false),
        @('Windows dir without src\Silvergun.sln', $notRepo, '/mnt/c/Projects/Silvergun/tests/scripts', $false),
        @('empty WSL source', $repoRoot, '', $false),
        @('WSL root', $repoRoot, '/', $false),
        @('drive root', $repoRoot, '/mnt/c', $false),
        @("'..' segment", $repoRoot, '/mnt/c/Projects/../Projects/Silvergun', $false),
        @('trailing slash', $repoRoot, '/mnt/c/Projects/Silvergun/', $false),
        @('the mirror', $repoRoot, ('/home/allisterb/' + $MirrorName), $false)
    )
    Write-Step 'Self-test: Get-MirrorSourceError'
    foreach ($case in $sourceCases) {
        $reason = Get-MirrorSourceError -WindowsRoot $case[1] -WslSource $case[2]
        $accepted = ($null -eq $reason)
        $ok = ($accepted -eq $case[3])
        if (-not $ok) { $failures++ }
        $outcome = if ($accepted) { 'ACCEPTED' } else { 'REFUSED (' + $reason + ')' }
        $mark = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Step ('  {0}  {1,-34} "{2}" -> {3}' -f $mark, $case[0], $case[2], $outcome)
    }

    $projectCases = @(
        @('NuGet test project', 'tests/Silvergun.PackageAnalysis.NuGet.Tests/Silvergun.PackageAnalysis.NuGet.Tests.csproj', $true),
        @('backslashes (not normalized here)', 'tests\Silvergun.PackageAnalysis.NuGet.Tests\Silvergun.PackageAnalysis.NuGet.Tests.csproj', $false),
        @('absolute', '/mnt/c/Projects/Silvergun/tests/X/X.csproj', $false),
        @("'..'", 'tests/../tests/Silvergun.PackageAnalysis.NuGet.Tests/Silvergun.PackageAnalysis.NuGet.Tests.csproj', $false),
        @('not a csproj', 'src/Silvergun.sln', $false),
        @('excluded dir', 'reference/projects/X/X.csproj', $false),
        @('missing file', 'tests/DoesNotExist/DoesNotExist.csproj', $false),
        @('shell metacharacters', 'tests/X;rm/X.csproj', $false)
    )
    Write-Step 'Self-test: Get-ProjectPathError'
    foreach ($case in $projectCases) {
        $reason = Get-ProjectPathError -ProjectPath $case[1] -WindowsRoot $repoRoot
        $accepted = ($null -eq $reason)
        $ok = ($accepted -eq $case[2])
        if (-not $ok) { $failures++ }
        $outcome = if ($accepted) { 'ACCEPTED' } else { 'REFUSED (' + $reason + ')' }
        $mark = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Step ('  {0}  {1,-34} -> {2}' -f $mark, $case[0], $outcome)
    }

    if ($failures -eq 0) { Write-Step 'Self-test: all guard cases behaved as expected.'; return 0 }
    Write-Step ("Self-test: $failures guard case(s) did NOT behave as expected.")
    return 1
}

#endregion

#region Main

function Invoke-Main {
    $total = [System.Diagnostics.Stopwatch]::StartNew()
    $timings = New-Object System.Collections.Generic.List[string]

    # ---- Preflight: arguments and both ends of the sync. Nothing is written until all of it passes.
    $step = [System.Diagnostics.Stopwatch]::StartNew()
    $windowsRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
    $projectPath = $Project.Replace('\', '/')
    $argumentErrors = @(@(
        (Get-ProjectPathError -ProjectPath $projectPath -WindowsRoot $windowsRoot),
        (Get-FrameworkError -Tfm $Framework),
        (Get-FilterError -TestFilter $Filter)
    ) | Where-Object { $null -ne $_ })
    if ($argumentErrors.Count -gt 0) {
        foreach ($e in $argumentErrors) { Write-Step ('REFUSED: ' + $e) }
        return 2
    }

    $homeQuery = Get-WslOutput @('-e', 'printenv', 'HOME')
    $userQuery = Get-WslOutput @('-e', 'id', '-un')
    if ($homeQuery.ExitCode -ne 0 -or $homeQuery.Lines.Count -ne 1 -or $userQuery.ExitCode -ne 0 -or $userQuery.Lines.Count -ne 1) {
        Write-Step 'REFUSED: could not read a single-line HOME and user name from WSL (is WSL running?).'
        return 2
    }
    $wslHome = [string]$homeQuery.Lines[0]
    $wslUser = [string]$userQuery.Lines[0]
    $destination = Get-MirrorDestination $wslHome
    $destinationError = Get-MirrorDestinationError -Destination $destination -WslHome $wslHome -WslUser $wslUser
    if ($null -ne $destinationError) { Write-Step ('REFUSED: ' + $destinationError); return 2 }
    # The textual check passed; now make sure no symlink (on HOME or the mirror itself) redirects it elsewhere.
    $resolved = Get-WslOutput @('-e', 'realpath', '-m', '--', $destination)
    if ($resolved.ExitCode -ne 0 -or $resolved.Lines.Count -ne 1 -or [string]$resolved.Lines[0] -cne $destination) {
        Write-Step ("REFUSED: destination '$destination' does not resolve to itself inside WSL (symlink?).")
        return 2
    }
    if ((Test-Wsl @('-e', 'test', '-e', $destination)) -and -not (Test-Wsl @('-e', 'test', '-d', $destination))) {
        Write-Step ("REFUSED: destination '$destination' exists and is not a directory.")
        return 2
    }

    $sourceQuery = Get-WslOutput @('-e', 'wslpath', '-a', '-u', $windowsRoot)
    $wslSource = ''
    if ($sourceQuery.ExitCode -eq 0 -and $sourceQuery.Lines.Count -eq 1) { $wslSource = ([string]$sourceQuery.Lines[0]).TrimEnd('/') }
    $sourceError = Get-MirrorSourceError -WindowsRoot $windowsRoot -WslSource $wslSource
    if ($null -ne $sourceError) { Write-Step ('REFUSED: ' + $sourceError); return 2 }
    if (-not (Test-Wsl @('-e', 'test', '-f', ($wslSource + '/src/Silvergun.sln')))) {
        Write-Step ("REFUSED: '$wslSource/src/Silvergun.sln' is not visible from WSL.")
        return 2
    }
    if (-not (Test-Wsl @('-e', 'test', '-f', ($wslSource + '/' + $projectPath)))) {
        Write-Step ("REFUSED: '$wslSource/$projectPath' is not visible from WSL.")
        return 2
    }
    $step.Stop()
    $timings.Add('preflight ' + (Format-Elapsed $step.Elapsed))
    Write-Step ("source      $wslSource/")
    Write-Step ("destination $destination/  (guard OK)")

    # ---- Sync.
    if ($NoSync) {
        Write-Step 'sync        skipped (-NoSync)'
        $timings.Add('sync skipped')
        if (-not (Test-Wsl @('-e', 'test', '-f', ($destination + '/src/Silvergun.sln')))) {
            Write-Step 'REFUSED: -NoSync but the mirror has never been synced (no src/Silvergun.sln). Run once without -NoSync.'
            return 2
        }
    }
    else {
        $rsyncArgs = @('-e', 'rsync', '-a', '--delete', '--chmod=go-w', '--info=stats1')
        foreach ($pattern in $RsyncExcludes) { $rsyncArgs += ('--exclude=' + $pattern) }
        $rsyncArgs += @('--', ($wslSource + '/'), ($destination + '/'))
        Write-Step ('sync: wsl ' + (Format-CommandLine $rsyncArgs))
        $step = [System.Diagnostics.Stopwatch]::StartNew()
        $rsyncExit = Invoke-WslStreaming $rsyncArgs
        $step.Stop()
        $timings.Add('sync ' + (Format-Elapsed $step.Elapsed))
        Write-Step ('sync        exit ' + $rsyncExit + ', ' + (Format-Elapsed $step.Elapsed))
        if ($rsyncExit -ne 0) {
            Write-Step 'rsync failed; not running tests.'
            Write-Step ('timings: ' + ($timings -join '; ') + '; total ' + (Format-Elapsed $total.Elapsed))
            return 3
        }
    }

    # ---- Test.
    $testArgs = @('--cd', $destination, '-e', 'env', 'DOTNET_NOLOGO=1', 'DOTNET_CLI_TELEMETRY_OPTOUT=1',
        'dotnet', 'test', ($destination + '/' + $projectPath), '-f', $Framework)
    if (-not [string]::IsNullOrEmpty($Filter)) { $testArgs += @('--filter', $Filter) }
    Write-Step ('test: wsl ' + (Format-CommandLine $testArgs))
    $step = [System.Diagnostics.Stopwatch]::StartNew()
    $testExit = Invoke-WslStreaming $testArgs
    $step.Stop()
    $timings.Add('test ' + (Format-Elapsed $step.Elapsed))
    Write-Step ('test        exit ' + $testExit + ', ' + (Format-Elapsed $step.Elapsed))
    Write-Step ('timings: ' + ($timings -join '; ') + '; total ' + (Format-Elapsed $total.Elapsed))
    return $testExit
}

$previousEncoding = $null
try { $previousEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { $previousEncoding = $null }

$exitCode = 1
if ($PSCmdlet.ParameterSetName -eq 'SelfTest') {
    $exitCode = Invoke-SelfTest
}
else {
    # One run at a time: two runs would race on the same mirror and the same Linux bin/ and obj/.
    $mutex = New-Object System.Threading.Mutex($false, 'Local\Silvergun.WslTestMirror')
    $acquired = $false
    try {
        $acquired = Wait-MirrorLock $mutex ([TimeSpan]::Zero)
        if (-not $acquired) {
            Write-Step "another wsl-test.ps1 run holds the mirror; waiting up to $LockTimeoutMinutes min..."
            $acquired = Wait-MirrorLock $mutex ([TimeSpan]::FromMinutes($LockTimeoutMinutes))
        }
        if ($acquired) { $exitCode = @(Invoke-Main)[-1] }
        else { Write-Step 'timed out waiting for the other run.'; $exitCode = 4 }
    }
    finally {
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

if ($null -ne $previousEncoding) { try { [Console]::OutputEncoding = $previousEncoding } catch { } }
exit $exitCode

#endregion
