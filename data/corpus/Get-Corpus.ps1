<#
.SYNOPSIS
    Builds pinned NuGet corpus manifests for the BenignCorpusHarness from the documented nuget.org v3
    API. Produces data/corpus/benign-top.manifest or data/corpus/benign-adversarial.manifest.

.DESCRIPTION
    Targets Windows PowerShell 5.1 ONLY (no pwsh on this machine, and nothing gets installed to get
    one). See docs/agent/tasks/corpus-acquisition-nuget-api.md, especially the "CORRECTION (2026-08-20)"
    section at the end, which is authoritative over the earlier "PowerShell 7+" line in the same file.

    Two manifests, two purposes:
      -Manifest top          ~100 top-downloaded, general-purpose packages (the SCALE corpus).
      -Manifest adversarial  ~40-60 packages chosen BECAUSE they should legitimately trip one of the
                              indicator categories ADR-0026 holds back (the FALSIFICATION corpus).
      -Manifest top-ext      ~100 further top-downloaded packages not in any other manifest, with
                              no-managed-code stubs skipped and at most 3 ids per family (C100+).
      -Manifest suspect      a FIXED id list of benign packages chosen because they should look like
                              something (embedded PEs, obfuscation, native loaders, downloaders, hooking,
                              scripting hosts). No search; versions only. See corpus-expansion-draft.md.

    API usage - the sanctioned path only:
      * Resolve resource URLs from the service index (https://api.nuget.org/v3/index.json) by @type.
        Hostnames are never hardcoded.
      * SearchQueryService: q=, take=, skip=, prerelease=false, semVerLevel=2.0.0.
      * PackageBaseAddress/3.0.0: {id-lower}/index.json enumerates all versions; the highest STABLE
        (non-prerelease) version is picked by hand-rolled numeric SemVer comparison (5.1 has no
        [SemanticVersion] type, and [version] mis-sorts prerelease tags and is not used here).

    This script produces manifests only. It never downloads a .nupkg (that stays with PackageCache at
    measurement time) and never writes a binary anywhere under data/.

.PARAMETER Manifest
    Which manifest to (re)build: 'top' or 'adversarial'.

.PARAMETER OutDir
    Where to write the manifest. Defaults to this script's own directory (data/corpus).

.PARAMETER CacheDir
    Where raw API responses are cached, OUTSIDE the repository by default (mirrors PackageCache's
    %LOCALAPPDATA%/Silvergun convention). A warm cache means a re-run makes zero network requests.

.PARAMETER Take
    Overrides the default target package count (100 for top; ~8 per category for adversarial). 0 keeps
    the built-in default. Useful for a small smoke run without spending the full request budget.

.PARAMETER DelaySeconds
    Minimum spacing between actual network requests. Cache hits are free and unthrottled. Default 1.0
    (project guardrail: ~1 request/second, including exploration).

.PARAMETER DryRun
    Resolves the service index (one real request, or a cache hit) and then only prints which further
    URLs WOULD be fetched, without fetching them and without writing a manifest file.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Get-Corpus.ps1 -Manifest top -Take 5 -DryRun
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('top', 'adversarial', 'top-ext', 'suspect')]
    [string]$Manifest,

    [string]$OutDir = '',

    [string]$CacheDir = (Join-Path $env:LOCALAPPDATA 'Silvergun\corpus-acquisition'),

    [int]$Take = 0,

    [double]$DelaySeconds = 1.0,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# $PSScriptRoot as a bare param-block default can resolve empty under -File with [CmdletBinding()] and
# a Mandatory parameter present (a documented 5.1 quirk in default-value evaluation scope) - resolve it
# here in the script body instead, where it is reliably populated.
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = $PSScriptRoot }

# TLS 1.2 must be set explicitly under 5.1 or every HTTPS call to nuget.org fails.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:UserAgent = 'Silvergun-CorpusAcquisition/1.0 (+https://github.com/allisterb/Silvergun; manifest builder, not the analyzer)'
$script:ServiceIndexUrl = 'https://api.nuget.org/v3/index.json'
$script:LastRequestAt = $null

# ---------------------------------------------------------------------------------------------------
# Caching / rate-limited HTTP
# ---------------------------------------------------------------------------------------------------

function Get-CacheKey {
    param([Parameter(Mandatory)][string]$Url)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Url)
        $hash = $sha256.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

# Every completed response (success or an ordinary error like 404) is cached as a {status, body}
# envelope, so a warm re-run never re-fetches even the edge cases. Only 429/403/a bot challenge are
# hard stops that are never cached-around - the whole run aborts and is reported, per guardrail #3/#4.
function Resolve-CachedEnvelope {
    param([Parameter(Mandatory)]$Envelope, [Parameter(Mandatory)][string]$Url)

    $status = [int]$Envelope.status
    if ($status -eq 200 -or $status -eq 202) {
        if ([string]::IsNullOrEmpty($Envelope.body)) { return $null }
        return ConvertFrom-Json -InputObject $Envelope.body
    }
    throw "HTTP $status (cached) for $Url"
}

function Invoke-CachedRequest {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$CacheDir,
        [Parameter(Mandatory)][double]$DelaySeconds,
        [Parameter(Mandatory)][hashtable]$Stats,
        [switch]$DryRun
    )

    $key = Get-CacheKey -Url $Url
    $cacheFile = Join-Path $CacheDir "$key.json"
    $urlFile = Join-Path $CacheDir "$key.url"

    if (Test-Path -LiteralPath $cacheFile) {
        $Stats.CacheHits++
        $envelope = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $cacheFile -Raw)
        return Resolve-CachedEnvelope -Envelope $envelope -Url $Url
    }

    if ($DryRun) {
        $Stats.WouldFetch++
        Write-Host "  DRY RUN would fetch: $Url"
        return $null
    }

    if ($null -ne $script:LastRequestAt) {
        $elapsed = (Get-Date) - $script:LastRequestAt
        $remaining = $DelaySeconds - $elapsed.TotalSeconds
        if ($remaining -gt 0) { Start-Sleep -Seconds $remaining }
    }

    $status = 0
    $bodyText = ''
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -Headers @{ 'User-Agent' = $script:UserAgent } -ErrorAction Stop
        $status = [int]$response.StatusCode
        $bodyText = [string]$response.Content

        if ($status -eq 202) {
            # Invoke-RestMethod would not throw here - a WAF challenge is HTTP 202 with an empty body
            # and an x-amzn-waf-action header, which only Invoke-WebRequest lets us inspect directly.
            $wafHeaderName = $response.Headers.Keys | Where-Object { $_ -ieq 'x-amzn-waf-action' } | Select-Object -First 1
            $wafValue = $null
            if ($wafHeaderName) { $wafValue = $response.Headers[$wafHeaderName] }
            if ($wafValue -eq 'challenge' -or [string]::IsNullOrEmpty($bodyText)) {
                throw "HARD STOP: bot challenge detected (HTTP 202, waf-action='$wafValue', body length $($bodyText.Length)) for $Url. A bot challenge is a refusal - stop and report, never circumvent."
            }
        }
    }
    catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        if ($null -ne $webResponse -and ($webResponse -is [System.Net.HttpWebResponse])) {
            $status = [int]$webResponse.StatusCode
            if ($status -eq 429 -or $status -eq 403) {
                throw "HARD STOP: HTTP $status from $Url. Guardrail requires stopping, not retrying, rotating user agents, or varying source addresses. $($_.Exception.Message)"
            }
            # An ordinary (non-429/403) HTTP error: cache it as a failure envelope below, do not abort.
            $bodyText = ''
        }
        else {
            throw
        }
    }
    finally {
        $script:LastRequestAt = Get-Date
    }

    $Stats.NetworkRequests++

    $envelope = [pscustomobject]@{ status = $status; body = $bodyText }
    $envelopeJson = $envelope | ConvertTo-Json -Compress -Depth 4
    [System.IO.File]::WriteAllText($cacheFile, $envelopeJson, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($urlFile, $Url, (New-Object System.Text.UTF8Encoding($false)))

    return Resolve-CachedEnvelope -Envelope $envelope -Url $Url
}

# ---------------------------------------------------------------------------------------------------
# Hand-rolled SemVer (5.1 has no [SemanticVersion]; [version] mis-sorts prerelease tags and is not
# used here at all). Prereleases are filtered out first; the remainder is compared as plain integer
# major/minor/patch[.revision] tuples - never as strings, so '10.0.0' sorts above '9.5.0'.
# ---------------------------------------------------------------------------------------------------

function ConvertTo-SemVerParts {
    param([string]$Version)

    if ([string]::IsNullOrWhiteSpace($Version)) { return $null }

    $core = $Version.Trim()
    $plusIndex = $core.IndexOf('+')
    if ($plusIndex -ge 0) { $core = $core.Substring(0, $plusIndex) }

    $dashIndex = $core.IndexOf('-')
    if ($dashIndex -ge 0) {
        # Prerelease tag present - not a stable release; excluded rather than string-compared.
        return $null
    }

    $segments = $core.Split('.')
    if ($segments.Length -lt 3) { return $null }

    $major = 0
    $minor = 0
    $patch = 0
    $revision = 0
    if (-not [int]::TryParse($segments[0], [ref]$major)) { return $null }
    if (-not [int]::TryParse($segments[1], [ref]$minor)) { return $null }
    if (-not [int]::TryParse($segments[2], [ref]$patch)) { return $null }
    if ($segments.Length -ge 4) {
        $rev = 0
        if ([int]::TryParse($segments[3], [ref]$rev)) { $revision = $rev }
    }

    return [pscustomobject]@{ Major = $major; Minor = $minor; Patch = $patch; Revision = $revision; Raw = $Version }
}

function Select-HighestStableVersion {
    param([string[]]$Versions)

    if (-not $Versions -or $Versions.Count -eq 0) { return $null }

    $parsed = New-Object System.Collections.Generic.List[object]
    foreach ($v in $Versions) {
        $p = ConvertTo-SemVerParts -Version $v
        if ($null -ne $p) { $parsed.Add($p) }
    }
    if ($parsed.Count -eq 0) { return $null }

    $best = $parsed[0]
    foreach ($p in $parsed) {
        if ($p.Major -gt $best.Major) { $best = $p; continue }
        if ($p.Major -lt $best.Major) { continue }
        if ($p.Minor -gt $best.Minor) { $best = $p; continue }
        if ($p.Minor -lt $best.Minor) { continue }
        if ($p.Patch -gt $best.Patch) { $best = $p; continue }
        if ($p.Patch -lt $best.Patch) { continue }
        if ($p.Revision -gt $best.Revision) { $best = $p }
    }

    return $best.Raw
}

function Show-SemVerEvidence {
    $sample = @('9.0.0', '9.5.2', '10.0.0', '2.1.0', '10.0.0-preview.1')
    $picked = Select-HighestStableVersion -Versions $sample
    $lexical = ($sample | Sort-Object)[-1]
    Write-Host "SemVer evidence (synthetic): input = $($sample -join ', ')"
    Write-Host "  semantic pick (this script, correct):        $picked"
    Write-Host "  lexical string-sort pick (wrong, for contrast): $lexical"
}

# ---------------------------------------------------------------------------------------------------
# nuget.org v3 API calls
# ---------------------------------------------------------------------------------------------------

function Search-NuGetPackages {
    param(
        [Parameter(Mandatory)][string]$SearchBaseUrl,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Query,
        [int]$Take = 20,
        [int]$Skip = 0,
        [Parameter(Mandatory)][string]$CacheDir,
        [Parameter(Mandatory)][double]$DelaySeconds,
        [Parameter(Mandatory)][hashtable]$Stats,
        [switch]$DryRun
    )

    $qEncoded = [uri]::EscapeDataString($Query)
    $url = "${SearchBaseUrl}?q=$qEncoded&take=$Take&skip=$Skip&prerelease=false&semVerLevel=2.0.0"
    $result = Invoke-CachedRequest -Url $url -CacheDir $CacheDir -DelaySeconds $DelaySeconds -Stats $Stats -DryRun:$DryRun
    if ($null -eq $result) { return @() }
    if ($result.PSObject.Properties.Match('data').Count -eq 0) { return @() }
    return $result.data
}

function Get-PackageVersions {
    param(
        [Parameter(Mandatory)][string]$PackageBaseUrl,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$CacheDir,
        [Parameter(Mandatory)][double]$DelaySeconds,
        [Parameter(Mandatory)][hashtable]$Stats,
        [switch]$DryRun
    )

    $idLower = $Id.ToLowerInvariant()
    $url = "$PackageBaseUrl$idLower/index.json"
    try {
        $result = Invoke-CachedRequest -Url $url -CacheDir $CacheDir -DelaySeconds $DelaySeconds -Stats $Stats -DryRun:$DryRun
    }
    catch {
        if ($_.Exception.Message -match '^HTTP 404') { return @() }
        throw
    }
    if ($null -eq $result) { return @() }
    if ($result.PSObject.Properties.Match('versions').Count -eq 0) { return @() }
    return $result.versions
}

# ---------------------------------------------------------------------------------------------------
# Manifest builders
# ---------------------------------------------------------------------------------------------------

function Add-OrUpdateCandidate {
    param([hashtable]$Candidates, $Hit)

    if ($null -eq $Hit) { return }
    if ($Hit.PSObject.Properties.Match('id').Count -eq 0 -or [string]::IsNullOrWhiteSpace($Hit.id)) { return }

    $key = $Hit.id.ToLowerInvariant()
    $downloads = 0L
    if ($Hit.PSObject.Properties.Match('totalDownloads').Count -gt 0 -and $null -ne $Hit.totalDownloads) {
        $downloads = [int64]$Hit.totalDownloads
    }

    if (-not $Candidates.ContainsKey($key) -or $downloads -gt $Candidates[$key].TotalDownloads) {
        $Candidates[$key] = @{ Id = $Hit.id; TotalDownloads = $downloads }
    }
}

function Get-RankedCandidates {
    param([hashtable]$Candidates)

    $list = New-Object System.Collections.Generic.List[object]
    foreach ($v in $Candidates.Values) { $list.Add($v) }

    $arr = $list.ToArray()
    $comparison = [System.Comparison[object]]{
        param($a, $b)
        if ($a.TotalDownloads -ne $b.TotalDownloads) {
            if ($a.TotalDownloads -gt $b.TotalDownloads) { return -1 } else { return 1 }
        }
        return [string]::CompareOrdinal($a.Id, $b.Id)
    }
    [Array]::Sort($arr, $comparison)
    return $arr
}

function Build-TopManifest {
    param([hashtable]$Ctx)

    $targetCount = 100
    if ($Ctx.Take -gt 0) { $targetCount = $Ctx.Take }

    Write-Host "Building TOP (scale) manifest: target $targetCount packages, ranked by totalDownloads."

    $candidates = @{}
    $pageSize = 100
    $pages = 10

    for ($p = 0; $p -lt $pages; $p++) {
        $skip = $p * $pageSize
        Write-Host "  search page $($p + 1)/$pages (skip=$skip, take=$pageSize, q='')"
        $hits = Search-NuGetPackages -SearchBaseUrl $Ctx.SearchUrl -Query '' -Take $pageSize -Skip $skip `
            -CacheDir $Ctx.CacheDir -DelaySeconds $Ctx.DelaySeconds -Stats $Ctx.Stats -DryRun:$Ctx.DryRun
        foreach ($hit in $hits) { Add-OrUpdateCandidate -Candidates $candidates -Hit $hit }
        if ($Ctx.DryRun -and $hits.Count -eq 0) { break }
    }

    $ranked = Get-RankedCandidates -Candidates $candidates
    Write-Host "  $($ranked.Count) distinct candidate id(s) collected across $pages page(s)."

    $selected = New-Object System.Collections.Generic.List[object]
    $tried = 0
    $maxTries = [Math]::Min($ranked.Count, ($targetCount * 2) + 20)

    foreach ($c in $ranked) {
        if ($selected.Count -ge $targetCount) { break }
        if ($tried -ge $maxTries) { break }
        $tried++

        $versions = Get-PackageVersions -PackageBaseUrl $Ctx.PackageBaseUrl -Id $c.Id `
            -CacheDir $Ctx.CacheDir -DelaySeconds $Ctx.DelaySeconds -Stats $Ctx.Stats -DryRun:$Ctx.DryRun
        $best = Select-HighestStableVersion -Versions $versions
        if ($null -eq $best) {
            $Ctx.Stats.Skipped.Add("top: $($c.Id) (totalDownloads=$($c.TotalDownloads)) - no stable version on PackageBaseAddress")
            continue
        }
        $selected.Add([pscustomobject]@{ Id = $c.Id; Version = $best; TotalDownloads = $c.TotalDownloads })
    }

    Write-Host "  selected $($selected.Count) package(s) (tried $tried candidate(s))."
    return $selected
}

# Held-back categories from ADR-0026, plus a deliberate falsification attempt against CallbackDomain.
# Hypotheses are recorded HERE, before any search runs - see PROVENANCE.md for the same text alongside
# the actual selections.
$script:AdversarialCategories = [ordered]@{
    'ExfilSink' = @{
        Terms      = @('discord webhook', 'slack webhook client', 'telegram bot client')
        Hypothesis = 'Discord/Slack/Telegram client and webhook libraries legitimately embed or construct the chat-webhook endpoint (discord.com/api/webhooks, hooks.slack.com, api.telegram.org) as a literal constant - exactly the ExfilSink pattern (paste/anonymous-drop/chat-webhook sinks).'
    }
    'DynamicDns' = @{
        Terms      = @('ngrok client', 'cloudflare tunnel client', 'dynamic dns update client')
        Hypothesis = 'Tunnel and dynamic-DNS clients (ngrok, Cloudflare Tunnel, no-ip/duckdns updaters) legitimately embed the provider hostname as a literal default endpoint - the DynamicDns pattern.'
    }
    'CredentialPath' = @{
        Terms      = @('aws sdk core', 'ssh.net client', 'windows credential manager')
        Hypothesis = 'AWS SDK, SSH client, and credential-manager libraries legitimately reference well-known credential file paths (~/.aws/credentials, ~/.ssh/id_*) as literal defaults - the CredentialPath pattern.'
    }
    'AutorunRegistry' = @{
        Terms      = @('windows service installer', 'windows task scheduler client', 'registry startup manager')
        Hypothesis = 'Windows service/startup/scheduled-task and registry-run utilities legitimately reference Run/RunOnce, Winlogon\Shell, or IFEO registry paths as literal constants - the AutorunRegistry pattern.'
    }
    'RawCodeHost' = @{
        Terms      = @('project template engine', 'code scaffolding tool', 'json schema code generator')
        Hypothesis = 'Template/scaffolding and schema-driven code-generation tools legitimately fetch templates or schemas from raw.githubusercontent.com/gist-style hosts as literal defaults - the RawCodeHost pattern.'
    }
    'PublicIpLiteral' = @{
        Terms      = @('geoip lookup library', 'dns client library', 'public ip address lookup')
        Hypothesis = 'GeoIP/DNS/public-IP libraries legitimately embed well-known public resolver or echo-service IP literals (e.g. 8.8.8.8, 1.1.1.1) as literal defaults - the PublicIpLiteral pattern.'
    }
    'CallbackDomain (falsification attempt)' = @{
        Terms      = @('webhook.site client', 'burp suite extension', 'out of band interaction testing', 'canary token client', 'interactsh client', 'penetration testing toolkit')
        Hypothesis = 'Pentest/OOB-interaction tooling (Burp extensions, webhook.site/request-catcher/canarytoken/interactsh clients, OOB-injection testers) legitimately calls out to an interaction-tracking domain by design. If any published package here trips CallbackDomain, that directly falsifies ADR-0026''s central claim ("a 0% share ... means the corpus contains no library of the kind that would legitimately use it") and must be reported by name, not folded into a share. (First 3 terms alone returned zero candidates - 3 more terms were added before the final run to make this a genuine attempt, not a token one; see PROVENANCE.md.)'
    }
}

function Build-AdversarialManifest {
    param([hashtable]$Ctx)

    $perCategoryCap = 8
    if ($Ctx.Take -gt 0) {
        $totalCats = $script:AdversarialCategories.Count
        $perCategoryCap = [Math]::Max(1, [Math]::Floor($Ctx.Take / $totalCats))
    }

    Write-Host "Building ADVERSARIAL (falsification) manifest: up to $perCategoryCap package(s)/category across $($script:AdversarialCategories.Count) categories."

    $allSelected = New-Object System.Collections.Generic.List[object]
    $categoryReport = New-Object System.Collections.Generic.List[object]
    $seen = @{}

    foreach ($catName in $script:AdversarialCategories.Keys) {
        $cat = $script:AdversarialCategories[$catName]
        Write-Host "-- $catName --"
        Write-Host "   hypothesis: $($cat.Hypothesis)"

        $candidates = @{}
        foreach ($term in $cat.Terms) {
            Write-Host "   search q='$term' (take=15)"
            $hits = Search-NuGetPackages -SearchBaseUrl $Ctx.SearchUrl -Query $term -Take 15 -Skip 0 `
                -CacheDir $Ctx.CacheDir -DelaySeconds $Ctx.DelaySeconds -Stats $Ctx.Stats -DryRun:$Ctx.DryRun
            foreach ($hit in $hits) { Add-OrUpdateCandidate -Candidates $candidates -Hit $hit }
        }

        $ranked = Get-RankedCandidates -Candidates $candidates
        $picked = New-Object System.Collections.Generic.List[object]

        foreach ($c in $ranked) {
            if ($picked.Count -ge $perCategoryCap) { break }
            $versions = Get-PackageVersions -PackageBaseUrl $Ctx.PackageBaseUrl -Id $c.Id `
                -CacheDir $Ctx.CacheDir -DelaySeconds $Ctx.DelaySeconds -Stats $Ctx.Stats -DryRun:$Ctx.DryRun
            $best = Select-HighestStableVersion -Versions $versions
            if ($null -eq $best) {
                $Ctx.Stats.Skipped.Add("adversarial/$catName`: $($c.Id) (totalDownloads=$($c.TotalDownloads)) - no stable version")
                continue
            }
            $entry = [pscustomobject]@{ Id = $c.Id; Version = $best; TotalDownloads = $c.TotalDownloads }
            $picked.Add($entry)

            $key = $c.Id.ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $allSelected.Add($entry)
            }
        }

        foreach ($p in $picked) { Write-Host "   selected: $($p.Id),$($p.Version) (totalDownloads=$($p.TotalDownloads))" }
        if ($picked.Count -eq 0) { Write-Host "   selected: (none found with a resolvable stable version)" }

        $categoryReport.Add([pscustomobject]@{
            Category   = $catName
            Terms      = $cat.Terms -join '; '
            Hypothesis = $cat.Hypothesis
            Selected   = $picked
        })
    }

    Write-Host "  selected $($allSelected.Count) distinct package(s) total across all categories."
    return @{ Entries = $allSelected; CategoryReport = $categoryReport }
}

# ---------------------------------------------------------------------------------------------------
# C100+ (top-ext) and C-suspect builders. Rules fixed in corpus-expansion-draft.md before any fetch.
# ---------------------------------------------------------------------------------------------------

function Get-ManifestIds {
    param([Parameter(Mandatory)][string]$Path)

    $ids = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $t = $line.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
        $ids[$t.Split(',')[0].ToLowerInvariant()] = $true
    }
    return $ids
}

# No managed implementation to scan: native runtime stubs, SDK/workload manifests, reference packs.
function Get-NoManagedCodeReason {
    param([Parameter(Mandatory)][string]$Id)

    if ($Id -match '^(?i)runtime\.') { return 'runtime.* stub' }
    if ($Id -match '(?i)\.runtime\.native\.') { return '*.runtime.native.* stub' }
    if ($Id -match '(?i)\.Manifest-') { return 'SDK manifest' }
    if ($Id -match '^(?i)Microsoft\.NET\.Workload\.') { return 'workload package' }
    if ($Id -match '(?i)\.Ref$') { return 'reference pack' }
    return $null
}

function Get-FamilyKey {
    param([Parameter(Mandatory)][string]$Id)

    # Vendor prefix (AWSSDK, OpenTelemetry, SQLitePCLRaw); Microsoft.* and System.* by their second part.
    $parts = $Id.ToLowerInvariant().Split('.')
    if ($parts.Length -ge 2 -and ($parts[0] -eq 'microsoft' -or $parts[0] -eq 'system')) { return "$($parts[0]).$($parts[1])" }
    return $parts[0]
}

function Build-TopExtManifest {
    param([hashtable]$Ctx)

    $targetCount = 100
    if ($Ctx.Take -gt 0) { $targetCount = $Ctx.Take }
    $familyCap = 3

    $existing = @{}
    foreach ($name in @('benign-top.manifest', 'c-build.manifest', 'benign-adversarial.manifest')) {
        foreach ($k in (Get-ManifestIds -Path (Join-Path $Ctx.OutDir $name)).Keys) { $existing[$k] = $name }
    }

    Write-Host "Building TOP-EXT manifest: target $targetCount packages, family cap $familyCap, excluding $($existing.Count) id(s) already in other manifests."

    $candidates = @{}
    $pageSize = 100
    $pages = 4
    for ($p = 0; $p -lt $pages; $p++) {
        $skip = $p * $pageSize
        Write-Host "  search page $($p + 1)/$pages (skip=$skip, take=$pageSize, q='')"
        $hits = Search-NuGetPackages -SearchBaseUrl $Ctx.SearchUrl -Query '' -Take $pageSize -Skip $skip `
            -CacheDir $Ctx.CacheDir -DelaySeconds $Ctx.DelaySeconds -Stats $Ctx.Stats -DryRun:$Ctx.DryRun
        foreach ($hit in $hits) { Add-OrUpdateCandidate -Candidates $candidates -Hit $hit }
        if ($Ctx.DryRun -and $hits.Count -eq 0) { break }
    }

    $ranked = Get-RankedCandidates -Candidates $candidates
    Write-Host "  $($ranked.Count) distinct candidate id(s) collected across $pages page(s)."

    $selected = New-Object System.Collections.Generic.List[object]
    $families = @{}
    $rank = 0
    foreach ($c in $ranked) {
        $rank++
        if ($selected.Count -ge $targetCount) { break }
        $key = $c.Id.ToLowerInvariant()
        if ($existing.ContainsKey($key)) { continue }

        $reason = Get-NoManagedCodeReason -Id $c.Id
        if ($null -ne $reason) {
            $Ctx.Stats.Skipped.Add("top-ext: rank $rank $($c.Id) - $reason")
            continue
        }
        $family = Get-FamilyKey -Id $c.Id
        if ($families.ContainsKey($family) -and $families[$family] -ge $familyCap) {
            $Ctx.Stats.Skipped.Add("top-ext: rank $rank $($c.Id) - family cap ($family)")
            continue
        }

        $versions = Get-PackageVersions -PackageBaseUrl $Ctx.PackageBaseUrl -Id $c.Id `
            -CacheDir $Ctx.CacheDir -DelaySeconds $Ctx.DelaySeconds -Stats $Ctx.Stats -DryRun:$Ctx.DryRun
        $best = Select-HighestStableVersion -Versions $versions
        if ($null -eq $best) {
            $Ctx.Stats.Skipped.Add("top-ext: rank $rank $($c.Id) - no stable version on PackageBaseAddress")
            continue
        }
        $families[$family] = 1 + $(if ($families.ContainsKey($family)) { $families[$family] } else { 0 })
        $selected.Add([pscustomobject]@{ Id = $c.Id; Version = $best; TotalDownloads = $c.TotalDownloads })
        Write-Host "   rank ${rank}: $($c.Id),$best (totalDownloads=$($c.TotalDownloads))"
    }

    Write-Host "  selected $($selected.Count) package(s); last rank examined $rank."
    return $selected
}

# Fixed list, recorded with its hypotheses in corpus-expansion-draft.md before any fetch.
$script:SuspectCategories = [ordered]@{
    'A. Commercial obfuscated or protected' = @('Aspose.Words', 'Aspose.Cells', 'Aspose.PDF', 'Syncfusion.Licensing',
        'Syncfusion.Pdf.Net.Core', 'Syncfusion.XlsIO.Net.Core', 'Spire.PDF', 'FreeSpire.PDF', 'IronPdf', 'DevExpress.Xpo',
        'Devart.Data.MySql', 'EO.Pdf')
    'B. Licensing and protection SDKs' = @('Standard.Licensing', 'Portable.Licensing', 'Cryptolens.Licensing',
        'LicenseSpring', 'SmartAssembly.Attributes', 'Obfuscar')
    'C. Embedded or merged assemblies' = @('Costura.Fody', 'Fody', 'ILMerge', 'ILRepack', 'ILRepack.Lib.MSBuild.Task',
        'NuGet.CommandLine', 'squirrel.windows', 'Clowd.Squirrel', 'Velopack')
    'D. Native loaders and wrappers' = @('SkiaSharp', 'SQLitePCLRaw.bundle_e_sqlite3', 'LibGit2Sharp',
        'Magick.NET-Q16-AnyCPU', 'OpenCvSharp4', 'Microsoft.ML.OnnxRuntime', 'Microsoft.Web.WebView2',
        'Microsoft.ClearScript', 'Tesseract')
    'E. Downloaders and process launchers' = @('Microsoft.Playwright', 'PuppeteerSharp', 'Selenium.WebDriver',
        'Selenium.WebDriver.ChromeDriver', 'WebDriverManager', 'Autoupdater.NET.Official',
        'NetSparkleUpdater.SparkleUpdater', 'CliWrap', 'Medallion.Shell', 'SimpleExec')
    'F. Install-time and tool packages' = @('EntityFramework', 'xunit.runner.console', 'NUnit.ConsoleRunner',
        'GitVersion.Tool', 'Nerdbank.GitVersioning', 'dotnet-ef', 'Cake.Tool', 'dotnet-script')
    'G. Runtime patching, hooking and PE tooling' = @('Lib.Harmony', 'MonoMod.RuntimeDetour', 'Reloaded.Hooks',
        'EasyHook', 'Iced', 'PeNet', 'AsmResolver.PE', 'dnlib')
    'H. Scripting and dynamic-code hosts' = @('Microsoft.CodeAnalysis.CSharp.Scripting', 'Jint', 'IronPython', 'NLua',
        'Microsoft.PowerShell.SDK')
    'I. System management' = @('System.Management', 'TaskScheduler', 'Topshelf', 'Vanara.PInvoke.Kernel32')
}

function Build-SuspectManifest {
    param([hashtable]$Ctx)

    Write-Host "Building SUSPECT manifest: fixed id list, $($script:SuspectCategories.Count) categories, no search."

    $selected = New-Object System.Collections.Generic.List[object]
    foreach ($catName in $script:SuspectCategories.Keys) {
        Write-Host "-- $catName --"
        foreach ($id in $script:SuspectCategories[$catName]) {
            $versions = Get-PackageVersions -PackageBaseUrl $Ctx.PackageBaseUrl -Id $id `
                -CacheDir $Ctx.CacheDir -DelaySeconds $Ctx.DelaySeconds -Stats $Ctx.Stats -DryRun:$Ctx.DryRun
            $best = Select-HighestStableVersion -Versions $versions
            if ($null -eq $best) {
                $Ctx.Stats.Skipped.Add("suspect/$catName`: $id - not found or no stable version")
                Write-Host "   $id - not resolved"
                continue
            }
            $selected.Add([pscustomobject]@{ Id = $id; Version = $best; TotalDownloads = 0 })
            Write-Host "   $id,$best"
        }
    }

    Write-Host "  selected $($selected.Count) package(s)."
    return $selected
}

# ---------------------------------------------------------------------------------------------------
# Manifest writer - format must match CorpusManifest.Load exactly: 'id,version', blank/'#' lines
# ignored, no inline comments on a data line (Parse() requires exactly one comma).
# ---------------------------------------------------------------------------------------------------

function Write-Manifest {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Header,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Entries
    )

    $arr = $Entries.ToArray()
    $comparison = [System.Comparison[object]]{
        param($a, $b)
        [string]::CompareOrdinal($a.Id, $b.Id)
    }
    [Array]::Sort($arr, $comparison)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($Header.TrimEnd())
    $lines.Add('')
    foreach ($e in $arr) { $lines.Add("$($e.Id),$($e.Version)") }
    $lines.Add('')

    $content = [string]::Join("`n", $lines.ToArray())
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $content, $encoding)

    Write-Host "wrote $Path ($($arr.Count) entries)"
}

# ---------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------

$stats = @{
    NetworkRequests = 0
    CacheHits       = 0
    WouldFetch      = 0
    Skipped         = (New-Object System.Collections.Generic.List[string])
}

New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "== Silvergun corpus acquisition (nuget.org v3 API, PowerShell 5.1) =="
Write-Host "UTC now: $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Host "Manifest target: $Manifest"
Write-Host "Cache dir: $CacheDir"
Write-Host "Out dir: $OutDir"
Write-Host "Delay: ${DelaySeconds}s between actual network requests (cache hits are free)"
if ($DryRun) { Write-Host "DRY RUN - no network calls beyond what is already cached; no manifest file will be written" }
Write-Host ""

$index = Invoke-CachedRequest -Url $script:ServiceIndexUrl -CacheDir $CacheDir -DelaySeconds $DelaySeconds -Stats $stats -DryRun:$DryRun
if ($null -eq $index) {
    Write-Host ""
    Write-Host "DRY RUN stopped before the service index was resolved (not cached yet). Nothing further to preview."
    Write-Host "Network requests: $($stats.NetworkRequests); cache hits: $($stats.CacheHits); would-fetch: $($stats.WouldFetch)"
    exit 0
}

$searchIds = @()
foreach ($r in $index.resources) {
    if ($r.'@type' -like 'SearchQueryService*') { $searchIds += [string]$r.'@id' }
}
if ($searchIds.Count -eq 0) { throw "Service index at $script:ServiceIndexUrl listed no SearchQueryService resource." }
$searchIdsArray = [string[]]$searchIds
[Array]::Sort($searchIdsArray, [System.StringComparer]::Ordinal)
$searchUrl = $searchIdsArray[0]

$baseIds = @()
foreach ($r in $index.resources) {
    if ($r.'@type' -eq 'PackageBaseAddress/3.0.0') { $baseIds += [string]$r.'@id' }
}
if ($baseIds.Count -eq 0) { throw "Service index at $script:ServiceIndexUrl listed no PackageBaseAddress/3.0.0 resource." }
$baseIdsArray = [string[]]$baseIds
[Array]::Sort($baseIdsArray, [System.StringComparer]::Ordinal)
$packageBaseUrl = $baseIdsArray[0]
if (-not $packageBaseUrl.EndsWith('/')) { $packageBaseUrl += '/' }

Write-Host "SearchQueryService candidates (ordinal @id sort, first chosen): $($searchIdsArray -join ', ')"
Write-Host "  chosen: $searchUrl"
Write-Host "PackageBaseAddress/3.0.0 candidates: $($baseIdsArray -join ', ')"
Write-Host "  chosen: $packageBaseUrl"
Write-Host ""

Show-SemVerEvidence
Write-Host ""

$boundaryId = 'Microsoft.Extensions.DependencyInjection'
$boundaryVersions = Get-PackageVersions -PackageBaseUrl $packageBaseUrl -Id $boundaryId `
    -CacheDir $CacheDir -DelaySeconds $DelaySeconds -Stats $stats -DryRun:$DryRun
if ($boundaryVersions -and $boundaryVersions.Count -gt 0) {
    $boundaryPick = Select-HighestStableVersion -Versions $boundaryVersions
    Write-Host "SemVer evidence (real package, 9.x/10.x boundary): $boundaryId has $($boundaryVersions.Count) version(s) on record."
    Write-Host "  highest stable pick (this script): $boundaryPick"
    $lexicalBoundary = ($boundaryVersions | Sort-Object)[-1]
    Write-Host "  lexical string-sort pick (wrong, for contrast): $lexicalBoundary"
}
else {
    Write-Host "SemVer boundary evidence: $boundaryId versions not available (dry run or cache miss)."
}
Write-Host ""

$ctx = @{
    SearchUrl      = $searchUrl
    PackageBaseUrl = $packageBaseUrl
    CacheDir       = $CacheDir
    DelaySeconds   = $DelaySeconds
    Stats          = $stats
    Take           = $Take
    DryRun         = [bool]$DryRun
    OutDir         = $OutDir
}

if ($Manifest -eq 'top-ext' -or $Manifest -eq 'suspect') {
    if ($Manifest -eq 'top-ext') {
        $entries = Build-TopExtManifest -Ctx $ctx
        $file = 'benign-top-ext.manifest'
        $header = @'
# Benign corpus (C100+) - further top-downloaded NuGet packages, pinned (id,version).
#
# Generated by data/corpus/Get-Corpus.ps1 -Manifest top-ext from the documented nuget.org v3 API. Rule
# (fixed before the fetch, see corpus-expansion-draft.md): ranks from 4 search pages by totalDownloads;
# ids already in benign-top, c-build or benign-adversarial skipped; runtime/native stubs, SDK/workload
# manifests and reference packs skipped; at most 3 ids per family (the id's first part, or first two for
# Microsoft.* and System.*; corrected after the first run, see PROVENANCE.md). Each id is
# pinned to its highest stable version. Skips and the run's date/request count: PROVENANCE.md.
# Benign by assumption, not by proof (ADR-0021). benign-top.manifest stays the frozen baseline.
#
# Format: id,version - one per line, sorted ordinally by id.
'@
    }
    else {
        $entries = Build-SuspectManifest -Ctx $ctx
        $file = 'benign-suspect.manifest'
        $header = @'
# Benign corpus (C-suspect) - benign packages chosen BECAUSE they should look like something:
# obfuscation, embedded executables/archives, native loaders, downloaders and process launchers,
# install-time tools, runtime patching, scripting hosts, system management. Pinned (id,version).
#
# Generated by data/corpus/Get-Corpus.ps1 -Manifest suspect from a FIXED id list (no search); versions
# from nuget.org PackageBaseAddress. Categories and hypotheses, recorded before the fetch:
# corpus-expansion-draft.md. Unresolved ids and the run's date/request count: PROVENANCE.md.
# A finding here is expected and is reported by name: the point is the base rate of benign capability.
# Benign by assumption, not by proof (ADR-0021).
#
# Format: id,version - one per line, sorted ordinally by id.
'@
    }
    if ($DryRun) {
        Write-Host "DRY RUN: would write $($entries.Count) entries to $(Join-Path $OutDir $file) (not written)."
    }
    else {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($e in $entries) { $list.Add($e) }
        Write-Manifest -Path (Join-Path $OutDir $file) -Header $header -Entries $list
    }
}
elseif ($Manifest -eq 'top') {
    $entries = Build-TopManifest -Ctx $ctx
    if ($DryRun) {
        Write-Host "DRY RUN: would write $($entries.Count) entries to $(Join-Path $OutDir 'benign-top.manifest') (not written)."
    }
    else {
        $header = @'
# Benign corpus (SCALE) - top-downloaded, general-purpose NuGet packages, pinned (id,version).
#
# Generated by data/corpus/Get-Corpus.ps1 from the documented nuget.org v3 API (SearchQueryService +
# PackageBaseAddress/3.0.0). See data/corpus/PROVENANCE.md for the exact queries, resolved endpoints,
# UTC date and request count for the run that produced this file.
#
# WHAT THIS IS: packages ranked by totalDownloads as reported by nuget.org's SearchQueryService, each
# pinned to its highest STABLE (non-prerelease) SemVer resolved from PackageBaseAddress. Purpose:
# tighten the confidence bound on the zero-prevalence indicator categories ADR-0026 holds back, and
# give median/p90 figures a population worth quoting. This is NOT a malware corpus and NOT proof of
# benignity - see ADR-0021: benign by assumption is not benign by proof.
#
# WHY VERSIONS ARE PINNED: the harness's first acceptance criterion is that two runs of the same
# manifest produce byte-identical output. A floating version would silently change the numbers a
# risk-scoring ADR is calibrated against.
#
# Format: id,version - one per line. Blank lines and lines starting with '#' are ignored. Entries are
# sorted ORDINALLY BY ID for script reproducibility - this is why the order differs from the
# hand-curated benign-corpus.manifest (which instead preserves append order so --take N stays
# comparable across additions; see PROVENANCE.md).
'@
        Write-Manifest -Path (Join-Path $OutDir 'benign-top.manifest') -Header $header -Entries $entries
    }
}
else {
    $result = Build-AdversarialManifest -Ctx $ctx
    if ($DryRun) {
        Write-Host "DRY RUN: would write $($result.Entries.Count) entries to $(Join-Path $OutDir 'benign-adversarial.manifest') (not written)."
    }
    else {
        $header = @'
# Benign corpus (ADVERSARIAL / FALSIFICATION) - packages selected BECAUSE they are expected to
# legitimately trip an ADR-0026 held-back indicator category, pinned (id,version).
#
# Generated by data/corpus/Get-Corpus.ps1 from the documented nuget.org v3 API. See
# data/corpus/PROVENANCE.md for the per-category search terms, the hypothesis recorded for each
# category BEFORE this run, resolved endpoints, UTC date and request count.
#
# WHAT THIS IS: the falsification corpus, not the scale corpus - it is what actually tests ADR-0026.
# Every package here was chosen because its stated purpose plausibly matches the pattern one of
# ExfilSink, DynamicDns, CredentialPath, AutorunRegistry, RawCodeHost, or PublicIpLiteral watches for,
# or (the CallbackDomain group) because it is pentest/OOB-interaction tooling that would legitimately
# reference an interaction-tracking domain. These packages were NOT hand-picked to come back clean.
# A hit here is a Critical finding against ADR-0026's central claim, not noise - see PROVENANCE.md.
#
# Format: id,version - one per line. Blank lines and lines starting with '#' are ignored. Entries are
# sorted ordinally by id for reproducibility; per-category grouping and rationale live in
# PROVENANCE.md, not inline, because a manifest data line is strictly 'id,version' (see
# CorpusManifest.Parse - a second comma or trailing comment is a hard parse error, by design).
'@
        Write-Manifest -Path (Join-Path $OutDir 'benign-adversarial.manifest') -Header $header -Entries $result.Entries
    }

    Write-Host ""
    Write-Host "== Adversarial category breakdown =="
    foreach ($cr in $result.CategoryReport) {
        Write-Host "-- $($cr.Category) --"
        Write-Host "   terms: $($cr.Terms)"
        Write-Host "   hypothesis: $($cr.Hypothesis)"
        foreach ($s in $cr.Selected) { Write-Host "   selected: $($s.Id),$($s.Version)" }
        if ($cr.Selected.Count -eq 0) { Write-Host "   selected: (none)" }
    }
}

Write-Host ""
Write-Host "== Summary =="
Write-Host "Network requests: $($stats.NetworkRequests)"
Write-Host "Cache hits: $($stats.CacheHits)"
if ($DryRun) { Write-Host "Would-fetch (dry run, NOT counted as a request): $($stats.WouldFetch)" }
if ($stats.Skipped.Count -gt 0) {
    Write-Host "Skipped ($($stats.Skipped.Count)):"
    foreach ($s in $stats.Skipped) { Write-Host "  - $s" }
}
