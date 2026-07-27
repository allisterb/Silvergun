---
name: project-project-health-intel-review
description: Review outcome for ADR 0015 / project-health-intel.md (GitHub repo health signal, Silvergun.Intel + CLI health verb + scan-package --health) — clean pass 2026-07-18, one Warning on repo-URL fallback
metadata:
  type: project
---

Reviewed 2026-07-18: `src/Silvergun.Intel/{RepositoryRef,ProjectHealth,ProjectHealthScorer,IProjectHealthSource,
GitHubProjectHealthSource,NuGetRepositoryResolver,ProjectHealthReport}.cs`, `PackageModel.cs`/`NuGetPackage.cs`
additive nuspec-repo fields, `Program.cs` `health` verb + `scan-package --health`, and the new report renderers
against ADR 0015 / `docs/agent/tasks/project-health-intel.md`. **Clean pass** — build succeeded
(`dotnet build src/Silvergun.CLI`), full existing+new test suites passed (115 in
`Silvergun.PackageAnalysis.NuGet.Tests`, 54 in `Silvergun.CLI.Tests`, at time of review). No csproj changes (no new
NuGet packages), no `ext/`/`reference/` touched.

**Verified solid:** `GitHubProjectHealthSource`/`NuGetRepositoryResolver` mirror the
`LibrariesIoPopularitySource` never-throws/cancellation pattern exactly (checked line-by-line — same
`catch (OperationCanceledException) when (ct.IsCancellationRequested) throw;` + generic `catch => null`
shape). `GitHubRepoUrl.TryParse` is provably total (no unguarded `Substring`/`IndexOf` paths). Token
(`SILVERGUN_GITHUB_TOKEN`) only ever reaches the `Authorization` header and a presence-only stderr line
(`Program.GitHubToken`), matching the existing `SelectPopularitySource`/libraries.io precedent. `health` verb
never calls `ScanExitCode` (no `--strict` gate); `scan-package`'s `ScanExitCode` call only reads
`AllFindings`/obfuscation/script-findings, confirming health is exit-code-inert. `PackageIdentityInfo`/
`PackageCapabilityReport` additions are trailing-optional positional-record params — confirmed additive
JSON/construction back-compat. Scoring formulas structurally verified distinct from OSSGadget's
`GitHubHealthAlgorithm` (reference/projects/OSSGadget-main) — that one is multi-call Octokit-based
(commits/PRs/issues/releases/contributors); Silvergun's is single-call star/fork/subscriber/age/push-recency —
no copying, just ADR 0015's "adapted, not ported" claim holding up.

**One Warning raised (not blocking):** `Program.ResolveLocalHealth` (scan-package --health path) does
`pkg.RepositoryUrl ?? pkg.ProjectUrl` — only falls back to `ProjectUrl` when `RepositoryUrl` is entirely
absent, NOT when `RepositoryUrl` is present but resolves to a non-GitHub host (e.g. GitLab) while `ProjectUrl`
would have resolved to GitHub. `NuGetRepositoryResolver.ResolveAsync` (the `health` verb's nuget.org path) DOES
try multiple candidates until one parses. Suggested fix: loop `[pkg.RepositoryUrl, pkg.ProjectUrl]` through
`GitHubRepoUrl.TryParse` like the resolver does, rather than a single `??` pick. Low severity — degrades to "no
health" gracefully, never crashes, never affects exit code — but worth checking again if this file is touched
in a follow-up task, since it's an easy one-line fix once flagged.

**Also worth reusing:** `HealthSectionRenderer.AsciiBar` returns a string containing literal `[`/`]` bracket
characters (`"[" + stars + "]"`) — these are Spectre markup metacharacters even though the value isn't "report
data" in the usual sense (names/paths/etc, see [[feedback_spectre_reports_review]]). The implementer correctly
wrapped it in `Esc(...)` before `grid.AddRow`. Good pattern to point future renderer work at: *any* string
built for markup — even a synthetic ASCII-art bar — needs `Esc` if it contains `[`/`]`, not just fields sourced
directly from untrusted report data.
