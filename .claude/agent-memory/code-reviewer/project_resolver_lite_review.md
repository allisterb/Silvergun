---
name: resolver-lite-review
description: Resolver-lite transitive NuGet dep walk (ADR 0018) review notes — (id,version) expansion-guard correctness technique and recurring checkpoints
metadata:
  type: project
---

Resolver-lite (`src/Silvergun.Intel/NuGetDependencyResolver.cs`, ADR 0018, task `resolver-lite-transitive-dependencies.md`) is a bounded best-effort transitive NuGet dep walk over `IPackageDependencyFetcher`. Phase 1 core reviewed; both file and `NuGetDependencyResolverTests.cs` were still untracked at review time (not yet committed).

**Why:** commodity VS/NuGet vuln-parity work feeding OSV; recall-over-precision (ADR-0002), deliberately NOT a `dotnet restore`.

**How to apply — recurring correctness checkpoints for this walk:**
- Expansion/visited guard MUST be keyed by `(id, version)` using the **resolved/fetched** version (not the requested range string), case-insensitive id + ordinal version. Guarding by id-alone reintroduces a false-negative: first-seen version's closure walked while node reports highest version (highest-wins unify). Both closures of an id reached at two versions must be walked. Termination = finite distinct (id,version) pairs + depth cap.
- Highest-wins unification stays isolated in `Unify` (single method, so policy can swap per deferred `--dep-conflicts` flag). Shallowest depth retained via `Math.Min`; `IsDirect = Depth==1`. Reported set = one node per id.
- `Unify` prefers a parseable candidate over an unparseable existing version; uses `TryParse` so it never throws.
- Never-throws-except-cancellation: fetch wrapped in try; rethrow only `catch (OperationCanceledException) when (ct.IsCancellationRequested)`; null fetch or any other throw ⇒ `complete=false; continue`. See [[project_hostile_input_never_throws]].
- Redundant re-fetch on repeat encounters is intentional (needed for cross-path version unification) — a perf trade-off, not a bug.

**Clean pass 2026-07-24** on the follow-up (id,version)-guard fix: prior graph-closure Warning fully resolved, 15/15 resolver tests green, no regressions. One Nit only: the expansion-guard key build (`expanded.Add((fetched.Id, fetched.Version))`) and `KeyEqualityComparer.GetHashCode` (`obj.Id.ToLowerInvariant()`) sit **outside** the fetch try/catch, so a fetcher returning a `FetchedPackage` with null `Id` would NRE and break the never-throws contract. Live fetcher sources Id from feed metadata (`chosen.Identity.Id`) so likelihood is low; defensive-hardening only.

**Phase 2 clean pass 2026-07-24** (OSV+report+CLI+render wiring): 242 NuGet.Tests + 92 CLI.Tests green. `OsvQueryBuilder.Build(package, resolved)` overload correct (self-query IsDependency:false + one dep query per resolved node at concrete version, deduped by (id,version), null⇒package-only, never floors declared deps — the single-arg path stayed byte-unchanged). Additive trailing `PackageCapabilityReport` fields normalize null→empty + NotRun with JSON back-compat. CLI: resolution gated on `depth>=1 && !noVulns`, `Math.Clamp(depth,0,MaxResolveDepth=8)`, negative rejected at parse, seed map skips unparseable ranges, whole resolver call try/catch⇒Partial+empty, one stderr note; `ScanExitCode`/`--strict` untouched. Renderer routes all dashes through `Dash(rich)` and untrusted id/version through `Esc`; footer downgrades off Clean on Partial. **One Warning:** stale comment in `TransitiveReportRendererTests.cs` (`TransitiveSection_AsciiOnlyByDefault`, ~lines 68-73) still claims the hardcoded-em-dash bug is live and the test "FAILS as of Phase 2" — the bug was fixed (renderer now uses `Dash(rich)`) and the test passes, so the comment is misleading and should be updated to record the fix. Recurring lesson: when a bug a test was written to catch gets fixed, update the test's explanatory comment too.
