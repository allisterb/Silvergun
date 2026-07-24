namespace Silvergun.Intel;

using System.Collections.Generic;

/// <summary>
/// Outcome of a resolver-lite transitive walk (ADR 0018). <see cref="NotRun"/> = resolution was not attempted
/// (e.g. <c>maxDepth &lt;= 0</c>); <see cref="Complete"/> = every reachable node within <c>maxDepth</c> was fetched;
/// <see cref="Partial"/> = at least one fetch failed (feed unreachable / package or version absent) so the graph is
/// incomplete and must not be reported as a clean all-clear.
/// </summary>
public enum DependencyResolutionStatus { NotRun, Complete, Partial }

/// <summary>
/// The resolved transitive set plus its honesty flag. When <see cref="Status"/> is <see cref="DependencyResolutionStatus.Partial"/>
/// the <see cref="Resolved"/> list is best-effort and incomplete; callers must surface that (no false all-clear).
/// </summary>
public sealed record DependencyResolutionResult(
    DependencyResolutionStatus Status,
    IReadOnlyList<ResolvedDependency> Resolved);
