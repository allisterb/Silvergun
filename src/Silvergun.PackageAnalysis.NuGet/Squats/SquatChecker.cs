namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Scores a target package id for typosquatting. Direction (initial): mutate the <em>target</em> id into
/// near-neighbors, then ask the <see cref="IPackagePopularitySource"/> whether any existing neighbor is far more
/// downloaded than the target — i.e. the target looks like a low-reputation squat of an established package.
/// </summary>
/// <remarks>
/// Future enhancement (not built here): the dual direction — carry a bundled top-N-popular id list, mutate those,
/// and flag when the target matches one of their neighbors.
/// </remarks>
public sealed class SquatChecker(IPackagePopularitySource popularity)
{
    #region Methods
    /// <summary>
    /// Generates candidates for <paramref name="targetId"/>, queries the popularity source, and returns findings
    /// where an existing candidate is popular enough to look like an established package being squatted. A candidate
    /// is flagged only when BOTH hold: it exceeds the absolute floor <see cref="MinCandidateDownloads"/> (so obscure
    /// neighbors of an absent/unknown target are not flagged), and it is at least <see cref="PopularityRatioThreshold"/>x
    /// more downloaded than the target (trivially true when the target is absent, i.e. target downloads == 0, which
    /// still lets a brand-new squat of a hugely popular package flag). Never throws: a failed or missing lookup
    /// (target or candidate) is skipped, not fatal.
    /// </summary>
    public async Task<Result<IReadOnlyList<SquatFinding>>> CheckAsync(string targetId, CancellationToken ct = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(targetId))
                return Result.Success<IReadOnlyList<SquatFinding>>(Array.Empty<SquatFinding>());

            var targetDownloads = await TryGetDownloadsAsync(targetId, ct) ?? 0;
            var candidates = SquatCandidateGenerator.Generate(targetId);
            var findings = new List<SquatFinding>();

            foreach (var candidate in candidates)
            {
                ct.ThrowIfCancellationRequested();

                var candidateDownloads = await TryGetDownloadsAsync(candidate.Name, ct);
                if (candidateDownloads is not long downloads)
                    continue;   // candidate does not exist on the feed, or lookup failed — skip.

                if (downloads >= MinCandidateDownloads && downloads >= PopularityRatioThreshold * targetDownloads)
                {
                    findings.Add(new SquatFinding(
                        TargetId: targetId,
                        SquattedCandidate: candidate.Name,
                        TargetDownloads: targetDownloads,
                        CandidateDownloads: downloads,
                        Reason: candidate.Reason,
                        Mutator: candidate.Mutator));
                }
            }

            return Result.Success<IReadOnlyList<SquatFinding>>(findings);
        }
        catch (OperationCanceledException)
        {
            return Result.Failure<IReadOnlyList<SquatFinding>>("Squat check was canceled.");
        }
        catch (Exception ex)
        {
            return Result.Failure<IReadOnlyList<SquatFinding>>($"Squat check failed for {targetId}.", ex);
        }
    }

    // Best-effort single lookup: a null result means "unknown/does not exist"; an exception is treated the same.
    private async Task<long?> TryGetDownloadsAsync(string packageId, CancellationToken ct)
    {
        try
        {
            return await popularity.GetDownloadCountAsync(packageId, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }
    #endregion

    #region Properties
    /// <summary>A candidate must be at least this many times more downloaded than the target to be flagged.</summary>
    public static long PopularityRatioThreshold { get; } = 10;

    /// <summary>
    /// Absolute floor: a candidate must exceed this download count to be considered an established package worth
    /// flagging. Gates out obscure neighbors when the target is absent/unknown (target downloads == 0).
    /// </summary>
    public static long MinCandidateDownloads { get; } = 10_000;
    #endregion
}
