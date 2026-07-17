namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System;
using System.Collections.Generic;

/// <summary>
/// Unions the NuGet-tuned mutators over a package id into a distinct, deterministic, offline set of candidate
/// near-neighbor names. The input id itself is excluded (case-insensitive), and empty mutations are dropped.
/// </summary>
public static class SquatCandidateGenerator
{
    #region Methods
    /// <summary>
    /// Generates the distinct squat candidates for <paramref name="packageId"/>. Deterministic and fully offline:
    /// the first mutation to produce a given name wins, and candidates are returned in generation order. NuGet ids
    /// are case-insensitive, so de-duplication and the input-exclusion are ordinal-case-insensitive.
    /// </summary>
    public static IReadOnlyList<SquatCandidate> Generate(string packageId)
    {
        var candidates = new List<SquatCandidate>();
        if (string.IsNullOrWhiteSpace(packageId))
            return candidates;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var mutator in NuGetMutators.Nuget)
        {
            foreach (var mutation in mutator.Generate(packageId))
            {
                var name = mutation.Mutated;
                if (string.IsNullOrEmpty(name)) continue;
                if (string.Equals(name, packageId, StringComparison.OrdinalIgnoreCase)) continue;
                if (!seen.Add(name)) continue;

                candidates.Add(new SquatCandidate(name, mutation.Reason, mutation.Mutator));
            }
        }

        return candidates;
    }
    #endregion
}
