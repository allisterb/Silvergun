namespace Silvergun.PackageAnalysis.NuGet.Squats;

/// <summary>A single generated near-neighbor of a package id, with the technique that produced it.</summary>
public sealed record SquatCandidate(string Name, string Reason, MutatorType Mutator);

/// <summary>
/// A detected likely typosquat: <paramref name="TargetId"/> looks like a low-reputation look-alike of the
/// established <paramref name="SquattedCandidate"/>, which is far more downloaded on the feed.
/// </summary>
public sealed record SquatFinding(
    string TargetId,
    string SquattedCandidate,   // an existing, more-popular near-neighbor
    long TargetDownloads,
    long CandidateDownloads,
    string Reason,
    MutatorType Mutator);
