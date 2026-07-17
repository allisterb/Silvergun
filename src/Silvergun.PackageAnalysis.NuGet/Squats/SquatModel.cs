namespace Silvergun.PackageAnalysis.NuGet.Squats;

/// <summary>A single generated near-neighbor of a package id, with the technique that produced it.</summary>
public sealed record SquatCandidate(string Name, string Reason, MutatorType Mutator);

/// <summary>
/// A detected likely typosquat: <paramref name="TargetId"/> looks like a low-reputation look-alike of the
/// established <paramref name="SquattedCandidate"/>, which is far more popular on the feed. The optional
/// <paramref name="CandidateSourceRank"/>/<paramref name="CandidateDependents"/> axes (libraries.io) explain a
/// flag driven by the stronger reputation signals rather than raw downloads; they are <c>null</c> when the source
/// does not supply them (e.g. keyless nuget.org).
/// </summary>
public sealed record SquatFinding(
    string TargetId,
    string SquattedCandidate,   // an existing, more-popular near-neighbor
    long TargetDownloads,
    long CandidateDownloads,
    string Reason,
    MutatorType Mutator,
    int? CandidateSourceRank = null,
    int? CandidateDependents = null);
