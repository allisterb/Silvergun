namespace Silvergun.Intel;

using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// A multi-axis popularity signal for a package (ADR 0011). Each axis is independently nullable so a source fills
/// only the axes it knows: nuget.org fills <see cref="DownloadCount"/>; libraries.io fills <see cref="SourceRank"/>
/// and <see cref="DependentsCount"/>. A <c>null</c> <see cref="PackagePopularity"/> (as opposed to one with null
/// axes) means the package is unknown to the source or the lookup failed.
/// </summary>
/// <param name="DownloadCount">Total feed download count (nuget.org / libraries.io), or <c>null</c> when unknown.</param>
/// <param name="SourceRank">libraries.io SourceRank (~0–30), harder to game than raw downloads; <c>null</c> when unknown.</param>
/// <param name="DependentsCount">Reverse-dependency count, <c>null</c> when unknown.</param>
public sealed record PackagePopularity(long? DownloadCount, int? SourceRank = null, int? DependentsCount = null);

/// <summary>
/// Abstraction over a package feed's popularity signal, so squat scoring is testable without hitting the network.
/// </summary>
public interface IPackagePopularitySource
{
    #region Methods
    /// <summary>
    /// Returns the multi-axis <see cref="PackagePopularity"/> for <paramref name="packageId"/>, or <c>null</c> if the
    /// package does not exist on the source (or the lookup is otherwise unknown/failed).
    /// </summary>
    Task<PackagePopularity?> GetPopularityAsync(string packageId, CancellationToken ct = default);
    #endregion
}
