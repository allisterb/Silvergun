namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Abstraction over a package feed's popularity signal, so squat scoring is testable without hitting the network.
/// </summary>
public interface IPackagePopularitySource
{
    #region Methods
    /// <summary>
    /// Returns the total download count for <paramref name="packageId"/>, or <c>null</c> if the package does not
    /// exist on the feed (or its count is unknown).
    /// </summary>
    Task<long?> GetDownloadCountAsync(string packageId, CancellationToken ct = default);
    #endregion
}
