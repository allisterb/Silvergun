namespace Silvergun.Intel;

using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Abstraction over a source of project-health intel for a resolved <see cref="RepositoryRef"/>, so the signal is
/// testable without hitting the network. A <c>null</c> result means "health unavailable/unknown" (404, rate-limit,
/// transport error, malformed response, unsupported host) — never an exception.
/// </summary>
public interface IProjectHealthSource
{
    #region Methods
    /// <summary>
    /// Returns the <see cref="ProjectHealth"/> for <paramref name="repo"/>, or <c>null</c> when unavailable/unknown.
    /// Never throws (except honoring cancellation).
    /// </summary>
    Task<ProjectHealth?> GetHealthAsync(RepositoryRef repo, CancellationToken ct = default);
    #endregion
}
