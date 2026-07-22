namespace Silvergun.Intel;

/// <summary>
/// One package@version to check for known vulnerabilities against OSV.dev (ADR 0017). <see cref="IsDependency"/>
/// distinguishes the scanned package itself (<c>false</c>) from a declared dependency checked at its range floor
/// (<c>true</c>), so a resulting <see cref="VulnerabilityFinding"/> can be labeled accordingly.
/// </summary>
public sealed record OsvQuery(string PackageId, string Version, bool IsDependency);
