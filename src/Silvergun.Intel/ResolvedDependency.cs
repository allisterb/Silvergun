namespace Silvergun.Intel;

/// <summary>
/// One resolved node in a package's transitive dependency graph (resolver-lite, ADR 0018). <see cref="Depth"/> 1 is a
/// declared direct dependency (<see cref="IsDirect"/> <c>true</c>); higher depths are transitive. <see cref="Version"/>
/// is the concrete version the resolver settled on for this id (see <see cref="NuGetDependencyResolver"/>'s highest-wins
/// unification — a documented approximation, not a <c>dotnet restore</c>).
/// </summary>
public sealed record ResolvedDependency(string Id, string Version, int Depth, bool IsDirect);
