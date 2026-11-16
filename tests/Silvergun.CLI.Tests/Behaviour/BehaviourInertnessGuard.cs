namespace Silvergun.CLI.Tests.Behaviour;

using System;
using System.Collections.Generic;
using System.Linq;

using Xunit;

/// <summary>
/// Collection fixture shared by the recall tests and the fixture sanity tests (task section 1.1): when the whole collection
/// has finished, including the in-process IL reads, no fixture assembly may be loaded in the TEST process. The CLI runs as a
/// child process, so this says nothing about what it loads. A violation fails the collection's cleanup.
/// </summary>
public sealed class BehaviourInertnessGuard : IDisposable
{
    public const string CollectionName = "Behaviour";

    public static IReadOnlyList<string> LoadedFixtureAssemblies() =>
        [.. AppDomain.CurrentDomain.GetAssemblies()
            .Select(a => a.GetName().Name ?? string.Empty)
            .Where(n => n.StartsWith("Silvergun.Behaviour.", StringComparison.Ordinal))];

    public void Dispose() =>
        Assert.True(LoadedFixtureAssemblies().Count == 0, $"fixture assembly loaded into the test process: {string.Join(", ", LoadedFixtureAssemblies())}");
}

[CollectionDefinition(BehaviourInertnessGuard.CollectionName)]
public sealed class BehaviourCollection : ICollectionFixture<BehaviourInertnessGuard>
{
}
