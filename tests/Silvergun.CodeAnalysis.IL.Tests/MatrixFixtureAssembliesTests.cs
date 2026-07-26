namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;

using Xunit;

/// <summary>
/// The <b>guard</b> on the TFM matrix itself, and the reason it is its own test class with no class fixture.
/// <para>
/// Every matrix theory is driven from <see cref="MatrixFixtureAssemblies.ByTargetFramework"/> — discovered by
/// enumerating the fixture project's <c>bin/{Configuration}</c> — so that adding a target framework to the
/// fixture automatically extends coverage. The cost of that is that a matrix which silently <em>shrank</em>
/// (the extra <c>ProjectReference</c> with <c>AdditionalProperties="TargetFramework=net472"</c> dropped from
/// this project's <c>.csproj</c>, or a stale <c>bin</c>) would simply produce fewer theory cases, and every
/// remaining test would still pass — proving nothing about net472.
/// </para>
/// <para>
/// These facts close that hole: they assert the discovered matrix is exactly the one the tests were written
/// against, so a shrunken matrix is <b>one</b> unambiguous failure rather than silently-absent theory cases.
/// They take no class fixture on purpose — a matrix problem must not be reported as "the fixture constructor
/// threw" across every other class.
/// </para>
/// </summary>
public sealed class MatrixFixtureAssembliesTests
{
    #region Methods
    /// <summary>
    /// The locator's own completeness check: the discovered set is exactly
    /// <see cref="MatrixFixtureAssemblies.ExpectedTargetFrameworks"/>. Both directions matter — a missing
    /// flavour means the matrix shrank, an extra one means it grew without a baseline being added here.
    /// </summary>
    [Fact]
    public void MatrixFixtureAssemblies_DiscoveredTargetFrameworks_AreExactlyTheExpectedMatrix()
    {
        var exception = Record.Exception(MatrixFixtureAssemblies.AssertMatrixIsComplete);

        Assert.Null(exception);
    }

    /// <summary>
    /// The same statement spelled out, so a failure says which flavour is missing rather than only that the
    /// sets differ: exactly two entries, keyed by exactly <c>net472</c> and <c>net10.0</c>.
    /// </summary>
    [Fact]
    public void ByTargetFramework_HoldsExactlyTheTwoMatrixFlavours()
    {
        var discovered = MatrixFixtureAssemblies.ByTargetFramework;

        Assert.Equal(2, discovered.Count);
        Assert.Equal(
            ["net10.0", "net472"],
            discovered.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(
            MatrixFixtureAssemblies.ExpectedTargetFrameworks.Order(StringComparer.Ordinal),
            discovered.Keys.Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// Every discovered path is a file that actually exists and is named after the fixture assembly. The
    /// locator selects by name rather than by a <c>*.dll</c> glob, so this also pins that a TFM directory
    /// holding only stale artifacts is not mistaken for a matrix flavour.
    /// </summary>
    [Fact]
    public void ByTargetFramework_EveryDiscoveredPath_IsAnExistingFixtureAssemblyFile()
    {
        Assert.All(MatrixFixtureAssemblies.ByTargetFramework, entry =>
        {
            Assert.True(File.Exists(entry.Value), $"Missing {entry.Key} fixture assembly at '{entry.Value}'.");
            Assert.Equal(MatrixFixtureAssemblies.AssemblyName + ".dll", Path.GetFileName(entry.Value));
            Assert.Equal(entry.Key, Path.GetFileName(Path.GetDirectoryName(entry.Value)));
        });
    }

    /// <summary>
    /// <b>Fail loudly, never skip.</b> Asking for a flavour that was not built throws and names what was
    /// actually found; it must never come back null or empty, which a caller could mistake for "nothing to
    /// check here".
    /// </summary>
    [Theory]
    [InlineData("net8.0")]      // deliberately dropped from the matrix — see the csproj comment.
    [InlineData("netstandard2.0")]
    [InlineData("net48")]
    public void For_TargetFrameworkThatWasNotBuilt_ThrowsNamingWhatWasFound(string targetFramework)
    {
        var exception = Assert.Throws<InvalidOperationException>(() => MatrixFixtureAssemblies.For(targetFramework));

        Assert.Contains(targetFramework, exception.Message, StringComparison.Ordinal);
        Assert.Contains(MatrixFixtureAssemblies.BinDirectory, exception.Message, StringComparison.Ordinal);
        foreach (var found in MatrixFixtureAssemblies.ByTargetFramework.Keys)
            Assert.Contains(found, exception.Message, StringComparison.Ordinal);
    }

    /// <summary>Every expected flavour resolves to its discovered path through <see cref="MatrixFixtureAssemblies.For"/>.</summary>
    [Theory]
    [MemberData(nameof(TargetFrameworks))]
    public void For_EveryExpectedTargetFramework_ReturnsTheDiscoveredPath(string targetFramework)
    {
        var path = MatrixFixtureAssemblies.For(targetFramework);

        Assert.False(string.IsNullOrWhiteSpace(path));
        Assert.Equal(MatrixFixtureAssemblies.ByTargetFramework[targetFramework], path);
    }
    #endregion

    #region Properties
    /// <summary>
    /// The expected matrix — used here rather than the discovered one, because these cases must exist even
    /// when discovery came back short. That is the whole point of the guard.
    /// </summary>
    public static TheoryData<string> TargetFrameworks =>
        [.. MatrixFixtureAssemblies.ExpectedTargetFrameworks.Order(StringComparer.Ordinal)];
    #endregion
}
