namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;

using Silvergun;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// <see cref="AssemblyScanResult.NotInventoried"/> (<c>docs/agent/tasks/entry-aliasing-coverage.md</c>, Review 2 W2):
/// the flag that tells a DECLARED ENTRY never written as a file of its own apart from a FILE, so reports can count and
/// list the two apart. It is derived, not stored: true iff both <see cref="PackageAssembly.FullPath"/> and
/// <see cref="PackageAssembly.Sha256"/> are null or empty — which <c>PackageScanner</c> produces for a lost entry and an
/// extracted file never has. Both fields ARE serialized, so the flag survives a JSON round trip without being a JSON
/// property of its own.
///
/// <para>The three row kinds are real, from one real scan: an analysed managed assembly, a file that failed to load
/// (a skip row that IS a file), and a lost entry (a NUL-bearing name, refused by both filesystems, so lost on both).</para>
/// </summary>
public sealed class NotInventoriedRowTests : IClassFixture<NotInventoriedRowFixture>
{
    #region Constructors
    public NotInventoriedRowTests(NotInventoriedRowFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: the flag on a real scan
    [Fact]
    public void NotInventoried_IsTrueOnlyForTheLostEntry_NotForAnAnalysedFileOrAFileThatFailedToLoad()
    {
        var report = fixture.Report;

        var analysed = Row(report, NotInventoriedRowFixture.ManagedEntry);
        Assert.Null(analysed.SkipReason);
        Assert.False(analysed.NotInventoried);

        // A skip row that is still a FILE: it has a path and a hash, so it is counted as a file that could not be analysed.
        var failed = Row(report, NotInventoriedRowFixture.NativeEntry);
        Assert.NotNull(failed.SkipReason);
        Assert.False(failed.NotInventoried);

        var lost = Row(report, NotInventoriedRowFixture.LostEntryEscaped);
        Assert.NotNull(lost.SkipReason);
        Assert.True(lost.NotInventoried);
        Assert.Equal(string.Empty, lost.Assembly.FullPath);
        Assert.Equal(string.Empty, lost.Assembly.Sha256);
    }
    #endregion

    #region Methods: the JSON round trip
    [Fact]
    public void NotInventoried_SurvivesTheReportJsonRoundTrip_WithoutBeingAJsonPropertyOfItsOwn()
    {
        var json = fixture.Report.ToJson();

        Assert.All(
            JsonNode.Parse(json)!["Assemblies"]!.AsArray(),
            row => Assert.False(row!.AsObject().ContainsKey(nameof(AssemblyScanResult.NotInventoried)), "NotInventoried must not be serialized."));
        var back = PackageCapabilityReport.FromJson(json)!;
        Assert.Equal(
            fixture.Report.Assemblies.Select(a => (a.Assembly.RelativePath, a.NotInventoried)),
            back.Assemblies.Select(a => (a.Assembly.RelativePath, a.NotInventoried)));
        Assert.Equal([false, false, true], back.Assemblies.OrderBy(a => a.Assembly.RelativePath, StringComparer.Ordinal).Select(a => a.NotInventoried));
    }
    #endregion

    #region Methods: the missing-field cases (JSON read back without FullPath and/or Sha256)
    // Both fields absent (a hand-edited or foreign JSON): the row reads as NOT inventoried, even an analysed one. Pinned
    // as the shipped predicate's behaviour; it errs toward "entry never extracted", which reports as incomplete rather
    // than dropping the row.
    [Fact]
    public void NotInventoried_ForAnAnalysedRowReadBackWithoutFullPathAndSha256_IsTrue()
    {
        var row = ReadBackWithout(NotInventoriedRowFixture.ManagedEntry, "FullPath", "Sha256");

        Assert.Null(row.Assembly.FullPath);
        Assert.Null(row.Assembly.Sha256);
        Assert.True(row.NotInventoried);
    }

    // Only one of the two absent: still a file (the predicate needs BOTH empty).
    [Theory]
    [InlineData("FullPath")]
    [InlineData("Sha256")]
    public void NotInventoried_ForAFileRowReadBackWithoutOnlyOneOfTheTwoFields_IsFalse(string missing)
    {
        Assert.False(ReadBackWithout(NotInventoriedRowFixture.ManagedEntry, missing).NotInventoried);
        Assert.False(ReadBackWithout(NotInventoriedRowFixture.NativeEntry, missing).NotInventoried);
    }

    // A lost row stays lost whether its empty fields are written out, absent, or null.
    [Fact]
    public void NotInventoried_ForTheLostRowReadBackWithoutBothFields_StaysTrue()
    {
        Assert.True(ReadBackWithout(NotInventoriedRowFixture.LostEntryEscaped, "FullPath", "Sha256").NotInventoried);
    }

    [Fact]
    public void NotInventoried_ForAnAnalysedRowReadBackWithBothFieldsNull_IsTrue()
    {
        var json = JsonNode.Parse(fixture.Report.ToJson())!;
        var assembly = RowNode(json, NotInventoriedRowFixture.ManagedEntry)["Assembly"]!.AsObject();
        assembly["FullPath"] = null;
        assembly["Sha256"] = null;

        Assert.True(Row(PackageCapabilityReport.FromJson(json.ToJsonString())!, NotInventoriedRowFixture.ManagedEntry).NotInventoried);
    }
    #endregion

    #region Methods: helpers
    private static AssemblyScanResult Row(PackageCapabilityReport report, string relativePath) =>
        Assert.Single(report.Assemblies, a => a.Assembly.RelativePath == relativePath);

    private static JsonObject RowNode(JsonNode report, string relativePath) =>
        Assert.Single(
            report["Assemblies"]!.AsArray().Select(n => n!.AsObject()),
            n => (string?)n["Assembly"]!["RelativePath"] == relativePath);

    // The report's JSON with the named Assembly fields removed from one row, read back, and that row returned.
    private AssemblyScanResult ReadBackWithout(string relativePath, params string[] fields)
    {
        var json = JsonNode.Parse(fixture.Report.ToJson())!;
        var assembly = RowNode(json, relativePath)["Assembly"]!.AsObject();
        foreach (var field in fields)
            Assert.True(assembly.Remove(field), $"precondition: the row's JSON has a {field} property to remove.");

        return Row(PackageCapabilityReport.FromJson(json.ToJsonString())!, relativePath);
    }
    #endregion

    #region Fields
    private readonly NotInventoriedRowFixture fixture;
    #endregion
}

/// <summary>
/// One real offline scan of a package holding an analysable managed assembly, a non-PE <c>.dll</c> (a file that fails
/// to load) and a NUL-bearing entry no filesystem writes (a declared entry lost on every platform).
/// </summary>
public sealed class NotInventoriedRowFixture : IDisposable
{
    #region Constructors
    public NotInventoriedRowFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-not-inventoried", "root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var managed = File.ReadAllBytes(typeof(Shapes).Assembly.Location);

        var path = Path.Combine(rootDir, "PkgNotInventoried.1.0.0.nupkg");
        var nuspec = NupkgBuilder.NuspecXml("PkgNotInventoried", "1.0.0", "Silvergun Tests", "NotInventoried test package.", "net8.0", []);
        NupkgBuilder.WriteNupkg(
            path,
            [("PkgNotInventoried.nuspec", Encoding.UTF8.GetBytes(nuspec)), (ManagedEntry, managed), (NativeEntry, NupkgBuilder.NotManagedBytes)],
            [(LostEntry, managed)]);

        var scan = PackageScanner.Scan(path, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        Report = scan.Value;
    }
    #endregion

    #region Properties
    public const string ManagedEntry = "lib/net8.0/Managed.dll";
    public const string NativeEntry = "lib/net8.0/native.dll";

    /// <summary>A NUL-bearing name: refused by both filesystems, so lost on both (measured 2026-08-22).</summary>
    public const string LostEntry = "lib/net8.0/no\0tinv.dll";

    /// <summary><see cref="LostEntry"/> as published (ADR 0031 decision 4).</summary>
    public const string LostEntryEscaped = @"lib/net8.0/no\x00tinv.dll";

    public PackageCapabilityReport Report { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        try
        {
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}
