namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

using Xunit;

/// <summary>
/// <c>docs/agent/tasks/capability-diff-versions.md</c>: <see cref="CapabilitySnapshot"/> is the serializable,
/// committable inventory a forthcoming <c>capability-diff</c> verb will compare across package versions. Its two
/// load-bearing properties are covered here:
/// <list type="bullet">
/// <item>determinism — <see cref="CapabilitySnapshot.ToJson"/> must be byte-identical across calls over equal
/// input, and must carry no wall-clock timestamp, or every regeneration of a baseline would be a spurious diff in
/// a consumer's repo;</item>
/// <item><see cref="CapabilitySnapshot.ToJson"/>/<see cref="CapabilitySnapshot.FromJson(string)"/> round-trip
/// fidelity, and <see cref="CapabilitySnapshot.From"/> threading the caller-supplied identity/completeness facts
/// through untouched.</item>
/// </list>
/// Deliberately NOT covered here (out of scope per the dispatch): <see cref="CapabilitySnapshot.FromJson"/>
/// refusing an unrecognized <see cref="CapabilitySnapshot.SchemaVersion"/> on read — <see cref="CapabilitySnapshot"/>
/// itself does not implement that refusal (see its own doc comment); it is deliberately left to the
/// forthcoming <c>capability-diff</c> verb, which is the consumer that knows which versions it can safely compare.
/// </summary>
public sealed class CapabilitySnapshotTests
{
    #region Methods — C: determinism (the load-bearing property)
    [Fact]
    public void ToJson_CalledTwiceOnTheSameInstance_IsByteIdentical()
    {
        var snapshot = Snapshot();

        var first = snapshot.ToJson();
        var second = snapshot.ToJson();

        Assert.Equal(first, second, StringComparer.Ordinal);
    }

    // Not just the same instance called twice: two INDEPENDENTLY constructed snapshots with equal field values
    // (including independently-built manifests/findings lists) must serialize identically — this is what makes a
    // regenerated baseline diff cleanly in a consumer's repo instead of spuriously, since regeneration always
    // builds a fresh object graph, never reuses the original instance.
    [Fact]
    public void ToJson_OverTwoEqualButIndependentlyConstructedSnapshots_IsByteIdentical()
    {
        var a = Snapshot();
        var b = Snapshot();   // separate CapabilityManifest/finding-list instances with equal content

        Assert.Equal(a.ToJson(), b.ToJson(), StringComparer.Ordinal);
    }

    [Fact]
    public void ToJson_EmitsNoTimestampLikePropertyAtAll()
    {
        var json = Snapshot().ToJson();

        using var doc = JsonDocument.Parse(json);
        var allPropertyNames = AllPropertyNames(doc.RootElement).ToArray();

        // No property whose NAME suggests a wall-clock capture — the exact guard against someone "helpfully"
        // adding one later (e.g. copying CapabilityReport.AnalyzedAt's shape onto the snapshot).
        string[] forbidden = ["AnalyzedAt", "Timestamp", "CreatedAt", "GeneratedAt", "Date"];
        foreach (var name in allPropertyNames)
            Assert.False(
                forbidden.Any(f => name.Contains(f, StringComparison.OrdinalIgnoreCase)),
                $"property '{name}' looks timestamp-like — the snapshot must carry no wall-clock timestamp.");

        // No property VALUE that merely looks like an ISO-8601 timestamp either, in case one leaked in under an
        // unexpected name.
        Assert.DoesNotMatch(new Regex(@"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"), json);
    }

    // CapabilityReport DOES carry AnalyzedAt; From(CapabilityReport, ...) must not let it leak into the snapshot.
    [Fact]
    public void From_CapabilityReport_DoesNotInheritTheReportsAnalyzedAt()
    {
        var knownTimestamp = new DateTimeOffset(2019, 3, 14, 1, 59, 26, TimeSpan.Zero);   // deliberately distinctive
        var report = new CapabilityReport(
            "A.dll", "/x/A.dll", knownTimestamp, [Finding(Capability.FileSystem)], 5, 5, 0, []);

        var snapshot = CapabilitySnapshot.From(report, "Some.Package", "1.0.0", "net10.0", Complete());
        var json = snapshot.ToJson();

        Assert.DoesNotContain("2019", json, StringComparison.Ordinal);
        Assert.DoesNotContain("AnalyzedAt", json, StringComparison.Ordinal);
    }
    #endregion

    #region Methods — D: round-trip fidelity
    [Fact]
    public void ToJsonFromJson_RoundTrips_AllFieldsIncludingManifestAndCompleteness()
    {
        var original = Snapshot();

        var restored = CapabilitySnapshot.FromJson(original.ToJson());

        Assert.NotNull(restored);
        Assert.Equal(original.SchemaVersion, restored!.SchemaVersion);
        Assert.Equal(original.PackageId, restored.PackageId);
        Assert.Equal(original.PackageVersion, restored.PackageVersion);
        Assert.Equal(original.AssemblyName, restored.AssemblyName);
        Assert.Equal(original.TargetFramework, restored.TargetFramework);
        Assert.Equal(original.Completeness, restored.Completeness);   // plain-field record: value equality works
        Assert.Equal(original.Manifest.Entries, restored.Manifest.Entries);   // element-wise, per entry
    }

    [Fact]
    public void FromJson_NullInput_ReturnsNull() => Assert.Null(CapabilitySnapshot.FromJson(null!));

    [Fact]
    public void ToJson_SerializesCapabilityEnumByName_NotByOrdinal()
    {
        var snapshot = Snapshot();

        var json = snapshot.ToJson();
        using var doc = JsonDocument.Parse(json);

        var entries = doc.RootElement.GetProperty("Manifest").GetProperty("Entries");
        Assert.True(entries.GetArrayLength() > 0);
        foreach (var entry in entries.EnumerateArray())
        {
            var capabilityProperty = entry.GetProperty("Capability");
            Assert.Equal(JsonValueKind.String, capabilityProperty.ValueKind);
            Assert.Contains(capabilityProperty.GetString(), Enum.GetValues<Capability>().Select(c => c.ToString()));
        }
    }

    // From(...) writes CurrentSchemaVersion; a hand-built record can carry any int, so this pins the FACTORY's
    // default specifically (acceptance criterion in area D of the dispatch).
    [Fact]
    public void From_CapabilityReport_SetsSchemaVersionToCurrentSchemaVersion()
    {
        var report = new CapabilityReport("A.dll", "/x/A.dll", DateTimeOffset.UnixEpoch, [], 1, 1, 0, []);

        var snapshot = CapabilitySnapshot.From(report, "Pkg", "1.0.0", "net10.0", Complete());

        Assert.Equal(CapabilitySnapshot.CurrentSchemaVersion, snapshot.SchemaVersion);
    }
    #endregion

    #region Methods — E: From(CapabilityReport, ...) threading
    [Fact]
    public void From_CapabilityReport_ThreadsPackageIdVersionTfmAndCompletenessUntouched()
    {
        var report = new CapabilityReport(
            "MyAssembly.dll", "/x/MyAssembly.dll", DateTimeOffset.UnixEpoch,
            [Finding(Capability.Network), Finding(Capability.Network), Finding(Capability.Registry)], 10, 8, 2, ["M.N: unresolved"]);
        var completeness = new ScanCompleteness(IsComplete: false, MethodsTotal: 10, MethodsAnalyzed: 8, MethodsSkipped: 2, AssemblyLoadFailures: 1);

        var snapshot = CapabilitySnapshot.From(report, "Contoso.Widgets", "2.1.0", "net10.0", completeness);

        Assert.Equal("Contoso.Widgets", snapshot.PackageId);
        Assert.Equal("2.1.0", snapshot.PackageVersion);
        Assert.Equal("net10.0", snapshot.TargetFramework);
        Assert.Equal("MyAssembly.dll", snapshot.AssemblyName);
        Assert.Equal(completeness, snapshot.Completeness);

        var expectedManifest = CapabilityManifest.From(report.Findings);
        Assert.Equal(expectedManifest.Entries, snapshot.Manifest.Entries);
    }

    // A single assembly analyzed outside any package — the doc comment's own stated case for why PackageId/
    // PackageVersion are optional.
    [Fact]
    public void From_CapabilityReport_WithNullPackageIdVersionAndTargetFramework_PreservesNulls()
    {
        var report = new CapabilityReport("Standalone.dll", "/x/Standalone.dll", DateTimeOffset.UnixEpoch, [], 3, 3, 0, []);

        var snapshot = CapabilitySnapshot.From(report, null, null, null, Complete());

        Assert.Null(snapshot.PackageId);
        Assert.Null(snapshot.PackageVersion);
        Assert.Null(snapshot.TargetFramework);
        Assert.Equal("Standalone.dll", snapshot.AssemblyName);

        // Nulls must round-trip as nulls too, not e.g. empty strings.
        var restored = CapabilitySnapshot.FromJson(snapshot.ToJson());
        Assert.NotNull(restored);
        Assert.Null(restored!.PackageId);
        Assert.Null(restored.PackageVersion);
        Assert.Null(restored.TargetFramework);
    }
    #endregion

    #region Methods — helpers
    private static CapabilitySnapshot Snapshot() =>
        new(
            SchemaVersion: CapabilitySnapshot.CurrentSchemaVersion,
            PackageId: "Contoso.Widgets",
            PackageVersion: "2.1.0",
            AssemblyName: "Contoso.Widgets.dll",
            TargetFramework: "net10.0",
            Manifest: CapabilityManifest.From(
            [
                Finding(Capability.FileSystem), Finding(Capability.FileSystem),
                Finding(Capability.Network),
                Finding(Capability.Registry), Finding(Capability.Registry), Finding(Capability.Registry),
            ]),
            Completeness: Complete());

    private static ScanCompleteness Complete() =>
        new(IsComplete: true, MethodsTotal: 10, MethodsAnalyzed: 10, MethodsSkipped: 0, AssemblyLoadFailures: 0);

    private static ApiCallFinding Finding(
        Capability capability, string callerType = "T", string callerMethod = "M", string calledApi = "Some.Api.Call") =>
        new(capability, ApiCallKind.Call, callerType, callerMethod, calledApi);

    private static System.Collections.Generic.IEnumerable<string> AllPropertyNames(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    yield return property.Name;
                    foreach (var nested in AllPropertyNames(property.Value))
                        yield return nested;
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                    foreach (var nested in AllPropertyNames(item))
                        yield return nested;
                break;
        }
    }
    #endregion
}
