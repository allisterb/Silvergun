namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System.Text.Json;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit tests for the YARA report POCOs (ADR 0016 / ADR 0002 / task <c>docs/agent/tasks/yara-scanning.md</c>).
/// The report DTO <see cref="YaraFinding"/> and the backend hit <see cref="YaraMatch"/> are strings-only,
/// serializable records: they must round-trip through <see cref="System.Text.Json.JsonSerializer"/> preserving
/// nullable fields (as <c>null</c>) and their tag / string lists, and their record equality must be
/// value-based over shared members.
/// </summary>
public sealed class YaraFindingJsonTests
{
    #region Methods
    // A fully-populated finding survives serialize => deserialize with every field intact.
    [Fact]
    public void YaraFinding_RoundTrip_PreservesAllFields()
    {
        var original = new YaraFinding(
            RuleName: "Win32_Trojan_Foo",
            Namespace: "malware",
            MalwareFamily: "Foo",
            DetectionName: "Trojan.Win32.Foo",
            Category: "MALWARE",
            Tags: new[] { "trojan", "suspicious" },
            RelativePath: "lib/net10.0/evil.dll");

        var restored = RoundTrip(original);

        Assert.Equal("Win32_Trojan_Foo", restored.RuleName);
        Assert.Equal("malware", restored.Namespace);
        Assert.Equal("Foo", restored.MalwareFamily);
        Assert.Equal("Trojan.Win32.Foo", restored.DetectionName);
        Assert.Equal("MALWARE", restored.Category);
        Assert.Equal(new[] { "trojan", "suspicious" }, restored.Tags);
        Assert.Equal("lib/net10.0/evil.dll", restored.RelativePath);
    }

    // The nullable metadata fields survive as null (a finding whose rule carried no meta / namespace).
    [Fact]
    public void YaraFinding_RoundTrip_PreservesNullFields()
    {
        var original = new YaraFinding(
            RuleName: "Bare_Rule",
            Namespace: null,
            MalwareFamily: null,
            DetectionName: null,
            Category: null,
            Tags: System.Array.Empty<string>(),
            RelativePath: "content/readme.txt");

        var restored = RoundTrip(original);

        Assert.Equal("Bare_Rule", restored.RuleName);
        Assert.Null(restored.Namespace);
        Assert.Null(restored.MalwareFamily);
        Assert.Null(restored.DetectionName);
        Assert.Null(restored.Category);
        Assert.Empty(restored.Tags);
        Assert.Equal("content/readme.txt", restored.RelativePath);
    }

    // YaraMatch (backend hit) round-trips preserving its tags and its string matches (identifier + offset).
    [Fact]
    public void YaraMatch_RoundTrip_PreservesTagsAndStrings()
    {
        var original = new YaraMatch(
            Rule: "SilverRule",
            Namespace: "ns1",
            Tags: new[] { "tag1", "tag2" },
            Strings: new[] { new YaraStringMatch("$a", 6), new YaraStringMatch("$b", 0x1a2b) });

        var json = JsonSerializer.Serialize(original);
        var restored = JsonSerializer.Deserialize<YaraMatch>(json)!;

        Assert.Equal("SilverRule", restored.Rule);
        Assert.Equal("ns1", restored.Namespace);
        Assert.Equal(new[] { "tag1", "tag2" }, restored.Tags);
        Assert.Equal(2, restored.Strings.Count);
        Assert.Equal("$a", restored.Strings[0].Identifier);
        Assert.Equal(6, restored.Strings[0].Offset);
        Assert.Equal("$b", restored.Strings[1].Identifier);
        Assert.Equal(0x1a2b, restored.Strings[1].Offset);
    }

    // Record value equality: two findings built from the same field values (sharing list references) are equal;
    // changing a single scalar field breaks equality.
    [Fact]
    public void YaraFinding_RecordEquality_IsValueBased()
    {
        var tags = new[] { "trojan" };
        var a = new YaraFinding("R", "ns", "Fam", "Det", "Cat", tags, "path.dll");
        var b = new YaraFinding("R", "ns", "Fam", "Det", "Cat", tags, "path.dll");
        var different = a with { MalwareFamily = "Other" };

        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.NotEqual(a, different);
    }

    // YaraStringMatch is a plain value record: equal identifier + offset compare equal, a different offset does not.
    [Fact]
    public void YaraStringMatch_RecordEquality_IsValueBased()
    {
        Assert.Equal(new YaraStringMatch("$a", 6), new YaraStringMatch("$a", 6));
        Assert.NotEqual(new YaraStringMatch("$a", 6), new YaraStringMatch("$a", 7));
    }
    #endregion

    #region Helpers
    private static YaraFinding RoundTrip(YaraFinding finding) =>
        JsonSerializer.Deserialize<YaraFinding>(JsonSerializer.Serialize(finding))!;
    #endregion
}
