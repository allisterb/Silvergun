namespace Silvergun.CLI.Tests.Behaviour;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using Xunit;
using Xunit.Abstractions;

/// <summary>
/// The behaviour recall measurement end to end (<c>docs/agent/tasks/behaviour-fixtures-recall.md</c> section 4): each of the 48
/// packages runs once through the real CLI (<see cref="BehaviourRuns"/>), and the live observation must equal the pinned
/// <see cref="BehaviourRow.Measured"/>. A change, an improvement included, turns the theory red and is recorded in
/// <see cref="BehaviourMeasured"/>: that is this measurement's red-to-green moment.
/// <para>
/// The invariants that must hold now: no twin fails the gate (a twin at exit 2 is a Critical finding against the gate: report
/// it, never change the twin) and no malicious row reads clean silently unless it is a pinned known miss whose Note names the
/// lever (ADR 0030). No fixture assembly is ever loaded into this process.
/// </para>
/// </summary>
[Trait("Category", "Behaviour")]
[Collection(BehaviourInertnessGuard.CollectionName)]
public sealed class BehaviourRecallTests : IClassFixture<BehaviourRuns>
{
    #region Constructors
    public BehaviourRecallTests(BehaviourRuns runs, ITestOutputHelper output)
    {
        this.runs = runs;
        this.output = output;
    }
    #endregion

    #region Methods: the pinned table
    public static IEnumerable<object[]> RowKeys => BehaviourGroundTruth.Rows.Select(r => new object[] { r.Key });

    [Theory]
    [MemberData(nameof(RowKeys))]
    public void Row_LiveObservation_EqualsThePinnedMeasured(string key)
    {
        var row = BehaviourGroundTruth.Row(key);
        Assert.False(row.Measured.SameAs(Observation.Unpinned), $"{key}: Measured is not pinned yet");

        var live = runs.Observe(Package(key));

        Assert.Equal(row.Measured.Render(), live.Render());
    }

    [Fact]
    public void Table_Has48Rows_29Malicious_19Twins_AndEveryFamilyKeepsItsCount()
    {
        var rows = BehaviourGroundTruth.Rows;

        Assert.Equal(48, rows.Count);
        Assert.Equal(29, rows.Count(r => r.Side == Side.Malicious));
        Assert.Equal(19, rows.Count(r => r.Side == Side.Twin));
        Assert.Equal(rows.Count, rows.Select(r => r.Key).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(BehaviourGroundTruth.FamilyCounts.Keys.OrderBy(k => k, StringComparer.Ordinal), rows.Select(r => r.Family).Distinct().OrderBy(k => k, StringComparer.Ordinal));
        foreach (var (family, (malicious, twins)) in BehaviourGroundTruth.FamilyCounts)
        {
            Assert.Equal(malicious, rows.Count(r => r.Family == family && r.Side == Side.Malicious));
            Assert.Equal(twins, rows.Count(r => r.Family == family && r.Side == Side.Twin));
        }
    }

    [Fact]
    public void Table_AndPackages_AreTheSameFortyEightKeys()
    {
        Assert.Equal(
            BehaviourGroundTruth.Rows.Select(r => r.Key).OrderBy(k => k, StringComparer.Ordinal),
            BehaviourPackages.All.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(38, BehaviourPackages.All.SelectMany(p => p.Entries).Select(e => Path.GetFileName(e.Entry)).Where(n => n.EndsWith(".dll", StringComparison.Ordinal)).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Predicted_GateOfEverySideIsFixed_AndNoAttentionPredictionWasMade()
    {
        Assert.All(BehaviourGroundTruth.Rows, r => Assert.Null(r.Predicted.Attention));
        Assert.All(BehaviourGroundTruth.Rows.Where(r => r.Side == Side.Twin), r => Assert.Equal(Verdict.Passes, r.Predicted.Gate));
        Assert.Equal(
            ["BF07a", "BF07b", "BF07c", "BF08c", "BF08d", "BF19a", "BF19b"],
            BehaviourGroundTruth.Rows.Where(r => r.Predicted.Gate == Verdict.Fails).Select(r => r.Id));
    }

    // Predicted.Text is the section 5 cell verbatim: its SHA-256 is pinned here, so this needs no spec file and always runs.
    [Fact]
    public void Predicted_Text_HashesToThePinnedSection5Digest()
    {
        var concatenated = string.Concat(BehaviourGroundTruth.Rows.Select(r => r.Predicted.Text));

        var actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(concatenated)));

        Assert.True(actual == Section5Sha256, $"section 5 cell text changed: digest is {actual}");
    }

    // docs/agent is not always on disk (it is gitignored). Without the spec the comparison cannot run, and says so in the
    // test output (xunit v2 here has no dynamic skip): the pinned digest above is what still guards the text.
    [Fact]
    public void Predicted_Text_IsByteIdenticalToSection5()
    {
        var spec = FindSpec();
        if (spec is null)
        {
            output.WriteLine("NOT COMPARED: docs/agent/tasks/behaviour-fixtures-recall.md was not found above the test output; section 5 was not parsed. Only the pinned SHA-256 check ran.");
            return;
        }

        var table = File.ReadLines(spec).SkipWhile(l => !l.StartsWith("## 5.", StringComparison.Ordinal)).Skip(1)
            .TakeWhile(l => !l.StartsWith("**Headline", StringComparison.Ordinal))
            .Where(l => l.StartsWith("| BF", StringComparison.Ordinal))
            .Select(l => l.Trim().Trim('|').Split('|').Select(c => c.Trim()).ToArray())
            .Select(c => (Ids: c[0], Fails: c[1].Contains("**Fails**", StringComparison.Ordinal), Primary: c[2], Twin: c[3]))
            .ToList();
        Assert.Equal(Section5Lines, table.Count);

        foreach (var row in BehaviourGroundTruth.Rows)
        {
            var line = row.Side == Side.Malicious
                ? table.Single(t => Covers(t.Ids, row.Id))
                : table.First(t => Regex.Match(t.Ids, @"BF\d\d").Value == row.Family);

            Assert.Equal(row.Side == Side.Malicious ? line.Primary : line.Twin, row.Predicted.Text);
            Assert.Equal(row.Side == Side.Malicious && line.Fails ? Verdict.Fails : Verdict.Passes, row.Predicted.Gate);
        }
    }
    #endregion

    #region Methods: the invariants
    [Fact]
    public void Twins_NeverFailTheGate()
    {
        var failing = BehaviourGroundTruth.Rows.Where(r => r.Side == Side.Twin && runs.Observe(Package(r.Key)).Exit == 2).Select(r => r.Key).ToList();

        Assert.True(failing.Count == 0, $"CRITICAL: benign twin(s) exit 2 under --strict: {string.Join(", ", failing)}");
    }

    [Fact]
    public void MaliciousRows_NeverReadCleanSilently_UnlessPinnedAsAKnownMissNamingTheLever()
    {
        var silent = BehaviourGroundTruth.Rows
            .Where(r => r.Side == Side.Malicious)
            .Where(r => runs.Observe(Package(r.Key)) is { Exit: 0, Attention: false, Signals.Count: 0 })
            .Where(r => !r.Note.Contains("Lever", StringComparison.Ordinal))
            .Select(r => r.Key).ToList();

        Assert.True(silent.Count == 0, $"malicious row(s) exit 0 with no attention and no signals, and no Note naming a lever (ADR 0030): {string.Join(", ", silent)}");
    }

    // The CLI's own verdict headline agrees with the attention computed from the JSON. BF02/BF03 twins are the false branch
    // (no attention); BF15 twin and the others are true. The indicator-only clause is covered by BehaviourAttentionPredicateTests.
    [Theory]
    [InlineData("BF07a/Malicious")]
    [InlineData("BF12b/Malicious")]
    [InlineData("BF16/Malicious")]
    [InlineData("BF02/Twin")]
    [InlineData("BF03/Twin")]
    [InlineData("BF15/Twin")]
    [InlineData("BF07/Twin")]
    [InlineData("BF01/Twin")]
    public void Attention_ComputedFromJson_AgreesWithTheHumanReportHeadline(string key)
    {
        var package = Package(key);
        var fromJson = runs.Observe(package).Attention;

        var headline = FooterHeadline.Of(runs.RunHuman(package).Output);

        Assert.Equal(fromJson, FooterHeadline.VerdictOf(headline) == "Findings present");
    }

    // Covers the TEST PROCESS only: the CLI runs as a child process and loads whatever it loads there. Tests locate fixtures by
    // file name and pass them as bytes inside a nupkg. This checks after every package has run; BehaviourInertnessGuard
    // repeats the check when the whole collection (this class and the in-process sanity reads) has finished.
    [Fact]
    public void FixtureAssemblies_AreNeverLoadedIntoTheTestProcess()
    {
        foreach (var row in BehaviourGroundTruth.Rows)
            runs.Observe(Package(row.Key));

        Assert.Empty(BehaviourInertnessGuard.LoadedFixtureAssemblies());
    }
    #endregion

    #region Methods: helpers
    private static PackageDef Package(string key) => BehaviourPackages.All.Single(p => p.Key == key);

    // True when a section 5 id cell ("BF01a/b", "BF08a, b", "BF07a/b/c", "BF19", "BF04") names the row id.
    private static bool Covers(string cell, string id)
    {
        var match = Regex.Match(cell, @"^(BF\d\d)([a-z](?:(?:/|, )[a-z])*)?$");
        Assert.True(match.Success, $"unreadable section 5 id cell '{cell}'");
        var prefix = match.Groups[1].Value;
        if (!match.Groups[2].Success)
            return id == prefix || (id.Length == prefix.Length + 1 && id.StartsWith(prefix, StringComparison.Ordinal) && char.IsAsciiLetterLower(id[^1]));
        return match.Groups[2].Value.Split('/', ',').Select(s => s.Trim()).Any(letter => id == prefix + letter);
    }

    private static string? FindSpec()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (Path.Combine(dir.FullName, "docs", "agent", "tasks", "behaviour-fixtures-recall.md") is { } path && File.Exists(path))
                return path;
        return null;
    }
    #endregion

    #region Fields
    // SHA-256 of the concatenated Predicted.Text of every row, in table order (the section 5 cells, verbatim).
    private const string Section5Sha256 = "F59DB77009AEB7AA9362D8A9D9F3B077A744982836DA29EAC609A564E1093ACD";

    // The data lines of section 5's table.
    private const int Section5Lines = 22;

    private readonly BehaviourRuns runs;

    private readonly ITestOutputHelper output;
    #endregion
}
