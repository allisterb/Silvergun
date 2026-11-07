namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

using Silvergun;

using Xunit;

/// <summary>
/// End-to-end cover for the ADR 0031 decision 4 defect measured in
/// <c>data/results/packaging-anomalies-top100-2026-08-22.md</c>: <b>an <c>InvisibleCharacter</c>
/// anomaly was reported with the invisible character still in it</b> — the one category whose entire premise is
/// "you cannot see this". A real <c>.nupkg</c> on disk goes through <see cref="PackageScanner.Scan"/> and the
/// reported <see cref="PackagingAnomaly.EntryName"/> is checked, in the DTO and in the JSON, for raw invisible
/// CODE POINTS. The escaper's own alphabet is property-tested in <see cref="YaraPathSafetyTests"/>; what is under
/// test here is that the pipeline actually delivers an escaped name.
///
/// <para><b>Why the JSON is re-serialized with <see cref="JavaScriptEncoder.UnsafeRelaxedJsonEscaping"/>.</b> That
/// is the second half of the defect and the reason it survived review. <see cref="PackageCapabilityReport.ToJson"/>
/// uses the default <see cref="JsonSerializerOptions"/>, whose encoder escapes every non-ASCII character — so the
/// JSON looked correct while carrying a raw U+200B in the model, and would look correct again the moment the
/// escaper regressed. Asserting against the relaxed encoder removes System.Text.Json's accidental masking, so a
/// regression has nowhere to hide. <see cref="ToJson_WithTheRelaxedEncoder_ShowsARawInvisibleCharacterWhenOneIsPresent"/>
/// is the negative control that proves this check can fail.</para>
///
/// <para><b>...and the limit of that, measured (2026-08-22, .NET 10).</b> The relaxed encoder unmasks U+200B and
/// U+00AD but still escapes U+FEFF and <b>every astral code point</b>, so no JSON payload can distinguish "we
/// escaped the Tag block" from "System.Text.Json did". The JSON sweep is therefore necessary but not sufficient,
/// and the astral guarantee rests on the DTO code-point sweep here and on the rendered-report sweep in
/// <c>Silvergun.CLI.Tests/InvisibleCharacterEntryNameCliTests</c>, neither of which passes through an encoder.
/// <see cref="ToJson_ForARawTagBlockCharacter_IsMaskedByBothEncoders_SoJsonIsNotTheAstralChannel"/> pins that
/// boundary so the JSON test is never mistaken for astral coverage.</para>
///
/// <para><b>Why nothing here shells out to the CLI and pipes stdout.</b> A console redirect transcodes: measured
/// the same day, an é became <c>0x82</c> (CP437) and an emoji became <c>??</c> on the way to a file, so "no raw
/// invisible bytes on stdout" would be a statement about the console encoder, not about us. The in-process string
/// and the UTF-8 bytes taken from it pass through no encoder at all, which is strictly stronger; the CLI's own
/// <c>--output &lt;file&gt;</c> path (which writes UTF-8 directly) is where a CLI-level version of this belongs.</para>
/// </summary>
public sealed class InvisibleCharacterAnomalyEscapingTests : IClassFixture<InvisibleNamePackageFixture>
{
    #region Constructors
    public InvisibleCharacterAnomalyEscapingTests(InvisibleNamePackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — the anomalies are actually produced (else every sweep below is vacuous)
    // One InvisibleCharacter anomaly per hostile entry, each naming its code point in the detail — including the
    // ASTRAL Tag-block one, which a char-wise scan could not see at all.
    [Fact]
    public void Scan_ForInvisibleEntryNames_ReportsOneInvisibleCharacterAnomalyPerHostileEntry()
    {
        var invisible = Scan()
            .PackagingAnomalies
            .Where(a => a.Category == PackagingAnomalyCategory.InvisibleCharacter)
            .ToArray();

        Assert.Equal(4, invisible.Length);
        Assert.Contains(invisible, a => a.Detail.Contains("U+200B", StringComparison.Ordinal));
        Assert.Contains(invisible, a => a.Detail.Contains("U+00AD", StringComparison.Ordinal));
        Assert.Contains(invisible, a => a.Detail.Contains("U+FEFF", StringComparison.Ordinal));
        Assert.Contains(invisible, a => a.Detail.Contains("U+E0041", StringComparison.Ordinal));
    }

    // The names come back in their escaped spelling, astral form included. Pinned literally so a change of escape
    // shape is a deliberate act: \U000E0041 is the only uppercase-hex escape in the scheme.
    [Fact]
    public void Scan_ForInvisibleEntryNames_ReportsTheEscapedSpellingOfEachName()
    {
        var names = Scan()
            .PackagingAnomalies
            .Where(a => a.Category == PackagingAnomalyCategory.InvisibleCharacter)
            .Select(a => a.EntryName)
            .ToArray();

        Assert.Contains(@"content/zero\u200bwidth.bin", names);
        Assert.Contains(@"content/soft\xadhyphen.bin", names);
        Assert.Contains(@"content/bom\ufeff.bin", names);
        Assert.Contains(@"content/tag\U000E0041.bin", names);
    }
    #endregion

    #region Methods — no raw invisible code point in the report DTO
    // The defect itself: an entry name that still contains the character reports nothing a reader can see. Checked
    // on CODE POINTS (runes), not glyphs — the astral Tag block is two chars and one code point, and a char-wise
    // check is exactly the mistake that produced the bug.
    [Fact]
    public void Scan_ForInvisibleEntryNames_CarriesNoRawInvisibleCodePointInAnyAnomalyField()
    {
        var report = Scan();

        Assert.NotEmpty(report.PackagingAnomalies);
        foreach (var anomaly in report.PackagingAnomalies)
        {
            AssertNoRawInvisible(anomaly.EntryName, $"{anomaly.Category}.EntryName");
            AssertNoRawInvisible(anomaly.Detail, $"{anomaly.Category}.Detail");
        }
    }

    // ...and the same sweep over every other path the report carries, since the same package's names reach the
    // inventory and the coverage-loss disclosure too.
    [Fact]
    public void Scan_ForInvisibleEntryNames_CarriesNoRawInvisibleCodePointInAnyReportedPath()
    {
        var report = Scan();

        foreach (var result in report.Assemblies)
            AssertNoRawInvisible(result.Assembly.RelativePath, nameof(PackageAssembly.RelativePath));
        foreach (var script in report.Scripts)
            AssertNoRawInvisible(script.RelativePath, nameof(PackageScript.RelativePath));
        foreach (var finding in report.ScriptFindings)
            AssertNoRawInvisible(finding.RelativePath, nameof(ScriptFinding.RelativePath));
    }
    #endregion

    #region Methods — no raw invisible code point in the JSON, with STJ's masking removed
    // The load-bearing JSON assertion. Serialized with the RELAXED encoder, so System.Text.Json's default
    // non-ASCII escaping cannot stand in for ours, the payload must still contain no raw invisible code point —
    // and no raw invisible UTF-8 byte sequence, which is the form the measurement actually caught (E2 80 8B).
    [Fact]
    public void ToJson_ForInvisibleEntryNames_CarriesNoRawInvisibleCodePointUnderTheRelaxedEncoder()
    {
        var report = Scan();

        var json = Relaxed(report);

        AssertNoRawInvisible(json, "the relaxed-encoder JSON");
        AssertNoRawInvisibleBytes(json);
        Assert.Contains(@"content/tag\\U000E0041.bin", json, StringComparison.Ordinal);   // ...and it is in there
    }

    // The report's OWN serializer (the one the CLI's --json and --output use) carries the same escaped names and
    // round-trips them unchanged. Its default encoder additionally escapes non-ASCII, which is belt-and-braces —
    // never the thing being relied on.
    [Fact]
    public void ToJson_ForInvisibleEntryNames_RoundTripsTheEscapedNames()
    {
        var report = Scan();

        var restored = PackageCapabilityReport.FromJson(report.ToJson());

        Assert.NotNull(restored);
        Assert.Equal(
            report.PackagingAnomalies.Select(a => a.EntryName),
            restored!.PackagingAnomalies.Select(a => a.EntryName));
        foreach (var anomaly in restored.PackagingAnomalies)
            AssertNoRawInvisible(anomaly.EntryName, nameof(PackagingAnomaly.EntryName));
    }

    // THE NEGATIVE CONTROL, and the whole reason the relaxed encoder is used above. A report whose EntryName still
    // holds a raw U+200B — i.e. the pre-fix behaviour — is invisible in the default JSON (STJ escapes it to
    // "\u200B" and it reads exactly like an escape WE produced) and plainly visible under the relaxed encoder.
    // So the default-encoder JSON is not evidence of anything, and the assertions above are not vacuous.
    [Fact]
    public void ToJson_WithTheRelaxedEncoder_ShowsARawInvisibleCharacterWhenOneIsPresent()
    {
        var unescaped = ReportWith(new PackagingAnomaly(
            PackagingAnomalyCategory.InvisibleCharacter,
            "content/zero\u200Bwidth.bin",                 // RAW, as the defect reported it
            "contains invisible character(s) U+200B"));

        var relaxed = Relaxed(unescaped);
        var byDefault = unescaped.ToJson();

        Assert.Contains('\u200B', relaxed);                                            // the check can see it...
        Assert.DoesNotContain('\u200B', byDefault);                                    // ...and the default cannot
        Assert.Contains("\\u200B", byDefault, StringComparison.Ordinal);               // STJ's escape, not ours
        Assert.Contains(Zwsp, RawInvisibleByteSequencesIn(relaxed));                   // ...and the same on bytes
        Assert.DoesNotContain(Zwsp, RawInvisibleByteSequencesIn(byDefault));
    }

    // The LIMIT of the JSON channel, measured rather than assumed (2026-08-22, .NET 10): the relaxed encoder
    // unmasks U+200B and U+00AD, but it still escapes U+FEFF and EVERY astral code point — a raw U+E0041 comes out
    // as the surrogate pair "\uDB40\uDC41" under both encoders. So for the Tag block, no JSON payload can
    // distinguish "we escaped it" from "System.Text.Json escaped it", and the JSON sweep above is necessary but
    // NOT sufficient there.
    //
    // Pinning it here keeps that boundary honest and stops the JSON test from being mistaken for astral coverage.
    // The astral guarantee is carried by the DTO code-point sweep in this class and by the rendered-report sweep in
    // Silvergun.CLI.Tests/InvisibleCharacterEntryNameCliTests, neither of which passes through an encoder at all.
    [Fact]
    public void ToJson_ForARawTagBlockCharacter_IsMaskedByBothEncoders_SoJsonIsNotTheAstralChannel()
    {
        var unescaped = ReportWith(new PackagingAnomaly(
            PackagingAnomalyCategory.InvisibleCharacter,
            "content/tag\U000E0041.bin",                  // RAW, as the pre-fix escaper left it
            "contains invisible character(s) U+E0041"));

        var relaxed = Relaxed(unescaped);

        Assert.DoesNotContain("\U000E0041", relaxed, StringComparison.Ordinal);
        Assert.DoesNotContain("\U000E0041", unescaped.ToJson(), StringComparison.Ordinal);
        Assert.DoesNotContain(TagA, RawInvisibleByteSequencesIn(relaxed));
        Assert.Contains(@"\uDB40\uDC41", relaxed, StringComparison.Ordinal);   // ...STJ's escape, in both

        // ...whereas the DTO the report is built from shows it plainly, which is where the real guarantee lives.
        Assert.Contains(
            0xE0041,
            unescaped.PackagingAnomalies[0].EntryName.EnumerateRunes().Select(r => r.Value));
    }
    #endregion

    #region Methods — helpers
    private PackageCapabilityReport Scan()
    {
        var scan = PackageScanner.Scan(fixture.NupkgPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    private static PackageCapabilityReport ReportWith(params PackagingAnomaly[] anomalies) =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            PackagingAnomalies: anomalies);

    // The same report shape ToJson produces, but with the encoder that does NOT escape non-ASCII — so what is left
    // in the payload is exactly what the model held.
    private static string Relaxed(PackageCapabilityReport report) =>
        JsonSerializer.Serialize(report, RelaxedOptions);

    private static void AssertNoRawInvisible(string text, string what)
    {
        var offenders = text.EnumerateRunes().Select(r => r.Value).Where(IsInvisible).Distinct().ToArray();

        Assert.True(
            offenders.Length == 0,
            $"{what} carried raw invisible code point(s) "
            + string.Join(", ", offenders.Select(cp => $"U+{cp:X4}")) + '.');
    }

    // The same statement one level down, on the wire form. The measurement caught the literal bytes E2 80 8B in a
    // report, so the bytes are asserted on directly rather than inferred from the decoded string.
    private static void AssertNoRawInvisibleBytes(string json)
    {
        var found = RawInvisibleByteSequencesIn(json);

        Assert.True(found.Length == 0, "the payload carried the raw UTF-8 bytes of " + string.Join(", ", found) + '.');
    }

    // Which of the invisible characters this suite cares about appear as their raw UTF-8 bytes in the payload.
    // Returned rather than asserted so the negative controls can assert the POSITIVE direction with it.
    private static string[] RawInvisibleByteSequencesIn(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json).AsSpan();
        var found = new List<string>();
        foreach (var (name, needle) in RawUtf8Sequences)
            if (bytes.IndexOf(needle) >= 0)
                found.Add(name);
        return [.. found];
    }

    // Everything YaraPathSafety.Escape is defined to render invisible-proof (a superset of ADR 0031's
    // InvisibleCharacter category — see YaraPathSafetyTests for why that asymmetry is deliberate).
    private static bool IsInvisible(int cp) =>
        cp is 0x00AD
             or >= 0x200B and <= 0x200F
             or >= 0x2060 and <= 0x2064
             or 0xFEFF
             or >= 0xE0000 and <= 0xE007F;
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions RelaxedOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    // The UTF-8 spellings of the invisible characters this package ships. E2 80 8B is the exact byte triple the
    // top-100 measurement found in a rendered report. Under either JSON encoder only the first two can appear at
    // all (see the class summary); the BOM and Tag-block rows are kept so a future encoder change that stopped
    // escaping them is caught rather than silently widening what the JSON channel can carry.
    private const string Zwsp = "U+200B ZERO WIDTH SPACE";
    private const string Shy = "U+00AD SOFT HYPHEN";
    private const string Bom = "U+FEFF ZERO WIDTH NO-BREAK SPACE";
    private const string TagA = "U+E0041 TAG LATIN CAPITAL LETTER A";

    private static readonly (string Name, byte[] Bytes)[] RawUtf8Sequences =
    [
        (Zwsp, [0xE2, 0x80, 0x8B]),
        (Shy, [0xC2, 0xAD]),
        (Bom, [0xEF, 0xBB, 0xBF]),
        (TagA, [0xF3, 0xA0, 0x81, 0x81]),
    ];

    private readonly InvisibleNamePackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages one <c>.nupkg</c> whose declared entry names carry an invisible character each: a zero-width space, a
/// soft hyphen, a BOM and an astral Tag-block character, plus one plain control entry. Built with pure BCL zip —
/// <see cref="System.IO.Compression.ZipArchive.CreateEntry(string)"/> stores the name verbatim — and analysed from
/// the CENTRAL DIRECTORY, so nothing here depends on whether a given filesystem can hold such a name.
/// </summary>
public sealed class InvisibleNamePackageFixture : IDisposable
{
    #region Constructors
    public InvisibleNamePackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-invisible-names-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        const string id = "PkgInvisibleNames";
        var payload = Encoding.UTF8.GetBytes("not an assembly\n");
        NupkgPath = Path.Combine(rootDir, $"{id}.1.0.0.nupkg");

        NupkgBuilder.WriteNupkg(
            NupkgPath,
            [
                ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                    id, "1.0.0", "Silvergun Tests",
                    "ADR 0031 decision 4 invisible-entry-name regression package.", "netstandard2.0", []))),
                ("content/zero\u200Bwidth.bin", payload),     // ZERO WIDTH SPACE
                ("content/soft\u00ADhyphen.bin", payload),    // SOFT HYPHEN
                ("content/bom\uFEFF.bin", payload),           // ZERO WIDTH NO-BREAK SPACE / BOM
                ("content/tag\U000E0041.bin", payload),       // TAG LATIN CAPITAL LETTER A — ASTRAL
                ("content/plain.bin", payload),               // ...and one name with nothing wrong with it
            ]);
    }
    #endregion

    #region Properties
    public string NupkgPath { get; }
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
