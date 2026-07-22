namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// A single per-file YARA rule hit produced by an <see cref="IYaraScanner"/> backend: the matched
/// <paramref name="Rule"/> name, its optional <paramref name="Namespace"/>, the rule <paramref name="Tags"/>,
/// and any matched <paramref name="Strings"/>. This is a backend-neutral POCO — it carries <b>no</b>
/// libyara.NET types (ADR 0016) so it compiles and serializes on both the net10.0 and net10.0-windows
/// builds. Phase 3 enriches these into the report DTO <see cref="YaraFinding"/> via the rule-metadata index.
/// </summary>
public sealed record YaraMatch(
    string Rule,
    string? Namespace,
    IReadOnlyList<string> Tags,
    IReadOnlyList<YaraStringMatch> Strings);
