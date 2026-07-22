namespace Silvergun.PackageAnalysis.NuGet.Yara;

using System.Reflection;

/// <summary>
/// Shared access to the embedded ReversingLabs + custom <c>.yara</c> rule sources (ADR 0016). Both the
/// cross-platform CLI backend (<see cref="YaraCliScanner"/>, which writes them to a temp dir for <c>yarac</c>)
/// and the rule-metadata index (<see cref="YaraRuleIndex"/>, which parses their <c>meta:</c> blocks) read the
/// rules through here so the manifest-resource lookup lives in exactly one place. The Windows in-process
/// backend consumes the same resources directly through its own <c>#if WINDOWS</c> path.
///
/// The rules are embedded by link under <c>Resources\YaraRules\</c> (see the csproj), so every rule resource
/// name contains <see cref="RuleResourceMarker"/> and ends in <c>.yara</c>. Reads are defensive: a resource
/// that cannot be opened is skipped rather than throwing.
/// </summary>
internal static class YaraRuleResources
{
    #region Methods
    /// <summary>The names of every embedded <c>.yara</c> rule resource, in a stable ordinal order.</summary>
    internal static IEnumerable<string> ResourceNames(Assembly? assembly = null)
    {
        assembly ??= typeof(YaraRuleResources).Assembly;
        return assembly.GetManifestResourceNames()
            .Where(n => n.Contains(RuleResourceMarker) && n.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.Ordinal);
    }

    /// <summary>
    /// Reads every embedded rule source as <c>(resourceName, text)</c>. A resource that fails to open or read
    /// is skipped (never throws), so a single unreadable entry cannot break rule compilation or indexing.
    /// </summary>
    internal static IEnumerable<(string ResourceName, string Text)> ReadAll(Assembly? assembly = null)
    {
        assembly ??= typeof(YaraRuleResources).Assembly;
        foreach (var name in ResourceNames(assembly))
        {
            string? text = null;
            try
            {
                using var stream = assembly.GetManifestResourceStream(name);
                if (stream is not null)
                {
                    using var reader = new StreamReader(stream);
                    text = reader.ReadToEnd();
                }
            }
            catch
            {
                text = null;
            }
            if (text is not null)
                yield return (name, text);
        }
    }
    #endregion

    #region Fields
    /// <summary>Substring marking the embedded YARA rule resources (ReversingLabs + Custom) under Resources/YaraRules.</summary>
    internal const string RuleResourceMarker = ".Resources.YaraRules.";
    #endregion
}
