namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

/// <summary>
/// Makes engine and OS text (C API error messages, exception messages, paths) safe for a scan result, a log line or the
/// worker protocol: escaped through <see cref="YaraPathSafety.Escape"/>, then cut to <see cref="MaxChars"/> chars, which
/// is the protocol's <c>reason</c> bound.
/// </summary>
internal static class YaraXText
{
    #region Methods
    /// <summary><paramref name="text"/> escaped and cut to at most <paramref name="maxChars"/> chars (marked <c>...</c>), never splitting a surrogate pair.</summary>
    internal static string Bounded(string? text, int maxChars = MaxChars)
    {
        var escaped = YaraPathSafety.Escape(text);
        if (escaped.Length <= maxChars)
            return escaped;

        var cut = Math.Max(0, maxChars - Ellipsis.Length);
        if (cut > 0 && char.IsHighSurrogate(escaped[cut - 1]))
            cut--;
        return escaped[..cut] + Ellipsis;
    }
    #endregion

    #region Fields
    /// <summary>The bound on every message the binding produces (the worker protocol's <c>reason</c> limit).</summary>
    internal const int MaxChars = 512;

    private const string Ellipsis = "...";
    #endregion
}
