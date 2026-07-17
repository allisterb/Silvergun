// Ported from OSSGadget (Shared/Helpers/StringExtensions.cs), (c) Microsoft Corporation, MIT License.
// Copy authorized 2026-07-16. Source: reference/projects/OSSGadget-main/src/Shared/Helpers/StringExtensions.cs
// Only the helpers used by the ported mutators are retained.
namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System;

/// <summary>String helpers used by the ported mutators.</summary>
internal static class SquatStringExtensions
{
    #region Methods
    /// <summary>Replaces the character at <paramref name="pos"/> in <paramref name="str"/> with <paramref name="c"/>.</summary>
    public static string ReplaceCharAtPosition(this string str, char c, int pos) =>
        string.IsNullOrEmpty(str) || pos < 0 || pos >= str.Length
            ? str
            : string.Concat(str[..pos], c, str[(pos + 1)..]);

    /// <summary>Replaces the first instance of <paramref name="oldValue"/> in <paramref name="source"/> with <paramref name="newValue"/>.</summary>
    public static string ReplaceAtStart(this string source, string oldValue, string newValue)
    {
        int place = source.IndexOf(oldValue, StringComparison.Ordinal);
        return place == -1 ? source : $"{source[..place]}{newValue}{source[(place + oldValue.Length)..]}";
    }

    /// <summary>Replaces the last instance of <paramref name="oldValue"/> in <paramref name="source"/> with <paramref name="newValue"/>.</summary>
    public static string ReplaceAtEnd(this string source, string oldValue, string newValue)
    {
        int place = source.LastIndexOf(oldValue, StringComparison.Ordinal);
        return place == -1 ? source : $"{source[..place]}{newValue}{source[(place + oldValue.Length)..]}";
    }
    #endregion
}
