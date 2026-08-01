namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

/// <summary>One pinned corpus member. The version is a literal, never a range: see <see cref="CorpusManifest"/>.</summary>
public sealed record ManifestEntry(string Id, string Version)
{
    #region Methods
    /// <summary>The normalized form that is hashed and used as a cache key - lower-cased id, verbatim version.</summary>
    public string Key => $"{Id.ToLowerInvariant()},{Version}";
    #endregion
}

/// <summary>
/// A parsed, pinned corpus manifest plus the hash that identifies it. The hash is taken over the <b>normalized
/// entry list</b> (<see cref="ManifestEntry.Key"/> joined by <c>\n</c>), not the raw file bytes, so that editing a
/// comment or changing line endings does not make an unchanged corpus look like a different measurement - while
/// adding, removing, reordering or re-pinning a package does.
/// <para>
/// Recording this hash in the report is what makes two measurements comparable at all: a density number is only
/// meaningful against the exact package set it was computed over.
/// </para>
/// </summary>
public sealed record CorpusManifest(string Path, string Hash, IReadOnlyList<ManifestEntry> Entries)
{
    #region Methods
    /// <summary>
    /// Reads <paramref name="path"/>, skipping blank and <c>#</c> lines, and keeps the first <paramref name="take"/>
    /// entries (<c>take &lt;= 0</c> keeps all). A line without exactly one comma, or with an empty id or version, is a
    /// hard error rather than a silent skip - a manifest is the experiment definition and must not degrade quietly.
    /// The hash covers the <em>kept</em> entries, so a <c>--take</c> subset is honestly identified as its own corpus.
    /// </summary>
    public static CorpusManifest Load(string path, int take)
    {
        var entries = File.ReadAllLines(path)
            .Select((line, index) => (Text: line.Trim(), Number: index + 1))
            .Where(l => l.Text.Length > 0 && !l.Text.StartsWith('#'))
            .Select(l => Parse(l.Text, l.Number, path))
            .ToList();

        if (take > 0 && entries.Count > take)
            entries = entries.Take(take).ToList();

        var canonical = string.Join("\n", entries.Select(e => e.Key));
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));

        return new CorpusManifest(path, hash, entries);
    }

    private static ManifestEntry Parse(string line, int number, string path)
    {
        var parts = line.Split(',');
        if (parts.Length != 2 || parts[0].Trim().Length == 0 || parts[1].Trim().Length == 0)
            throw new FormatException($"{path}({number}): expected 'id,version', got '{line}'.");

        return new ManifestEntry(parts[0].Trim(), parts[1].Trim());
    }
    #endregion
}
