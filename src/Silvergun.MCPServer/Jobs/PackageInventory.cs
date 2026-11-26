namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// <c>inventory.json</c> (task S1, ADR 0034's inventory as rows), the input of S2's <c>list_files</c> and <c>read_file</c>.
/// One row per extracted file under the job's <c>files/</c> (and each unpacked single-file bundle entry the report
/// analysed), and one per declared entry that never became a file of its own, with the reason.
/// <list type="bullet">
///   <item><description><c>path</c>, for extracted files, is the package-relative path escaped losslessly
///     (<see cref="UntrustedText.EscapeBounded(string, int)"/>: distinct names stay distinct) and bounded; for bundle and
///     not-extracted rows it is the report's own escaped form, the only one there is (<c>pathForm: "report"</c>).</description></item>
///   <item><description><c>file</c> is the raw path relative to the job directory, which only the server opens, after its
///     own containment check; null when the name is too long to keep.</description></item>
/// </list>
/// Links are listed but never followed or hashed. The whole file stays under <see cref="MaxChars"/>: rows past it, or past
/// <see cref="MaxRows"/>, are not listed and <c>truncated</c> says so. A hostile name can cost its row, never the job.
/// </summary>
public static class PackageInventory
{
    #region Methods
    public static JsonObject Build(PackageCapabilityReport report, string filesDir, string nupkgPath, IReadOnlyList<(string Path, string Label)> hostPaths)
    {
        var jobDir = Path.GetDirectoryName(filesDir)!;
        var contentRoot = NuGetPackage.ContentRootOf(filesDir, nupkgPath);
        var assemblies = report.Assemblies.Where(a => a.Assembly.FullPath.Length > 0).Select(a => a.Assembly.FullPath).ToHashSet(StringComparer.Ordinal);
        var scripts = report.Scripts.Select(s => s.FullPath).ToHashSet(StringComparer.Ordinal);
        // NativeBinary.RelativePath is YaraPathSafety-escaped at construction, so it is looked up by that same escape.
        var native = report.NativeBinaries.GroupBy(n => n.RelativePath, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

        var rows = new JsonArray();
        long chars = 0;
        var truncated = false;
        bool Add(JsonObject row)
        {
            var size = row.ToJsonString(JobProtocol.JsonOptions).Length + 1;
            if (rows.Count >= MaxRows || chars + size > MaxChars)
                return !(truncated = true);
            rows.Add(row);
            chars += size;
            return true;
        }

        var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0, IgnoreInaccessible = true, ReturnSpecialDirectories = false };
        foreach (var full in Directory.EnumerateFiles(filesDir, "*", options).Order(StringComparer.Ordinal))
        {
            var underRoot = full.StartsWith(contentRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal);
            var rel = underRoot ? NuGetPackage.RelativeUnderRoot(contentRoot, full) : OutsideRoot + Path.GetRelativePath(filesDir, full).Replace('\\', '/');
            var link = (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0;
            var nativeRow = native.GetValueOrDefault(YaraPathSafety.Escape(rel));
            var kind = assemblies.Contains(full) ? "assembly"
                : scripts.Contains(full) ? "script"
                : underRoot && !rel.Contains('/') && rel.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) ? "manifest"
                : nativeRow is not null ? "native"
                : "other";
            var file = Relative(jobDir, full);
            if (!Add(Row(UntrustedText.EscapeBounded(rel, MaxPathChars), "lossless", file.Length <= MaxFileChars ? file : null,
                    link ? null : new FileInfo(full).Length, link ? null : Sha256(full), kind, underRoot ? NuGetPackage.RoleOf(rel) : PackageItemRole.Other,
                    nativeRow, link ? "a link; not followed" : file.Length > MaxFileChars ? "its name is too long to serve" : null)))
                break;
        }

        // Unpacked single-file bundle entries the report analysed, at their "host!/entry" paths.
        var bundles = filesDir + "-bundles" + Path.DirectorySeparatorChar;
        foreach (var a in report.Assemblies.Where(a => a.Assembly.FullPath.StartsWith(bundles, StringComparison.Ordinal) && File.Exists(a.Assembly.FullPath)))
            if (!Add(Row(Bounded(a.Assembly.RelativePath), "report", Relative(jobDir, a.Assembly.FullPath) is var f && f.Length <= MaxFileChars ? f : null,
                    new FileInfo(a.Assembly.FullPath).Length, a.Assembly.Sha256, "assembly", a.Assembly.Role, native.GetValueOrDefault(a.Assembly.RelativePath), null)))
                break;

        // Declared entries that never became a file of their own (ADR 0030): listed, with why, never readable.
        foreach (var a in report.Assemblies.Where(a => a.NotInventoried))
            if (!Add(Row(Bounded(a.Assembly.RelativePath), "report", null, null, null, "notExtracted", a.Assembly.Role, null,
                    UntrustedText.EscapeBounded(HostPaths.Reduce(a.SkipReason ?? "not extracted", hostPaths), MaxReasonChars))))
                break;

        return new JsonObject { ["rows"] = rows, ["truncated"] = truncated };
    }

    private static JsonObject Row(string path, string pathForm, string? file, long? size, string? sha256, string kind, PackageItemRole role, NativeBinary? native, string? note) => new()
    {
        ["path"] = path,
        ["pathForm"] = pathForm,
        ["file"] = file,
        ["size"] = size,
        ["sha256"] = sha256,
        ["kind"] = kind,
        ["role"] = JsonNamingPolicy.CamelCase.ConvertName(role.ToString()),
        ["format"] = native is null ? null : JsonNamingPolicy.CamelCase.ConvertName(native.Format.ToString()),
        ["note"] = note,
    };

    // An already-escaped report path, cut to the row bound at an escape boundary (never inside "\U000E0041"), with the
    // escaper's hash suffix.
    private static string Bounded(string escaped)
    {
        if (escaped.Length <= MaxPathChars)
            return escaped;
        var cut = MaxPathChars;
        var slash = escaped.LastIndexOf('\\', cut - 1, Math.Min(cut, MaxEscapeChars));
        if (slash >= 0 && slash + EscapeLength(escaped, slash) > cut)
            cut = slash;
        return escaped[..cut] + UntrustedText.CutSuffix(escaped, escaped.Length - cut);
    }

    // The length of the escape starting at `at` (a backslash), as UntrustedText writes them.
    private static int EscapeLength(string text, int at) => at + 1 >= text.Length ? 1 : text[at + 1] switch
    {
        'x' => 4,
        'u' => 6,
        'U' => 10,
        _ => 2,
    };

    // Forward-slash path relative to the job directory, by ordinal prefix (the files are enumerated under it).
    private static string Relative(string jobDir, string full) => full[(jobDir.Length + 1)..].Replace('\\', '/');

    private static string? Sha256(string full)
    {
        try
        {
            using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
    #endregion

    #region Fields
    /// <summary>Rows past this are not listed; <c>truncated</c> says so.</summary>
    public const int MaxRows = 100_000;

    /// <summary>The serialized size the rows may take, well under <see cref="JobArtifacts.MaxInventoryBytes"/>.</summary>
    public const long MaxChars = 96L * 1024 * 1024;

    private const int MaxPathChars = 512;
    private const int MaxEscapeChars = 10;
    private const int MaxFileChars = 1024;
    private const int MaxReasonChars = 400;

    // The prefix of a file the extractor wrote outside the content root (none is expected).
    private const string OutsideRoot = "<outside-content-root>/";
    #endregion
}
