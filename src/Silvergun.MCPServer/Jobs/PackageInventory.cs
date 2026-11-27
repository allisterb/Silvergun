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
/// The inventory row file (task S1, ADR 0034's inventory as rows; S2's <c>list_files</c> and <c>read_file</c>). One row
/// per extracted file under the job's <c>files/</c> (and each unpacked single-file bundle entry the report analysed), and
/// one per declared entry that never became a file of its own, with the reason.
/// <list type="bullet">
///   <item><description><c>path</c>, for extracted files, is the package-relative path escaped losslessly
///     (<see cref="UntrustedText.EscapeBounded(string, int)"/>: distinct names stay distinct) and bounded; for bundle and
///     not-extracted rows it is the report's own escaped form, the only one there is (<c>pathForm: "report"</c>). It is the
///     key <c>read_file</c> takes.</description></item>
///   <item><description><c>file</c> is the raw path relative to the job directory, which only the server opens, after its
///     own containment check, and never serves; null when the name is too long to keep.</description></item>
/// </list>
/// Links are listed but never followed or hashed. Rows past <see cref="MaxChars"/> or <see cref="MaxRows"/> are not listed,
/// and the index says the list is truncated. A hostile name can cost its row, never the job.
/// </summary>
public static class PackageInventory
{
    #region Methods
    /// <summary>Writes the rows; returns the served path of every listed file, for the finding rows to name.</summary>
    public static PackagePaths Write(PackageCapabilityReport report, string filesDir, string nupkgPath, IReadOnlyList<(string Path, string Label)> hostPaths, RowWriter rows)
    {
        var paths = new PackagePaths();
        var jobDir = Path.GetDirectoryName(filesDir)!;
        var contentRoot = NuGetPackage.ContentRootOf(filesDir, nupkgPath);
        var assemblies = report.Assemblies.Where(a => a.Assembly.FullPath.Length > 0).Select(a => a.Assembly.FullPath).ToHashSet(StringComparer.Ordinal);
        var scripts = report.Scripts.Select(s => s.FullPath).ToHashSet(StringComparer.Ordinal);
        // NativeBinary.RelativePath is YaraPathSafety-escaped at construction, so it is looked up by that same escape.
        var native = report.NativeBinaries.GroupBy(n => n.RelativePath, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var keep = new HashSet<string>(StringComparer.Ordinal) { "path" };

        var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0, IgnoreInaccessible = true, ReturnSpecialDirectories = false };
        var listed = true;
        foreach (var full in Directory.EnumerateFiles(filesDir, "*", options).Order(StringComparer.Ordinal))
        {
            var underRoot = full.StartsWith(contentRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal);
            var rel = underRoot ? NuGetPackage.RelativeUnderRoot(contentRoot, full) : OutsideRoot + Path.GetRelativePath(filesDir, full).Replace('\\', '/');
            var link = (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0;
            var reported = YaraPathSafety.Escape(rel);
            var nativeRow = native.GetValueOrDefault(reported);
            var kind = assemblies.Contains(full) ? "assembly"
                : scripts.Contains(full) ? "script"
                : underRoot && !rel.Contains('/') && rel.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) ? "manifest"
                : nativeRow is not null ? "native"
                : "other";
            var file = Relative(jobDir, full);
            var path = UntrustedText.EscapeBounded(rel, MaxPathChars);
            var servable = !link && file.Length <= MaxFileChars;
            if (!(listed = Add(Row(path, "lossless", servable ? file : null, link ? null : new FileInfo(full).Length, link ? null : Sha256(full), kind,
                    underRoot ? NuGetPackage.RoleOf(rel) : PackageItemRole.Other, nativeRow,
                    link ? "a link; not followed" : file.Length > MaxFileChars ? "its name is too long to serve" : null), full, reported)))
                break;
        }

        // Unpacked single-file bundle entries the report analysed, at their "host!/entry" paths.
        var bundles = filesDir + "-bundles" + Path.DirectorySeparatorChar;
        foreach (var a in report.Assemblies.Where(a => listed && a.Assembly.FullPath.StartsWith(bundles, StringComparison.Ordinal) && File.Exists(a.Assembly.FullPath)))
        {
            var path = RowFile.Cut(a.Assembly.RelativePath, MaxPathChars);
            var file = Relative(jobDir, a.Assembly.FullPath);
            if (!(listed = Add(Row(path, "report", file.Length <= MaxFileChars ? file : null, new FileInfo(a.Assembly.FullPath).Length, a.Assembly.Sha256,
                    "assembly", a.Assembly.Role, native.GetValueOrDefault(a.Assembly.RelativePath), null), a.Assembly.FullPath, a.Assembly.RelativePath)))
                break;
        }

        // Declared entries that never became a file of their own (ADR 0030): listed, with why, never readable.
        foreach (var a in report.Assemblies.Where(a => listed && a.NotInventoried))
            if (!(listed = Add(Row(RowFile.Cut(a.Assembly.RelativePath, MaxPathChars), "report", null, null, null, "notExtracted", a.Assembly.Role, null,
                    HostPaths.Reduce(a.SkipReason ?? "not extracted", hostPaths)), null, null)))
                break;

        return paths;

        // Lists a row, and maps its file only when the row was written; false when a cap stops the list.
        bool Add(JsonObject row, string? full, string? reported)
        {
            var before = rows.Rows;
            if (!rows.Add(row, keep, Unservable))
                return false;
            if (rows.Rows > before && full is not null && reported is not null)
                paths.Add(full, reported, RowFile.UntrustedValue(row, "path")!);
            return true;
        }
    }

    // One row, as list_files serves it but for `file`, which the server strips.
    private static JsonObject Row(string path, string pathForm, string? file, long? size, string? sha256, string kind, PackageItemRole role, NativeBinary? native, string? note)
    {
        var row = new JsonObject
        {
            ["path"] = new JsonObject { ["untrusted"] = path },
            ["pathForm"] = pathForm,
            ["file"] = file,
            ["readable"] = file is not null && kind != "notExtracted",
            ["size"] = size,
            ["sha256"] = sha256,
            ["kind"] = kind,
            ["role"] = JsonNamingPolicy.CamelCase.ConvertName(role.ToString()),
            ["format"] = native is null ? null : JsonNamingPolicy.CamelCase.ConvertName(native.Format.ToString()),
        };
        if (note is not null)
            row["note"] = ToolEnvelope.Untrusted(note, MaxReasonChars);
        return row;
    }

    // A row whose raw `file` (which no cut can shorten) keeps it from fitting: still listed, never readable (S2 review round 2,
    // W2), so a deep non-ASCII path costs only its readability, never its row.
    private static JsonObject Unservable(JsonObject row)
    {
        row["file"] = null;
        row["readable"] = false;
        row["note"] = ToolEnvelope.Untrusted("its name is too long to serve", MaxReasonChars);
        return row;
    }

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
    /// <summary>Rows past this are not listed; the index says the list is truncated.</summary>
    public const int MaxRows = 100_000;

    /// <summary>The bytes the rows may take, under <see cref="JobArtifacts.MaxInventoryBytes"/>.</summary>
    public const long MaxChars = 96L * 1024 * 1024;

    private const int MaxPathChars = 512;
    private const int MaxFileChars = 1024;
    private const int MaxReasonChars = 400;

    // The prefix of a file the extractor wrote outside the content root (none is expected).
    private const string OutsideRoot = "<outside-content-root>/";
    #endregion
}

/// <summary>
/// The served path of every file the inventory lists, so a finding names a file exactly as <c>list_files</c> and
/// <c>read_file</c> do. Looked up by the extracted file's full path, or by the report's escaped relative path; a report path
/// two files share is ambiguous and has no served path.
/// </summary>
public sealed class PackagePaths
{
    #region Methods
    public void Add(string fullPath, string reported, string served)
    {
        byFile[fullPath] = served;
        byReported[reported] = byReported.TryGetValue(reported, out var other) && other != served ? null : served;
    }

    /// <summary>The served path of the file at <paramref name="fullPath"/>, or null when it is not listed.</summary>
    public string? OfFile(string fullPath) => byFile.GetValueOrDefault(fullPath);

    /// <summary>The served path of the file a report names by <paramref name="reported"/>, or null when none or several are.</summary>
    public string? OfReported(string reported) => byReported.GetValueOrDefault(reported);
    #endregion

    #region Fields
    private readonly Dictionary<string, string> byFile = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string?> byReported = new(StringComparer.Ordinal);
    #endregion
}
