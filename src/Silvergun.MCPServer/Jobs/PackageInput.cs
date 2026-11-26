namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Checks an <c>analyze_package</c> path and copies the file into the cache while hashing it (task S1). The job reads only
/// the copy, so the input can change or vanish afterwards without changing what was analysed. Problems are values; the
/// messages name the agent's own argument only by its file name.
/// </summary>
public static class PackageInput
{
    #region Methods
    /// <summary>The full path of an acceptable input, or the status and reason it is refused.</summary>
    public static (string? FullPath, ToolStatus Status, string? Problem) Check(string? path, IReadOnlyList<string> roots)
    {
        if (string.IsNullOrWhiteSpace(path))
            return Refuse(ToolStatus.InvalidArgument, "path is empty");
        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Refuse(ToolStatus.InvalidArgument, "path is not a valid path");
        }

        if (roots.FirstOrDefault(r => IsUnder(full, r)) is not { } root)
            return Refuse(ToolStatus.OutsideRoots, "path is not under any root the server was started with; only the person who started it can add one");

        try
        {
            if (LinkOnPath(root, full) is { } link)
                return Refuse(ToolStatus.NotPermitted, $"'{UntrustedText.Escape(Path.GetFileName(link))}' on the path is a link or junction, which the server does not follow");
            var info = new FileInfo(full);
            if (!info.Exists)
                return Directory.Exists(full) ? Refuse(ToolStatus.InvalidArgument, "path is a directory, not a .nupkg file") : Refuse(ToolStatus.NotFound, "there is no file at path");

            // A FIFO, socket or device reports size 0 (and opening a FIFO blocks), so the size floor also keeps those out.
            return info.Length < MinPackageBytes ? Refuse(ToolStatus.InvalidArgument, "path is empty or not a regular file")
                : info.Length > MaxPackageBytes ? Refuse(ToolStatus.InvalidArgument, $"the file is over {MaxPackageBytes / (1024 * 1024)} MiB")
                : (full, ToolStatus.Succeeded, null);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return Refuse(ToolStatus.NotFound, "there is no file at path");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Refuse(ToolStatus.NotPermitted, $"path could not be examined ({ex.GetType().Name})");
        }
    }

    /// <summary>
    /// Copies <paramref name="source"/> to <paramref name="destination"/> while hashing it, refusing more than
    /// <see cref="MaxPackageBytes"/>. The open is bounded in time (a file swapped for a FIFO after the check would block it).
    /// The SHA-256 (lowercase hex) and size, or why not; the destination is deleted on failure.
    /// </summary>
    public static async Task<(string? Sha256, long Bytes, string? Problem)> CopyAsync(string source, string destination, CancellationToken ct)
    {
        try
        {
            var open = Task.Run(() => new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.SequentialScan), ct);
            if (await Task.WhenAny(open, Task.Delay(OpenTimeout, ct)) != open)
            {
                // An open that completes later is closed then, never leaked.
                _ = open.ContinueWith(t => t.Result.Dispose(), TaskContinuationOptions.OnlyOnRanToCompletion);
                return (null, 0, "the file could not be opened in time (it may not be a regular file)");
            }
            await using var input = await open;
            if (!input.CanSeek)
                return (null, 0, "path is not a regular file");
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long total = 0;
            await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.SequentialScan))
            {
                var buffer = new byte[1024 * 1024];
                int read;
                while ((read = await input.ReadAsync(buffer, ct)) > 0)
                {
                    total += read;
                    if (total > MaxPackageBytes)
                        return Fail($"the file grew past {MaxPackageBytes / (1024 * 1024)} MiB while it was copied");
                    sha.AppendData(buffer.AsSpan(0, read));
                    await output.WriteAsync(buffer.AsMemory(0, read), ct);
                }
                await output.FlushAsync(ct);
            }
            return total < MinPackageBytes ? Fail("the file is too small to be a package") : (Convert.ToHexStringLower(sha.GetHashAndReset()), total, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Fail($"the file could not be copied ({ex.GetType().Name})");
        }

        (string?, long, string?) Fail(string why)
        {
            try { File.Delete(destination); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* incoming/ is swept later */ }
            return (null, 0, why);
        }
    }

    private static bool IsUnder(string full, string root)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
        return full.StartsWith(prefix, comparison);
    }

    // The first component below `root`, down to and including `full`, that is a link (a reparse point: junction, symbolic
    // link, mount point), or null. The entry's own attributes are read, so a link is never followed.
    private static string? LinkOnPath(string root, string full)
    {
        var prefix = Path.EndsInDirectorySeparator(root) ? root.Length : root.Length + 1;
        var ends = Enumerable.Range(prefix, full.Length - prefix).Where(i => full[i] == Path.DirectorySeparatorChar).Append(full.Length);
        foreach (var end in ends)
        {
            var part = full[..end];
            try
            {
                if ((File.GetAttributes(part) & FileAttributes.ReparsePoint) != 0)
                    return part;
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
            {
                return null;
            }
        }
        return null;
    }

    private static (string?, ToolStatus, string?) Refuse(ToolStatus status, string why) => (null, status, why);
    #endregion

    #region Fields
    public const long MaxPackageBytes = 512L * 1024 * 1024;

    // The smallest zip: an empty end-of-central-directory record.
    private const long MinPackageBytes = 22;

    private static readonly TimeSpan OpenTimeout = TimeSpan.FromSeconds(5);
    #endregion
}
