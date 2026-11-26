namespace Silvergun.MCPServer.Jobs;

using System.Buffers.Binary;
using System.IO;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// What a cache entry was produced by (task S1 design): the Silvergun version and a hash of every rule the analysis
/// ships. The rules (YARA, script, capability map) are all manifest resources of the two analysis assemblies, so the rules
/// hash covers them by construction. Computed once, on first use: never at start-up (task D4a).
/// </summary>
public static class BuildIdentity
{
    #region Properties
    /// <summary>SHA-256 (lowercase hex) over the analysis assemblies' manifest resources, each framed by name and length.</summary>
    public static string RulesHash => rulesHash.Value;

    /// <summary>
    /// The cache's build key, first 16 hex of a sha256 over: the version, the rules hash, the module version ids of the
    /// assemblies whose code decides a result (so two builds at one commit never share entries), the build flavour (the
    /// Windows build's YARA backends differ), and the YARA engine selection the job child inherits.
    /// </summary>
    public static string BuildKey => buildKey.Value;
    #endregion

    #region Methods
    private static string ComputeRulesHash()
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[sizeof(long)];
        foreach (var assembly in new[] { typeof(PackageScanner).Assembly, typeof(AssemblyAnalyzer).Assembly })
            foreach (var name in assembly.GetManifestResourceNames().Order(StringComparer.Ordinal))
            {
                using var stream = assembly.GetManifestResourceStream(name)!;
                var nameBytes = Encoding.UTF8.GetBytes(name);
                BinaryPrimitives.WriteInt64LittleEndian(length, nameBytes.LongLength);
                sha.AppendData(length);
                sha.AppendData(nameBytes);
                BinaryPrimitives.WriteInt64LittleEndian(length, stream.Length);
                sha.AppendData(length);
                var buffer = new byte[81920];
                int read;
                while ((read = stream.Read(buffer)) > 0)
                    sha.AppendData(buffer.AsSpan(0, read));
            }
        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }

    // The module version id of the Silvergun CLI assembly beside this one (the job child runs it: its report projection and
    // gate decide results), read from metadata without loading it; "none" when there is no such file.
    private static string CliModuleVersionId()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.dll");
            if (!File.Exists(path))
                return "none";
            using var pe = new PEReader(File.OpenRead(path));
            var metadata = pe.GetMetadataReader();
            return metadata.GetGuid(metadata.GetModuleDefinition().Mvid).ToString("N");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException or InvalidOperationException)
        {
            return "unreadable";
        }
    }
    #endregion

    #region Fields
    private static readonly Lazy<string> rulesHash = new(ComputeRulesHash);

    private static readonly Lazy<string> buildKey = new(() =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n",
        [
            ServerState.SilvergunVersion,
            RulesHash,
            .. new[] { typeof(BuildIdentity), typeof(PackageScanner), typeof(AssemblyAnalyzer), typeof(Silvergun.CodeAnalysis.IL.Ssa.SsaValue),
                    typeof(Runtime), typeof(Silvergun.Intel.VulnerabilityFinding) }
                .Select(t => t.Assembly.ManifestModule.ModuleVersionId.ToString("N")),
            CliModuleVersionId(),
#if WINDOWS
            "windows",
#else
            "portable",
#endif
            Environment.GetEnvironmentVariable("SILVERGUN_YARA_ENGINE")?.Trim().ToLowerInvariant() ?? "",
            // The portable build's YARA backend is the classic CLI named here, or none.
            Environment.GetEnvironmentVariable("SILVERGUN_YARA_PATH") ?? "",
        ]))))[..16]);
    #endregion
}
