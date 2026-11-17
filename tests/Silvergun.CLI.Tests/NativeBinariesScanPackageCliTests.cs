namespace Silvergun.CLI.Tests;

using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;

using Xunit;

/// <summary>
/// native-binaries-1 through the real <c>scan-package</c> verb, in a child process: an extensionless ELF executable
/// under <c>tools/</c> reaches the JSON as a <c>NativeBinaries</c> entry with <c>NativeBinaryScanStatus: Completed</c>,
/// and adds no <c>Completeness</c> caveat (facts layer: native binaries gate nothing and do not make a run incomplete).
/// Every run is <c>--no-vulns --no-yara</c> (offline, deterministic).
/// </summary>
public sealed class NativeBinariesScanPackageCliTests
{
    #region Methods
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanPackage_WithAnExtensionlessElfUnderTools_ReportsItInTheJson_WithNoNativeCaveat()
    {
        var nupkg = BuildNupkg("SilvergunNativeElf", ("tools/node", PieElf()));
        try
        {
            var run = RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--json", "--allow-incomplete");

            Assert.True(run.Exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, run.Exit);
            using var doc = JsonDocument.Parse(run.Output);
            var root = doc.RootElement;
            Assert.Equal("Completed", root.GetProperty("NativeBinaryScanStatus").GetString());
            Assert.False(root.TryGetProperty("NativeBinaryScanUnavailableReason", out _));
            var binary = Assert.Single(root.GetProperty("NativeBinaries").EnumerateArray());
            Assert.Equal("tools/node", binary.GetProperty("RelativePath").GetString());
            Assert.Equal("Elf", binary.GetProperty("Format").GetString());
            Assert.Equal("Executable", binary.GetProperty("Kind").GetString());
            Assert.Equal("x64", binary.GetProperty("Architecture").GetString());
            Assert.Equal("Tools", binary.GetProperty("Role").GetString());
            Assert.Equal(PieElf().Length, binary.GetProperty("Size").GetInt64());
            var caveats = root.GetProperty("Completeness").GetProperty("Caveats").EnumerateArray().Select(e => e.GetString()!).ToArray();
            Assert.DoesNotContain(caveats, c => c.Contains("native", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            TryDelete(nupkg);
        }
    }

    // The human report names it in its section and footer.
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanPackage_WithAnExtensionlessElfUnderTools_HumanReportHasTheSectionAndFooterLine()
    {
        var nupkg = BuildNupkg("SilvergunNativeElfHuman", ("tools/node", PieElf()));
        try
        {
            var run = RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--allow-incomplete");

            Assert.True(run.Exited, "CLI did not exit within the timeout.");
            Assert.Contains("Native binaries", run.Output, StringComparison.Ordinal);
            Assert.Contains("tools/node", run.Output, StringComparison.Ordinal);
            Assert.Contains("Native binaries: 1 (1 executable(s))", run.Output, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(nupkg);
        }
    }
    #endregion

    #region Methods: helpers
    // A 64-bit little-endian x86-64 ET_DYN with one PT_INTERP program header: a PIE executable, header only.
    private static byte[] PieElf()
    {
        var b = new byte[64 + 56];
        b[0] = 0x7F; b[1] = (byte)'E'; b[2] = (byte)'L'; b[3] = (byte)'F';
        b[4] = 2; b[5] = 1; b[6] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(16), 3);       // ET_DYN
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(18), 0x3E);    // EM_X86_64
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(32), 64);      // e_phoff
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(52), 64);      // e_ehsize
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(54), 56);      // e_phentsize
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(56), 1);       // e_phnum
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(64), 3);       // PT_INTERP
        return b;
    }

    private static string BuildNupkg(string id, params (string Entry, byte[] Bytes)[] entries)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>native-binaries-1 test package.</description>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-native-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
            foreach (var (entry, bytes) in entries)
                Write(zip, entry, bytes);
        }
        return path;

        static void Write(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }

    private static CliRun RunCli(params string[] args)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.Latin1,
            StandardErrorEncoding = Encoding.Latin1,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";

        using var process = Process.Start(psi)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeoutMs))
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            return new CliRun(-1, string.Empty, string.Empty, false);
        }

        return new CliRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), true);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Nested types
    private sealed record CliRun(int Exit, string Output, string Error, bool Exited);
    #endregion

    #region Fields
    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    private const int TimeoutMs = 120_000;
    #endregion
}
