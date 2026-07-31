namespace Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture;

using System.Diagnostics;
using System.IO;
using System.Net.Http;

/// <summary>
/// Exactly four sensitive call sites and nothing else — the counterpart of the ILSpy spike's
/// <c>07-threeapis.dll</c> (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §0.3). None is ever
/// executed; the assembly exists to be copied <b>alone into an empty directory</b> and analyzed there, where
/// <b>no</b> reference resolves and every callee's <c>ContainingType.ResolvedType</c> and
/// <c>ResolvedMethod</c> are CCI's <c>Dummy</c> sentinels.
/// <para>
/// The capability catalog must still match all three capabilities from the unresolved <em>references</em>
/// alone. Kept to four call sites so a test can name the produced key, node id and capability exactly rather
/// than asserting "contains something plausible".
/// </para>
/// </summary>
public static class ThreeApis
{
    /// <summary><c>System.IO.File.ReadAllText</c> — FileSystem, a plain <c>call</c>.</summary>
    public static string ReadsFile(string path) => File.ReadAllText(path);

    /// <summary><c>System.Net.Http.HttpClient..ctor</c> — Network, a <c>newobj</c>.</summary>
    public static object CreatesHttpClient() => new HttpClient();

    /// <summary><c>System.Diagnostics.Process.Start(System.String)</c> — ProcessExecution, a <c>call</c>.</summary>
    public static object StartsProcess(string fileName) => Process.Start(fileName);

    /// <summary>
    /// <c>System.Diagnostics.Process.Start(System.Diagnostics.ProcessStartInfo)</c> — the second overload, so
    /// the node id's parameter type is itself an unresolved reference that must still render in full.
    /// </summary>
    public static object StartsProcessFromStartInfo(ProcessStartInfo startInfo) => Process.Start(startInfo);
}
