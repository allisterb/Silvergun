namespace Silvergun.MCPServer.Jobs;

using System.IO;
using System.Text.Json;
using System.Threading;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>
/// The child half of inspect worker protocol v1 (<see cref="InspectProtocol"/>, task S3), run by <c>__worker inspect</c>: it
/// reads one request, loads the assembly with CCI, lists the method, and answers with one <c>inspected</c> record. When its
/// stdin ends after the request (the server is gone) it exits at once. Its reasons are fixed text naming an exception type,
/// never a path. Never throws.
/// </summary>
public static class InspectWorker
{
    #region Methods
    /// <summary>Serves one request over the raw streams; returns the process exit code.</summary>
    public static int Run(string? protocol, Stream stdin, Stream stdout) =>
        Run(protocol, stdin, stdout, () => Environment.Exit(JobProtocol.ExitParentGone));

    /// <summary>One <c>fatal</c> record for a command line that never reached <see cref="Run(string?, Stream, Stream)"/>; returns its exit code.</summary>
    public static int Refuse(Stream stdout, string reason) => new JobWorker.Writer(stdout).Fatal(reason);

    /// <summary><see cref="Run(string?, Stream, Stream)"/> with the parent-gone action as a test seam.</summary>
    public static int Run(string? protocol, Stream stdin, Stream stdout, Action parentGone)
    {
        var writer = new JobWorker.Writer(stdout);
        if (protocol != InspectProtocol.Version.ToString())
            return writer.Fatal($"unsupported protocol; expected __worker inspect --protocol {InspectProtocol.Version}");

        var reader = new WorkerLineReader(stdin, JobProtocol.MaxRequestLineBytes);
        var (status, line) = reader.ReadLine();
        if (status != WorkerLineStatus.Line)
            return writer.Fatal("no request line was read");
        if (RequestProblem(line, out var request) is { } problem)
            return writer.Fatal(problem);

        new Thread(() => { try { reader.ReadLine(); } catch (Exception ex) when (ex is IOException or ObjectDisposedException) { } parentGone(); })
            { IsBackground = true, Name = "inspect-worker-stdin-watch" }.Start();

        try
        {
            writer.Write(new JobReady(InspectProtocol.Version));
            using var reads = CciAssertions.BeginScope();
            var loaded = AssemblyAnalyzer.Load(request!.Assembly);
            if (!loaded.IsSuccess)
                return writer.Fatal("the file could not be loaded as a .NET assembly" + (loaded.Exception is { } ex ? $" ({ex.GetType().Name})" : ""));
            using var assembly = loaded.Value;
            var page = MethodListing.Render(assembly, request.Token, request.Offset, request.MaxChars, Display);
            writer.Write(new JobInspected(page.Found, page.Type, page.Name, page.Id, page.Body, page.IlBytes, page.MaxStack, page.Locals,
                page.Instructions, page.Shown, page.Next, page.Text, reads.Count, page.HandlersNotShown));
            return JobProtocol.ExitDone;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return writer.Fatal($"the method could not be listed ({ex.GetType().Name})");
        }
    }

    // Package text for the listing: escaped losslessly, invisible code points too, and cut at an escape boundary.
    private static string Display(string text, int maxChars) => ToolEnvelope.Escaped(text, maxChars);

    // Why `line` is not a usable request, or null with `request` set.
    private static string? RequestProblem(byte[] line, out InspectRequest? request)
    {
        request = null;
        try
        {
            request = JsonSerializer.Deserialize<InspectRequest>(line, JobProtocol.JsonOptions);
        }
        catch (JsonException)
        {
            return "the request is not valid JSON for the protocol";
        }
        return request is null ? "the request is null"
            : request.Protocol != InspectProtocol.Version ? $"the request is for protocol {request.Protocol}"
            : request.Assembly is null || !Path.IsPathFullyQualified(request.Assembly) || !File.Exists(request.Assembly) ? "the assembly is not an existing absolute path"
            : request.Token >> 24 != 0x06 ? "the token is not a MethodDef token"
            : request.MaxChars is < InspectProtocol.MinChars or > InspectProtocol.MaxChars ? "maxChars is out of range"
            : null;
    }
    #endregion
}
