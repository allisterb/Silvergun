namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;

using Silvergun.CodeAnalysis.IL;
using Silvergun.MCPServer.Jobs;

/// <summary>
/// The child half of inspect protocol v1 in-process (task S3): <see cref="InspectWorker.Run(string?, Stream, Stream, Action)"/>
/// over streams. Every refusal is one <c>fatal</c> record, exit 3, with no path in its reason; a valid request is
/// <c>ready</c> then <c>inspected</c>, which is what <see cref="MethodListing.Render"/> gives; stdin ending calls parent-gone.
/// </summary>
public sealed class InspectWorkerTests : IDisposable
{
    #region Methods
    [Theory]
    [InlineData(null)]
    [InlineData("2")]
    [InlineData("01")]
    [InlineData("")]
    public void Run_WithAnUnsupportedProtocol_IsOneFatal(string? protocol) =>
        AssertSingleFatal(Run(protocol, Request(fixture, 0x06000002)), "protocol");

    [Fact]
    public void Run_WithNoRequestLine_IsOneFatal() => AssertSingleFatal(Run("1", ""), "request");

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"protocol\":1,\"assembly\":")]
    [InlineData("null")]
    [InlineData("[1,2,3]")]
    [InlineData("{\"protocol\":1,\"assembly\":\"x\",\"token\":-1,\"offset\":0,\"maxChars\":8000}")]
    [InlineData("{\"protocol\":1,\"assembly\":\"x\",\"token\":\"0x06000001\",\"offset\":0,\"maxChars\":8000}")]
    public void Run_WithABadRequestLine_IsOneFatal(string line) => AssertSingleFatal(Run("1", line + "\n"), "request");

    [Fact]
    public void Run_WithARequestForAnotherProtocol_IsOneFatal() =>
        AssertSingleFatal(Run("1", Request(fixture, 0x06000002, protocol: 2)), "protocol");

    [Theory]
    [InlineData(0x02000001u)]
    [InlineData(0x0a000002u)]
    [InlineData(0x00000001u)]
    [InlineData(0xFF000001u)]
    public void Run_WithATokenThatIsNoMethodDef_IsOneFatal(uint token) =>
        AssertSingleFatal(Run("1", Request(fixture, token)), "MethodDef");

    [Theory]
    [InlineData("missing")]
    [InlineData("relative")]
    [InlineData("a directory")]
    [InlineData("null")]
    public void Run_WithAnAssemblyThatIsNoExistingAbsoluteFile_IsOneFatal_WithNoPathInItsReason(string what)
    {
        var assembly = what switch
        {
            "missing" => Path.Combine(dirs.Base, "secret-dir", "missing.dll"),
            "relative" => Path.Combine("secret-dir", "Inspect.Fixture.dll"),
            "a directory" => dirs.Base,
            _ => null,
        };

        var run = Run("1", Request(assembly!, 0x06000002));

        var reason = AssertSingleFatal(run, "absolute path");
        Assert.DoesNotContain("secret-dir", reason);
        Assert.DoesNotContain(dirs.Base, reason);
    }

    [Theory]
    [InlineData(InspectProtocol.MinChars - 1)]
    [InlineData(InspectProtocol.MaxChars + 1)]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void Run_WithMaxCharsOutOfRange_IsOneFatal(int maxChars) =>
        AssertSingleFatal(Run("1", Request(fixture, 0x06000002, maxChars: maxChars)), "maxChars");

    [Theory]
    [InlineData(InspectProtocol.MinChars)]
    [InlineData(InspectProtocol.MaxChars)]
    public void Run_AtTheMaxCharsBounds_Lists(int maxChars) =>
        Assert.Equal(JobProtocol.ExitDone, Run("1", Request(fixture, 0x06000002, maxChars: maxChars)).Exit);

    /// <summary>A valid request: <c>ready</c>, then one <c>inspected</c> record that is the in-process listing, field for field; exit 0.</summary>
    [Fact]
    public void Run_AValidRequest_IsReadyThenInspected_WithTheListing()
    {
        var token = InspectFixtures.Token(analyzer, InspectFixtures.ListingType, "Sample");

        var run = Run("1", Request(fixture, token));

        Assert.Equal(JobProtocol.ExitDone, run.Exit);
        Assert.Equal(["ready", "inspected"], run.Records.Select(Type));
        Assert.Equal(InspectProtocol.Version, run.Records[0].GetProperty("protocol").GetInt32());
        var inspected = Assert.IsType<JobInspected>(JsonSerializer.Deserialize<JobMessage>(run.Records[1].GetRawText(), JobProtocol.JsonOptions));
        var page = MethodListing.Render(analyzer, token, 0, InspectProtocol.MinChars, InspectFixtures.Display);
        Assert.Equal(new JobInspected(page.Found, page.Type, page.Name, page.Id, page.Body, page.IlBytes, page.MaxStack, page.Locals, page.Instructions, page.Shown,
            page.Next, page.Text, 0), inspected);
        Assert.True(run.RawStdout.All(b => b < 0x80), "a stdout record is not ASCII");
    }

    [Fact]
    public void Run_AnOffsetAndAPage_ArePassedThrough()
    {
        var token = InspectFixtures.Token(analyzer, InspectFixtures.ListingType, "Long");

        var run = Run("1", Request(fixture, token, offset: 600));

        var inspected = Inspected(run);
        Assert.NotNull(inspected.Next);
        Assert.True(inspected.Next > 600);
        Assert.StartsWith("IL_0258: ldstr", inspected.Listing.Split('\n').First(l => l.StartsWith("IL_", StringComparison.Ordinal)));
    }

    [Fact]
    public void Run_ATokenNoMethodHas_IsInspectedNotFound()
    {
        var inspected = Inspected(Run("1", Request(fixture, 0x06FFFFF0)));

        Assert.False(inspected.Found);
        Assert.Equal("", inspected.Listing);
    }

    [Fact]
    public void Run_AHostileMethod_IsInspected_WithEveryStringDisplayable()
    {
        var path = InspectFixtures.WriteHostile(dirs.Base);
        uint token;
        using (var hostile = InspectFixtures.Load(path))
            token = InspectFixtures.Token(hostile, Hostile3.TypeName, Hostile3.MethodName);

        var run = Run("1", Request(path, token));

        var inspected = Inspected(run);
        foreach (var s in new[] { inspected.Listing, inspected.DeclaringType!, inspected.Name!, inspected.Id! })
            Hostile3.AssertDisplayable(s, "the inspected record");
        Assert.True(run.RawStdout.All(b => b < 0x80), "a stdout record is not ASCII");
    }

    /// <summary>A file that is not an assembly: after <c>ready</c>, one fatal naming no path.</summary>
    [Fact]
    public void Run_AFileThatIsNoAssembly_IsReadyThenFatal_WithNoPath()
    {
        var path = Path.Combine(dirs.Base, "secret-name.dll");
        var bytes = new byte[512];
        new Random(3).NextBytes(bytes);
        (bytes[0], bytes[1]) = ((byte)'M', (byte)'Z');
        File.WriteAllBytes(path, bytes);

        var run = Run("1", Request(path, 0x06000001));

        Assert.Equal(JobProtocol.ExitFatal, run.Exit);
        Assert.Equal(["ready", "fatal"], run.Records.Select(Type));
        var reason = run.Records[1].GetProperty("reason").GetString()!;
        Assert.Contains("could not be loaded", reason);
        Assert.DoesNotContain("secret-name", reason);
        Assert.DoesNotContain(dirs.Base, reason);
    }

    [Fact]
    public void Run_WhenStdinEndsAfterTheRequest_CallsParentGone()
    {
        using var gone = new ManualResetEventSlim();

        var run = Run("1", Request(fixture, 0x06000002), () => gone.Set());

        Assert.Equal(JobProtocol.ExitDone, run.Exit);
        Assert.True(gone.Wait(TimeSpan.FromSeconds(10)), "parent-gone was not called when stdin ended");
    }

    [Fact]
    public void Run_WhileStdinStaysOpen_DoesNotCallParentGone()
    {
        var calls = 0;
        using var stdin = new HeldStdin(Encoding.UTF8.GetBytes(Request(fixture, 0x06000002)));
        using var stdout = new MemoryStream();

        var exit = InspectWorker.Run("1", stdin, stdout, () => Interlocked.Increment(ref calls));
        Thread.Sleep(300);

        Assert.Equal(JobProtocol.ExitDone, exit);
        Assert.Equal(0, Volatile.Read(ref calls));
    }

    /// <summary>A refusal on a request is never parent-gone: the watch starts only once a request checks out.</summary>
    [Fact]
    public void Run_ARefusedRequest_NeverCallsParentGone()
    {
        var calls = 0;

        Run("1", "not json\n", () => Interlocked.Increment(ref calls));
        Thread.Sleep(300);

        Assert.Equal(0, Volatile.Read(ref calls));
    }

    [Fact]
    public void Refuse_IsOneFatalRecord()
    {
        using var stdout = new MemoryStream();

        var exit = InspectWorker.Refuse(stdout, "bad arguments");

        Assert.Equal(JobProtocol.ExitFatal, exit);
        var record = Assert.Single(Records(stdout.ToArray()));
        Assert.Equal("fatal", Type(record));
        Assert.Equal("bad arguments", record.GetProperty("reason").GetString());
    }

    public void Dispose()
    {
        analyzer.Dispose();
        dirs.Dispose();
    }
    #endregion

    #region Methods: helpers
    private static string Request(string assembly, uint token, int protocol = 1, uint offset = 0, int maxChars = InspectProtocol.MinChars) =>
        JsonSerializer.Serialize(new InspectRequest(protocol, assembly, token, offset, maxChars), JobProtocol.JsonOptions) + "\n";

    private static WorkerRun Run(string? protocol, string stdinText, Action? parentGone = null)
    {
        using var stdin = new MemoryStream(Encoding.UTF8.GetBytes(stdinText));
        using var stdout = new MemoryStream();
        var exit = InspectWorker.Run(protocol, stdin, stdout, parentGone ?? (() => { }));
        var raw = stdout.ToArray();
        return new WorkerRun(exit, Records(raw), raw);
    }

    private static JobInspected Inspected(WorkerRun run)
    {
        Assert.Equal(JobProtocol.ExitDone, run.Exit);
        Assert.Equal(["ready", "inspected"], run.Records.Select(Type));
        return Assert.IsType<JobInspected>(JsonSerializer.Deserialize<JobMessage>(run.Records[1].GetRawText(), JobProtocol.JsonOptions));
    }

    private static List<JsonElement> Records(byte[] stdout)
    {
        var text = Encoding.UTF8.GetString(stdout);
        Assert.True(text.Length == 0 || text.EndsWith('\n'), "the last stdout record is not newline-terminated");
        return [.. text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => JsonDocument.Parse(l).RootElement.Clone())];
    }

    private static string Type(JsonElement record) => record.GetProperty("type").GetString()!;

    private static string AssertSingleFatal(WorkerRun run, string reasonMentions)
    {
        Assert.Equal(JobProtocol.ExitFatal, run.Exit);
        var record = Assert.Single(run.Records);
        Assert.Equal("fatal", Type(record));
        var reason = record.GetProperty("reason").GetString()!;
        Assert.Contains(reasonMentions, reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar), reason, StringComparison.OrdinalIgnoreCase);
        return reason;
    }
    #endregion

    #region Nested types
    private sealed record WorkerRun(int Exit, List<JsonElement> Records, byte[] RawStdout);

    // A stdin that yields its bytes and then blocks (as the server's open pipe does) until disposed.
    private sealed class HeldStdin(byte[] bytes) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (position < bytes.Length)
            {
                var n = Math.Min(count, bytes.Length - position);
                Array.Copy(bytes, position, buffer, offset, n);
                position += n;
                return n;
            }
            closed.Wait();
            throw new ObjectDisposedException(nameof(HeldStdin));
        }

        protected override void Dispose(bool disposing)
        {
            closed.Set();
            base.Dispose(disposing);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private readonly ManualResetEventSlim closed = new();
        private int position;
    }
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    private readonly string fixture;
    private readonly AssemblyAnalyzer analyzer;
    #endregion

    #region Constructors
    public InspectWorkerTests()
    {
        fixture = InspectFixtures.Write(dirs.Base);
        analyzer = InspectFixtures.Load(fixture);
    }
    #endregion
}

/// <summary>The CLI's <c>__worker inspect</c> command lines that never reach a session: one fatal record on stdout, exit 3.</summary>
public sealed class InspectWorkerCliTests
{
    #region Methods
    public static TheoryData<string[]> BadCommandLines() => new()
    {
        { ["__worker", "inspect", "--bogus"] },
        { ["__worker", "inspect", "--protocol", "1", "--bogus"] },
        { ["__worker", "inspect", "--protocol", "2"] },
        { ["__worker", "inspect"] },
    };

    [Theory]
    [MemberData(nameof(BadCommandLines))]
    public async System.Threading.Tasks.Task BadCommandLine_IsOneFatalRecord_AndExit3(string[] args)
    {
        using var dirs = new TestDirs();
        using var child = McpChildProcess.Start(args, dirs.Root);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"{string.Join(' ', args)}: did not exit\n{exit.Stderr}");
        Assert.True(exit.ExitCode == JobProtocol.ExitFatal, $"{string.Join(' ', args)}: exit {exit.ExitCode}\n{exit.Stderr}");
        Assert.Equal(0, child.TrailingBytes);
        var line = Assert.Single(child.Lines);
        using var doc = JsonDocument.Parse(line);
        Assert.Equal("fatal", doc.RootElement.GetProperty("type").GetString());
        Assert.False(string.IsNullOrWhiteSpace(doc.RootElement.GetProperty("reason").GetString()));
    }
    #endregion
}

/// <summary>
/// The parent half of an inspect run (task S3): <see cref="JobProcess.Run"/> with an <see cref="InspectRequest"/> against
/// scripted fakes. An inspect run ends at <c>inspected</c>, a job run at <c>done</c>; each is a protocol violation in the
/// other; a line over the run's record cap fails; a crash is Failed; the child is gone whatever happened.
/// </summary>
public sealed class InspectProcessTests
{
    #region Methods
    [Fact]
    public void Run_AnInspectedRecord_Completes_WithIt()
    {
        using var dirs = new TestDirs();
        var fake = new FakeChild(dirs, [FakeChild.Ready, FakeChild.Inspected()]);

        var result = RunInspect(fake);

        Assert.True(result.Status == JobRunStatus.Completed, $"{result.Status}: {result.Reason}");
        Assert.Null(result.Done);
        Assert.NotNull(result.Inspected);
        Assert.Equal("Fake.Type", result.Inspected!.DeclaringType);
        Assert.Equal(2, result.Inspected.Shown);
        fake.AssertAllGone();
    }

    /// <summary>The inspect cap is the run's own: a 100 KiB result line, over the job protocol's 16 KiB, is read whole.</summary>
    [Fact]
    public void Run_AResultLineOverTheJobCapButWithinTheInspectCap_Completes()
    {
        using var dirs = new TestDirs();
        var big = FakeChild.Inspected(r => r["listing"] = new string('a', 100 * 1024));
        Assert.True(big.Length > JobProtocol.MaxRecordLineBytes);
        var fake = new FakeChild(dirs, [FakeChild.Ready, big]);

        var result = RunInspect(fake);

        Assert.True(result.Status == JobRunStatus.Completed, $"{result.Status}: {result.Reason}");
        Assert.Equal(100 * 1024, result.Inspected!.Listing.Length);
    }

    [Fact]
    public void Run_ALineOverMaxRecordBytes_Fails()
    {
        using var dirs = new TestDirs();
        var huge = FakeChild.Inspected(r => r["listing"] = new string('a', InspectProtocol.MaxResultLineBytes + 10));
        var fake = new FakeChild(dirs, [FakeChild.Ready, huge], sleep: true);

        var result = RunInspect(fake);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains(InspectProtocol.MaxResultLineBytes.ToString(), result.Reason);
        Assert.Null(result.Inspected);
        fake.AssertAllGone();
    }

    [Fact]
    public void Run_DoneInAnInspectRun_IsAProtocolViolation()
    {
        using var dirs = new TestDirs();
        var fake = new FakeChild(dirs, [FakeChild.Ready, FakeChild.ValidDone], sleep: true);

        var result = RunInspect(fake);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains("broke protocol", result.Reason);
        Assert.Null(result.Done);
        fake.AssertAllGone();
    }

    [Fact]
    public void Run_InspectedInAJobRun_IsAProtocolViolation()
    {
        using var dirs = new TestDirs();
        var fake = new FakeChild(dirs, [FakeChild.Ready, FakeChild.Inspected()], sleep: true);

        var result = JobProcess.Run(fake.Launch, new JobRequest(JobProtocol.Version, dirs.Base, JobDepth.Standard, false), TimeSpan.FromSeconds(60), 0, 0,
            _ => { }, CancellationToken.None);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains("broke protocol", result.Reason);
        Assert.Null(result.Inspected);
        fake.AssertAllGone();
    }

    [Fact]
    public void Run_InspectedBeforeReady_IsAProtocolViolation()
    {
        using var dirs = new TestDirs();
        var fake = new FakeChild(dirs, [FakeChild.Inspected()], sleep: true);

        var result = RunInspect(fake);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains("broke protocol", result.Reason);
    }

    [Fact]
    public void Run_InspectedThenANonZeroExit_Fails()
    {
        using var dirs = new TestDirs();
        var fake = new FakeChild(dirs, [FakeChild.Ready, FakeChild.Inspected()], exitCode: 5);

        var result = RunInspect(fake);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains("exited", result.Reason);
    }

    /// <summary>A crash after <c>ready</c> (exit 35, as a FailFast ends a process) is Failed with the exit beside it.</summary>
    [Fact]
    public void Run_ACrash_IsFailed()
    {
        using var dirs = new TestDirs();
        var fake = new FakeChild(dirs, [FakeChild.Ready], exitCode: 35);

        var result = RunInspect(fake);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains("ended", result.Reason);
        Assert.Null(result.Inspected);
        fake.AssertAllGone();
    }

    [Fact]
    public void Run_AFatal_IsFailedWithItsReason()
    {
        using var dirs = new TestDirs();
        var fake = new FakeChild(dirs, [FakeChild.Ready, """{"type":"fatal","reason":"the method could not be listed (BadImageFormatException)"}"""], exitCode: 3);

        var result = RunInspect(fake);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains("BadImageFormatException", result.Reason);
    }
    #endregion

    #region Methods: helpers
    private static JobRunResult RunInspect(FakeChild fake)
    {
        var result = JobProcess.Run(fake.Launch, new InspectRequest(InspectProtocol.Version, @"C:\nowhere.dll", 0x06000001, 0, InspectProtocol.MinChars),
            TimeSpan.FromSeconds(60), 0, 0, _ => { }, CancellationToken.None, InspectProtocol.MaxResultLineBytes);
        Assert.True(fake.Pids.Count > 0, $"the fake never started ({result.Status}: {result.Reason})");
        return result;
    }
    #endregion
}
