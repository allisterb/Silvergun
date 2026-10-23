namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Silvergun;

using Xunit;

/// <summary>
/// <see cref="CappedTextWriter"/>, the worker's stderr cap (ADR 0033 worker protocol v1: "stderr is diagnostics, escaped
/// and ≤ 64 KiB in total (the worker truncates)"). Measured at the byte level, through a real UTF-8
/// <see cref="StreamWriter"/> like the one <see cref="Runtime.WithStderrLogging"/> wraps: the inner stream never receives
/// more than the cap, a multi-byte character is never split (the output always decodes strictly), the truncation marker
/// is written exactly once and nothing follows it, and all of that holds under concurrent writers.
/// </summary>
public sealed class CappedTextWriterTests
{
    #region Methods
    public static TheoryData<string, int> Widths() => new()
    {
        { "a", 1 },
        { ((char)0x00E9).ToString(), 2 },       // e-acute
        { ((char)0x20AC).ToString(), 3 },       // euro sign
        { char.ConvertFromUtf32(0x1F600), 4 },  // an astral emoji (a surrogate pair)
    };

    // Many small writes of one character width until the cap: the output is a whole number of those characters, then
    // the marker, within the cap and filled to within one character of it.
    [Theory]
    [MemberData(nameof(Widths))]
    public void ManySmallWrites_StopAtTheCap_WithoutSplittingACharacter(string unit, int width)
    {
        using var sink = new Sink();
        var chunk = string.Concat(Enumerable.Repeat(unit, 7));

        for (var i = 0; i < 100_000 && !sink.Writer.Truncated; i++)
            sink.Writer.Write(chunk);

        AssertCappedOutput(sink, unit, width);
    }

    [Theory]
    [MemberData(nameof(Widths))]
    public void OneHugeWrite_IsCutAtACharacterBoundary(string unit, int width)
    {
        using var sink = new Sink();

        sink.Writer.Write(string.Concat(Enumerable.Repeat(unit, 200_000)));

        AssertCappedOutput(sink, unit, width);
    }

    // A surrogate pair written one char at a time (as a char-by-char logger would) is still never split.
    [Fact]
    public void SurrogatePairsWrittenCharByChar_AreNeverSplit()
    {
        using var sink = new Sink();
        var pair = char.ConvertFromUtf32(0x1F600);

        for (var i = 0; i < 100_000 && !sink.Writer.Truncated; i++)
        {
            sink.Writer.Write(pair[0]);
            sink.Writer.Write(pair[1]);
        }

        var bytes = sink.Bytes();
        Assert.True(bytes.Length <= Cap, $"{bytes.Length} bytes > cap {Cap}");
        var text = Strict.GetString(bytes);   // throws on a split sequence
        Assert.EndsWith(CappedTextWriter.TruncationMarker, text, StringComparison.Ordinal);
    }

    // Once truncated, every overload is a no-op: the marker is the last thing the inner writer ever receives.
    [Fact]
    public void AfterTheMarker_NothingIsWritten_ByAnyOverload()
    {
        using var sink = new Sink(maxBytes: 200);
        sink.Writer.Write(new string('x', 500));
        var before = sink.Bytes();

        sink.Writer.Write('y');
        sink.Writer.Write("more");
        sink.Writer.Write(new[] { 'a', 'b', 'c' }, 0, 3);
        sink.Writer.Write("span".AsSpan());
        sink.Writer.WriteLine("line");
        sink.Writer.Write(42);
        sink.Writer.Write(new StringBuilder("sb"));
        sink.Writer.Flush();

        Assert.Equal(before, sink.Bytes());
        Assert.Equal(1, Count(Strict.GetString(before), CappedTextWriter.TruncationMarker));
        Assert.EndsWith(CappedTextWriter.TruncationMarker, Strict.GetString(before), StringComparison.Ordinal);
    }

    [Fact]
    public void BelowTheCap_TextPassesThroughVerbatim_WithNoMarker()
    {
        using var sink = new Sink(maxBytes: 200);

        sink.Writer.Write("hello ");
        sink.Writer.WriteLine("world");

        Assert.Equal("hello world" + Environment.NewLine, Strict.GetString(sink.Bytes()));
        Assert.False(sink.Writer.Truncated);
    }

    // The marker's bytes are budgeted inside the cap: text filling the cap less the marker is not truncated, and one more
    // byte truncates with the total landing exactly on the cap.
    [Fact]
    public void TheMarkerIsBudgetedInsideTheCap_ToTheByte()
    {
        var marker = Encoding.UTF8.GetByteCount(CappedTextWriter.TruncationMarker);
        using var sink = new Sink(maxBytes: 1000);

        sink.Writer.Write(new string('a', 1000 - marker));
        Assert.False(sink.Writer.Truncated);

        sink.Writer.Write("b");
        Assert.True(sink.Writer.Truncated);
        Assert.Equal(1000, sink.Bytes().Length);
        Assert.Equal(1000, sink.Writer.BytesWritten);
        Assert.Equal(new string('a', 1000 - marker) + CappedTextWriter.TruncationMarker, Strict.GetString(sink.Bytes()));
    }

    [Fact]
    public void TheCapCannotBeSmallerThanTheMarker()
    {
        var marker = Encoding.UTF8.GetByteCount(CappedTextWriter.TruncationMarker);

        Assert.Throws<ArgumentOutOfRangeException>(() => new CappedTextWriter(TextWriter.Null, marker - 1));
        using var ok = new CappedTextWriter(TextWriter.Null, marker);
    }

    // Eight threads write numbered lines as fast as they can. The writer is the only lock: the output must still be
    // within the cap, each write must land whole (or be the one cut write), the marker must appear once, at the end, and
    // BytesWritten must equal what the inner stream actually received.
    [Fact]
    public async Task ConcurrentWriters_StayWithinTheCap_WithWholeWritesAndOneMarker()
    {
        using var sink = new Sink();
        using var start = new ManualResetEventSlim();

        var writers = Enumerable.Range(0, 8).Select(t => Task.Factory.StartNew(() =>
        {
            start.Wait();
            for (var i = 0; i < 50_000 && !sink.Writer.Truncated; i++)
                sink.Writer.Write($"T{t}-{i:D6}-{new string((char)('a' + t), 20)}\n");
        }, TaskCreationOptions.LongRunning)).ToArray();
        start.Set();
        await Task.WhenAll(writers);

        var bytes = sink.Bytes();
        Assert.True(bytes.Length <= Cap, $"{bytes.Length} bytes > cap {Cap}");
        Assert.Equal(bytes.Length, sink.Writer.BytesWritten);
        var text = Strict.GetString(bytes);
        Assert.Equal(1, Count(text, CappedTextWriter.TruncationMarker));
        Assert.EndsWith(CappedTextWriter.TruncationMarker, text, StringComparison.Ordinal);

        var body = text[..^CappedTextWriter.TruncationMarker.Length];
        var lines = body.Split('\n');
        var whole = lines[..^1];   // the last piece is the cut write (possibly empty)
        Assert.NotEmpty(whole);
        Assert.All(whole, line => Assert.Matches(LinePattern, line));
        foreach (var thread in whole.GroupBy(l => l[1]))
        {
            var sequence = thread.Select(l => int.Parse(l[3..9])).ToArray();
            Assert.Equal(sequence.OrderBy(i => i), sequence);   // each thread's writes arrive whole and in order
        }
    }
    #endregion

    #region Methods: helpers
    private static void AssertCappedOutput(Sink sink, string unit, int width)
    {
        var bytes = sink.Bytes();
        Assert.True(bytes.Length <= Cap, $"{bytes.Length} bytes > cap {Cap}");
        Assert.True(sink.Writer.Truncated);
        Assert.Equal(bytes.Length, sink.Writer.BytesWritten);

        var text = Strict.GetString(bytes);   // throws on a split multi-byte sequence
        Assert.Equal(1, Count(text, CappedTextWriter.TruncationMarker));
        Assert.EndsWith(CappedTextWriter.TruncationMarker, text, StringComparison.Ordinal);

        var body = text[..^CappedTextWriter.TruncationMarker.Length];
        Assert.Equal(0, body.Length % unit.Length);
        Assert.True(body.Replace(unit, "").Length == 0, "the body holds something other than whole copies of the character");
        var markerBytes = Encoding.UTF8.GetByteCount(CappedTextWriter.TruncationMarker);
        Assert.InRange(Encoding.UTF8.GetByteCount(body), Cap - markerBytes - (width - 1), Cap - markerBytes);
    }

    private static int Count(string text, string part)
    {
        var count = 0;
        for (var at = text.IndexOf(part, StringComparison.Ordinal); at >= 0; at = text.IndexOf(part, at + part.Length, StringComparison.Ordinal))
            count++;
        return count;
    }
    #endregion

    #region Nested types
    // A CappedTextWriter over the same kind of inner writer production uses (UTF-8, no BOM, AutoFlush), over a stream
    // whose bytes the test can inspect.
    private sealed class Sink : IDisposable
    {
        public Sink(long maxBytes = Cap)
        {
            Writer = new CappedTextWriter(new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true }, maxBytes);
        }

        public CappedTextWriter Writer { get; }

        public byte[] Bytes()
        {
            Writer.Flush();
            return stream.ToArray();
        }

        public void Dispose() => Writer.Dispose();

        private readonly MemoryStream stream = new();
    }
    #endregion

    #region Fields
    private const long Cap = Runtime.WorkerStderrCapBytes;

    private static readonly Encoding Strict = new UTF8Encoding(false, throwOnInvalidBytes: true);

    private static readonly Regex LinePattern = new(@"^T[0-7]-\d{6}-([a-h])\1{19}$");
    #endregion
}
