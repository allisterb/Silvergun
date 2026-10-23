namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using Xunit;

/// <summary>
/// Worker protocol v1 (ADR 0033 FINAL FORM; the contract and its 2026-10-22 amendments are in
/// <c>docs/agent/tasks/yarax-worker.md</c>), task T1: the parent's strict <see cref="WorkerResponseReader"/>, the bounded
/// <see cref="WorkerLineReader"/> under it, the worker's <see cref="WorkerRequestReader"/>, the
/// <see cref="WorkerProtocolWriter"/> both sides use, and the <see cref="YaraWorker"/> loop over in-memory streams.
///
/// <para>The worker is hostile. Every limit is pinned at its exact boundary (the last accepted value and the first
/// rejected one), every rejection is a <see cref="WorkerStreamTerminal.Violation"/> (never confused with a clean
/// <see cref="WorkerStreamTerminal.Done"/> or a plain <see cref="WorkerStreamTerminal.Eof"/>), and the records accepted
/// before a breach are kept as partial findings while the offending record never is (ADR 0032). Units follow amendment
/// (d): the line limit is UTF-8 bytes excluding the <c>\n</c>; character limits are UTF-16 code units.</para>
/// </summary>
public sealed class YaraWorkerProtocolTests
{
    #region Methods: WorkerLineReader
    [Fact]
    public void LineReader_ALineOfExactlyTheLimit_ExcludingItsNewline_IsAccepted()
    {
        var reader = new WorkerLineReader(Stream(Ascii('a', WorkerProtocol.MaxLineBytes), "\n"u8.ToArray()));

        var (status, bytes) = reader.ReadLine();

        Assert.Equal(WorkerLineStatus.Line, status);
        Assert.Equal(WorkerProtocol.MaxLineBytes, bytes.Length);
        Assert.Equal(WorkerLineStatus.Eof, reader.ReadLine().Status);
    }

    [Fact]
    public void LineReader_ALineOneByteOverTheLimit_IsTooLong()
    {
        var reader = new WorkerLineReader(Stream(Ascii('a', WorkerProtocol.MaxLineBytes + 1), "\n"u8.ToArray()));

        Assert.Equal(WorkerLineStatus.TooLong, reader.ReadLine().Status);
    }

    // The bound is enforced WHILE reading: an endless line costs the limit plus at most one read buffer (64 KiB), and
    // then the reader stops touching the stream for good.
    [Fact]
    public void LineReader_AnEndlessLine_StopsAfterAboutTheLimitAndNeverReadsAgain()
    {
        var endless = new EndlessStream((byte)'a');
        var reader = new WorkerLineReader(endless);

        Assert.Equal(WorkerLineStatus.TooLong, reader.ReadLine().Status);
        var consumed = endless.BytesRead;
        Assert.InRange(consumed, WorkerProtocol.MaxLineBytes + 1, WorkerProtocol.MaxLineBytes + 64 * 1024);

        Assert.Equal(WorkerLineStatus.TooLong, reader.ReadLine().Status);
        Assert.Equal(consumed, endless.BytesRead);
    }

    [Fact]
    public void LineReader_DistinguishesACleanEndFromAHalfWrittenLine()
    {
        var clean = new WorkerLineReader(Stream("{}\n"u8.ToArray()));
        Assert.Equal(WorkerLineStatus.Line, clean.ReadLine().Status);
        Assert.Equal(WorkerLineStatus.Eof, clean.ReadLine().Status);

        var half = new WorkerLineReader(Stream("{}\n{\"type\""u8.ToArray()));
        Assert.Equal(WorkerLineStatus.Line, half.ReadLine().Status);
        Assert.Equal(WorkerLineStatus.Truncated, half.ReadLine().Status);
        Assert.Equal(WorkerLineStatus.Truncated, half.ReadLine().Status);   // terminal
    }

    [Fact]
    public void LineReader_InvalidUtf8_IsTerminal()
    {
        var reader = new WorkerLineReader(Stream([0x7B, 0xC3, 0x28, 0x7D, 0x0A, 0x7B, 0x7D, 0x0A]));   // {<bad 2-byte seq>}\n{}\n

        Assert.Equal(WorkerLineStatus.InvalidUtf8, reader.ReadLine().Status);
        Assert.Equal(WorkerLineStatus.InvalidUtf8, reader.ReadLine().Status);
    }

    [Fact]
    public void LineReader_AStreamThatFails_IsAnIoErrorNotAnException()
    {
        var reader = new WorkerLineReader(new ThrowingStream());

        Assert.Equal(WorkerLineStatus.IoError, reader.ReadLine().Status);
    }
    #endregion

    #region Methods: WorkerResponseReader, the happy path
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5)]
    public void Reader_ReadyThenOneResultPerRequestThenDone_IsComplete(int n)
    {
        var outcome = Read(n, [ReadyLine, .. Enumerable.Range(0, n).Select(i => Scanned(i)), Done(n)]);

        Assert.True(outcome.IsComplete);
        Assert.Equal(n, Assert.IsType<WorkerStreamTerminal.Done>(outcome.Terminal).Record.Count);
        Assert.NotNull(outcome.Ready);
        Assert.Equal(Enumerable.Range(0, n), outcome.Results.Select(r => r.Index));
    }

    [Fact]
    public void Reader_Next_ReturnsTheAcceptedRecords_AndNullAtTheTerminal()
    {
        var reader = Reader(1, ReadyLine, Scanned(0, Hit("R1", "ns", "[\"t1\",\"t2\"]")), Done(1));

        var ready = Assert.IsType<WorkerReady>(reader.Next());
        var result = Assert.IsType<WorkerResult>(reader.Next());
        Assert.Null(reader.Next());

        Assert.Equal(("yara-x", "1.22.0", 5, "passed"), (ready.Engine, ready.EngineVersion, ready.RuleCount, ready.Canary));
        var hit = Assert.Single(result.Hits!);
        Assert.Equal(("R1", "ns"), (hit.Rule, hit.Namespace));
        Assert.Equal(new[] { "t1", "t2" }, hit.Tags);
        Assert.IsType<WorkerStreamTerminal.Done>(reader.Terminal);
    }

    [Theory]
    [InlineData("timeout")]
    [InlineData("error")]
    [InlineData("skipped")]
    public void Reader_ANonScannedResultWithAReason_IsAccepted(string status)
    {
        var outcome = Read(1, ReadyLine, NotScanned(0, status, "why"), Done(1));

        Assert.True(outcome.IsComplete);
        Assert.Equal("why", outcome.Results[0].Reason);
        Assert.Null(outcome.Results[0].Hits);
    }

    // Amendment (e): an empty namespace is allowed, an empty rule name is not.
    [Fact]
    public void Reader_AHitWithAnEmptyNamespace_IsAccepted()
    {
        Assert.True(Read(1, ReadyLine, Scanned(0, Hit("R", "")), Done(1)).IsComplete);
    }
    #endregion

    #region Methods: WorkerResponseReader, exact limits
    public static TheoryData<string, int, bool> NameLimitCases()
    {
        var data = new TheoryData<string, int, bool>();
        foreach (var field in new[] { "rule", "namespace", "tag" })
        {
            data.Add(field, WorkerProtocol.MaxNameChars, true);
            data.Add(field, WorkerProtocol.MaxNameChars + 1, false);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(NameLimitCases))]
    public void Reader_RuleNamespaceAndTag_AreBoundedAt256Chars(string field, int length, bool accepted)
    {
        var text = new string('n', length);
        var hit = field switch
        {
            "rule" => Hit(text),
            "namespace" => Hit("R", text),
            _ => Hit("R", "default", $"[{J(text)}]"),
        };

        AssertAcceptedOrViolation(Read(1, ReadyLine, Scanned(0, hit), Done(1)), accepted, acceptedResults: 1,
            $"{(field == "rule" ? "rule name" : field)} exceeds 256 chars");
    }

    // Amendment (d): character limits count UTF-16 code units, so 128 astral characters (256 units) are the most a name
    // may hold, and 129 (258 units) are too many.
    [Theory]
    [InlineData(128, true)]
    [InlineData(129, false)]
    public void Reader_NameLimit_CountsUtf16CodeUnits(int astralChars, bool accepted)
    {
        var rule = string.Concat(Enumerable.Repeat(char.ConvertFromUtf32(0x1F600), astralChars));

        AssertAcceptedOrViolation(Read(1, ReadyLine, Scanned(0, Hit(rule)), Done(1)), accepted, acceptedResults: 1, "rule name exceeds 256 chars");
    }

    [Theory]
    [InlineData(512, true)]
    [InlineData(513, false)]
    public void Reader_AResultReason_IsBoundedAt512Chars(int length, bool accepted)
    {
        AssertAcceptedOrViolation(Read(1, ReadyLine, NotScanned(0, "error", new string('r', length)), Done(1)), accepted, acceptedResults: 1, "reason exceeds 512 chars");
    }

    [Theory]
    [InlineData(512, true)]
    [InlineData(513, false)]
    public void Reader_AFatalReason_IsBoundedAt512Chars(int length, bool accepted)
    {
        var outcome = Read(0, ReadyLine, Fatal(new string('f', length)));

        if (accepted)
            Assert.Equal(new string('f', length), Assert.IsType<WorkerStreamTerminal.Fatal>(outcome.Terminal).Reason);
        else
            Assert.Contains("fatal reason exceeds 512 chars", Violation(outcome), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(64, true)]
    [InlineData(65, false)]
    public void Reader_TagsPerHit_AreBoundedAt64(int tags, bool accepted)
    {
        var hit = Hit("R", "default", "[" + string.Join(",", Enumerable.Range(0, tags).Select(i => J("t" + i))) + "]");

        AssertAcceptedOrViolation(Read(1, ReadyLine, Scanned(0, hit), Done(1)), accepted, acceptedResults: 1, "more than 64 tags");
    }

    [Theory]
    [InlineData(1024, true)]
    [InlineData(1025, false)]
    public void Reader_HitsPerFile_AreBoundedAt1024(int hits, bool accepted)
    {
        var all = Enumerable.Range(0, hits).Select(i => Hit("R" + i)).ToArray();

        AssertAcceptedOrViolation(Read(1, ReadyLine, Scanned(0, all), Done(1)), accepted, acceptedResults: 1, "more than 1024 hits");
    }

    public static TheoryData<string, int, bool> ReadyFieldCases()
    {
        var data = new TheoryData<string, int, bool>();
        foreach (var field in new[] { "engine", "engineVersion", "rulesSha256", "canary" })
        {
            data.Add(field, WorkerProtocol.MaxNameChars, true);
            data.Add(field, WorkerProtocol.MaxNameChars + 1, false);
        }
        return data;
    }

    // Amendment (c): every ready string is bounded at 256 chars.
    [Theory]
    [MemberData(nameof(ReadyFieldCases))]
    public void Reader_ReadyStrings_AreBoundedAt256Chars(string field, int length, bool accepted)
    {
        var values = new Dictionary<string, string> { ["engine"] = "yara-x", ["engineVersion"] = "1.22.0", ["rulesSha256"] = Sha, ["canary"] = "passed" };
        values[field] = new string('v', length);
        var ready = $"{{\"type\":\"ready\",\"protocol\":1,\"engine\":{J(values["engine"])},\"engineVersion\":{J(values["engineVersion"])},\"ruleCount\":5,\"rulesSha256\":{J(values["rulesSha256"])},\"canary\":{J(values["canary"])},\"ruleSourceErrors\":0}}";

        var outcome = Read(0, ready, Done(0));

        if (accepted)
            Assert.True(outcome.IsComplete);
        else
        {
            Assert.Contains("ready field exceeds 256 chars", Violation(outcome), StringComparison.Ordinal);
            Assert.Null(outcome.Ready);
        }
    }

    // A whole record of exactly 1 MiB (JSON whitespace pads it) is one line the reader must accept; one more byte is not.
    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    public void Reader_TheLineLimitIsOneMiBOfUtf8_ExcludingTheNewline(int over, bool accepted)
    {
        var result = Scanned(0);
        var padded = result[..1] + new string(' ', WorkerProtocol.MaxLineBytes + over - result.Length) + result[1..];
        Assert.Equal(WorkerProtocol.MaxLineBytes + over, Encoding.UTF8.GetByteCount(padded));

        var outcome = Read(1, ReadyLine, padded, Done(1));

        AssertAcceptedOrViolation(outcome, accepted, acceptedResults: 1, "line exceeds 1048576 bytes");
    }
    #endregion

    #region Methods: WorkerResponseReader, rejected input
    // (what, the record, a fragment the violation reason must contain). "malformed record" is the schema-level rejection
    // (System.Text.Json under the strict context options); the others are the reader's own shape checks.
    public static TheoryData<string, string, string> MalformedResultLines() => new()
    {
        { "JSON null", "null", "record is JSON null" },
        { "an empty line", "", Malformed },
        { "whitespace only", "   ", Malformed },
        { "not an object", "[1,2]", Malformed },
        { "the discriminator is not the first property", "{\"index\":0,\"type\":\"result\",\"status\":\"scanned\",\"hits\":[]}", Malformed },
        { "a duplicate property", "{\"type\":\"result\",\"index\":0,\"index\":0,\"status\":\"scanned\",\"hits\":[]}", Malformed },
        { "a duplicate discriminator", "{\"type\":\"result\",\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[]}", Malformed },
        { "a wrong-case property name", "{\"type\":\"result\",\"Index\":0,\"status\":\"scanned\",\"hits\":[]}", Malformed },
        { "a wrong-case discriminator value", "{\"type\":\"Result\",\"index\":0,\"status\":\"scanned\",\"hits\":[]}", Malformed },
        { "an unknown type", "{\"type\":\"progress\",\"index\":0}", Malformed },
        { "no type", "{\"index\":0,\"status\":\"scanned\",\"hits\":[]}", Malformed },
        { "an unknown field", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[],\"extra\":1}", Malformed },
        { "an unknown field in a hit", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[{\"rule\":\"R\",\"namespace\":\"n\",\"tags\":[],\"x\":1}]}", Malformed },
        { "an integer status", "{\"type\":\"result\",\"index\":0,\"status\":0,\"hits\":[]}", Malformed },
        { "a comma-joined status", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned, error\",\"hits\":[]}", Malformed },
        { "a wrong-case status", "{\"type\":\"result\",\"index\":0,\"status\":\"Scanned\",\"hits\":[]}", Malformed },
        { "an unknown status", "{\"type\":\"result\",\"index\":0,\"status\":\"clean\",\"hits\":[]}", Malformed },
        { "a missing index", "{\"type\":\"result\",\"status\":\"scanned\",\"hits\":[]}", Malformed },
        { "a string index", "{\"type\":\"result\",\"index\":\"0\",\"status\":\"scanned\",\"hits\":[]}", Malformed },
        { "a fractional index", "{\"type\":\"result\",\"index\":0.5,\"status\":\"scanned\",\"hits\":[]}", Malformed },
        { "a null hit", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[null]}", "a null hit" },
        { "a null tag", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[{\"rule\":\"R\",\"namespace\":\"n\",\"tags\":[null]}]}", "a null tag" },
        { "a null rule", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[{\"rule\":null,\"namespace\":\"n\",\"tags\":[]}]}", Malformed },
        { "a null namespace", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[{\"rule\":\"R\",\"namespace\":null,\"tags\":[]}]}", Malformed },
        { "a null tags array", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[{\"rule\":\"R\",\"namespace\":\"n\",\"tags\":null}]}", Malformed },
        { "a hit with no tags property", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[{\"rule\":\"R\",\"namespace\":\"n\"}]}", Malformed },
        { "an empty rule name", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[{\"rule\":\"\",\"namespace\":\"n\",\"tags\":[]}]}", "empty rule name" },
        { "a scanned result with a reason", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"reason\":\"x\",\"hits\":[]}", "scanned result carries a reason" },
        { "a scanned result without hits", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\"}", "has no hits array" },
        { "a scanned result with null hits", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":null}", "has no hits array" },
        { "a skipped result with hits", "{\"type\":\"result\",\"index\":0,\"status\":\"skipped\",\"reason\":\"x\",\"hits\":[]}", "skipped result carries hits" },
        { "an error result without a reason", "{\"type\":\"result\",\"index\":0,\"status\":\"error\"}", "error result has no reason" },
        { "a timeout result without a reason", "{\"type\":\"result\",\"index\":0,\"status\":\"timeout\"}", "timeout result has no reason" },
        { "trailing content after the object", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[]} {}", Malformed },
        { "two records on one line", "{\"type\":\"result\",\"index\":0,\"status\":\"scanned\",\"hits\":[]}{\"type\":\"done\",\"count\":1}", Malformed },
    };

    // Each malformed record arrives after a valid ready and a valid result 0 (n = 2): the stream ends in a Violation that
    // names the problem, result 0 is kept, and the malformed record never is.
    [Theory]
    [MemberData(nameof(MalformedResultLines))]
    public void Reader_AMalformedRecord_IsAViolation_KeepingOnlyTheEarlierResults(string what, string line, string reason)
    {
        var bad = line.Replace("\"index\":0", "\"index\":1").Replace("\"index\":\"0\"", "\"index\":\"1\"");

        var outcome = Read(2, ReadyLine, Scanned(0), bad, Scanned(1), Done(2));

        Assert.True(outcome.Terminal is WorkerStreamTerminal.Violation, $"{what}: ended {outcome.Terminal}");
        Assert.Contains(reason, Violation(outcome), StringComparison.Ordinal);
        Assert.Equal(new[] { 0 }, outcome.Results.Select(r => r.Index));
        Assert.False(outcome.IsComplete);
    }

    [Fact]
    public void Reader_AUtf8ByteOrderMark_IsAViolation()
    {
        var bytes = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.UTF8.GetBytes(ReadyLine + "\n" + Done(0) + "\n")).ToArray();

        var outcome = new WorkerResponseReader(Stream(bytes), 0).ReadToEnd();

        Assert.IsType<WorkerStreamTerminal.Violation>(outcome.Terminal);
        Assert.Null(outcome.Ready);
    }

    [Fact]
    public void Reader_ResultBeforeReady_IsAViolation()
    {
        var outcome = Read(1, Scanned(0), ReadyLine, Done(1));

        Assert.Contains("before ready", Violation(outcome), StringComparison.Ordinal);
        Assert.Empty(outcome.Results);
    }

    [Fact]
    public void Reader_DoneBeforeReady_IsAViolation() =>
        Assert.Contains("before ready", Violation(Read(0, Done(0))), StringComparison.Ordinal);

    [Fact]
    public void Reader_ASecondReady_IsAViolation() =>
        Assert.Contains("second ready", Violation(Read(0, ReadyLine, ReadyLine, Done(0))), StringComparison.Ordinal);

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public void Reader_AReadyForAnotherProtocol_IsAViolation(int protocol)
    {
        var outcome = Read(0, ReadyLine.Replace("\"protocol\":1", $"\"protocol\":{protocol}"), Done(0));

        Assert.Contains("protocol", Violation(outcome), StringComparison.Ordinal);
        Assert.Null(outcome.Ready);
    }

    [Fact]
    public void Reader_AReadyWithANegativeRuleCount_IsAViolation() =>
        Assert.Contains("negative", Violation(Read(0, ReadyLine.Replace("\"ruleCount\":5", "\"ruleCount\":-1"), Done(0))), StringComparison.Ordinal);

    // Amendment G1 (2026-10-22 (e)): `ruleSourceErrors` is required (an int >= 0). A ready without it is malformed, so a
    // worker that does not report its compile errors can never be trusted by omission.
    [Fact]
    public void Reader_AReadyWithoutRuleSourceErrors_IsAViolation()
    {
        var outcome = Read(0, ReadyLine.Replace(",\"ruleSourceErrors\":0", ""), Done(0));

        Assert.Contains(Malformed, Violation(outcome), StringComparison.Ordinal);
        Assert.Null(outcome.Ready);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("-2147483648")]
    public void Reader_AReadyWithANegativeRuleSourceErrors_IsAViolation(string value)
    {
        var outcome = Read(0, ReadyLine.Replace("\"ruleSourceErrors\":0", $"\"ruleSourceErrors\":{value}"), Done(0));

        Assert.Contains("negative ruleSourceErrors", Violation(outcome), StringComparison.Ordinal);
        Assert.Null(outcome.Ready);
    }

    // A non-integer count is a schema error, never coerced.
    [Theory]
    [InlineData("\"0\"")]
    [InlineData("0.5")]
    [InlineData("null")]
    public void Reader_AReadyWithANonIntegerRuleSourceErrors_IsAViolation(string value) =>
        Assert.Contains(Malformed, Violation(Read(0, ReadyLine.Replace("\"ruleSourceErrors\":0", $"\"ruleSourceErrors\":{value}"), Done(0))), StringComparison.Ordinal);

    // The reader only bounds it; a positive count is a well-formed ready (the PARENT refuses it under G1, which
    // YaraXWorkerScannerTests pins), and the value reaches the parent intact.
    [Fact]
    public void Reader_AReadyWithAPositiveRuleSourceErrors_IsAccepted_AndCarriesTheCount()
    {
        var outcome = Read(0, ReadyLine.Replace("\"ruleSourceErrors\":0", "\"ruleSourceErrors\":3"), Done(0));

        Assert.True(outcome.IsComplete, outcome.Terminal.ToString());
        Assert.Equal(3, outcome.Ready!.RuleSourceErrors);
    }

    [Fact]
    public void Reader_AReadyWithAnUnknownField_IsAViolation() =>
        Assert.IsType<WorkerStreamTerminal.Violation>(Read(0, ReadyLine[..^1] + ",\"extra\":true}", Done(0)).Terminal);

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public void Reader_ADoneCountOtherThanTheRequestCount_IsAViolation(int count)
    {
        var outcome = Read(1, ReadyLine, Scanned(0), Done(count));

        Assert.Contains("done count", Violation(outcome), StringComparison.Ordinal);
        Assert.Single(outcome.Results);   // the valid result before it is kept
    }

    [Fact]
    public void Reader_DoneBeforeEveryResult_IsAViolation() =>
        Assert.Contains("done after 1 of 2", Violation(Read(2, ReadyLine, Scanned(0), Done(2))), StringComparison.Ordinal);

    [Theory]
    [InlineData(new[] { 1 }, "out of order")]
    [InlineData(new[] { 0, 0 }, "out of order")]
    [InlineData(new[] { 0, 2, 1 }, "out of order")]
    [InlineData(new[] { 3 }, "out of range")]
    [InlineData(new[] { -1 }, "out of range")]
    public void Reader_IndicesMustBeInRangeOnceEachAndInOrder(int[] indices, string expected)
    {
        var outcome = Read(3, [ReadyLine, .. indices.Select(i => Scanned(i)), Done(3)]);

        Assert.Contains(expected, Violation(outcome), StringComparison.Ordinal);
        Assert.Equal(Enumerable.Range(0, outcome.Results.Count), outcome.Results.Select(r => r.Index));
    }
    #endregion

    #region Methods: WorkerResponseReader, terminal states
    // Amendment (b): fatal is a valid terminal at any point, and results accepted before it are kept.
    [Fact]
    public void Reader_FatalBeforeReady_IsTheFatalTerminal()
    {
        var outcome = Read(1, Fatal("rules failed"));

        Assert.Equal("rules failed", Assert.IsType<WorkerStreamTerminal.Fatal>(outcome.Terminal).Reason);
        Assert.Null(outcome.Ready);
        Assert.False(outcome.IsComplete);
    }

    [Fact]
    public void Reader_FatalAfterSomeResults_KeepsThem()
    {
        var outcome = Read(3, ReadyLine, Scanned(0, Hit("Found")), NotScanned(1, "timeout", "slow"), Fatal("bad request"));

        Assert.IsType<WorkerStreamTerminal.Fatal>(outcome.Terminal);
        Assert.Equal(new[] { 0, 1 }, outcome.Results.Select(r => r.Index));
        Assert.Equal("Found", outcome.Results[0].Hits!.Single().Rule);
        Assert.False(outcome.IsComplete);
    }

    // The fatal reason is worker text; the terminal carries it escaped, so it is safe to log verbatim.
    [Fact]
    public void Reader_AFatalReason_IsEscapedInTheTerminal()
    {
        var outcome = Read(0, Fatal("a\nb" + (char)0x202E + "c"));

        var reason = Assert.IsType<WorkerStreamTerminal.Fatal>(outcome.Terminal).Reason;
        Assert.Equal("a\\nb\\u202ec", reason);
    }

    // Amendment (g): a stream that just stops at a line boundary (a crash, a kill) is Eof, never Done; one that stops in
    // the middle of a line is a Violation. Both keep what came before and both are incomplete.
    [Fact]
    public void Reader_AStreamEndingAtALineBoundary_IsEof_KeepingTheResults()
    {
        var outcome = Read(3, ReadyLine, Scanned(0), Scanned(1));

        Assert.IsType<WorkerStreamTerminal.Eof>(outcome.Terminal);
        Assert.Equal(new[] { 0, 1 }, outcome.Results.Select(r => r.Index));
        Assert.False(outcome.IsComplete);
    }

    [Fact]
    public void Reader_AStreamEndingInsideALine_IsAViolation_KeepingTheResults()
    {
        var bytes = Encoding.UTF8.GetBytes(ReadyLine + "\n" + Scanned(0) + "\n" + Scanned(1));   // no final \n

        var outcome = new WorkerResponseReader(Stream(bytes), 2).ReadToEnd();

        Assert.Contains("truncated", Violation(outcome), StringComparison.Ordinal);
        Assert.Equal(new[] { 0 }, outcome.Results.Select(r => r.Index));
    }

    [Fact]
    public void Reader_AnEmptyStream_IsEof()
    {
        var outcome = new WorkerResponseReader(Stream(Array.Empty<byte>()), 1).ReadToEnd();

        Assert.IsType<WorkerStreamTerminal.Eof>(outcome.Terminal);
        Assert.Null(outcome.Ready);
    }

    [Fact]
    public void Reader_AnInvalidUtf8Line_IsAViolation_KeepingTheResults()
    {
        var bytes = Encoding.UTF8.GetBytes(ReadyLine + "\n" + Scanned(0) + "\n").Concat(new byte[] { 0x7B, 0xFF, 0x7D, 0x0A }).ToArray();

        var outcome = new WorkerResponseReader(Stream(bytes), 2).ReadToEnd();

        Assert.Contains("UTF-8", Violation(outcome), StringComparison.Ordinal);
        Assert.Single(outcome.Results);
    }

    // After a terminal the reader never reads again: bytes after `done` (amendment (f)) are not read, and later
    // calls return null without touching the stream.
    [Fact]
    public void Reader_NextAfterATerminal_ReturnsNullWithoutReading()
    {
        var stream = new OneLinePerReadStream(ReadyLine, Done(0), "{\"type\":\"garbage\"}", Scanned(7));
        var reader = new WorkerResponseReader(stream, 0);

        Assert.IsType<WorkerReady>(reader.Next());
        Assert.Null(reader.Next());
        var reads = stream.Reads;

        Assert.Null(reader.Next());
        Assert.Null(reader.Next());
        Assert.Equal(reads, stream.Reads);
        Assert.IsType<WorkerStreamTerminal.Done>(reader.Terminal);
    }

    [Fact]
    public void Reader_NextAfterAViolation_ReturnsNullWithoutReading()
    {
        var stream = new OneLinePerReadStream(ReadyLine, "null", Scanned(0), Done(1));
        var reader = new WorkerResponseReader(stream, 1);

        reader.ReadToEnd();
        var reads = stream.Reads;

        Assert.Null(reader.Next());
        Assert.Equal(reads, stream.Reads);
        Assert.IsType<WorkerStreamTerminal.Violation>(reader.Terminal);
    }

    [Fact]
    public void Reader_RejectsANegativeRequestCount() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new WorkerResponseReader(Stream(Array.Empty<byte>()), -1));
    #endregion

    #region Methods: WorkerRequestReader
    [Fact]
    public void RequestReader_InOrderRequests_AreAccepted_ThenACleanEof()
    {
        var reader = new WorkerRequestReader(Stream(Encoding.UTF8.GetBytes(Request(0, "a") + "\n" + Request(1, "b") + "\n")));

        Assert.Equal("a", reader.Next()!.Path);
        Assert.Equal("b", reader.Next()!.Path);
        Assert.Null(reader.Next());
        Assert.Equal(2, reader.Count);
        Assert.IsType<WorkerStreamTerminal.Eof>(reader.Terminal);
    }

    public static TheoryData<string, string> MalformedRequests() => new()
    {
        { "an index that does not start at 0", Request(1, "a") + "\n" },
        { "a skipped index", Request(0, "a") + "\n" + Request(2, "b") + "\n" },
        { "a repeated index", Request(0, "a") + "\n" + Request(0, "b") + "\n" },
        { "an unknown field", "{\"index\":0,\"path\":\"a\",\"x\":1}\n" },
        { "a wrong-case field", "{\"Index\":0,\"path\":\"a\"}\n" },
        { "an empty path", Request(0, "") + "\n" },
        { "a null path", "{\"index\":0,\"path\":null}\n" },
        { "a missing path", "{\"index\":0}\n" },
        { "JSON null", "null\n" },
        { "a truncated last line", Request(0, "a") + "\n" + Request(1, "b") },
    };

    [Theory]
    [MemberData(nameof(MalformedRequests))]
    public void RequestReader_AMalformedStream_EndsInAViolation(string what, string input)
    {
        var reader = new WorkerRequestReader(Stream(Encoding.UTF8.GetBytes(input)));

        while (reader.Next() is not null) { }

        Assert.True(reader.Terminal is WorkerStreamTerminal.Violation, $"{what}: ended {reader.Terminal}");
    }
    #endregion

    #region Methods: WorkerProtocolWriter
    // One record = one write of one whole line, followed by a flush, so a reader on the other end of a pipe never sees
    // half a record and never waits on one sitting in a buffer.
    [Fact]
    public void Writer_WritesEachRecordAsOneLineInOneWrite_FollowedByAFlush()
    {
        var stream = new RecordingStream();
        var writer = new WorkerProtocolWriter(stream);

        writer.Write(new WorkerReady(1, "stub", "", 0, "", "skipped"));
        writer.Write(new WorkerResult(0, WorkerScanStatus.Skipped, "no engine"));
        writer.Write(new WorkerDone(1));
        writer.Write(new WorkerRequest(0, "a"));

        Assert.Equal(new[] { "W", "F", "W", "F", "W", "F", "W", "F" }, stream.Operations.Select(o => o.Kind));
        Assert.All(stream.Operations.Where(o => o.Kind == "W"), w =>
        {
            Assert.Equal(1, w.Bytes.Count(b => b == (byte)'\n'));
            Assert.Equal((byte)'\n', w.Bytes[^1]);
            Assert.Equal((byte)'{', w.Bytes[0]);   // no BOM, no leading whitespace
        });
    }

    [Fact]
    public void Writer_OmitsNullHitsAndReasons_AndUsesTheExactWireNames()
    {
        var stream = new MemoryStream();
        var writer = new WorkerProtocolWriter(stream);

        writer.Write(new WorkerResult(0, WorkerScanStatus.Skipped, "no engine"));
        writer.Write(new WorkerResult(1, WorkerScanStatus.Scanned, Hits: [new WorkerHit("R", "default", ["t"])]));
        writer.Write(new WorkerResult(2, WorkerScanStatus.Timeout, "slow"));
        writer.Write(new WorkerResult(3, WorkerScanStatus.Error, "denied"));
        writer.Write(new WorkerFatal("boom"));

        Assert.Equal(
            "{\"type\":\"result\",\"index\":0,\"status\":\"skipped\",\"reason\":\"no engine\"}\n"
            + "{\"type\":\"result\",\"index\":1,\"status\":\"scanned\",\"hits\":[{\"rule\":\"R\",\"namespace\":\"default\",\"tags\":[\"t\"]}]}\n"
            + "{\"type\":\"result\",\"index\":2,\"status\":\"timeout\",\"reason\":\"slow\"}\n"
            + "{\"type\":\"result\",\"index\":3,\"status\":\"error\",\"reason\":\"denied\"}\n"
            + "{\"type\":\"fatal\",\"reason\":\"boom\"}\n",
            Encoding.UTF8.GetString(stream.ToArray()));
    }

    // What one side writes, the other side's strict reader accepts unchanged, hostile strings included.
    [Fact]
    public void Writer_RoundTripsThroughTheStrictReader()
    {
        var hostile = "q\"b\\s\n" + (char)0x202E + "\0" + char.ConvertFromUtf32(0x1F600) + (char)0x200B;
        var stream = new MemoryStream();
        var writer = new WorkerProtocolWriter(stream);
        var ready = new WorkerReady(1, "yara-x", "1.22.0", 3, Sha, "passed");
        var results = new[]
        {
            new WorkerResult(0, WorkerScanStatus.Scanned, Hits: [new WorkerHit(hostile, "", [hostile, "t2"]), new WorkerHit("R2", "ns", [])]),
            new WorkerResult(1, WorkerScanStatus.Scanned, Hits: []),
            new WorkerResult(2, WorkerScanStatus.Error, hostile),
        };

        writer.Write(ready);
        foreach (var result in results)
            writer.Write(result);
        writer.Write(new WorkerDone(3));
        stream.Position = 0;
        var outcome = new WorkerResponseReader(stream, 3).ReadToEnd();

        Assert.True(outcome.IsComplete, outcome.Terminal.ToString());
        Assert.Equal(ready, outcome.Ready);
        Assert.Equal(results.Length, outcome.Results.Count);
        foreach (var (expected, actual) in results.Zip(outcome.Results))
        {
            Assert.Equal((expected.Index, expected.Status, expected.Reason), (actual.Index, actual.Status, actual.Reason));
            Assert.Equal(expected.Hits?.Count, actual.Hits?.Count);
            foreach (var (eh, ah) in (expected.Hits ?? []).Zip(actual.Hits ?? []))
            {
                Assert.Equal((eh.Rule, eh.Namespace), (ah.Rule, ah.Namespace));
                Assert.Equal(eh.Tags, ah.Tags);
            }
        }
    }

    [Fact]
    public void Writer_RequestsRoundTripThroughTheWorkersReader()
    {
        var stream = new MemoryStream();
        var writer = new WorkerProtocolWriter(stream);
        string[] paths = [@"C:\x\NUL", "/tmp/a b/" + (char)0x202E + "c", "\\\\?\\C:\\long"];
        for (var i = 0; i < paths.Length; i++)
            writer.Write(new WorkerRequest(i, paths[i]));
        stream.Position = 0;

        var reader = new WorkerRequestReader(stream);
        var read = new List<WorkerRequest>();
        while (reader.Next() is { } request)
            read.Add(request);

        Assert.Equal(paths.Select((p, i) => new WorkerRequest(i, p)), read);
        Assert.IsType<WorkerStreamTerminal.Eof>(reader.Terminal);
    }
    #endregion

    #region Methods: the YaraWorker loop over in-memory streams
    [Fact]
    public void Worker_WithTheStub_AnswersEveryRequestInOrder()
    {
        var stdout = new MemoryStream();

        var exit = YaraWorker.Run("1", Stream(Encoding.UTF8.GetBytes(Request(0, "a") + "\n" + Request(1, "b") + "\n")), stdout, new StubYaraWorkerEngine());

        Assert.Equal(WorkerProtocol.ExitDone, exit);
        stdout.Position = 0;
        var outcome = new WorkerResponseReader(stdout, 2).ReadToEnd();
        Assert.True(outcome.IsComplete);
        Assert.Equal("stub", outcome.Ready!.Engine);
        Assert.All(outcome.Results, r => Assert.Equal((WorkerScanStatus.Skipped, "no engine"), (r.Status, r.Reason)));
    }

    // An engine that throws costs that one file (an error result), never the stream; the engine's own index is
    // overridden by the request's, so a confused engine cannot misattribute a result.
    [Fact]
    public void Worker_AnEngineThatThrowsOrMisnumbers_CostsOneFile_NotTheStream()
    {
        var stdout = new MemoryStream();
        var engine = new ScriptedEngine(request => request.Index switch
        {
            0 => throw new InvalidOperationException("boom\n" + new string('x', 2000)),
            _ => new WorkerResult(99, WorkerScanStatus.Scanned, Hits: []),
        });

        var exit = YaraWorker.Run("1", Stream(Encoding.UTF8.GetBytes(Request(0, "a") + "\n" + Request(1, "b") + "\n")), stdout, engine);

        Assert.Equal(WorkerProtocol.ExitDone, exit);
        stdout.Position = 0;
        var outcome = new WorkerResponseReader(stdout, 2).ReadToEnd();
        Assert.True(outcome.IsComplete, outcome.Terminal.ToString());
        Assert.Equal(WorkerScanStatus.Error, outcome.Results[0].Status);
        Assert.StartsWith("engine error: InvalidOperationException: boom\\n", outcome.Results[0].Reason, StringComparison.Ordinal);
        Assert.True(outcome.Results[0].Reason!.Length <= WorkerProtocol.MaxReasonChars);
        Assert.Equal((1, WorkerScanStatus.Scanned), (outcome.Results[1].Index, outcome.Results[1].Status));
    }

    [Fact]
    public void Worker_AnEngineThatFailsToStart_SendsOnlyItsFatal_AndExitsThree()
    {
        var stdout = new MemoryStream();

        var exit = YaraWorker.Run("1", Stream(Encoding.UTF8.GetBytes(Request(0, "a") + "\n")), stdout, new ScriptedEngine(_ => throw new InvalidOperationException(), new WorkerFatal("no rules")));

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        Assert.Equal("{\"type\":\"fatal\",\"reason\":\"no rules\"}\n", Encoding.UTF8.GetString(stdout.ToArray()));
    }

    [Fact]
    public void Worker_WhenStdoutBreaks_ExitsThreeWithoutThrowing()
    {
        var exit = YaraWorker.Run("1", Stream(Array.Empty<byte>()), new ThrowingStream(), new StubYaraWorkerEngine());

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
    }
    #endregion

    #region Methods: helpers
    private static WorkerStreamOutcome Read(int requests, params string[] lines) => Reader(requests, lines).ReadToEnd();

    private static WorkerResponseReader Reader(int requests, params string[] lines) =>
        new(Stream(Encoding.UTF8.GetBytes(string.Concat(lines.Select(l => l + "\n")))), requests);

    private static string Violation(WorkerStreamOutcome outcome) =>
        Assert.IsType<WorkerStreamTerminal.Violation>(outcome.Terminal).Reason;

    // A rejection must name the limit it broke, so a malformed test record cannot pass as a "rejected" boundary case.
    private static void AssertAcceptedOrViolation(WorkerStreamOutcome outcome, bool accepted, int acceptedResults, string violationNames)
    {
        if (accepted)
        {
            Assert.True(outcome.IsComplete, outcome.Terminal.ToString());
            Assert.Equal(acceptedResults, outcome.Results.Count);
        }
        else
        {
            Assert.Contains(violationNames, Violation(outcome), StringComparison.Ordinal);
            Assert.Empty(outcome.Results);   // the offending record is never accepted
        }
    }

    private static MemoryStream Stream(params byte[][] parts) => new(parts.SelectMany(p => p).ToArray(), writable: false);

    private static MemoryStream Stream(byte[] bytes) => new(bytes, writable: false);

    private static byte[] Ascii(char c, int count) => Enumerable.Repeat((byte)c, count).ToArray();

    private static string J(string text) => JsonSerializer.Serialize(text);

    private static string Hit(string rule = "R", string ns = "default", string tags = "[]") =>
        $"{{\"rule\":{J(rule)},\"namespace\":{J(ns)},\"tags\":{tags}}}";

    private static string Scanned(int index, params string[] hits) =>
        $"{{\"type\":\"result\",\"index\":{index},\"status\":\"scanned\",\"hits\":[{string.Join(",", hits)}]}}";

    private static string NotScanned(int index, string status, string reason) =>
        $"{{\"type\":\"result\",\"index\":{index},\"status\":\"{status}\",\"reason\":{J(reason)}}}";

    private static string Done(int count) => $"{{\"type\":\"done\",\"count\":{count}}}";

    private static string Fatal(string reason) => $"{{\"type\":\"fatal\",\"reason\":{J(reason)}}}";

    private static string Request(int index, string path) => $"{{\"index\":{index},\"path\":{J(path)}}}";
    #endregion

    #region Nested types
    private sealed class ScriptedEngine(Func<WorkerRequest, WorkerResult> scan, WorkerMessage? start = null) : IYaraWorkerEngine
    {
        public WorkerMessage Start() => start ?? new WorkerReady(1, "test", "0", 1, Sha, "passed");

        public WorkerResult Scan(WorkerRequest request) => scan(request);
    }

    // An infinite stream of one byte value, counting what was read.
    private sealed class EndlessStream(byte value) : Stream
    {
        public long BytesRead { get; private set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Array.Fill(buffer, value, offset, count);
            BytesRead += count;
            return count;
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
    }

    // Hands out exactly one line per Read call, so "did the reader read again" is observable.
    private sealed class OneLinePerReadStream(params string[] lines) : Stream
    {
        private readonly Queue<byte[]> pending = new(lines.Select(l => Encoding.UTF8.GetBytes(l + "\n")));

        public int Reads { get; private set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Reads++;
            if (!pending.TryDequeue(out var line))
                return 0;
            Assert.True(line.Length <= count, "test line larger than the reader's buffer");
            line.CopyTo(buffer, offset);
            return line.Length;
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
    }

    // Every read and write fails the way a broken pipe does.
    private sealed class ThrowingStream : Stream
    {
        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("broken pipe");
        public override void Write(byte[] buffer, int offset, int count) => throw new IOException("broken pipe");
        public override void Write(ReadOnlySpan<byte> buffer) => throw new IOException("broken pipe");
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    // Records every write (with its bytes) and every flush, in order.
    private sealed class RecordingStream : Stream
    {
        public List<(string Kind, byte[] Bytes)> Operations { get; } = [];

        public override void Write(byte[] buffer, int offset, int count) => Operations.Add(("W", buffer.AsSpan(offset, count).ToArray()));
        public override void Write(ReadOnlySpan<byte> buffer) => Operations.Add(("W", buffer.ToArray()));
        public override void Flush() => Operations.Add(("F", []));
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
    #endregion

    #region Fields
    private const string Malformed = "malformed record";

    private static readonly string Sha = new('a', 64);

    // Amendment G1 (2026-10-22 (e)): `ruleSourceErrors` is a required field of every ready.
    private static readonly string ReadyLine =
        $"{{\"type\":\"ready\",\"protocol\":1,\"engine\":\"yara-x\",\"engineVersion\":\"1.22.0\",\"ruleCount\":5,\"rulesSha256\":\"{Sha}\",\"canary\":\"passed\",\"ruleSourceErrors\":0}}";
    #endregion
}
