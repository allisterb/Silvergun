namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Cci;

using Xunit;

/// <summary>
/// ADR 0022 Stage 1 (<c>docs/agent/tasks/cci-assertions-stage1.md</c>, acceptance criterion 2), in process: a failed
/// <see cref="CciDebug"/> or <see cref="Contract"/> assertion is recorded and execution continues, in the default
/// <see cref="CciAssertionMode.RecordAndContinue"/> mode; <see cref="CciAssertionScope"/> counts what its own logical
/// flow raised (nested scopes all count, other flows do not), keeps the first <see cref="CciAssertionScope.MaxRecords"/>
/// records and closes idempotently.
/// <para>
/// <b>Why a failed contract can be raised in a test host at all.</b> Before Stage 1 a failed <c>Contract.Assume</c> was
/// <c>Environment.FailFast</c>; now CCI's module initializer marks every contract failure handled. Each contract test
/// first asserts <see cref="CciAssertions.IsInstalled"/>, which is also what runs that initializer, so a missing handler
/// fails a premise instead of the host. The fresh-process proof is <see cref="CciAssertionsFreshProcessTests"/>.
/// </para>
/// <para>
/// These tests read <see cref="CciAssertions.Mode"/> and never change it; the ones that do are in
/// <see cref="CciAssertionsThrowModeTests"/>, which runs alone (<see cref="CciAssertionModeCollection"/>).
/// <see cref="CciAssertions.Total"/> is process-wide and other tests may raise into it concurrently, so it is only ever
/// asserted to have risen by at least what a test raised.
/// </para>
/// </summary>
public sealed class CciAssertionsTests
{
    #region Methods
    // ---- premises ------------------------------------------------------------------------------------------------

    /// <summary>
    /// <see cref="CciDebug"/> and <see cref="Contract"/>'s <c>Assert</c>/<c>Assume</c> are <c>[Conditional("DEBUG")]</c> at
    /// the call site: in a Release build of this project the calls below compile to nothing and every "recorded" assertion
    /// would fail for that reason alone.
    /// </summary>
    [Fact]
    public void Premise_ThisSuiteIsCompiledWithDebug_SoTheConditionalCallsExist() =>
        Assert.True(DebugDefined, "Silvergun.CodeAnalysis.IL.Tests was compiled without DEBUG: the [Conditional(\"DEBUG\")] assertion calls in these tests are compiled out.");

    [Fact]
    public void Premise_TheModeIsRecordAndContinue_TheDefault() =>
        Assert.True(CciAssertions.Mode == CciAssertionMode.RecordAndContinue,
            $"CciAssertions.Mode is {CciAssertions.Mode}: is {CciAssertions.ModeVariable} set in this environment? These tests need the default mode.");

    [Fact]
    public void IsInstalled_OnceCciAssertionsIsTouched_IsTrue() => Assert.True(CciAssertions.IsInstalled);

    [Fact]
    public void Premise_MaxRecordsIs16() => Assert.Equal(16, CciAssertionScope.MaxRecords);

    // ---- record and continue -------------------------------------------------------------------------------------

    /// <summary>
    /// Each channel, failed once inside a scope: execution reaches the next statement, the scope holds exactly that one
    /// record with the channel's kind, and the process-wide total rose. <see cref="CciDebug"/> records its message and
    /// detail verbatim; a contract records the BCL's display message, which contains the user message.
    /// </summary>
    [Theory]
    [InlineData(Channel.DebugAssert, CciAssertionKind.DebugAssert)]
    [InlineData(Channel.DebugAssertWithDetail, CciAssertionKind.DebugAssert)]
    [InlineData(Channel.DebugFail, CciAssertionKind.DebugFail)]
    [InlineData(Channel.DebugFailWithDetail, CciAssertionKind.DebugFail)]
    [InlineData(Channel.ContractAssert, CciAssertionKind.ContractAssert)]
    [InlineData(Channel.ContractAssume, CciAssertionKind.ContractAssume)]
    public void AFailedAssertion_Continues_AndIsRecordedInTheScope_WithItsKindAndMessage(Channel channel, CciAssertionKind kind)
    {
        Assert.True(CciAssertions.IsInstalled);
        var token = Token();
        var before = CciAssertions.Total;
        var continued = false;

        using (var scope = CciAssertions.BeginScope())
        {
            Raise(channel, token);
            continued = true;

            var record = Assert.Single(scope.Records);
            Assert.Equal(1, scope.Count);
            Assert.Equal(kind, record.Kind);
            if (channel is Channel.ContractAssert or Channel.ContractAssume)
            {
                Assert.Contains(token, record.Message, StringComparison.Ordinal);
                Assert.Null(record.Condition);   // no contract rewriter: the BCL is given no condition text
            }
            else
            {
                Assert.Equal(token, record.Message);
                Assert.Equal(channel is Channel.DebugAssertWithDetail or Channel.DebugFailWithDetail ? Detail : null, record.Condition);
            }
        }

        Assert.True(continued);
        Assert.True(CciAssertions.Total >= before + 1, $"Total went from {before} to {CciAssertions.Total}.");
    }

    /// <summary>The message-less overload records an empty message, not null.</summary>
    [Fact]
    public void ADebugAssertWithoutAMessage_IsRecordedWithAnEmptyMessage()
    {
        using var scope = CciAssertions.BeginScope();

        CciDebug.Assert(false);

        var record = Assert.Single(scope.Records);
        Assert.Equal((CciAssertionKind.DebugAssert, string.Empty, (string?)null), (record.Kind, record.Message, record.Condition));
    }

    /// <summary>Twin: assertions that hold record nothing, on every channel.</summary>
    [Fact]
    public void AnAssertionThatHolds_RecordsNothing()
    {
        using var scope = CciAssertions.BeginScope();

        CciDebug.Assert(true);
        CciDebug.Assert(true, "holds");
        CciDebug.Assert(true, "holds", Detail);
        Contract.Assert(true, "holds");
        Contract.Assume(true, "holds");

        Assert.Equal(0, scope.Count);
        Assert.Empty(scope.Records);
    }

    /// <summary>No scope is needed for a failure to be survived: one raised with none open continues and is counted in Total.</summary>
    [Theory]
    [InlineData(Channel.DebugAssert)]
    [InlineData(Channel.ContractAssume)]
    public void AFailedAssertion_WithNoScopeOpen_Continues_AndRaisesTotal(Channel channel)
    {
        Assert.True(CciAssertions.IsInstalled);
        var before = CciAssertions.Total;

        Raise(channel, Token());

        Assert.True(CciAssertions.Total >= before + 1, $"Total went from {before} to {CciAssertions.Total}.");
    }

    // ---- nesting -------------------------------------------------------------------------------------------------

    /// <summary>
    /// Every open scope of the flow counts a failure, the innermost as much as the outermost; once a scope closes it
    /// counts no more, while the ones around it go on.
    /// </summary>
    [Fact]
    public void NestedScopes_AllCountAFailure_AndAClosedOneStopsCounting()
    {
        Assert.True(CciAssertions.IsInstalled);
        var (a, b, c) = (Token(), Token(), Token());
        using var outer = CciAssertions.BeginScope();
        using var middle = CciAssertions.BeginScope();
        var inner = CciAssertions.BeginScope();

        CciDebug.Assert(false, a);
        inner.Dispose();
        CciDebug.Fail(b);
        middle.Dispose();
        Contract.Assume(false, c);

        Assert.Equal((3, 2, 1), (outer.Count, middle.Count, inner.Count));
        Assert.Equal([a, b], outer.Records.Take(2).Select(r => r.Message));
        Assert.Contains(c, outer.Records[2].Message, StringComparison.Ordinal);
        Assert.Equal([a, b], middle.Records.Select(r => r.Message));
        Assert.Equal([a], inner.Records.Select(r => r.Message));
        // One failure, one record object, shared by every scope that saw it.
        Assert.Same(outer.Records[0], inner.Records[0]);
    }

    // ---- other flows ---------------------------------------------------------------------------------------------

    /// <summary>A scope opened on another thread does not see a failure raised on this flow, while this flow's own scope does.</summary>
    [Fact]
    public void AScopeOnAnotherThread_DoesNotSeeAFailureRaisedOnThisFlow()
    {
        using var opened = new ManualResetEventSlim();
        using var raised = new ManualResetEventSlim();
        var otherCount = -1;
        var other = new Thread(() =>
        {
            using var scope = CciAssertions.BeginScope();
            opened.Set();
            raised.Wait(Timeout);
            otherCount = scope.Count;
        });

        using var mine = CciAssertions.BeginScope();
        other.Start();
        Assert.True(opened.Wait(Timeout));
        CciDebug.Assert(false, Token());
        raised.Set();
        Assert.True(other.Join(Timeout));

        Assert.Equal(0, otherCount);
        Assert.Equal(1, mine.Count);
    }

    /// <summary>
    /// Vice versa: a failure raised on another thread is not seen by this flow's scope. The thread is started before the
    /// scope opens, as independent concurrent work is (another <see cref="AssemblyDisassembler.Create"/>), so it does not
    /// inherit the scope; it raises while the scope is open.
    /// </summary>
    [Fact]
    public void AFailureRaisedOnAnotherThread_IsNotSeenByThisFlowsScope()
    {
        Assert.True(CciAssertions.IsInstalled);
        using var go = new ManualResetEventSlim();
        var other = new Thread(() =>
        {
            go.Wait(Timeout);
            CciDebug.Assert(false, Token());
            Contract.Assume(false, Token());
        });
        other.Start();

        using var mine = CciAssertions.BeginScope();
        go.Set();
        Assert.True(other.Join(Timeout));

        Assert.Equal(0, mine.Count);
        Assert.Empty(mine.Records);
    }

    /// <summary>The same for a task: one that opens its own scope sees only its own failure, and this flow's scope not that one.</summary>
    [Fact]
    public async Task AScopeInAnotherTask_AndThisFlowsScope_EachSeeOnlyTheirOwnFailures()
    {
        var mineToken = Token();
        var theirsToken = Token();

        var theirs = Task.Run(async () =>
        {
            using var scope = CciAssertions.BeginScope();
            await Task.Yield();
            CciDebug.Assert(false, theirsToken);
            return scope.Records.Select(r => r.Message).ToArray();
        });
        // Opened after the task started (the task is not on this scope's flow), and checked before awaiting it.
        string[] seenHere;
        using (var mine = CciAssertions.BeginScope())
        {
            CciDebug.Assert(false, mineToken);
            seenHere = [.. mine.Records.Select(r => r.Message)];
        }

        Assert.Equal([theirsToken], await theirs);
        Assert.Equal([mineToken], seenHere);
    }

    /// <summary>
    /// Pinned semantics of the <see cref="AsyncLocal{T}"/> chain: work started from INSIDE an open scope (here a
    /// <see cref="Task.Run(Action)"/> on a pool thread) inherits it with the execution context, so its failures are on the
    /// scope's logical flow and count. A thread is not what isolates a scope; a flow is.
    /// </summary>
    [Fact]
    public async Task ATaskStartedInsideAnOpenScope_IsOnItsLogicalFlow_AndItsFailureCounts()
    {
        var token = Token();
        using var scope = CciAssertions.BeginScope();

        await Task.Run(() => CciDebug.Assert(false, token));

        Assert.Equal([token], scope.Records.Select(r => r.Message));
    }

    /// <summary>
    /// Exact under concurrency: four threads, each with its own scope, raise 50 failures each at the same time (a barrier
    /// lines them up); every scope counts exactly its own 50 and holds only its own records.
    /// </summary>
    [Fact]
    public void ConcurrentScopes_EachCountExactlyTheirOwnFailures()
    {
        const int Threads = 4;
        const int PerThread = 50;
        using var barrier = new Barrier(Threads);
        var results = new (int Count, string[] Messages)[Threads];
        var prefixes = Enumerable.Range(0, Threads).Select(_ => Token()).ToArray();

        var threads = Enumerable.Range(0, Threads).Select(t => new Thread(() =>
        {
            using var scope = CciAssertions.BeginScope();
            barrier.SignalAndWait(Timeout);
            for (var i = 0; i < PerThread; i++)
                CciDebug.Assert(false, $"{prefixes[t]}-{i}");
            results[t] = (scope.Count, [.. scope.Records.Select(r => r.Message)]);
        })).ToArray();
        foreach (var thread in threads)
            thread.Start();
        Assert.All(threads, t => Assert.True(t.Join(Timeout)));

        for (var t = 0; t < Threads; t++)
        {
            Assert.Equal(PerThread, results[t].Count);
            Assert.Equal(Enumerable.Range(0, CciAssertionScope.MaxRecords).Select(i => $"{prefixes[t]}-{i}"), results[t].Messages);
        }
    }

    // ---- records cap ---------------------------------------------------------------------------------------------

    /// <summary>20 failures: Count is the true 20, Records the first 16 in the order raised.</summary>
    [Fact]
    public void Records_CapAtMaxRecords_InOrder_WhileCountKeepsTheTrueNumber()
    {
        var tokens = Enumerable.Range(0, 20).Select(i => $"{Token()}-{i}").ToArray();
        using var scope = CciAssertions.BeginScope();

        foreach (var token in tokens)
            CciDebug.Assert(false, token);

        Assert.Equal(20, scope.Count);
        Assert.Equal(tokens.Take(CciAssertionScope.MaxRecords), scope.Records.Select(r => r.Message));
    }

    /// <summary>Records is a snapshot: a later failure does not change a list already read.</summary>
    [Fact]
    public void Records_IsASnapshot()
    {
        using var scope = CciAssertions.BeginScope();
        CciDebug.Assert(false, Token());
        var first = scope.Records;

        CciDebug.Assert(false, Token());

        Assert.Single(first);
        Assert.Equal(2, scope.Records.Count);
    }

    // ---- dispose -------------------------------------------------------------------------------------------------

    /// <summary>
    /// Disposing a scope twice is harmless: the second does not close the scope around it, which goes on counting, and
    /// once that one is disposed (twice, too) the flow has no scope left to count into.
    /// </summary>
    [Fact]
    public void DisposingTwice_IsHarmless_AndLeavesTheEnclosingScopeCurrent()
    {
        var outer = CciAssertions.BeginScope();
        var inner = CciAssertions.BeginScope();

        inner.Dispose();
        inner.Dispose();
        CciDebug.Assert(false, Token());
        outer.Dispose();
        outer.Dispose();
        CciDebug.Assert(false, Token());

        Assert.Equal((1, 0), (outer.Count, inner.Count));
        using var after = CciAssertions.BeginScope();
        CciDebug.Assert(false, Token());
        Assert.Equal((1, 1), (outer.Count, after.Count));
    }

    private static void Raise(Channel channel, string token)
    {
        switch (channel)
        {
            case Channel.DebugAssert: CciDebug.Assert(false, token); break;
            case Channel.DebugAssertWithDetail: CciDebug.Assert(false, token, Detail); break;
            case Channel.DebugFail: CciDebug.Fail(token); break;
            case Channel.DebugFailWithDetail: CciDebug.Fail(token, Detail); break;
            case Channel.ContractAssert: Contract.Assert(false, token); break;
            case Channel.ContractAssume: Contract.Assume(false, token); break;
            default: throw new ArgumentOutOfRangeException(nameof(channel));
        }
    }

    // A message no other test raises, so a record is attributable.
    internal static string Token() => $"silvergun-cci-test-{Guid.NewGuid():N}";
    #endregion

    #region Fields
    internal const string Detail = "synthetic detail";

#if DEBUG
    internal const bool DebugDefined = true;
#else
    internal const bool DebugDefined = false;
#endif

    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    #endregion

    #region Child types
    public enum Channel { DebugAssert, DebugAssertWithDetail, DebugFail, DebugFailWithDetail, ContractAssert, ContractAssume }
    #endregion
}

/// <summary>
/// <see cref="CciAssertions.Mode"/> is process-global, so a test that changes it would hand Throw-mode behaviour to any
/// test that happened to run concurrently (an <see cref="AssemblyDisassembler.Create"/> in another class would throw out of
/// CCI instead of continuing). <c>DisableParallelization</c> makes xUnit run this collection by itself, after every
/// parallel collection has finished, and each test restores the mode in <c>finally</c>.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CciAssertionModeCollection
{
    public const string Name = "CCI assertion mode (process-global, run alone)";
}

/// <summary>
/// Throw mode (ADR 0022 Stage 1, acceptance criterion 2: "throw mode throws, and the mode is restored"): a failed
/// <see cref="CciDebug"/> assertion throws <see cref="CciAssertionException"/> carrying its record; a failed contract is
/// unwound, so the BCL throws its internal <c>System.Diagnostics.Contracts.ContractException</c>. Either way the failure is
/// still recorded first. See <see cref="CciAssertionModeCollection"/> for why these run alone.
/// </summary>
[Collection(CciAssertionModeCollection.Name)]
public sealed class CciAssertionsThrowModeTests
{
    #region Methods
    [Fact]
    public void ThrowMode_AFailedCciDebugAssert_ThrowsCciAssertionException_CarryingItsRecord_AndIsStillRecorded()
    {
        var token = CciAssertionsTests.Token();
        using var scope = CciAssertions.BeginScope();

        var thrown = InThrowMode(() => CciDebug.Assert(false, token, CciAssertionsTests.Detail));

        var exception = Assert.IsType<CciAssertionException>(thrown);
        var record = Assert.Single(scope.Records);
        Assert.Same(record, exception.Record);
        Assert.Equal((CciAssertionKind.DebugAssert, token, CciAssertionsTests.Detail), (record.Kind, record.Message, record.Condition));
        Assert.Contains(token, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ThrowMode_ACciDebugFail_ThrowsCciAssertionException()
    {
        var token = CciAssertionsTests.Token();
        using var scope = CciAssertions.BeginScope();

        var exception = Assert.IsType<CciAssertionException>(InThrowMode(() => CciDebug.Fail(token)));

        Assert.Equal((CciAssertionKind.DebugFail, token), (exception.Record.Kind, exception.Record.Message));
        Assert.Equal(1, scope.Count);
    }

    /// <summary>
    /// A failed contract in Throw mode is unwound (<c>SetUnwind</c>), so the BCL throws its internal
    /// <c>ContractException</c> (not public, hence matched by name), carrying the user message. Recorded first.
    /// </summary>
    [Theory]
    [InlineData(CciAssertionsTests.Channel.ContractAssume, CciAssertionKind.ContractAssume)]
    [InlineData(CciAssertionsTests.Channel.ContractAssert, CciAssertionKind.ContractAssert)]
    public void ThrowMode_AFailedContract_ThrowsTheBclContractException_AndIsStillRecorded(CciAssertionsTests.Channel channel, CciAssertionKind kind)
    {
        Assert.True(CciAssertions.IsInstalled);
        var token = CciAssertionsTests.Token();
        using var scope = CciAssertions.BeginScope();

        var thrown = InThrowMode(() =>
        {
            if (channel == CciAssertionsTests.Channel.ContractAssume)
                Contract.Assume(false, token);
            else
                Contract.Assert(false, token);
        });

        Assert.NotNull(thrown);
        Assert.Equal("System.Diagnostics.Contracts.ContractException", thrown!.GetType().FullName);
        Assert.Contains(token, thrown.Message, StringComparison.Ordinal);
        Assert.Equal(kind, Assert.Single(scope.Records).Kind);
    }

    /// <summary>Twin: Throw mode throws only on failure; an assertion that holds is silent.</summary>
    [Fact]
    public void ThrowMode_AnAssertionThatHolds_DoesNotThrow()
    {
        using var scope = CciAssertions.BeginScope();

        var thrown = InThrowMode(() =>
        {
            CciDebug.Assert(true, "holds");
            Contract.Assume(true, "holds");
        });

        Assert.Null(thrown);
        Assert.Equal(0, scope.Count);
    }

    // Runs action in Throw mode and returns what it threw (null if nothing); the mode in force before is restored in
    // finally, and checked restored, whatever the action did.
    private static Exception? InThrowMode(Action action)
    {
        var previous = CciAssertions.Mode;
        Exception? thrown;
        try
        {
            CciAssertions.Mode = CciAssertionMode.Throw;
            thrown = Record.Exception(action);
        }
        finally
        {
            CciAssertions.Mode = previous;
        }
        Assert.Equal(previous, CciAssertions.Mode);
        return thrown;
    }
    #endregion
}
