namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Cilica.IR.Utils;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// The in-lift deadline (docs/agent/tasks/ssa-facts-s4.md, "An in-lift deadline"):
/// <see cref="SsaSession.Lift(Func{MethodIdentity, bool}, CancellationToken)"/> makes every method lifted once its token
/// is cancelled Unknown with <see cref="SsaFailureKind.TimedOut"/>, and <see cref="SsaSinkFacts.Extract"/> turns such an
/// outcome into its time-budget cut, so the kind never reaches a fact. Nothing runs on the lift's thread inside the adapter
/// or Cilica's import for a test to cancel from, so the deterministic tests cancel before a lift starts (before the call,
/// between two outcomes, or by the folder's clock between sites), and one test races a real cancel against a real lift to
/// reach a cancel after adaptation began (review round 1, W1: the session is then spent). Cilica's own suite covers the
/// per-instruction check (ILImporterCancellationTests).
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaLiftDeadlineTests : IClassFixture<SsaSinkFactsFixture>
{
    #region Constructors
    public SsaLiftDeadlineTests(SsaSinkFactsFixture fixture, Xunit.Abstractions.ITestOutputHelper output) => (this.fixture, this.output) = (fixture, output);
    #endregion

    #region Methods
    // ---- SsaSession.Lift(select, cancellation) --------------------------------------------------------------------------

    [Fact]
    public void Lift_CancelledToken_EverySelectedMethodTimedOut_NothingThrows()
    {
        using var session = SsaSession.Open([fixture.SitesPath]);
        var expected = session.Lift(_ => true).Select(o => o.NodeId).ToArray();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        var outcomes = session.Lift(_ => true, cancelled.Token).ToArray();

        Assert.True(expected.Length > 10, $"Only {expected.Length} methods: the folder is too small to say much.");
        Assert.Equal(expected, outcomes.Select(o => o.NodeId));
        Assert.All(outcomes, o => AssertTimedOut(o, SsaFailureKind.Adapter));
    }

    [Fact]
    public void Lift_UncancelledToken_SameOutcomesAsWithout()
    {
        using var plain = SsaSession.Open([fixture.SitesPath]);
        using var byDefault = SsaSession.Open([fixture.SitesPath]);
        using var live = SsaSession.Open([fixture.SitesPath]);
        using var source = new CancellationTokenSource();

        var expected = plain.Lift(_ => true).Select(Summary).ToArray();
        var withDefault = byDefault.Lift(_ => true, default).Select(Summary).ToArray();
        var withLive = live.Lift(_ => true, source.Token).Select(Summary).ToArray();

        Assert.Contains(expected, s => s.Contains("| Lifted |", StringComparison.Ordinal));
        Assert.Contains(expected, s => !s.Contains("| Lifted |", StringComparison.Ordinal));
        Assert.Equal(expected, withDefault);
        Assert.Equal(expected, withLive);
        Assert.False(source.IsCancellationRequested);
    }

    // The token is read as each lift starts, not once per call: cancelled after the first outcome, the first stands as it
    // lifted and every later method is TimedOut, none dropped.
    [Fact]
    public void Lift_CancelledBetweenOutcomes_LaterMethodsTimedOut_EarlierAsLifted()
    {
        using var reference = SsaSession.Open([fixture.SitesPath]);
        using var session = SsaSession.Open([fixture.SitesPath]);
        var expected = reference.Lift(_ => true).ToArray();
        using var cancellation = new CancellationTokenSource();

        var outcomes = new List<SsaMethodOutcome>();
        foreach (var outcome in session.Lift(_ => true, cancellation.Token))
        {
            outcomes.Add(outcome);
            if (outcomes.Count == 1)
                cancellation.Cancel();
        }

        Assert.Equal(expected.Select(o => o.NodeId), outcomes.Select(o => o.NodeId));
        Assert.Equal(Summary(expected[0]), Summary(outcomes[0]));
        Assert.All(outcomes.Skip(1), o => AssertTimedOut(o, SsaFailureKind.Adapter));
    }

    // The universe's token is reset after each lift: once a cancelled lift is done, the same session lifts and extracts as
    // a fresh one does (the type-mapping check would otherwise fail every later lift).
    [Fact]
    public void Lift_AfterACancelledLift_TheSessionLiftsNormally()
    {
        using var reference = SsaSession.Open([fixture.SitesPath]);
        using var session = SsaSession.Open([fixture.SitesPath]);
        var expected = reference.Lift(_ => true).Select(Summary).ToArray();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.All(session.Lift(_ => true, cancelled.Token).ToArray(), o => AssertTimedOut(o, SsaFailureKind.Adapter));

        var again = session.Lift(_ => true).Select(Summary).ToArray();
        var all = session.Lift().Select(o => new SsaSinkFactsFixture.LiftSummary(o.NodeId, o.Method.MethodName, o.Failure)).ToArray();
        var facts = SsaSinkFacts.Extract(session, fixture.Sites);

        Assert.Equal(expected, again);
        Assert.Equal(fixture.Outcomes, all);
        Assert.Equal(Json(fixture.Facts), Json(facts));
    }

    // ---- SsaSinkFacts.Extract -----------------------------------------------------------------------------------------

    // The in-lift deadline is the folder's budget, on the folder's clock: one timer, due at FolderTime, not periodic.
    // Here it has passed before the first lift: every node is cut, as the between-node check would cut it, and the
    // TimedOut outcome is not counted as a method or a failure.
    [Fact]
    public void Extract_DeadlinePassedBeforeTheFirstLift_EverySiteNotRun_TimeBudget()
    {
        var clock = new DeadlineClock(fireAtRead: 0);

        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { FolderTime = TimeSpan.FromSeconds(1) }, clock);

        Assert.Equal((1, TimeSpan.FromSeconds(1), Timeout.InfiniteTimeSpan), (clock.Timers, clock.Due, clock.Period));
        Assert.True(clock.Fired);
        Assert.Equal((false, true, 0), (facts.MethodBudget, facts.TimeBudget, facts.MethodsLifted));
        Assert.Empty(facts.Unknown);
        Assert.Equal(fixture.Sites, facts.Sites.Select(f => f.Site));
        Assert.All(facts.Sites, f => AssertWithout(f, SsaSiteStatus.NotRun, TimeBudgetReason));
    }

    // The deadline fires while ReadsConstant's one site is read (clock reads: the start, the time left, its node, its
    // site), so TwoSites' lift starts cancelled: TwoSites is cut, both its sites NotRun (time), and ReadsConstant reads as
    // it does unbounded. The between-node and between-site checks never cut on this clock (it never moves), so only the
    // TimedOut lift can.
    [Fact]
    public void Extract_DeadlineDuringAnEarlierNode_TheNextLiftTimedOut_CutThere()
    {
        var clock = new DeadlineClock(fireAtRead: 3);

        var facts = SsaSinkFacts.Extract(fixture.Session, MidNodeSites(), new SsaFactBounds { FolderTime = TimeSpan.FromSeconds(1) }, clock);

        Assert.True(clock.Fired);
        Assert.Equal((false, true, 1), (facts.MethodBudget, facts.TimeBudget, facts.MethodsLifted));
        Assert.Empty(facts.Unknown);
        var reads = Assert.Single(facts.Sites, f => f.Site.NodeId == fixture.NodeIdOf("ReadsConstant"));
        Assert.Equal(SsaSiteStatus.Analyzed, reads.Status);
        Assert.Equal(Json(Assert.Single(fixture.Facts.Sites, f => f.Site == reads.Site)), Json(reads));
        var two = facts.Sites.Where(f => f.Site.NodeId == fixture.NodeIdOf("TwoSites")).ToArray();
        Assert.Equal(2, two.Length);
        Assert.All(two, f => AssertWithout(f, SsaSiteStatus.NotRun, TimeBudgetReason));
    }

    // A node's definitions are read all together or not at all: the deadline fires after Mixed's first definition was
    // lifted (at Mixed's node check, read 2 after the start and the time left), so its second definition is TimedOut and
    // Mixed is dropped whole, with every node after it.
    [Fact]
    public void Extract_DeadlineBetweenTwoDefinitionsOfANode_TheNodeIsDroppedWhole()
    {
        var mixed = fixture.MergeNodeIdOf("Mixed");
        Assert.Equal(mixed, fixture.MergeSites[0].NodeId);
        Assert.Equal(2, fixture.MergeSession.Lift(m => CanonicalName.NodeId(m) == mixed).Count());
        var clock = new DeadlineClock(fireAtRead: 2);

        var facts = SsaSinkFacts.Extract(fixture.MergeSession, fixture.MergeSites, new SsaFactBounds { FolderTime = TimeSpan.FromSeconds(1) }, clock);

        Assert.True(clock.Fired);
        Assert.Equal((false, true), (facts.MethodBudget, facts.TimeBudget));
        // The first definition was tried (lifted or failed) before the cut; the second, TimedOut, is not counted.
        Assert.Equal(1, facts.MethodsLifted + facts.Unknown.Sum(u => u.Methods));
        Assert.DoesNotContain(facts.Unknown, u => u.Kind == SsaFailureKind.TimedOut);
        Assert.Contains(facts.Sites, f => f.Site.NodeId != mixed);
        Assert.All(facts.Sites, f => AssertWithout(f, SsaSiteStatus.NotRun, TimeBudgetReason));
    }

    // Twin: a deadline that never fires never cuts, even at a FolderTime of one tick, and the facts are the unbounded ones.
    [Fact]
    public void Extract_DeadlineNeverFires_NoTimeBudget_SameFacts()
    {
        var clock = new DeadlineClock(fireAtRead: int.MaxValue);

        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { FolderTime = TimeSpan.FromTicks(1) }, clock);

        Assert.Equal((1, false), (clock.Timers, clock.Fired));
        Assert.False(facts.TimeBudget);
        Assert.Equal(Json(fixture.Facts), Json(facts));
    }

    // A long FolderTime is a valid bound (Validated only asks it be positive; the worker protocol caps it at 365 days), so
    // the deadline built from it must not throw: Extract is documented as "Nothing about the input throws". 49 days is
    // under a timer's longest due time (uint.MaxValue - 1 ms, about 49.7 days); 60 and 365 are over it.
    [Theory]
    [InlineData(49)]
    [InlineData(60)]
    [InlineData(365)]
    public void Extract_FolderTimeOfManyDays_DoesNotThrow_SameFacts(int days)
    {
        var bounds = new SsaFactBounds { FolderTime = TimeSpan.FromDays(days) };

        var thrown = Record.Exception(() => SsaSinkFacts.Extract(fixture.Session, fixture.Sites, bounds));

        Assert.True(thrown is null, $"Extract threw {thrown?.GetType().Name}: {thrown?.Message}");
        Assert.Equal(Json(fixture.Facts), Json(SsaSinkFacts.Extract(fixture.Session, fixture.Sites, bounds)));
    }

    // Past a timer's longest due time there is no timer at all: only the checks between nodes and sites apply.
    [Fact]
    public void Extract_FolderTimePastTheTimerLimit_NoTimer_SameFacts()
    {
        var clock = new DeadlineClock(fireAtRead: int.MaxValue);

        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { FolderTime = TimeSpan.FromDays(60) }, clock);

        Assert.Equal(0, clock.Timers);
        Assert.Equal(Json(fixture.Facts), Json(facts));
    }

    // Review round 1: the deadline is the folder's time left when the lifts start (FolderTime less the elapsed time, read
    // once after the start), at least a tick. 400 ms gone of 1 s leaves 600 ms; all of it or more gone leaves one tick,
    // and the between-node check then cuts the folder before its first node.
    [Theory]
    [InlineData(400, 600 * TimeSpan.TicksPerMillisecond, false)]
    [InlineData(1000, 1L, true)]
    [InlineData(5000, 1L, true)]
    public void Extract_TheDeadlineIsTheFolderTimeLeft(int elapsedMs, long dueTicks, bool cut)
    {
        var clock = new SteppedClock(TimeSpan.Zero, TimeSpan.FromMilliseconds(elapsedMs));

        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { FolderTime = TimeSpan.FromSeconds(1) }, clock);

        Assert.Equal((1, TimeSpan.FromTicks(dueTicks)), (clock.Timers, clock.Due));
        Assert.Equal(cut, facts.TimeBudget);
        if (cut)
            Assert.All(facts.Sites, f => AssertWithout(f, SsaSiteStatus.NotRun, TimeBudgetReason));
        else
            Assert.Equal(Json(fixture.Facts), Json(facts));
    }

    // ---- A spent session (review round 1, W1) ---------------------------------------------------------------------------

    // Once spent, every later lift is TimedOut with the "earlier lift" reason, whatever its token, and Extract over the
    // session cuts the folder at its first node. Nothing outside the session can land a cancel after adaptation began
    // deterministically (no hook runs on the lift's thread there), so this sets the session's private flag by reflection;
    // Lift_CancelledWhileLifting_NoLaterOutcomeDiffersFromAFreshSession reaches it for real.
    [Fact]
    public void Lift_SpentSession_EveryLaterLiftTimedOutAsEarlierCut_WhateverItsToken()
    {
        using var session = SsaSession.Open([fixture.SitesPath]);
        Assert.DoesNotContain(fixture.Outcomes, o => o.Failure is { Kind: SsaFailureKind.Unreadable or SsaFailureKind.ReaderAssertion });
        var spent = typeof(SsaSession).GetField("spent", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.True(spent is { FieldType.Name: nameof(Boolean) }, "SsaSession has no private bool 'spent' field.");
        spent!.SetValue(session, true);
        using var live = new CancellationTokenSource();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        var plain = session.Lift().ToArray();
        var selected = session.Lift(_ => true).ToArray();
        var withLive = session.Lift(_ => true, live.Token).ToArray();
        var withCancelled = session.Lift(_ => true, cancelled.Token).ToArray();
        var facts = SsaSinkFacts.Extract(session, fixture.Sites);

        Assert.Equal(fixture.Outcomes.Count, plain.Length);
        Assert.All(new[] { plain, selected, withLive, withCancelled }, run =>
        {
            Assert.Equal(fixture.Outcomes.Count, run.Length);
            Assert.All(run, AssertSpent);
        });
        Assert.Equal((false, true, 0), (facts.MethodBudget, facts.TimeBudget, facts.MethodsLifted));
        Assert.Empty(facts.Unknown);
        Assert.All(facts.Sites, f => AssertWithout(f, SsaSiteStatus.NotRun, TimeBudgetReason));
    }

    // Review round 1, W1, after the reviewer's probe: a cancel that lands while a lift runs, at points staggered over a real
    // lift of the compiled fixture. A cancel after adaptation began spends the session (every later lift is TimedOut,
    // "earlier lift"); a cancel at the top check does not (the session lifts as a fresh one does). Either way no outcome,
    // before the cut or after it, is ever a different success or failure than a fresh session gives: the poisoning
    // property. Which way each trial goes depends on timing; the property holds on every path, so the test does not.
    [Fact]
    public void Lift_CancelledWhileLifting_NoLaterOutcomeDiffersFromAFreshSession()
    {
        var path = SsaBodyFixture.CompiledFixturePath;
        Dictionary<string, string> reference;
        TimeSpan full;
        using (var warm = SsaSession.Open([path]))
            _ = warm.Lift().Count();
        using (var fresh = SsaSession.Open([path]))
        {
            var timer = System.Diagnostics.Stopwatch.StartNew();
            var outcomes = fresh.Lift().ToArray();
            full = timer.Elapsed;
            reference = outcomes.ToDictionary(Key, Value, StringComparer.Ordinal);
        }
        Assert.True(reference.Count > 20, $"Only {reference.Count} methods: the fixture is too small to race.");
        Func<MethodIdentity, bool> half = id => CanonicalName.NodeId(id).Length % 2 == 0;
        var (spentTrials, topChecks, uncut) = (0, 0, 0);
        var budget = System.Diagnostics.Stopwatch.StartNew();

        for (var trial = 0; trial < RaceTrials && budget.Elapsed < RaceBudget; trial++)
        {
            using var session = SsaSession.Open([path]);
            using var cancellation = new CancellationTokenSource();
            var delay = TimeSpan.FromTicks(full.Ticks * (trial + 1) / (RaceTrials + 1));
            string? cut = null;
            using (var canceller = Canceller(cancellation, delay))
            {
                foreach (var outcome in session.Lift(_ => true, cancellation.Token))
                {
                    if (outcome.Failure is { Kind: SsaFailureKind.TimedOut } failure)
                    {
                        cut = failure.Reason;
                        break;
                    }
                    Assert.True(reference[Key(outcome)] == Value(outcome), $"trial {trial}: before the cut, {SsaText.Of(outcome)} differs from a fresh session's.");
                }
            }

            var later = session.Lift().ToArray();
            var laterSelected = session.Lift(half).ToArray();
            var isSpent = later.Any(o => o.Failure?.Reason == EarlierCut);
            if (cut is not null && !cut.EndsWith("(Adapter)", StringComparison.Ordinal))
                Assert.True(isSpent, $"trial {trial}: cut at '{cut}', after adaptation began, but the session is not spent.");
            Assert.True(cut is not null || !isSpent, $"trial {trial}: no lift was cut, but the session is spent.");
            foreach (var run in new[] { later, laterSelected })
            {
                foreach (var outcome in run)
                {
                    var expected = reference[Key(outcome)];
                    if (isSpent && !IsDecidedBeforeLifting(expected))
                        AssertSpent(outcome);
                    else
                        Assert.True(expected == Value(outcome), $"trial {trial} (cut at '{cut}', spent {isSpent}): {SsaText.Of(outcome)} differs from a fresh session's.");
                }
            }
            Assert.Equal(reference.Count, later.Length);
            (spentTrials, topChecks, uncut) = isSpent ? (spentTrials + 1, topChecks, uncut) : cut is null ? (spentTrials, topChecks, uncut + 1) : (spentTrials, topChecks + 1, uncut);
        }
        output.WriteLine($"full lift {full.TotalMilliseconds:F1} ms over {reference.Count} methods; trials: {spentTrials} spent, {topChecks} cut at the top check, {uncut} not cut; {budget.Elapsed.TotalSeconds:F1} s");    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    // ReadsConstant's one site, then TwoSites' two: two nodes, one definition each.
    private SinkSite[] MidNodeSites()
    {
        var two = fixture.Sites.Where(s => s.NodeId == fixture.NodeIdOf("TwoSites")).ToArray();
        Assert.Equal(2, two.Length);
        Assert.True(string.CompareOrdinal(fixture.NodeIdOf("ReadsConstant"), fixture.NodeIdOf("TwoSites")) < 0);
        return [fixture.SiteOf("ReadsConstant"), .. two];
    }

    private static void AssertSpent(SsaMethodOutcome outcome)
    {
        Assert.True(outcome.Failure is { Kind: SsaFailureKind.TimedOut }, SsaText.Of(outcome));
        Assert.Equal(EarlierCut, outcome.Failure!.Reason);
        Assert.Null(outcome.Body);
    }

    // A thread that cancels at `delay` after it starts, spinning for precision (a timer's resolution is about 15 ms).
    private static Disposable Canceller(CancellationTokenSource cancellation, TimeSpan delay)
    {
        var stop = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            while (clock.Elapsed < delay)
            {
                if (stop.IsSet)
                    return;
                Thread.SpinWait(64);
            }
            cancellation.Cancel();
        }) { IsBackground = true };
        thread.Start();
        return new Disposable(() =>
        {
            stop.Set();
            thread.Join();
            stop.Dispose();
        });
    }

    // Kinds decided before a lift starts (the body unreadable, CCI's table assertions, an untrusted core) are given even
    // in a spent session.
    private static bool IsDecidedBeforeLifting(string value) =>
        value.StartsWith($"{SsaFailureKind.Unreadable}: ", StringComparison.Ordinal)
        || value.StartsWith($"{SsaFailureKind.ReaderAssertion}: CCI failed", StringComparison.Ordinal) && value.EndsWith("reading the assembly's type table", StringComparison.Ordinal)
        || value.StartsWith($"{SsaFailureKind.Adapter}: Its primitive types cannot be trusted", StringComparison.Ordinal);

    private static string Key(SsaMethodOutcome outcome) => $"{outcome.AssemblyPath}|{outcome.MethodToken:X8}|{outcome.NodeId}";

    // How it failed, or its printed body: what a poisoned memo would change.
    private static string Value(SsaMethodOutcome outcome)
    {
        if (outcome.Failure is { } failure)
            return $"{failure.Kind}: {failure.Reason}";
        var writer = new StringWriter();
        IRPrinter.ExportPlain(outcome.Body!, writer);
        return "Lifted\n" + writer;
    }

    private static void AssertTimedOut(SsaMethodOutcome outcome, SsaFailureKind stage)
    {
        Assert.True(outcome.Failure is { Kind: SsaFailureKind.TimedOut }, SsaText.Of(outcome));
        Assert.Equal($"The lift's deadline passed while it ran ({stage})", outcome.Failure!.Reason);
        Assert.Null(outcome.Body);
    }

    private static void AssertWithout(SsaSinkFact fact, SsaSiteStatus status, string reason)
    {
        Assert.True(fact.Status == status, $"{SsaText.Printable(Json(fact))}: expected {status}.");
        Assert.Equal(reason, fact.Reason);
        Assert.Null(fact.Receiver);
        Assert.Empty(fact.Arguments);
        Assert.Equal((0, false), (fact.ArgumentCount, fact.Merged));
        Assert.Null(fact.FailureKind);
    }

    // An outcome whole: where it came from, how it failed, and its printed body with each instruction's IL offset.
    private static string Summary(SsaMethodOutcome outcome)
    {
        var writer = new StringWriter();
        writer.WriteLine($"{outcome.NodeId} | {outcome.AssemblyPath} | {outcome.MethodToken:X8} | {outcome.Failure?.Kind.ToString() ?? "Lifted"} | {outcome.Failure?.Reason}");
        if (outcome.Body is { } body)
        {
            IRPrinter.ExportPlain(body, writer);
            writer.WriteLine(string.Join(",", body.Instructions().Select(i => outcome.OffsetOf(i)?.ToString() ?? "-")));
        }
        return writer.ToString();
    }

    private static string Json(object? value) => JsonSerializer.Serialize(value);
    #endregion

    #region Fields
    private const string TimeBudgetReason = "the folder's SSA time budget was spent before its method";

    private const string EarlierCut = "An earlier lift in this session was cut by its deadline while adapting, so what the session read may be partial";

    // The race's trials, staggered over one full lift, and its wall-clock bound (the reviewer's probe found 4 poisoned
    // sessions in 30 random trials before the fix).
    private const int RaceTrials = 16;

    private static readonly TimeSpan RaceBudget = TimeSpan.FromSeconds(5);

    private readonly SsaSinkFactsFixture fixture;

    private readonly Xunit.Abstractions.ITestOutputHelper output;
    #endregion

    #region Child types
    // A clock whose timestamp never moves, so Extract's own between-node and between-site checks never cut; its one timer
    // (the in-lift deadline) fires on the read numbered fireAtRead (the first read is 0), or as soon as it is created when
    // that read has already happened. It fires on the reading thread, so the cut is deterministic.
    private sealed class DeadlineClock(int fireAtRead) : TimeProvider
    {
        public int Reads { get; private set; }

        public int Timers { get; private set; }

        public TimeSpan? Due { get; private set; }

        public TimeSpan? Period { get; private set; }

        public bool Fired => timer?.Fired ?? false;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp()
        {
            if (Reads++ == fireAtRead)
                timer?.Fire();
            return 0;
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            Timers++;
            (Due, Period) = (dueTime, period);
            timer = new ScriptedTimer(callback, state);
            if (Reads > fireAtRead)
                timer.Fire();
            return timer;
        }

        private ScriptedTimer? timer;
    }

    // A clock that reads each of `reads` in turn, then the last for ever. Its timers never fire: it records the deadline's
    // due time only.
    private sealed class SteppedClock(params TimeSpan[] reads) : TimeProvider
    {
        public int Timers { get; private set; }

        public TimeSpan? Due { get; private set; }

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => reads[Math.Min(next++, reads.Length - 1)].Ticks;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            Timers++;
            Due = dueTime;
            return new ScriptedTimer(callback, state);
        }

        private int next;
    }

    private sealed class Disposable(Action dispose) : IDisposable
    {
        public void Dispose() => dispose();
    }

    private sealed class ScriptedTimer(TimerCallback callback, object? state) : ITimer
    {
        public bool Fired { get; private set; }

        public void Fire()
        {
            if (Fired || disposed)
                return;
            Fired = true;
            callback(state);
        }

        public bool Change(TimeSpan dueTime, TimeSpan period) => !disposed;

        public void Dispose() => disposed = true;

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        private bool disposed;
    }
    #endregion
}
