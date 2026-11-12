namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Diagnostics;
using System.Linq;

using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// <c>CilicaAssertions</c>' throwing listener is process-wide (<see cref="Trace.Listeners"/>), so these tests run alone:
/// <c>DisableParallelization</c> makes xUnit run the collection by itself after every parallel collection, when every SSA
/// test class has disposed its sessions.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CilicaAssertionsCollection
{
    public const string Name = "Cilica assertion listener (process-global, run alone)";
}

/// <summary>
/// The listener is leased (<c>ssa-facts-s4.md</c> §4, S4.4 review): each open <see cref="SsaSession"/> holds a lease from
/// <see cref="SsaSession.Open"/> to <see cref="SsaSession.Dispose"/>, so a failed <c>Trace.Fail</c>/<c>Debug.Assert</c> throws
/// <see cref="CilicaAssertionException"/> only while a session is open, and code after SSA (a later graph build in the same
/// worker) fails fast as it would without SSA. <c>Trace.Fail</c> is only ever called here while the listener is asserted to be
/// first: without it, it would FailFast this test host.
/// </summary>
[Collection(CilicaAssertionsCollection.Name)]
public sealed class CilicaAssertionsTests
{
    #region Constructors
    public CilicaAssertionsTests() =>
        Assert.True(Ours() == 0, "a CilicaAssertions listener is installed before the test: some test left an SsaSession (or a lease) open");
    #endregion

    #region Methods
    [Fact]
    public void WhileASessionIsOpen_TheListenerIsFirst_AndTraceFailThrows()
    {
        using var session = SsaSession.Open([]);

        Assert.True(IsOurs(Trace.Listeners[0]), $"the first listener is {Trace.Listeners[0].GetType().FullName}");
        Assert.Equal(1, Ours());
        var thrown = Assert.Throws<CilicaAssertionException>(() => Trace.Fail("cilica-assertions-test", "detail"));
        Assert.Equal("Assertion failed: cilica-assertions-test: detail", thrown.Message);
    }

    [Fact]
    public void AfterTheSessionIsDisposed_TheListenerIsGone()
    {
        var before = Trace.Listeners.Count;
        var session = SsaSession.Open([]);
        Assert.Equal(before + 1, Trace.Listeners.Count);

        session.Dispose();

        Assert.Equal(0, Ours());
        Assert.Equal(before, Trace.Listeners.Count);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TwoOverlappingSessions_KeepOneListener_UntilBothAreDisposed(bool firstOpenedFirstClosed)
    {
        var first = SsaSession.Open([]);
        var second = SsaSession.Open([]);
        try
        {
            Assert.Equal(1, Ours());
            Assert.True(IsOurs(Trace.Listeners[0]));

            (firstOpenedFirstClosed ? first : second).Dispose();

            Assert.Equal(1, Ours());
            Assert.True(IsOurs(Trace.Listeners[0]));
            Assert.Throws<CilicaAssertionException>(() => Trace.Fail("still leased"));
        }
        finally
        {
            first.Dispose();
            second.Dispose();
        }

        Assert.Equal(0, Ours());
    }

    /// <summary>Disposing a session twice releases its lease once: another session's lease still holds the listener.</summary>
    [Fact]
    public void DisposingASessionTwice_ReleasesItsLeaseOnce()
    {
        using var other = SsaSession.Open([]);
        var twice = SsaSession.Open([]);

        twice.Dispose();
        twice.Dispose();

        Assert.Equal(1, Ours());
        Assert.Throws<CilicaAssertionException>(() => Trace.Fail("other still leased"));
        other.Dispose();
        Assert.Equal(0, Ours());
    }

    /// <summary>The leases themselves: one listener however many are held, a double dispose releases once.</summary>
    [Fact]
    public void Leases_InstallOneListener_AndADoubleDisposeReleasesOnce()
    {
        var a = CilicaAssertions.Acquire();
        var b = CilicaAssertions.Acquire();
        try
        {
            Assert.Equal(1, Ours());

            a.Dispose();
            a.Dispose();

            Assert.Equal(1, Ours());
        }
        finally
        {
            a.Dispose();
            b.Dispose();
        }

        Assert.Equal(0, Ours());
        using (CilicaAssertions.Acquire())
            Assert.Equal(1, Ours());   // and it can be leased again
        Assert.Equal(0, Ours());
    }

    /// <summary>An <see cref="SsaSession.Open"/> that throws (bounds that are not positive) releases the lease it took.</summary>
    [Fact]
    public void AnOpenThatThrows_ReleasesItsLease()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SsaSession.Open([], SsaBounds.Default with { MaxDepth = 0 }));

        Assert.Equal(0, Ours());
    }

    private static bool IsOurs(TraceListener listener) => listener.GetType().DeclaringType == typeof(CilicaAssertions);

    private static int Ours() => Trace.Listeners.Cast<TraceListener>().Count(IsOurs);
    #endregion
}
