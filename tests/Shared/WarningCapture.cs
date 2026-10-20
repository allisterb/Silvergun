namespace Silvergun.Tests.Shared;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

using Microsoft.Extensions.Logging;

/// <summary>
/// Captures the warnings logged through the shared <c>Runtime</c> logger by the code a test runs <b>on its own async
/// flow</b>, for as long as the capture is alive (<c>using var warnings = new WarningCapture();</c>). The one way a test
/// in this repository observes <c>Runtime.Warn</c>.
///
/// <para><b>Why not a plain swap of <c>Runtime.logger</c>.</b> That field is process-global and xunit runs test
/// collections in parallel, so a swapped-in logger also collects every other running test's warnings, and two
/// overlapping swap-and-restore pairs restore each other's logger (one capture goes deaf mid-test, the other is left
/// installed for good). Some tests assert an exact COUNT of a warning ("logged once"), or that one was NOT logged, and
/// both need a capture that sees exactly this test's warnings. So a forwarding logger is installed once and left in
/// place — it passes everything on to whatever logger was there — and records a warning only into the capture
/// registered on the current async flow (an <see cref="AsyncLocal{T}"/>, which also flows into <c>Task.Run</c>,
/// <c>new Thread</c> and <c>Parallel</c> work started from that flow). The code under test logs on the calling flow.</para>
///
/// <para><b>Nothing else may write <c>Runtime.logger</c> while a capture is alive.</b> A displaced forwarder makes the
/// capture silently stop collecting: a flaky red for an <c>Assert.Single</c>, and a VACUOUS PASS for an
/// <c>Assert.Empty</c>. The writers, and how each is closed:</para>
/// <list type="number">
/// <item><b>The first-ever <c>Runtime.Initialize</c></b> replaces the logger, once per process — and many fixtures call
/// it, from parallel collections. The constructor makes that call itself, BEFORE installing the forwarder, so by the
/// time any capture exists the process is initialised and every later <c>Initialize</c> is a no-op (it tests
/// <c>RuntimeInitialized</c> under its own lock).</item>
/// <item><b>A test swapping the field itself.</b> None does: every test that observes warnings uses this class
/// (<c>UninventoriedEntryTests</c>, <c>StringConstantsSharedSeamTests</c> and
/// <c>IndicatorAnalysisTruncationTests</c> used to swap). Keep it that way.</item>
/// <item><b>Anything else that displaces it anyway</b> is caught at the read: <see cref="Warnings"/> throws when the
/// forwarder is no longer installed, rather than returning a list that is empty because nobody was listening.</item>
/// </list>
/// <para><c>WarningCaptureTests</c> (in the NuGet suite) pins all three.</para>
///
/// <para>Shared by <c>Silvergun.PackageAnalysis.NuGet.Tests</c> and <c>Silvergun.CodeAnalysis.IL.Tests</c> via a
/// linked <c>&lt;Compile&gt;</c> item, like <c>FatHeaderPatcher</c>; each test process installs its own forwarder.</para>
/// </summary>
internal sealed class WarningCapture : IDisposable
{
    #region Constructors
    public WarningCapture()
    {
        // Writer 1 above: settle the one-time logger replacement now, so it cannot happen under a live forwarder.
        // Idempotent and locked; these are the arguments every fixture in both suites passes.
        Silvergun.Runtime.Initialize("Silvergun", "TESTS");

        lock (gate)
        {
            if (Silvergun.Runtime.logger is not Forwarder)
                Silvergun.Runtime.logger = new Forwarder(Silvergun.Runtime.logger);
        }

        _previous = current.Value;
        current.Value = this;
    }
    #endregion

    #region Properties
    /// <summary>Every warning captured so far, formatted, in order. Throws if the forwarder was displaced (see
    /// writer 3 in the class remarks), because then an empty list would mean "not listening", not "not logged".</summary>
    public IReadOnlyList<string> Warnings =>
        Silvergun.Runtime.logger is Forwarder
            ? _messages.ToArray()
            : throw new InvalidOperationException(
                "Runtime.logger was replaced while a WarningCapture was alive, so this capture stopped collecting: "
                + "something other than WarningCapture wrote that field. Route the test through WarningCapture.");
    #endregion

    #region Methods
    public void Dispose() => current.Value = _previous;
    #endregion

    #region Fields
    private static readonly object gate = new();
    private static readonly AsyncLocal<WarningCapture?> current = new();

    private readonly ConcurrentQueue<string> _messages = new();
    private readonly WarningCapture? _previous;
    #endregion

    #region Nested types
    private sealed class Forwarder(ILogger inner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => inner.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => logLevel == LogLevel.Warning || inner.IsEnabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
                current.Value?._messages.Enqueue(formatter(state, exception));
            inner.Log(logLevel, eventId, state, exception, formatter);
        }
    }
    #endregion
}
