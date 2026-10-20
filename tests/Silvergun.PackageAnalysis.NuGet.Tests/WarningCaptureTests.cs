namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging.Abstractions;

using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// The shared <see cref="WarningCapture"/> keeps collecting while every other writer of the process-global
/// <c>Runtime.logger</c> does its worst (task F-test, W1). The YARA tests built on it assert exact counts
/// (<c>Assert.Single</c>) and absences (<c>Assert.Empty</c>); a capture that silently stopped listening would make the
/// first flaky and the second vacuous.
///
/// <para>Each competing writer is triggered for real, while a capture is alive, and the capture is shown still to
/// receive its warning: (1) the first-ever <c>Runtime.Initialize</c>, simulated by putting the runtime back into its
/// never-initialised state; (2) another test's capture opening and closing concurrently, the job a plain
/// swap-and-restore used to do in <c>UninventoriedEntryTests</c>; (3) a writer that displaces the forwarder anyway,
/// which must make the capture fail loudly rather than read empty.</para>
///
/// <para>These tests rewrite process-global logger state, so they run in a collection with parallelization disabled:
/// xunit runs such collections after all parallel collections have finished, alone.</para>
/// </summary>
[Collection(RuntimeLoggerStateCollection.Name)]
public sealed class WarningCaptureTests
{
    #region Methods
    // Writer 1. A fresh process has RuntimeInitialized == false, and the first Initialize call — made by any fixture, in
    // any collection, at any moment — replaces Runtime.logger. If that happened after a capture had installed its
    // forwarder, the forwarder was gone for good and the capture heard nothing. The capture now settles the one-time
    // replacement itself before installing, so an Initialize while it is alive is a no-op.
    [Fact]
    public void Capture_WhenTheRuntimeIsInitializedForTheFirstTimeWhileItIsAlive_StillReceivesTheWarning()
    {
        using var fresh = FreshRuntime.Enter();
        Assert.False(Silvergun.Runtime.RuntimeInitialized, "Ground truth: the runtime must start uninitialised, or this test is vacuous.");
        var marker = Marker();
        using var capture = new WarningCapture();

        Silvergun.Runtime.Initialize("Silvergun", "TESTS");   // what a fixture constructor in a parallel collection does
        Silvergun.Runtime.Warn("first-initialize {0}", marker);

        Assert.Equal(new[] { $"first-initialize {marker}" }, Mine(capture.Warnings, marker));
    }

    // Writer 2. Two captures on two flows, overlapping and closed OUT of stack order: A opens, B opens, A logs and closes,
    // then B logs. With plain swap-and-restore that sequence is the failure — A's close restores the logger B replaced, so
    // B goes deaf, and B's close then reinstalls A's dead capture for the rest of the run. Here each capture receives
    // exactly its own warning, neither sees the other's, and a capture opened after both have closed still works.
    [Fact]
    public async Task Captures_OverlappingOnTwoFlowsAndClosedOutOfOrder_EachReceiveExactlyTheirOwnWarning()
    {
        var marker = Marker();
        using var aOpened = new SemaphoreSlim(0);
        using var bOpened = new SemaphoreSlim(0);
        using var aClosed = new SemaphoreSlim(0);

        var a = Task.Run(async () =>
        {
            var capture = new WarningCapture();
            aOpened.Release();
            await Step(bOpened);
            Silvergun.Runtime.Warn("a {0}", marker);
            var seen = capture.Warnings;
            capture.Dispose();
            aClosed.Release();
            return seen;
        });
        var b = Task.Run(async () =>
        {
            await Step(aOpened);
            using var capture = new WarningCapture();
            bOpened.Release();
            await Step(aClosed);
            Silvergun.Runtime.Warn("b {0}", marker);
            return capture.Warnings;
        });
        var seenByA = await a;
        var seenByB = await b;

        using var after = new WarningCapture();
        Silvergun.Runtime.Warn("after {0}", marker);

        Assert.Equal(new[] { $"a {marker}" }, Mine(seenByA, marker));
        Assert.Equal(new[] { $"b {marker}" }, Mine(seenByB, marker));
        Assert.Equal(new[] { $"after {marker}" }, Mine(after.Warnings, marker));
    }

    // Writer 3. Anything that still replaces Runtime.logger under a live capture must not turn "nobody was listening" into
    // "nothing was logged": reading the capture throws, so an Assert.Empty over it fails instead of passing vacuously.
    [Fact]
    public void Warnings_WhenRuntimeLoggerIsReplacedWhileTheCaptureIsAlive_ThrowsInsteadOfReadingEmpty()
    {
        using var capture = new WarningCapture();
        var installed = Silvergun.Runtime.logger;
        Silvergun.Runtime.logger = NullLogger.Instance;   // the competing writer
        try
        {
            Silvergun.Runtime.Warn("lost {0}", Marker());

            var ex = Assert.Throws<InvalidOperationException>(() => capture.Warnings);
            Assert.Contains("Runtime.logger was replaced", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            Silvergun.Runtime.logger = installed;
        }
    }

    // The control for the test above: with the forwarder in place an empty capture reads as empty, without throwing.
    [Fact]
    public void Warnings_WhenNothingWasLoggedOnThisFlow_IsEmpty()
    {
        using var capture = new WarningCapture();

        Assert.Empty(capture.Warnings);
    }
    #endregion

    #region Helpers
    private static string Marker() => "wc-" + Guid.NewGuid().ToString("N");

    // The warnings this test logged (each carries its unique marker), so the assertions are exact counts.
    private static string[] Mine(IReadOnlyList<string> warnings, string marker) =>
        warnings.Where(w => w.Contains(marker, StringComparison.Ordinal)).ToArray();

    private static async Task Step(SemaphoreSlim signal) =>
        Assert.True(await signal.WaitAsync(TimeSpan.FromSeconds(30)), "The other flow never reached its step.");
    #endregion

    #region Nested types
    // Puts Runtime back into the state of a process that has never called Initialize, and restores what was there on
    // dispose. Derives from Runtime only to reach the protected RuntimeInitialized setter and Initialize's lock; it is
    // never instantiated.
    private abstract class FreshRuntime : Silvergun.Runtime
    {
        public static IDisposable Enter()
        {
            lock (__lock)
            {
                var (initialized, previous, factory, provider) = (RuntimeInitialized, logger, loggerFactory, loggerProvider);
                var (toolName, logName, debug) = (ToolName, LogName, DebugEnabled);

                RuntimeInitialized = false;
                logger = NullLogger.Instance;

                return new Restore(() =>
                {
                    lock (__lock)
                    {
                        (RuntimeInitialized, logger, loggerFactory, loggerProvider) = (initialized, previous, factory, provider);
                        (ToolName, LogName, DebugEnabled) = (toolName, logName, debug);
                    }
                });
            }
        }

        private sealed class Restore(Action restore) : IDisposable
        {
            public void Dispose() => restore();
        }
    }
    #endregion
}

/// <summary>
/// Tests that rewrite the process-global <c>Runtime</c> logger state. Parallelization is disabled so that, while they
/// run, no other test is logging or capturing.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class RuntimeLoggerStateCollection
{
    public const string Name = "runtime-logger-state";
}
