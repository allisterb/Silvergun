namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Diagnostics;
using System.Threading;

/// <summary>A <c>Debug.Assert</c> that failed inside a Debug build of Cilica, raised as an exception so it costs one method.</summary>
public sealed class CilicaAssertionException(string message) : Exception(message);

/// <summary>
/// Turns failed <c>Debug.Assert</c>/<c>Trace.Fail</c> calls into <see cref="CilicaAssertionException"/>s instead of a
/// process-killing FailFast, by putting a throwing listener first in <see cref="Trace.Listeners"/>. Process-wide, but only
/// while a lease is held (each open <see cref="SsaSession"/> holds one), so an assert outside SSA, in a graph build after
/// it, still fails fast as it would without SSA. It only matters for Debug builds (Release compiles asserts out).
/// </summary>
internal static class CilicaAssertions
{
    #region Methods
    /// <summary>Installs the listener if no lease is held; it stays until every lease is disposed.</summary>
    public static IDisposable Acquire()
    {
        lock (gate)
        {
            if (leases == 0)
                Trace.Listeners.Insert(0, listener);
            leases++;
        }
        return new Lease();
    }

    private static void Release()
    {
        lock (gate)
        {
            if (--leases == 0)
                Trace.Listeners.Remove(listener);
        }
    }
    #endregion

    #region Fields
    private static readonly object gate = new();
    private static readonly ThrowingListener listener = new();
    private static int leases;
    #endregion

    #region Child types
    private sealed class Lease : IDisposable
    {
        #region Methods
        public void Dispose()
        {
            if (Interlocked.Exchange(ref released, 1) == 0)
                Release();
        }
        #endregion

        #region Fields
        private int released;
        #endregion
    }

    private sealed class ThrowingListener : TraceListener
    {
        public override void Fail(string? message, string? detailMessage) =>
            throw new CilicaAssertionException("Assertion failed: " + message + (detailMessage is { Length: > 0 } detail ? ": " + detail : ""));

        public override void Fail(string? message) => Fail(message, null);

        public override void Write(string? message) { }

        public override void WriteLine(string? message) { }
    }
    #endregion
}
