namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Diagnostics;

/// <summary>A <c>Debug.Assert</c> that failed inside a Debug build of Cilica, raised as an exception so it costs one method.</summary>
public sealed class CilicaAssertionException(string message) : Exception(message);

/// <summary>
/// Turns failed <c>Debug.Assert</c>/<c>Trace.Fail</c> calls into <see cref="CilicaAssertionException"/>s instead of a
/// process-killing FailFast, by putting a throwing listener first in <see cref="Trace.Listeners"/>. Process-wide and
/// idempotent; it only matters for a Debug build of Cilica (Release compiles its asserts out).
/// </summary>
internal static class CilicaAssertions
{
    #region Methods
    public static void Install()
    {
        lock (gate)
        {
            foreach (var listener in Trace.Listeners)
            {
                if (listener is ThrowingListener)
                    return;
            }
            Trace.Listeners.Insert(0, new ThrowingListener());
        }
    }
    #endregion

    #region Fields
    private static readonly object gate = new();
    #endregion

    #region Child types
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
