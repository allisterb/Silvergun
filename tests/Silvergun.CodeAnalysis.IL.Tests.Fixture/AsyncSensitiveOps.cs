namespace Silvergun.CodeAnalysis.IL.Tests.Fixture;

using System;
using System.Threading.Tasks;

#pragma warning disable SYSLIB0014 // WebClient is obsolete; used only as a static-analysis target, never executed.

/// <summary>
/// Sensitive-API calls buried inside exception-handling-heavy, compiler-generated shapes: an
/// <c>async</c> state machine (<c>MoveNext</c>) and an <c>ldftn</c> method-pointer load. These are
/// the shapes the old TAC lifter failed to lift (ADR 0005), so the calls only surface when the scan
/// runs over the bytecode model directly. Methods are analyzed statically, never executed.
/// </summary>
public class AsyncSensitiveOps
{
    /// <summary>
    /// Network + file-system calls inside a try/catch across an <c>await</c>. The compiler emits an
    /// async state machine whose <c>MoveNext</c> carries heavy try/catch with the exception object on
    /// the stack at handler entry — the exact EH shape that tripped the TAC lifter. The WebClient
    /// ctor, <c>DownloadString</c>, and <c>File.ReadAllText</c> call sites live in that state machine.
    /// </summary>
    public async Task<string> DownloadInTryCatchAsync(string url)
    {
        try
        {
            await Task.Delay(1);
            var client = new System.Net.WebClient();
            return client.DownloadString(url);
        }
        catch (Exception)
        {
            return System.IO.File.ReadAllText(url);
        }
    }

    /// <summary>
    /// Returns a delegate wrapping a sensitive API without calling it, emitting an <c>ldftn</c>
    /// (<c>LoadMethodAddressInstruction</c>) of <c>File.ReadAllText</c> — exercises
    /// <see cref="ApiCallKind.MethodPointerLoad"/> and closes the delegate-wrapping evasion vector.
    /// </summary>
    public Func<string, string> CaptureFileReader() => System.IO.File.ReadAllText;
}

#pragma warning restore SYSLIB0014
