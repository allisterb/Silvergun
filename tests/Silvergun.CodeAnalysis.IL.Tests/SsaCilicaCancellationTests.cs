namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;
using System.Threading;

using Cilica;
using Cilica.IR.Utils;
using Cilica.Passes;

using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

using ILImporter = Cilica.Frontend.ILImporter;
using IrBody = Cilica.IR.MethodBody;

/// <summary>
/// Cancellation inside Cilica's promotion and verification (docs/agent/tasks/names-chars-and-lift-cancellation.md §2):
/// <c>new SsaPromotion(CancellationToken)</c> and <c>IRVerifier.Verify/Diagnose(body, CancellationToken)</c>, over the
/// bodies of the compiled fixture as <see cref="SsaSession"/> imports them. A cancelled token stops each with
/// <see cref="OperationCanceledException"/> (never a diagnostic, never an <c>IRVerificationException</c>), ahead of an input
/// that fails; <c>default</c> or a live token gives what the old overloads give. Only the first check each stage reaches is
/// observed: a token cancelled before the call trips it, and nothing a test supplies runs on the thread inside the pass or
/// the verifier to cancel at a later check (per phi, per block renamed, per value, per exceptional-path block).
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaCilicaCancellationTests : IClassFixture<SsaCilicaCancellationFixture>
{
    #region Constructors
    public SsaCilicaCancellationTests(SsaCilicaCancellationFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- SsaPromotion ---------------------------------------------------------------------------------------------------

    /// <summary>Every imported body with a local slot: promotion with a cancelled token throws OperationCanceled for that token.</summary>
    [Fact]
    public void SsaPromotion_CancelledToken_ThrowsOperationCanceled_OnEveryBodyWithASlot()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var withSlots = 0;

        foreach (var outcome in fixture.Lifted)
        {
            var body = Import(outcome);
            if (!body.LocalVars().Any())
                continue;
            withSlots++;

            var thrown = Record.Exception(() => Promote(body, new SsaPromotion(cancelled.Token)));

            Assert.True(thrown is OperationCanceledException, $"{SsaText.Of(outcome)}: {thrown?.GetType().Name ?? "no exception"}");
            Assert.Equal(cancelled.Token, ((OperationCanceledException)thrown!).CancellationToken);
        }
        Assert.True(withSlots >= 5, $"Only {withSlots} bodies have a slot: too few to say much.");
    }

    /// <summary>
    /// <c>default</c> and a live token promote every body to the same IR as the parameterless pass, which is the IR the
    /// session's own lift (through the token overloads) produced.
    /// </summary>
    [Fact]
    public void SsaPromotion_DefaultOrLiveToken_PromotesAsTheParameterlessPass()
    {
        using var live = new CancellationTokenSource();

        foreach (var outcome in fixture.Lifted)
        {
            var expected = Promoted(outcome, new SsaPromotion());

            Assert.Equal(expected, Promoted(outcome, new SsaPromotion(default)));
            Assert.Equal(expected, Promoted(outcome, new SsaPromotion(live.Token)));
            Assert.Equal(expected, Print(outcome.Body!));
        }
        Assert.False(live.IsCancellationRequested);
    }

    // ---- IRVerifier -----------------------------------------------------------------------------------------------------

    /// <summary>
    /// Verify and Diagnose with a cancelled token throw OperationCanceled on every body, imported and promoted: Diagnose
    /// does not map it to an "Invalid IR structure" diagnostic, and Verify does not turn it into an IRVerificationException.
    /// </summary>
    [Fact]
    public void IRVerifier_CancelledToken_VerifyAndDiagnoseThrowOperationCanceled()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        foreach (var outcome in fixture.Lifted)
        {
            foreach (var body in new[] { Import(outcome), outcome.Body! })
            {
                AssertCancelled(() => IRVerifier.Diagnose(body, cancelled.Token), cancelled.Token, outcome);
                AssertCancelled(() => IRVerifier.Verify(body, cancelled.Token), cancelled.Token, outcome);
            }
        }
    }

    /// <summary>A body that fails verification on its own (a foreign block as its entry's successor) still reports the cancellation, not its errors.</summary>
    [Fact]
    public void IRVerifier_CancelledToken_IsSeenBeforeAnInputThatFailsToVerify()
    {
        var body = Invalid();
        Assert.Contains(IRVerifier.Diagnose(body), d => d.Severity == DiagnosticSeverity.Error);
        Assert.Throws<IRVerificationException>(() => IRVerifier.Verify(body));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        AssertCancelled(() => IRVerifier.Diagnose(body, cancelled.Token), cancelled.Token, null);
        AssertCancelled(() => IRVerifier.Verify(body, cancelled.Token), cancelled.Token, null);
    }

    /// <summary>
    /// <c>default</c> and a live token diagnose every body as the one-argument overload does (each diagnostic's severity,
    /// location and message), valid bodies before and after promotion and an invalid one; Verify passes or throws alike.
    /// </summary>
    [Fact]
    public void IRVerifier_DefaultOrLiveToken_DiagnosesAsTheOneArgumentOverload()
    {
        using var live = new CancellationTokenSource();
        var bodies = fixture.Lifted.SelectMany(o => new[] { Import(o), o.Body! }).Append(Invalid()).ToArray();
        var diagnosed = 0;

        foreach (var body in bodies)
        {
            var expected = Diagnostics(IRVerifier.Diagnose(body));
            diagnosed += expected.Length > 0 ? 1 : 0;

            Assert.Equal(expected, Diagnostics(IRVerifier.Diagnose(body, default)));
            Assert.Equal(expected, Diagnostics(IRVerifier.Diagnose(body, live.Token)));
            Assert.Equal(Verified(() => IRVerifier.Verify(body)), Verified(() => IRVerifier.Verify(body, default)));
            Assert.Equal(Verified(() => IRVerifier.Verify(body)), Verified(() => IRVerifier.Verify(body, live.Token)));
        }
        Assert.True(diagnosed >= 1, "No body had a diagnostic: the comparison never saw one.");
        Assert.False(live.IsCancellationRequested);
    }

    // ---- Helpers --------------------------------------------------------------------------------------------------------

    private static void AssertCancelled(Action verify, CancellationToken token, SsaMethodOutcome? outcome)
    {
        var thrown = Record.Exception(verify);
        var what = outcome is null ? "the invalid body" : SsaText.Of(outcome);
        Assert.True(thrown is OperationCanceledException, $"{what}: {thrown?.GetType().Name ?? "no exception"}");
        Assert.Equal(token, ((OperationCanceledException)thrown!).CancellationToken);
    }

    // A fresh import of a lifted method, before promotion (the session's own import of it was promoted).
    private static IrBody Import(SsaMethodOutcome outcome) => ILImporter.ParseCode(outcome.Body!.Definition);

    private static void Promote(IrBody body, IMethodPass pass) =>
        PassRunner.Run(pass, new MethodTransformContext(new Compilation(body.Definition.Module, new VoidLogger(), new CompilationSettings()), body));

    // The printed body after a fresh import is promoted by `pass`, or how that failed.
    private static string Promoted(SsaMethodOutcome outcome, IMethodPass pass)
    {
        try
        {
            var body = Import(outcome);
            Promote(body, pass);
            return Print(body);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return $"{ex.GetType().Name}: {ex.Message}";
        }
    }

    private static string Print(IrBody body)
    {
        var writer = new StringWriter();
        IRPrinter.ExportPlain(body, writer);
        return writer.ToString();
    }

    private static (DiagnosticSeverity, object?, string?)[] Diagnostics(System.Collections.Generic.IEnumerable<Diagnostic> diagnostics) =>
        diagnostics.Select(d => (d.Severity, (object?)d.Location, d.Message)).ToArray();

    private static string Verified(Action verify) => Record.Exception(verify) is { } ex ? $"{ex.GetType().Name}: {ex.Message}" : "verified";

    // A lifted body whose entry block branches to another body's block: an operand that does not belong to the method.
    private IrBody Invalid()
    {
        var body = Import(fixture.Lifted[0]);
        var foreign = Import(fixture.Lifted[1]).EntryBlock;
        body.EntryBlock.SetBranch(foreign);
        return body;
    }
    #endregion

    #region Fields
    private readonly SsaCilicaCancellationFixture fixture;
    #endregion
}

/// <summary>The compiled fixture lifted once; its lifted outcomes, with their session kept open for lazy members.</summary>
public sealed class SsaCilicaCancellationFixture : IDisposable
{
    #region Constructors
    public SsaCilicaCancellationFixture()
    {
        lifted = new SsaLifted([SsaBodyFixture.CompiledFixturePath]);
        Lifted = lifted.Outcomes.Where(o => o.IsLifted).ToArray();
        Assert.True(Lifted.Length > 20, $"Only {Lifted.Length} methods lifted.");
    }
    #endregion

    #region Properties
    public SsaMethodOutcome[] Lifted { get; }
    #endregion

    #region Methods
    public void Dispose() => lifted.Dispose();
    #endregion

    #region Fields
    private readonly SsaLifted lifted;
    #endregion
}
