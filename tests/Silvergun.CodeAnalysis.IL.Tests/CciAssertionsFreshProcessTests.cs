namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

using Xunit;

/// <summary>
/// ADR 0022 Stage 1 in a <b>fresh</b> process (acceptance criterion 2, "the module initializer is installed before the
/// first CCI use"): the probe's <c>assertions</c> verb (<see cref="AssertionProbe"/>) reads
/// <see cref="CciAssertions.IsInstalled"/> as its first touch of the CCI assembly, then fails a <c>Contract.Assume</c>,
/// a <c>Contract.Assert</c> and a <see cref="CciDebug.Assert(bool, string)"/> with no scope open. In a test host that
/// cannot be shown: other tests have long since opened scopes, and <see cref="CciAssertions.BeginScope"/> subscribes the
/// handler itself.
/// <para>
/// <b>Out of process by necessity.</b> Should the handler not be subscribed, the first failed contract is
/// <c>Environment.FailFast</c> again (ADR-0021): it would kill this host, and here it is a child's exit code instead.
/// The mode variable is set (or removed) explicitly per child, so the developer's shell cannot change the outcome.
/// </para>
/// </summary>
public sealed class CciAssertionsFreshProcessTests
{
    #region Methods
    [Fact]
    public void FreshProcess_DefaultMode_InstalledAtFirstTouch_EveryChannelContinues_AndIsCounted()
    {
        var result = Run(null);

        Assert.True(result.ExitedCleanly, $"The assertions probe did not exit cleanly - {result.Describe()}");
        Assert.Equal(
            ["INSTALLED True", "DEBUG True", "MODE RecordAndContinue", "ASSUME CONTINUED", "ASSERT CONTINUED", "DEBUG-ASSERT CONTINUED", "RECORDED 3", "DONE"],
            Lines(result.StandardOutput));
    }

    /// <summary>
    /// <c>SILVERGUN_CCI_ASSERTIONS=throw</c> (any case) starts the process in Throw mode: each channel throws (a contract
    /// as the BCL's <c>ContractException</c>, <see cref="CciDebug"/> as <see cref="CciAssertionException"/>), and each is
    /// still recorded.
    /// </summary>
    [Theory]
    [InlineData("throw")]
    [InlineData("THROW")]
    public void FreshProcess_ThrowVariable_StartsInThrowMode_AndEveryChannelThrows(string value)
    {
        var result = Run(value);

        Assert.True(result.ExitedCleanly, $"The assertions probe did not exit cleanly - {result.Describe()}");
        Assert.Equal(
            ["INSTALLED True", "DEBUG True", "MODE Throw", "ASSUME THREW ContractException", "ASSERT THREW ContractException",
             $"DEBUG-ASSERT THREW {nameof(CciAssertionException)}", "RECORDED 3", "DONE"],
            Lines(result.StandardOutput));
    }

    /// <summary>Twin: any other value of the variable is the default mode, never Throw.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("1")]
    [InlineData("throws")]
    [InlineData("record")]
    public void FreshProcess_AnyOtherValueOfTheVariable_IsTheDefaultMode(string value)
    {
        var result = Run(value);

        Assert.True(result.ExitedCleanly, $"The assertions probe did not exit cleanly - {result.Describe()}");
        Assert.Contains("MODE RecordAndContinue", Lines(result.StandardOutput));
        Assert.Contains("ASSUME CONTINUED", Lines(result.StandardOutput));
    }

    [Fact]
    public void Premise_TheModeVariableIsNamedAsTheSpecSays() => Assert.Equal("SILVERGUN_CCI_ASSERTIONS", CciAssertions.ModeVariable);

    // value null: the variable is removed from the child's environment.
    private static ProbeResult Run(string? value) =>
        ChildProcessProbe.Run(ProbeExe, CciAssertionsTests.Timeout, new Dictionary<string, string?> { [CciAssertions.ModeVariable] = value }, AssertionProbe.Verb);

    private static string[] Lines(string output) => output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
    #endregion

    #region Fields
    private static readonly string ProbeExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe");
    #endregion
}
