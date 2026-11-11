namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

using Cilica.AsmIO;

using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// The SSA adapter's test classes run one after another (each session provisions the host's CoreLib through CCI, and
/// Cilica's model assumes one thread per resolver), but in parallel with the rest of the suite.
/// </summary>
[CollectionDefinition(Name)]
public sealed class SsaSessionCollection
{
    #region Fields
    public const string Name = "SSA adapter sessions";
    #endregion
}

/// <summary>
/// One <see cref="SsaSession"/> over some assemblies, lifted once (<see cref="Outcomes"/>), kept open so the lifted
/// bodies' lazy members can still be read. Every input is read as metadata only.
/// </summary>
internal sealed class SsaLifted : IDisposable
{
    #region Constructors
    public SsaLifted(IEnumerable<string> paths, SsaBounds? bounds = null)
    {
        Session = SsaSession.Open(paths, bounds);
        Outcomes = Session.Lift().ToList();
    }
    #endregion

    #region Properties
    public SsaSession Session { get; }

    public IReadOnlyList<SsaMethodOutcome> Outcomes { get; }
    #endregion

    #region Methods
    /// <summary>The one outcome of <paramref name="type"/> (innermost name).<paramref name="method"/>.</summary>
    public SsaMethodOutcome Of(string type, string method)
    {
        var matches = Outcomes.Where(o => o.Method.DeclaringType.NestingChain[^1] == type && o.Method.MethodName == method).ToArray();
        Assert.True(matches.Length == 1, $"Expected one outcome for {type}::{method}, found {matches.Length}.");
        return matches[0];
    }

    /// <summary>The adapted IL body of a method that lifted (asserting it did).</summary>
    public ILMethodBody Il(string type, string method)
    {
        var outcome = Of(type, method);
        AssertLifted(outcome);
        return outcome.Body!.Definition.ILBody ?? throw new InvalidOperationException("A lifted method has no IL body.");
    }

    public static void AssertLifted(SsaMethodOutcome outcome) =>
        Assert.True(outcome.IsLifted, $"{SsaText.Of(outcome)} did not lift.");

    /// <summary>Asserts the method failed as <paramref name="kind"/>, with <paramref name="reasonPart"/> in its reason if given.</summary>
    public static void AssertFailed(SsaMethodOutcome outcome, SsaFailureKind kind, string? reasonPart = null)
    {
        Assert.False(outcome.IsLifted, $"{SsaText.Of(outcome)} lifted; expected {kind}.");
        Assert.True(outcome.Failure!.Kind == kind, $"{SsaText.Of(outcome)}: expected {kind}.");
        if (reasonPart is not null)
            Assert.True(outcome.Failure.Reason.Contains(reasonPart, StringComparison.Ordinal), $"{SsaText.Of(outcome)}: expected '{reasonPart}' in the reason.");
        Assert.Null(outcome.Body);
    }

    public void Dispose() => Session.Dispose();
    #endregion
}

/// <summary>Diagnostics text for SSA outcomes, escaped to printable ASCII (a reason may carry metadata names).</summary>
internal static class SsaText
{
    #region Methods
    public static string Of(SsaMethodOutcome outcome) =>
        Printable($"{outcome.NodeId} [{(outcome.Failure is { } f ? f.Kind + ": " + f.Reason : "lifted")}]");

    public static string Printable(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            if (c is >= ' ' and < (char)0x7F and not '\\')
                builder.Append(c);
            else
                builder.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:X4}");
        }
        return builder.ToString();
    }
    #endregion
}

/// <summary>A temporary directory for one test's emitted fixtures; removed (best effort) on dispose.</summary>
internal sealed class SsaTempDirectory : IDisposable
{
    #region Constructors
    public SsaTempDirectory() => Path = Directory.CreateTempSubdirectory("silvergun-ssa-").FullName;
    #endregion

    #region Properties
    public string Path { get; }
    #endregion

    #region Methods
    /// <summary>A new subdirectory, so one assembly name can be written in several variants.</summary>
    public string Sub(string name) => Directory.CreateDirectory(System.IO.Path.Combine(Path, name)).FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
    #endregion
}
