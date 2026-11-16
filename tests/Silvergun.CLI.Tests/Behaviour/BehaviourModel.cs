namespace Silvergun.CLI.Tests.Behaviour;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>Which half of a behaviour pair a package is.</summary>
public enum Side { Malicious, Twin }

/// <summary>Does <c>--strict</c> exit 2 (<see cref="Fails"/>) or not.</summary>
public enum Verdict { Fails, Passes }

public enum Detector { Capability, Indicator, Obfuscation, ScriptRule, Yara, Anomaly, ReachTrigger, ReachInfo, SsaSite, ValueSignal }

/// <summary>
/// One piece of evidence a detector named. Key: rule id, indicator category, capability, obfuscation kind, anomaly
/// category, <c>Class[/Direct]>Capability</c> for reachability statements (<c>Class[/Direct]>Capability+With</c> for a
/// co-reach one), the rendered call text for SSA sites, <c>Signal/Kind</c> for a folder's SSA value signal;
/// <c>"?"</c> in a prediction marks a cell the architect did not check.
/// </summary>
public sealed record Signal(Detector Detector, string Key)
{
    public override string ToString() => $"{Detector}:{Key}";

    public static Signal Parse(string text)
    {
        var at = text.IndexOf(':', StringComparison.Ordinal);
        return new Signal(Enum.Parse<Detector>(text[..at]), text[(at + 1)..]);
    }
}

/// <summary>Architect's prediction (written before any fixture existed). <c>Text</c> is the section 5 cell verbatim; <c>Attention</c> is null because section 5 made no attention prediction.</summary>
public sealed record Prediction(Verdict Gate, bool? Attention, string Text);

/// <summary>What one package run showed. <c>Signals</c> are distinct and ordinally sorted.</summary>
public sealed record Observation(int Exit, bool Attention, IReadOnlyList<Signal> Signals, string YaraStatus, bool Complete)
{
    /// <summary>The marker of a row whose Measured value has not been pinned yet.</summary>
    public static Observation Unpinned { get; } = new(-1, false, [], "Unpinned", false);

    /// <summary>One canonical line, so equality is by value and a failure shows the difference.</summary>
    public string Render() =>
        $"exit={Exit} attention={Attention} complete={Complete} yara={YaraStatus} :: "
        + string.Join(" | ", Signals.Select(s => s.ToString()));

    /// <summary>Equal by value: the record's own equality would compare the signal lists by reference.</summary>
    public bool SameAs(Observation other) => string.Equals(Render(), other.Render(), StringComparison.Ordinal);
}

public sealed record BehaviourRow(string Id, Side Side, string Vector, string Ttp, Prediction Predicted, Observation Measured, string Note)
{
    public string Key => $"{Id}/{Side}";

    /// <summary>The family, <c>BF07</c> for <c>BF07a</c>.</summary>
    public string Family => Id[..4];
}
