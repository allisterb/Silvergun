namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The cross-layer parity assertion, factored out of <see cref="CanonicalNameParityTests"/> so it can be run
/// against more than one assembly: the same <see cref="CciNames"/>/<see cref="ModelNames"/> rendering of one
/// assembly, read through raw CCI and through Analysis.Net's <c>Model</c>, must produce identical
/// <see cref="CanonicalName.ClassificationKey"/> and <see cref="CanonicalName.NodeId"/> sets for method
/// definitions and for call sites. If the two layers ever render the same method differently, capability
/// classification and call-graph nodes silently diverge.
/// </summary>
public static class CanonicalNameParity
{
    #region Methods
    /// <summary>
    /// Asserts set equality of both keys, over definitions and call sites, reporting the symmetric difference
    /// per side so a failure names the offending entries instead of just "sets differ".
    /// </summary>
    public static void AssertLayersAgree(LayerNames cci, LayerNames model)
    {
        var differences = new List<string>();

        Compare("definition ClassificationKey", cci.DefinitionKeys, model.DefinitionKeys, differences);
        Compare("definition NodeId", cci.DefinitionNodeIds, model.DefinitionNodeIds, differences);
        Compare("call-site ClassificationKey", cci.CallSiteKeys, model.CallSiteKeys, differences);
        Compare("call-site NodeId", cci.CallSiteNodeIds, model.CallSiteNodeIds, differences);

        Assert.True(differences.Count == 0, string.Join(Environment.NewLine, differences));
    }

    private static void Compare(string what, IReadOnlySet<string> cci, IReadOnlySet<string> model, List<string> differences)
    {
        var onlyCci = cci.Except(model, StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToArray();
        var onlyModel = model.Except(cci, StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToArray();

        if (onlyCci.Length == 0 && onlyModel.Length == 0)
            return;

        differences.Add(
            $"{what}: {cci.Count} CCI vs {model.Count} Model; " +
            $"{onlyCci.Length} only in CCI, {onlyModel.Length} only in Model." +
            Render("  only in CCI:   ", onlyCci) +
            Render("  only in Model: ", onlyModel));
    }

    private static string Render(string label, IReadOnlyList<string> names) =>
        names.Count == 0
            ? string.Empty
            : Environment.NewLine + string.Join(Environment.NewLine, names.Take(MaxReported).Select(n => label + n)) +
              (names.Count > MaxReported ? $"{Environment.NewLine}  … and {names.Count - MaxReported} more" : string.Empty);
    #endregion

    #region Fields
    private const int MaxReported = 40;
    #endregion
}
