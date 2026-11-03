namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Xunit;

/// <summary>
/// The waypoints in <see cref="MechanismGroundTruth"/> were read through raw CCI (<see cref="MechanismCallSites"/>),
/// but the CHA graph walks Analysis.Net's <c>Model</c> (ADR-0020 decision 3) and names nodes with
/// <see cref="ModelNames"/>. This pins that both layers render the mechanism fixture identically — so the ground
/// truth is valid for the layer that will be checked against it — and measures the one documented divergence:
/// the <c>&lt;Module&gt;</c> pseudo-type, which the <c>Model</c> drops (cha-call-graph.md, A2).
/// </summary>
public sealed class MechanismLayerParityTests : IClassFixture<MechanismLayersFixture>
{
    public MechanismLayerParityTests(MechanismLayersFixture fixture)
    {
        layers = fixture.Layers;
        debugLayers = fixture.DebugLayers;
    }

    /// <summary>
    /// The same parity on the Debug-built fixture (A2 S2), whose waypoints were read through raw CCI too: both layers
    /// render every definition and call site alike. It has no module initializer, so there is no exception at all.
    /// </summary>
    [Fact]
    public void Layers_AgreeOnTheDebugFixture()
    {
        Assert.Empty(Only(debugLayers.CciLayer.DefinitionNodeIds, debugLayers.ModelLayer.DefinitionNodeIds));
        Assert.Empty(Only(debugLayers.ModelLayer.DefinitionNodeIds, debugLayers.CciLayer.DefinitionNodeIds));
        Assert.Empty(Only(debugLayers.CciLayer.CallSiteNodeIds, debugLayers.ModelLayer.CallSiteNodeIds));
        Assert.Empty(Only(debugLayers.ModelLayer.CallSiteNodeIds, debugLayers.CciLayer.CallSiteNodeIds));
        Assert.Contains("MechanismFixture.Debug.Async.AsyncProbes.<Probe>d__0.MoveNext()", debugLayers.ModelLayer.DefinitionNodeIds);
    }

    [Fact]
    public void Layers_AgreeOnTheMechanismFixture_ExceptTheModuleTypeInitializer()
    {
        var cci = layers.CciLayer;
        var model = layers.ModelLayer;

        // Measured: the Model never surfaces <Module>..cctor, and with it the only call sites of the two
        // [ModuleInitializer] methods - so on the Model side nothing calls Startup.Init. That is the
        // "module initializers are silently invisible" gap the A2 graph must close or report.
        Assert.Equal(["<Module>..cctor()"], Only(cci.DefinitionNodeIds, model.DefinitionNodeIds));
        Assert.Empty(Only(model.DefinitionNodeIds, cci.DefinitionNodeIds));
        Assert.Equal(
            ["MechanismFixture.ModuleInit.SafeStartup.InitSafe()", "MechanismFixture.ModuleInit.Startup.Init()"],
            Only(cci.CallSiteNodeIds, model.CallSiteNodeIds));
        Assert.Empty(Only(model.CallSiteNodeIds, cci.CallSiteNodeIds));
    }

    /// <summary>
    /// Every own waypoint names a bodied definition of the Model layer of its own assembly: the Debug fixture's
    /// (<c>MechanismFixture.Debug.</c>) in <see cref="MechanismLayersFixture.DebugLayers"/>, the rest in the Release
    /// fixture's — except the Dependency's, the other assembly.
    /// </summary>
    [Fact]
    public void ModelLayer_NamesEveryBodiedOwnWaypointDefinition()
    {
        var debugPrefix = "^" + Regex.Escape(MechanismGroundTruth.RootNamespace + ".Debug.");
        var missing = MechanismGroundTruth.Paths.SelectMany(p => p.Waypoints)
            .Concat(MechanismGroundTruth.Opacities.Select(o => o.Site))
            .Where(MechanismGroundTruth.IsOwn)
            .Distinct(StringComparer.Ordinal)
            .Where(w => !w.Contains("Dependency", StringComparison.Ordinal))   // the other assembly
            .Where(w => !w.Contains("getpid", StringComparison.Ordinal))       // bodyless extern: not a Model method
            .Where(w => !(w.StartsWith(debugPrefix, StringComparison.Ordinal) ? debugLayers : layers).ModelLayer.DefinitionNodeIds.Any(new Regex(w).IsMatch))
            .ToArray();

        Assert.Empty(missing);
        Assert.Contains(MechanismGroundTruth.Paths.SelectMany(p => p.Waypoints), w => w.StartsWith(debugPrefix, StringComparison.Ordinal));
    }

    private static string[] Only(IReadOnlySet<string> left, IReadOnlySet<string> right) =>
        left.Except(right, StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToArray();

    private readonly CanonicalNameLayersFixture layers;
    private readonly CanonicalNameLayersFixture debugLayers;
}

/// <summary>
/// Both object models' rendering of the mechanism fixture, and of the Debug-built one (see
/// <see cref="CanonicalNameLayersFixture"/>).
/// </summary>
public sealed class MechanismLayersFixture : IDisposable
{
    #region Constructors
    public MechanismLayersFixture()
    {
        Layers = new CanonicalNameLayersFixture(MechanismFixtureAssemblies.Fixture);
        try
        {
            DebugLayers = new CanonicalNameLayersFixture(MechanismFixtureAssemblies.DebugFixture);
        }
        catch (Exception)
        {
            // A partially constructed fixture is never disposed by xUnit; release what already loaded.
            Layers.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public CanonicalNameLayersFixture Layers { get; }

    /// <summary>The Debug-built fixture's two layers (<c>MechanismFixture.Debug</c>).</summary>
    public CanonicalNameLayersFixture DebugLayers { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Layers.Dispose();
        DebugLayers.Dispose();
    }
    #endregion
}
