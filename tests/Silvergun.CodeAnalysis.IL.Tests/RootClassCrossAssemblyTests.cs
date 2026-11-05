namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// S1 review N2 (the PublicContract row of reachability R1, S1.2): an own class ancestor's new slot masks an override
/// only when the override can see it. Over <c>RootFixture</c> and <c>RootFixture.Other</c> indexed TOGETHER, where
/// <c>RootFixture.Other.OtherBase</c> hides <c>Object.ToString</c> with an <c>internal new virtual string ToString()</c>:
/// an override from <c>RootFixture</c> cannot see that slot and binds to Object's, so its slot is external; the override in
/// <c>RootFixture.Other</c> binds to the internal one, so its slot is own.
/// </summary>
public sealed class RootClassCrossAssemblyTests : IClassFixture<RootFixturePairModel>
{
    #region Constructors
    public RootClassCrossAssemblyTests(RootFixturePairModel fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // The premise: both assemblies are own, and the base's slot is an assembly-only new slot.
    [Fact]
    public void Premise_BothAssembliesAreIndexed_AndTheBaseSlotIsAnInternalNewSlot()
    {
        Assert.Equal([RootFixtureAssemblies.FixtureName, RootFixtureAssemblies.OtherName], fixture.Index.Assemblies);
        var slot = Assert.Single(fixture.Index.Definitions("RootFixture.Other.OtherBase.ToString()"));
        Assert.Equal(RootFixtureAssemblies.OtherName, slot.Assembly);
        Assert.Equal(Model.Types.VisibilityKind.Assembly, slot.Definition.Visibility);
        Assert.True(slot.Definition.IsVirtual && slot.Definition.IsNewSlot);
        Assert.False(Assert.Single(fixture.Index.Definitions(CrossOverride)).Definition.IsNewSlot);
    }

    [Fact]
    public void Override_OfAnInternalSlotDeclaredInAnotherAssembly_IsPublicContract()
    {
        Assert.Equal(RootClass.PublicContract, Roots(CrossOverride));
    }

    [Fact]
    public void Override_OfAnInternalSlotDeclaredInTheSameAssembly_IsHidden()
    {
        Assert.Equal(RootClass.Hidden, Roots("RootFixture.Other.SameAssemblyOverride.ToString()"));
        Assert.Equal(RootClass.Hidden, Roots("RootFixture.Other.OtherBase.ToString()"));
    }

    private RootClass Roots(string nodeId) => Assert.Single(fixture.Graph.Facts.Methods, f => f.NodeId == nodeId).Roots;
    #endregion

    #region Fields
    private const string CrossOverride = "RootFixture.Slots.CrossAssemblyOverride.ToString()";

    private readonly RootFixturePairModel fixture;
    #endregion
}

/// <summary><c>RootFixture</c> and <c>RootFixture.Other</c> loaded and indexed together, the graph built with the built-in map.</summary>
public sealed class RootFixturePairModel : IDisposable
{
    #region Constructors
    public RootFixturePairModel()
    {
        Assemblies = ModelAssemblies.Load(RootFixtureAssemblies.Fixture, RootFixtureAssemblies.Other);
        try
        {
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
        }
        catch (Exception)
        {
            Assemblies.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public MethodGraph Graph { get; }
    #endregion

    #region Methods
    public void Dispose() => Assemblies.Dispose();
    #endregion
}
