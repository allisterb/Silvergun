namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Phase A1 acceptance criterion 5: the direct-subtype map built in <see cref="MemberIndex"/> (spec §2.1 — not
/// Analysis.Net's <c>ClassHierarchy</c>), keyed on <b>definition-normalized</b> type node ids, over the mechanism
/// fixture. These are the sets A2's CHA fan-out and state-machine edges will be driven from.
/// </summary>
public sealed class MemberIndexSubtypeTests : IClassFixture<MechanismMethodGraphFixture>
{
    #region Constructors
    public MemberIndexSubtypeTests(MechanismMethodGraphFixture fixture) => index = fixture.Index;
    #endregion

    #region Methods
    [Fact]
    public void DirectSubtypes_OfIProbe_AreItsTwoImplementors()
    {
        Assert.Equal([Fixture("Interface.EnvProbe"), Fixture("Interface.QuietProbe")], index.DirectSubtypes(Fixture("Interface.IProbe")));
    }

    [Fact]
    public void DirectSubtypes_OfIBaz_IsA()
    {
        Assert.Equal([Fixture("Generics.A")], index.DirectSubtypes(Fixture("Generics.IBaz")));
    }

    [Fact]
    public void DirectSubtypes_OfAVirtualBase_IsItsOverridingSubclass()
    {
        Assert.Equal([Fixture("Virtual.EnvWorker")], index.DirectSubtypes(Fixture("Virtual.Worker")));
    }

    /// <summary>
    /// Every async state machine — the method's, the async lambda's (nested in <c>&lt;&gt;c</c>) and the async
    /// local function's, interesting and twin alike — is a direct subtype of the PLATFORM interface
    /// <c>IAsyncStateMachine</c>, although they are Release-built structs. Since A2 S2 so are the AsyncIterator
    /// mechanism's three: the <c>await foreach</c> consumer's struct <c>&lt;Consumes&gt;d__0</c>, and both async
    /// iterators' state machines, which are classes even in Release (and are also below <c>IAsyncEnumerator`1</c>).
    /// </summary>
    [Fact]
    public void DirectSubtypes_OfIAsyncStateMachine_AreAllNineStateMachines()
    {
        Assert.Equal(
            [
                Fixture("Async.AsyncLambdaCase.<>c.<<RunsAsyncLambda>b__0_0>d"),
                Fixture("Async.AsyncLambdaCase.<>c.<<RunsAsyncLambdaSafe>b__1_0>d"),
                Fixture("Async.AsyncLocalCase.<<CallsAsyncLocal>g__Read|0_0>d"),
                Fixture("Async.AsyncLocalCase.<<CallsAsyncLocalSafe>g__Read|1_0>d"),
                Fixture("Async.AsyncProbes.<Probe>d__0"),
                Fixture("Async.AsyncProbes.<ProbeSafe>d__1"),
                Fixture("AsyncIterator.Consumers.<Consumes>d__0"),
                Fixture("AsyncIterator.Sequences.<Env>d__0"),
                Fixture("AsyncIterator.Sequences.<EnvSafe>d__1"),
            ],
            index.DirectSubtypes("System.Runtime.CompilerServices.IAsyncStateMachine"));
        Assert.Equal(
            [Fixture("AsyncIterator.Sequences.<Env>d__0"), Fixture("AsyncIterator.Sequences.<EnvSafe>d__1")],
            index.DirectSubtypes("System.Collections.Generic.IAsyncEnumerator`1"));
    }

    /// <summary>
    /// Definition-normalized: the iterators implement <c>IEnumerator&lt;string&gt;</c>, and are found under the
    /// generic DEFINITION <c>System.Collections.Generic.IEnumerator`1</c> (and under the non-generic
    /// <c>IEnumerator</c>), never under an instantiated key.
    /// </summary>
    [Fact]
    public void DirectSubtypes_OfIEnumerator_AreTheIterators_UnderTheGenericDefinition()
    {
        string[] iterators = [Fixture("Iterator.Sequences.<Enum>d__0"), Fixture("Iterator.Sequences.<EnumSafe>d__1")];

        Assert.Equal(iterators, index.DirectSubtypes("System.Collections.Generic.IEnumerator`1"));
        Assert.Equal(iterators, index.DirectSubtypes("System.Collections.IEnumerator"));
        Assert.Empty(index.DirectSubtypes("System.Collections.Generic.IEnumerator`1<System.String>"));
    }

    [Fact]
    public void Supertypes_AreDefinitionNormalized_AndSorted()
    {
        var iterator = Assert.Single(index.Types(Fixture("Iterator.Sequences.<Enum>d__0")));

        Assert.Equal(
            ["System.Collections.Generic.IEnumerable`1", "System.Collections.Generic.IEnumerator`1", "System.Collections.IEnumerable",
             "System.Collections.IEnumerator", "System.IDisposable", "System.Object"],
            iterator.Supertypes);
        Assert.Equal(MechanismFixtureAssemblies.FixtureName, iterator.Assembly);
    }

    [Fact]
    public void DirectSubtypes_OfAnUnknownType_IsEmpty_AndTypesOfAnUnknownTypeIsEmpty()
    {
        Assert.Empty(index.DirectSubtypes("No.Such.Type"));
        Assert.Empty(index.Types("No.Such.Type"));
    }

    [Fact]
    public void TypeIds_CoverBothAssemblies()
    {
        Assert.Contains(Fixture("Dependency.EnvReader"), index.TypeIds);
        Assert.Contains(Fixture("Interface.IProbe"), index.TypeIds);
        Assert.Equal(MechanismFixtureAssemblies.DependencyName, Assert.Single(index.Types(Fixture("Dependency.EnvReader"))).Assembly);
    }

    private static string Fixture(string typeIdWithoutRoot) => $"{MechanismGroundTruth.RootNamespace}.{typeIdWithoutRoot}";
    #endregion

    #region Fields
    private readonly MemberIndex index;
    #endregion
}
