namespace Silvergun.CodeAnalysis.IL.Tests;

using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// <see cref="AssemblyAnalyzer.Methods"/> is now a <b>candidate</b> set — every method that MAY carry an IL body,
/// selected from pure metadata flags (<c>!IsAbstract &amp;&amp; !IsExternal</c>) with no <c>Body</c> dereference.
/// The dereference moved into <see cref="AssemblyAnalyzer.TryReadBody"/>, inside each consumer's per-method guard
/// (<c>docs/agent/tasks/per-method-body-read-granularity.md</c>).
/// <para>
/// The predicate split is only safe if it is <b>equivalent</b> to the old body-dereferencing filter on clean input:
/// the spec measured that across 17 assemblies, and the equality pinned here — candidate count ==
/// <see cref="CapabilityReport.MethodsTotal"/> — is what guarantees the denominator did not shift. If a clean
/// assembly ever gained a candidate with no body, the two would diverge and the coverage ratio reported to CI would
/// quietly change meaning.
/// </para>
/// </summary>
public sealed class CandidateMethodSetTests
{
    public CandidateMethodSetTests() => Runtime.Initialize("Silvergun", "TESTS");

    // The filter itself: not one abstract and not one external method survives it.
    [Fact]
    public void Methods_YieldsNoAbstractAndNoExternalMethod()
    {
        using var assembly = Load();

        Assert.All(assembly.Methods, method =>
        {
            Assert.False(method.IsAbstract, $"Abstract method in the candidate set: {method.Name.Value}");
            Assert.False(method.IsExternal, $"External method in the candidate set: {method.Name.Value}");
        });
    }

    // ... and the assertion above is not vacuous: the module really does declare both shapes, and both are excluded.
    // ICanonicalMarker.Mark is an interface method (abstract); NativeInteropOps.ShowMessage is a [DllImport]
    // (external). Without this, a Methods property that returned nothing at all would pass the test above.
    [Fact]
    public void Methods_ExcludesTheAbstractAndExternalMethodsTheModuleDeclares()
    {
        using var assembly = Load();
        var all = assembly.Module.GetAllTypes().SelectMany(type => type.Methods).ToArray();
        var candidates = assembly.Methods.ToArray();

        Assert.Contains(all, m => m.Name.Value == "Mark" && m.IsAbstract);
        Assert.Contains(all, m => m.Name.Value == "ShowMessage" && m.IsExternal);

        Assert.DoesNotContain(candidates, m => m.Name.Value == "Mark");
        Assert.DoesNotContain(candidates, m => m.Name.Value == "ShowMessage");
        Assert.True(candidates.Length < all.Length, "The candidate filter excluded nothing at all.");
    }

    // THE equivalence: on a clean assembly every candidate has a readable body, so the candidate count is exactly the
    // method total the report publishes. This is the measurement the spec demanded before accepting the split.
    [Fact]
    public void Methods_OnACleanAssembly_CountEqualsMethodsTotal()
    {
        using var assembly = Load();

        var result = new CapabilityAnalysis(assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);

        Assert.Equal(assembly.Methods.Count(), result.Value.MethodsTotal);
        Assert.Equal(0, result.Value.MethodsSkipped);
    }

    // The same equivalence over genuine, EH-heavy production IL rather than a hand-written fixture — a second,
    // independent assembly, so the equality is a property of the predicate and not of one curated input.
    [Fact]
    public void Methods_OnRealRuntimeAssembly_CountEqualsMethodsTotal()
    {
        var create = AssemblyAnalyzer.Load(typeof(Silvergun.Runtime).Assembly.Location);
        Assert.True(create.IsSuccess, create.Message);
        using var assembly = create.Value;

        var result = new CapabilityAnalysis(assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);

        Assert.Equal(assembly.Methods.Count(), result.Value.MethodsTotal);
    }

    // Enumerating the candidate set must not read a single body — that is the entire point of the split, and it is
    // what makes a hostile body a one-method problem. Proven on the input designed to break it: enumerating the
    // PATCHED assembly (whose Shapes.Loop body cannot be read) must complete without throwing, where the old
    // Body-dereferencing filter threw here and cost the caller the whole assembly.
    [Fact]
    public void Methods_EnumerationDoesNotReadBodies_EvenWhenOneIsUnreadable()
    {
        using var fixture = new UnreadableMethodBodyFixture();

        var thrown = Record.Exception(() => fixture.Patched.Methods.ToArray());

        Assert.Null(thrown);
        Assert.Equal(fixture.Clean.Methods.Count(), fixture.Patched.Methods.Count());
    }

    private static AssemblyAnalyzer Load()
    {
        var result = AssemblyAnalyzer.Load(typeof(Shapes).Assembly.Location);
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }
}
