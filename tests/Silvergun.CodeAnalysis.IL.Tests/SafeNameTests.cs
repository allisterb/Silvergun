namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

using Microsoft.Cci;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// Direct coverage for <see cref="AssemblyAnalyzer.SafeName"/>, the best-effort method-naming seam hoisted out of
/// two identical private copies (one in <c>CapabilityAnalysis</c>, one in <c>ObfuscationAnalysis</c>) into one
/// <c>public static</c> member.
/// <para>
/// It exists because <c>method.Name.Value</c> is itself a metadata read a crafted module can make throw, and it is
/// called from inside guards that are <em>already reporting a failure</em> — a throw there escapes the per-method
/// guard and costs the whole assembly, which is exactly the defect
/// <c>docs/agent/tasks/per-method-body-read-granularity.md</c> was written to remove. So "never throws" is the
/// contract, not an implementation detail.
/// </para>
/// <para>
/// The failing case cannot be reached through a real module (CCI tolerates a corrupt <c>MethodDef.Name</c>
/// string-heap index — measured in the spec, <c>MethodsSkipped: 0</c>), so it is driven through a
/// <see cref="DispatchProxy"/> standing in for an <see cref="IMethodDefinition"/> whose metadata reads throw. That
/// is the reason the seam was made public in the first place.
/// </para>
/// </summary>
public sealed class SafeNameTests
{
    #region Constructors
    public SafeNameTests() => Runtime.Initialize("Silvergun", "TESTS");
    #endregion

    #region Methods — the seam itself
    // The ordinary case: a well-formed method is named by its own metadata, not by the fallback. Asserted against
    // method.Name.Value read directly rather than a literal, so it states "SafeName is transparent when the read
    // succeeds" instead of restating one fixture method's name.
    [Fact]
    public void SafeName_OnWellFormedMethod_ReturnsTheMethodName()
    {
        using var assembly = LoadFixture();
        var method = AllMethods(assembly).First(m => m.Name.Value == "Loop");

        Assert.Equal(method.Name.Value, AssemblyAnalyzer.SafeName(method));
        Assert.Equal("Loop", AssemblyAnalyzer.SafeName(method));
    }

    // Transparency must not depend on the method having a body: SafeName is called on P/Invoke and abstract
    // declarations too (the interop seam names every declaration it drops), and those never reach TryReadBody.
    [Theory]
    [InlineData("Mark")]            // ICanonicalMarker.Mark — abstract
    [InlineData("ShowMessage")]     // NativeInteropOps.ShowMessage — [DllImport], external
    public void SafeName_OnBodylessMethod_StillReturnsTheMethodName(string methodName)
    {
        using var assembly = LoadFixture();
        var method = AllMethods(assembly).First(m => m.Name.Value == methodName);

        Assert.Equal(methodName, AssemblyAnalyzer.SafeName(method));
    }

    // THE failure mode: the name read throws. SafeName must swallow it and yield the token — if the exception
    // escaped, it would escape the very guard that called SafeName to report a different failure.
    [Fact]
    public void SafeName_WhenTheNameReadThrows_ReturnsTheUnreadableTokenWithoutThrowing()
    {
        var method = ThrowingMethodDefinition.Create();

        var thrown = Record.Exception(() => AssemblyAnalyzer.SafeName(method));

        Assert.Null(thrown);
        Assert.Equal(UnreadableToken, AssemblyAnalyzer.SafeName(method));
    }

    // The same contract one dereference further along: method.Name resolves, but reading its Value throws. Both
    // halves of "method.Name.Value" are metadata reads, and only covering the first would leave the second — the
    // one that actually touches the string heap — untested.
    [Fact]
    public void SafeName_WhenTheNameValueReadThrows_ReturnsTheUnreadableTokenWithoutThrowing()
    {
        var method = ThrowingNameValueMethodDefinition.Create();

        var thrown = Record.Exception(() => AssemblyAnalyzer.SafeName(method));

        Assert.Null(thrown);
        Assert.Equal(UnreadableToken, AssemblyAnalyzer.SafeName(method));
    }

    // The token is a contract with whoever reads a skip reason or a warning, so it is pinned literally: it must be
    // visibly not-a-method-name (the angle brackets are what stop it colliding with a real identifier) and it must
    // never be empty, which would render as a blank where a method name belongs.
    [Fact]
    public void SafeName_UnreadableToken_IsTheAngleBracketedSentinel()
    {
        Assert.Equal("<unreadable>", AssemblyAnalyzer.SafeName(ThrowingMethodDefinition.Create()));
    }
    #endregion

    #region Methods — the hoist cannot silently diverge
    // The point of the hoist: ONE implementation, so the two consumers cannot drift apart. The fallback token is a
    // const, which the C# compiler inlines as an ldstr at every use site — so if either consumer ever reacquires a
    // private copy of the fallback, the literal reappears in that consumer's IL. Read out of the shipped assembly
    // with Silvergun's own analyzer, which is the only way to see a const after compilation.
    //
    // This carries one dependency on the source: AssemblyAnalyzer.UnreadableName must stay PRIVATE. Const
    // inlining happens at the CONSUMER's use site, so widening it to public/internal — for instance so this file
    // could reference it instead of re-declaring UnreadableToken below — would emit an ldstr into every
    // referencing type and fail this test on entirely correct code. Read such a failure as that, not as a real
    // divergence. The guard is otherwise robust: were the const to become a static readonly field, the ldstr
    // simply moves to AssemblyAnalyzer's own cctor, which is still AssemblyAnalyzer, and the assertion holds.
    [Fact]
    public void SafeName_UnreadableToken_IsLoadedOnlyByAssemblyAnalyzer()
    {
        using var self = LoadAnalysisAssembly();

        var loaders = TypesLoadingString(self, UnreadableToken).ToArray();

        Assert.Equal([AnalyzerType], loaders);
    }

    // The other direction: both consumers must actually go THROUGH the seam. Without this, the test above would
    // still pass for a consumer that dropped the fallback entirely and let method.Name.Value throw out of its
    // guard — the original defect, reintroduced.
    [Theory]
    [InlineData(CapabilityType)]
    [InlineData(ObfuscationType)]
    public void SafeName_BothConsumers_CallTheSharedSeam(string consumerType)
    {
        using var self = LoadAnalysisAssembly();

        var callers = MethodsOf(self, consumerType)
            .Where(m => Operations(m).Any(IsSafeNameCall))
            .Select(m => m.Name.Value)
            .ToArray();

        Assert.NotEmpty(callers);
    }
    #endregion

    #region Methods — helpers
    private static AssemblyAnalyzer LoadFixture() => Load(typeof(Shapes).Assembly.Location);

    private static AssemblyAnalyzer LoadAnalysisAssembly() => Load(typeof(AssemblyAnalyzer).Assembly.Location);

    private static AssemblyAnalyzer Load(string path)
    {
        var result = AssemblyAnalyzer.Load(path);
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }

    private static IEnumerable<IMethodDefinition> AllMethods(AssemblyAnalyzer assembly) =>
        assembly.Module.GetAllTypes().SelectMany(type => type.Methods);

    // Every method declared by the named type OR by a type nested inside it (closures and iterator/async state
    // machines are nested types, and a lambda is exactly where a duplicated fallback could hide).
    private static IEnumerable<IMethodDefinition> MethodsOf(AssemblyAnalyzer assembly, string typeFullName) =>
        assembly.Module.GetAllTypes()
            .Where(type => IsOrIsNestedIn(AssemblyAnalyzer.TypeName(type), typeFullName))
            .SelectMany(type => type.Methods);

    private static bool IsOrIsNestedIn(string typeName, string outer) =>
        typeName == outer || typeName.StartsWith(outer + ".", StringComparison.Ordinal);

    // The distinct declaring types (outermost name) whose IL contains `ldstr value`, ordered for a stable message.
    private static IEnumerable<string> TypesLoadingString(AssemblyAnalyzer assembly, string value) =>
        assembly.Module.GetAllTypes()
            .SelectMany(type => type.Methods.SelectMany(Operations)
                .Where(op => op.OperationCode == OperationCode.Ldstr && (op.Value as string) == value)
                .Select(_ => AssemblyAnalyzer.TypeName(type)))
            .Select(Outermost)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);

    // "Ns.Outer.<>c" -> "Ns.Outer": a compiler-generated nested type is attributed to the type that declares it,
    // so a lambda in a consumer is reported as that consumer rather than as a name no reader would recognise.
    private static string Outermost(string typeName) =>
        typeName.Contains(".<", StringComparison.Ordinal)
            ? typeName[..typeName.IndexOf(".<", StringComparison.Ordinal)]
            : typeName;

    // Guarded, because this walks a whole real assembly: a body that cannot be read contributes no operations
    // rather than failing the test with an exception from CCI.
    private static IEnumerable<IOperation> Operations(IMethodDefinition method) =>
        AssemblyAnalyzer.TryReadBody(method) is { Body: { } body } ? body.Operations : [];

    private static bool IsSafeNameCall(IOperation op) =>
        op.OperationCode == OperationCode.Call &&
        op.Value is IMethodReference callee &&
        callee.Name.Value == nameof(AssemblyAnalyzer.SafeName) &&
        AssemblyAnalyzer.TypeName(callee.ContainingType) == AnalyzerType;
    #endregion

    #region Fields
    private const string UnreadableToken = "<unreadable>";

    private const string AnalyzerType = "Silvergun.CodeAnalysis.IL.AssemblyAnalyzer";
    private const string CapabilityType = "Silvergun.CodeAnalysis.IL.CapabilityAnalysis";
    private const string ObfuscationType = "Silvergun.CodeAnalysis.IL.ObfuscationAnalysis";
    #endregion

    #region Child types
    /// <summary>
    /// An <see cref="IMethodDefinition"/> whose every metadata read throws — the shape a crafted module presents to
    /// a guard that is trying to name the method it is already failing on. Built with
    /// <see cref="DispatchProxy"/> because CCI's interface is far too wide to hand-implement and only one member
    /// matters here.
    /// </summary>
    public class ThrowingMethodDefinition : DispatchProxy
    {
        public static IMethodDefinition Create() => DispatchProxy.Create<IMethodDefinition, ThrowingMethodDefinition>();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
            throw new BadImageFormatException($"metadata read of '{targetMethod?.Name}' failed.");
    }

    /// <summary>
    /// The one-dereference-later variant: <c>Name</c> resolves to an <see cref="IName"/> whose <c>Value</c> throws.
    /// </summary>
    public class ThrowingNameValueMethodDefinition : DispatchProxy
    {
        public static IMethodDefinition Create() =>
            DispatchProxy.Create<IMethodDefinition, ThrowingNameValueMethodDefinition>();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
            targetMethod?.Name == "get_Name"
                ? DispatchProxy.Create<IName, ThrowingName>()
                : throw new BadImageFormatException($"metadata read of '{targetMethod?.Name}' failed.");
    }

    /// <summary>An <see cref="IName"/> whose string heap read throws.</summary>
    public class ThrowingName : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
            throw new BadImageFormatException($"string heap read of '{targetMethod?.Name}' failed.");
    }
    #endregion
}
