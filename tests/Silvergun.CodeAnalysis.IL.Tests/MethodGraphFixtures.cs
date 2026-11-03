namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using ModelBytecode = Model.Bytecode;
using ModelTypes = Model.Types;

/// <summary>
/// One call-site instruction of an indexed body, read <b>independently of <see cref="MethodGraph"/></b> straight
/// from Analysis.Net's bytecode, so the graph's own bookkeeping can be checked against it.
/// </summary>
public sealed record ModelCallSite(MemberIndex.IndexedMethod Caller, uint Offset, ModelTypes.IMethodReference Target, MethodEdgeKind Kind)
{
    #region Properties
    /// <summary>The node id of the reference exactly as written at the site (instantiation and all).</summary>
    public string ReferenceNodeId => CanonicalName.NodeId(ModelNames.Of(Target));

    /// <summary>The name of the assembly that declares the reference's type, or null if unreadable.</summary>
    public string? DeclaringAssembly => Target.ContainingType?.ContainingAssembly?.Name;

    /// <summary>
    /// Whether the instruction dispatches virtually (<c>callvirt</c>, <c>ldvirtftn</c>) — the
    /// <c>virtualSite</c> argument of <see cref="MemberIndex.DispatchTargets"/>.
    /// </summary>
    public bool IsVirtual => Kind is MethodEdgeKind.CallVirt or MethodEdgeKind.Ldvirtftn;

    /// <summary>What <see cref="MemberIndex.DispatchTargets"/> answers for this site in <paramref name="index"/>.</summary>
    public IReadOnlyList<string>? DispatchTargets(MemberIndex index) => index.DispatchTargets(Target, index.Resolve(Target), IsVirtual);
    #endregion

    #region Methods
    /// <summary>Every call/callvirt/newobj/ldftn/ldvirtftn in every bodied method of <paramref name="index"/>, in index then IL order.</summary>
    public static IReadOnlyList<ModelCallSite> All(MemberIndex index) =>
        [.. index.Methods.Where(m => m.Definition.HasBody).SelectMany(Of)];

    /// <summary>The number of <c>calli</c> instructions in every bodied method of <paramref name="index"/>.</summary>
    public static int IndirectCalls(MemberIndex index) =>
        index.Methods.Where(m => m.Definition.HasBody)
            .Sum(m => m.Definition.Body.Instructions.Count(i => i is ModelBytecode.IndirectMethodCallInstruction));

    private static IEnumerable<ModelCallSite> Of(MemberIndex.IndexedMethod caller) =>
        caller.Definition.Body.Instructions.OfType<ModelBytecode.Instruction>().Select(i => i switch
        {
            ModelBytecode.MethodCallInstruction call => new ModelCallSite(caller, i.Offset, call.Method,
                call.Operation == ModelBytecode.MethodCallOperation.Virtual ? MethodEdgeKind.CallVirt : MethodEdgeKind.Call),
            ModelBytecode.CreateObjectInstruction create => new ModelCallSite(caller, i.Offset, create.Constructor, MethodEdgeKind.NewObj),
            ModelBytecode.LoadMethodAddressInstruction load => new ModelCallSite(caller, i.Offset, load.Method,
                load.Operation == ModelBytecode.LoadMethodAddressOperation.Virtual ? MethodEdgeKind.Ldvirtftn : MethodEdgeKind.Ldftn),
            _ => null,
        }).OfType<ModelCallSite>();
    #endregion
}

/// <summary>
/// Shared xUnit class fixture: both mechanism-fixture assemblies (<c>MechanismFixture</c> + <c>.Dependency</c>)
/// loaded with <see cref="AssemblyDisassembler"/>, indexed TOGETHER, and the A1 static graph built over them with the
/// default budget. Read as metadata only — nothing in the fixture is executed.
/// </summary>
public sealed class MechanismMethodGraphFixture : IDisposable
{
    #region Constructors
    public MechanismMethodGraphFixture()
    {
        Assemblies = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        try
        {
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
            Sites = ModelCallSite.All(Index);
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

    /// <summary>Every call site of the indexed bodies, read independently of the graph.</summary>
    public IReadOnlyList<ModelCallSite> Sites { get; }
    #endregion

    #region Methods
    /// <summary>The call sites in the own method <paramref name="callerNodeId"/> whose reference names <paramref name="referenceNodeId"/>.</summary>
    public IReadOnlyList<ModelCallSite> SitesIn(string callerNodeId, string referenceNodeId) =>
        [.. Sites.Where(s => s.Caller.NodeId == callerNodeId && s.ReferenceNodeId == referenceNodeId)];

    public void Dispose() => Assemblies.Dispose();
    #endregion
}

/// <summary>
/// The shared netstandard2.0 fixture (<c>Silvergun.CodeAnalysis.IL.Tests.Fixture</c>) indexed on its own: unlike the
/// mechanism fixture it calls own generic types through instantiations whose PARAMETERS are substituted
/// (<c>GenericBox&lt;string&gt;.Holds(string)</c>), the case that needs <see cref="ResolutionKind.Substituted"/>.
/// </summary>
public sealed class SharedFixtureMethodGraphFixture : IDisposable
{
    #region Constructors
    public SharedFixtureMethodGraphFixture()
    {
        Assemblies = ModelAssemblies.Load(Path);
        try
        {
            Index = Assemblies.Index();
            Sites = ModelCallSite.All(Index);
        }
        catch (Exception)
        {
            Assemblies.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public static string Path => typeof(Shapes).Assembly.Location;

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }
    #endregion

    #region Methods
    public void Dispose() => Assemblies.Dispose();
    #endregion
}
