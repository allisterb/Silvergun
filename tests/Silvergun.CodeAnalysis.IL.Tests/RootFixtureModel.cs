namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Model.Types;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// The root-class fixture (<see cref="RootFixtureAssemblies.Fixture"/>) loaded through the real loader, indexed
/// <b>alone</b> (its host stubs stay external), and its graph built with the built-in map.
/// </summary>
public sealed class RootFixtureModel : IDisposable
{
    #region Constructors
    public RootFixtureModel()
    {
        Assemblies = ModelAssemblies.Load(RootFixtureAssemblies.Fixture);
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

    /// <summary>Built with <see cref="CapabilityMap.Default"/>.</summary>
    public MethodGraph Graph { get; }
    #endregion

    #region Methods
    /// <summary>The single indexed definition of the type <paramref name="typeId"/> (fails loudly when absent or repeated).</summary>
    public ITypeDefinition Type(string typeId) =>
        Index.Types(typeId) is [var only] ? only.Definition : throw new InvalidOperationException($"'{typeId}' is indexed {Index.Types(typeId).Count} time(s), not once.");

    /// <summary>The single indexed definition with node id <paramref name="nodeId"/>.</summary>
    public MemberIndex.IndexedMethod Method(string nodeId) =>
        Index.Definitions(nodeId) is [var only] ? only : throw new InvalidOperationException($"'{nodeId}' is indexed {Index.Definitions(nodeId).Count} time(s), not once.");

    public void Dispose() => Assemblies.Dispose();
    #endregion
}
