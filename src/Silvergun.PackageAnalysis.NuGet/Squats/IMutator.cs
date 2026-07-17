// Ported from OSSGadget (oss-find-squats-lib), (c) Microsoft Corporation, MIT License.
// Copy authorized 2026-07-16. Source: reference/projects/OSSGadget-main/src/oss-find-squats-lib/Mutators/IMutator.cs
// The PackageURL/Generate(PackageURL) overload and the packageurl-dotnet dependency were dropped;
// only the pure, offline Generate(string) form is retained.
namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System.Collections.Generic;

/// <summary>A name-perturbation generator that models one typosquatting technique.</summary>
public interface IMutator
{
    #region Properties
    /// <summary>An enum specifying which kind of mutator this is.</summary>
    MutatorType Kind { get; }
    #endregion

    #region Methods
    /// <summary>Generates the typosquat mutations for a string.</summary>
    /// <param name="arg">The string to generate mutations for.</param>
    /// <returns>A sequence of mutations, each carrying the mutated name and the reason.</returns>
    IEnumerable<Mutation> Generate(string arg);
    #endregion
}
