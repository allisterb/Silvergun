// Ported from OSSGadget (oss-find-squats-lib), (c) Microsoft Corporation, MIT License.
// Copy authorized 2026-07-16. Source: reference/projects/OSSGadget-main/src/oss-find-squats-lib/Mutators/MutatorType.cs
namespace Silvergun.PackageAnalysis.NuGet.Squats;

/// <summary>An enum used by classes that implement <see cref="IMutator"/> to specify which kind they are.</summary>
public enum MutatorType
{
    /// <summary>The value has not been set.</summary>
    Unspecified,
    /// <summary>A mutator which was not included with the ported OSSGadget set.</summary>
    Custom,
    AddCharacter,
    AddContainingCharacter,
    AsciiHomoglyph,
    BitFlip,
    CloseLetters,
    DoubleHit,
    Duplicator,
    NamespaceInName,
    Prefix,
    RemovedCharacter,
    RemovedNamespace,
    RemoveSeparatedSection,
    ReplaceCharacter,
    SeparatorChanged,
    SeparatorRemoved,
    Substitution,
    Suffix,
    SwapOrderOfLetters,
    UnicodeHomoglyph,
    VowelSwap
}
