// The NuGetMutators preset is reproduced from OSSGadget (oss-find-squats-lib/MutateExtension.cs),
// (c) Microsoft Corporation, MIT License. Copy authorized 2026-07-16.
// Source: reference/projects/OSSGadget-main/src/oss-find-squats-lib/MutateExtension.cs
namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System.Collections.Generic;
using System.Linq;

/// <summary>The NuGet-tuned mutator presets ported from OSSGadget's <c>MutateExtension</c>.</summary>
internal static class NuGetMutators
{
    #region Properties
    /// <summary>The default set of mutators for an arbitrary package feed.</summary>
    public static IReadOnlyList<IMutator> BaseMutators { get; } = new IMutator[]
    {
        new AddCharacterMutator(),
        new AddContainingCharacterMutator(),
        new AsciiHomoglyphMutator(),
        new BitFlipMutator(),
        new CloseLettersMutator(),
        new DoubleHitMutator(),
        new DuplicatorMutator(),
        new NamespaceInNameMutator(),
        new PrefixMutator(),
        new RemovedCharacterMutator(),
        new RemoveNamespaceMutator(),
        new RemoveSeparatedSectionMutator(),
        new ReplaceCharacterMutator(),
        new SeparatorChangedMutator(),
        new SeparatorRemovedMutator(),
        new SuffixMutator(),
        new SwapOrderOfLettersMutator(),
        new UnicodeHomoglyphMutator(),
        new VowelSwapMutator()
    };

    /// <summary>
    /// Variations tuned for NuGet/C#. Follows OSSGadget's tuning: excludes <see cref="UnicodeHomoglyphMutator"/>,
    /// re-adds <see cref="CloseLettersMutator"/>/<see cref="DoubleHitMutator"/> that ignore '/', and adds the
    /// <c>net</c>/<c>.net</c>/<c>nuget</c>/<c>core</c>/<c>.core</c> suffixes while skipping the trailing-'.' suffix.
    /// </summary>
    /// <remarks>
    /// Deviations from OSSGadget's literal preset, both implementing the documented "excludes '.'-separator
    /// mutation" intent (NuGet treats "Foo.Bar." == "Foo.Bar", so a dot-separator swap is a same-package false
    /// positive): the <see cref="SeparatorChangedMutator"/> drops '.' from its separators, and the
    /// <see cref="ReplaceCharacterMutator"/> drops the alternate separators '-'/'_' from its replacement set so it
    /// cannot re-create a dot-separator swap (e.g. "Foo.Bar" => "Foo-Bar"). Dot removal ("Foo.Bar" => "FooBar")
    /// via <see cref="SeparatorRemovedMutator"/> is retained — it is a genuine distinct id.
    /// </remarks>
    public static IReadOnlyList<IMutator> Nuget { get; } = BaseMutators
        .Where(x => x is not UnicodeHomoglyphMutator
                     and not SuffixMutator
                     and not CloseLettersMutator
                     and not DoubleHitMutator
                     and not SeparatorChangedMutator
                     and not ReplaceCharacterMutator)
        .Concat(new IMutator[]
        {
            new CloseLettersMutator(additionalExcludedChars: new[] { '/' }),
            new DoubleHitMutator(additionalExcludedChars: new[] { '/' }),
            new SuffixMutator(additionalSuffixes: new[] { "net", ".net", "nuget", "core", ".core" }, skipSuffixes: new[] { "." }),
            new SeparatorChangedMutator(overrideSeparators: new[] { '-', '_' }),
            new ReplaceCharacterMutator(skipChars: new[] { '-', '_' })
        })
        .ToArray();
    #endregion
}
