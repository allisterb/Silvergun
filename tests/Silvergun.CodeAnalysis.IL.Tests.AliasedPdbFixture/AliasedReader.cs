extern alias CapFixture;

namespace Silvergun.CodeAnalysis.IL.Tests.AliasedPdbFixture;

/// <summary>
/// The one method of the PDB-reader regression fixture. The <c>extern alias</c> above puts an AliasAssemblyReference
/// import (naming the AssemblyRef row of <c>Silvergun.CodeAnalysis.IL.Tests.IndicatorCapFixture</c>) into this
/// assembly's portable PDB; the <c>typeof</c> keeps that reference in the metadata. <see cref="LocalName"/> is the
/// source name of the local below, which Model reports only when the PDB was read. Never called.
/// </summary>
public static class AliasedReader
{
    /// <summary>The source name of <see cref="Read"/>'s local.</summary>
    public const string LocalName = "aliasedPdbLocal";

    public static int Read()
    {
        var aliasedPdbLocal = typeof(CapFixture::Silvergun.CodeAnalysis.IL.Tests.IndicatorCapFixture.IndicatorCapPayloads).Name.Length;
        return aliasedPdbLocal + 1;
    }
}
