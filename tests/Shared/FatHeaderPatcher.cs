namespace Silvergun.Tests.Shared;

using System;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

/// <summary>
/// Builds the hostile fixture for <c>docs/agent/tasks/per-method-body-read-granularity.md</c> at <b>test time</b>:
/// copies a real, project-built assembly and corrupts exactly one method's IL so its body cannot be read, leaving
/// every other method byte-identical. A corrupt binary is deliberately NOT committed — it is derived from a fixture
/// the build already produces, so it cannot rot against a recompile and there is no opaque blob in the repo.
/// <para>
/// The corruption is the one the spec measured as reaching <c>MethodDefinition.get_Body</c>: an out-of-range
/// <b>fat-header <c>CodeSize</c></b>. A method body begins with either a tiny header (one byte, low two bits
/// <c>0b10</c>) or a fat header (low two bits <c>0b11</c>) whose layout is
/// <c>[flags+size:2][MaxStack:2][CodeSize:4][LocalVarSigTok:4]</c> — so <c>CodeSize</c> sits at header offset 4
/// (ECMA-335 II.25.4.3). Writing a value that runs past the section makes CCI's
/// <c>MemoryReader.GetMemoryBlockAt</c> throw out of <c>PEFileReader.GetMethodIL</c>, which is exactly the
/// per-method read the analyses now guard.
/// </para>
/// <para>
/// The metadata is untouched, so the file still loads: the failure is scoped to one body, which is the point —
/// it distinguishes "one method skipped" from "the whole assembly lost".
/// </para>
/// <para>Shared by <c>Silvergun.CodeAnalysis.IL.Tests</c> and <c>Silvergun.CLI.Tests</c> via a linked
/// <c>&lt;Compile&gt;</c> item, so the two suites corrupt the input identically rather than keeping two
/// copies of the offset arithmetic that could drift apart.</para>
/// </summary>
public static class FatHeaderPatcher
{
    /// <summary>
    /// The value written over <c>CodeSize</c>. Large enough to run past the end of any real text section (so the
    /// read fails) while staying positive as a signed 32-bit integer, which keeps the failure an ordinary
    /// out-of-range argument rather than a negative-length path that a reader might handle differently.
    /// </summary>
    public const uint OutOfRangeCodeSize = 0x7FFF_FFF0;

    /// <summary>
    /// Writes <paramref name="targetPath"/> as a copy of <paramref name="sourcePath"/> in which
    /// <paramref name="declaringTypeName"/>.<paramref name="methodName"/> has an unreadable body, and returns the
    /// target path. Throws <see cref="InvalidOperationException"/> — never silently produces an unpatched copy —
    /// when the method is not found exactly once, has no IL body, or carries a tiny header (a tiny header has no
    /// <c>CodeSize</c> field to corrupt; pick a method with locals or exception handling instead).
    /// </summary>
    public static string WriteCopyWithUnreadableBody(
        string sourcePath, string targetPath, string declaringTypeName, string methodName)
    {
        var image = File.ReadAllBytes(sourcePath);
        var header = FatHeaderOffset(image, declaringTypeName, methodName);

        BitConverter.GetBytes(OutOfRangeCodeSize).CopyTo(image, header + CodeSizeFieldOffset);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(targetPath))!);
        File.WriteAllBytes(targetPath, image);
        return targetPath;
    }

    /// <summary>
    /// File offset of the fat method header of the single method definition named
    /// <paramref name="declaringTypeName"/>.<paramref name="methodName"/>.
    /// </summary>
    private static int FatHeaderOffset(byte[] image, string declaringTypeName, string methodName)
    {
        using var stream = new MemoryStream(image, writable: false);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();

        var matches = metadata.MethodDefinitions
            .Select(metadata.GetMethodDefinition)
            .Where(definition =>
                definition.RelativeVirtualAddress != 0 &&
                metadata.GetString(definition.Name) == methodName &&
                metadata.GetString(metadata.GetTypeDefinition(definition.GetDeclaringType()).Name) == declaringTypeName)
            .ToArray();

        if (matches.Length != 1)
        {
            throw new InvalidOperationException(
                $"Expected exactly one method '{declaringTypeName}.{methodName}' with an IL body, found {matches.Length}. "
                + "The patcher must corrupt one known method, so an ambiguous or absent target is a hard error.");
        }

        var offset = FileOffset(pe, matches[0].RelativeVirtualAddress);
        if ((image[offset] & MethodHeaderKindMask) != FatMethodHeader)
        {
            throw new InvalidOperationException(
                $"'{declaringTypeName}.{methodName}' has a TINY method header (0x{image[offset]:X2}), which encodes its "
                + "code size in the header byte itself and has no CodeSize field to corrupt. Choose a method with "
                + "locals, exception handling, or a body of 64+ bytes.");
        }

        return offset;
    }

    /// <summary>Section-relative RVA to raw file offset, the standard PE mapping.</summary>
    private static int FileOffset(PEReader pe, int rva)
    {
        var index = pe.PEHeaders.GetContainingSectionIndex(rva);
        if (index < 0)
            throw new InvalidOperationException($"RVA 0x{rva:X} lies outside every PE section.");

        var section = pe.PEHeaders.SectionHeaders[index];
        return section.PointerToRawData + (rva - section.VirtualAddress);
    }

    // ECMA-335 II.25.4: the low two bits of the first header byte select the format, and CorILMethod_FatFormat
    // is 0b11 (the tiny format is 0b10). CodeSize is the 4 bytes at fat-header offset 4.
    private const int MethodHeaderKindMask = 0x03;
    private const int FatMethodHeader = 0x03;
    private const int CodeSizeFieldOffset = 4;
}
