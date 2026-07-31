namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

/// <summary>
/// Builds the <b>unreadable caller name</b> fixture at test time — the in-repo equivalent of the ILSpy spike's
/// <c>05-badname.dll</c> (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §2.2.2, §6). It copies a real,
/// project-built assembly and overwrites exactly one <c>MethodDef.Name</c> column with a <c>#Strings</c> offset
/// that lies past the end of the heap, so that method's name cannot be read while every other byte of the image
/// is untouched. Same discipline as <see cref="Silvergun.Tests.Shared.FatHeaderPatcher"/> and
/// <see cref="CyclicEnumPatcher"/>: <b>no crafted binary is committed</b>, so the fixture cannot rot against a
/// recompile and there is no opaque blob in the repo.
/// <para>
/// <b>What the corruption does.</b> ECMA-335 II.22.26: a <c>MethodDef</c> row is
/// <c>RVA(4) | ImplFlags(2) | Flags(2) | Name(#Strings index) | Signature(#Blob index) | ParamList(Param index)</c>,
/// so <c>Name</c> begins at row offset 8. CCI reads it through
/// <c>StringStreamReader</c> → <c>MemoryReader.PeekUTF8NullTerminated</c>
/// (<c>ext/analysis-net/cci/PEReaderAndWriter/PEReader/UnmanagedReadWrite.cs:582</c>), which returns
/// <b><c>""</c></b> — not an exception — for an offset at or past the heap's end. That is precisely the
/// degradation the spike measured: the finding survives, attributed to its declaring type, with an empty method
/// name.
/// </para>
/// <para>
/// <b>Why the value differs from the spike's.</b> <c>05-badname</c> used <c>0x70000000</c>, which is only
/// representable when <c>#Strings</c> exceeds 64 KB and the column widens to 4 bytes — the reason that input had
/// to be built on a 2,201-method image. Our fixtures are small, so the column is 2 bytes and the largest
/// representable index, <c>0xFFFF</c>, is used instead. Both are "past the end of the heap", which is the only
/// property the failure mode depends on; the width is confirmed per image rather than assumed, and an index that
/// would land <em>inside</em> the heap is a hard error rather than a silently harmless patch.
/// </para>
/// </summary>
public static class UnreadableMethodNamePatcher
{
    #region Methods
    /// <summary>
    /// Writes <paramref name="targetPath"/> as a copy of <paramref name="sourcePath"/> in which
    /// <paramref name="declaringTypeName"/>.<paramref name="methodName"/> has an unreadable name, and returns the
    /// target path. Type and method names are the bare metadata names (no namespace).
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The method is not found exactly once, the <c>MethodDef</c> row layout cannot be confirmed, the
    /// out-of-range index does not fit the <c>Name</c> column, or the written image does not read back as
    /// intended — never a silently unpatched copy.
    /// </exception>
    public static string WriteCopyWithUnreadableMethodName(
        string sourcePath, string targetPath, string declaringTypeName, string methodName)
    {
        var image = File.ReadAllBytes(sourcePath);

        // Planned against the pristine image and applied afterwards: the plan holds a MetadataReader over the
        // buffer, and mutating it underneath one would invalidate the reader.
        var edit = Plan(image, declaringTypeName, methodName);
        Write(image, edit.Offset, edit.Width, edit.Value);
        Verify(image, edit.RowNumber, edit.Value, declaringTypeName);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(targetPath))!);
        File.WriteAllBytes(targetPath, image);
        return targetPath;
    }

    // The single edit: where the Name column of the target row lives, how wide it is, and the out-of-range
    // #Strings index to write over it.
    private static (int RowNumber, int Offset, int Width, uint Value) Plan(
        byte[] image, string declaringTypeName, string methodName)
    {
        using var stream = new MemoryStream(image, writable: false);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();

        var matches = metadata.MethodDefinitions
            .Where(handle =>
                metadata.GetString(metadata.GetMethodDefinition(handle).Name) == methodName &&
                metadata.GetString(metadata.GetTypeDefinition(metadata.GetMethodDefinition(handle).GetDeclaringType()).Name) == declaringTypeName)
            .ToArray();

        if (matches.Length != 1)
        {
            throw new InvalidOperationException(
                $"Expected exactly one method '{declaringTypeName}.{methodName}', found {matches.Length}. "
                + "The patcher must corrupt one known method, so an ambiguous or absent target is a hard error.");
        }

        var handle = matches[0];
        var rowSize = metadata.GetTableRowSize(TableIndex.MethodDef);
        var tableStart = pe.PEHeaders.MetadataStartOffset + metadata.GetTableMetadataOffset(TableIndex.MethodDef);
        var rowNumber = MetadataTokens.GetRowNumber(handle);
        var offset = tableStart + ((rowNumber - 1) * rowSize) + FixedColumnWidth;
        var width = NameColumnWidth(metadata, image, tableStart, rowSize, handle);

        // The index must land PAST the heap: at or beyond its length is what makes the read return "" instead
        // of some other, still-readable string, which would make the fixture prove nothing.
        var heapSize = (uint)metadata.GetHeapSize(HeapIndex.String);
        var value = width == 2 ? ushort.MaxValue : OutOfRangeWideIndex;
        if (value < heapSize)
        {
            throw new InvalidOperationException(
                $"The largest index the {width}-byte Name column can hold (0x{value:X}) still lands inside the "
                + $"{heapSize}-byte #Strings heap, so the name would remain readable. Use a smaller fixture.");
        }

        return (rowNumber, offset, width, value);
    }

    // Confirms the width of the Name column (2 or 4 bytes, depending on whether #Strings exceeds 64 KB) by
    // reading the probe row back at every layout consistent with the row size and requiring BOTH heap indices to
    // round-trip to what MetadataReader reports. A wrong width would corrupt an unrelated column and make the
    // fixture meaningless, so an unconfirmable or ambiguous layout is a hard error rather than a guess.
    private static int NameColumnWidth(
        MetadataReader metadata, byte[] image, int tableStart, int rowSize, MethodDefinitionHandle probe)
    {
        var definition = metadata.GetMethodDefinition(probe);
        var row = tableStart + ((MetadataTokens.GetRowNumber(probe) - 1) * rowSize);

        var widths =
            (from name in IndexWidths
             from signature in IndexWidths
             from parameters in IndexWidths
             where FixedColumnWidth + name + signature + parameters == rowSize
             where Read(image, row + FixedColumnWidth, name) == (uint)MetadataTokens.GetHeapOffset(definition.Name)
             where Read(image, row + FixedColumnWidth + name, signature) == (uint)MetadataTokens.GetHeapOffset(definition.Signature)
             select name)
            .Distinct()
            .ToArray();

        return widths.Length == 1
            ? widths[0]
            : throw new InvalidOperationException(
                $"Could not confirm the MethodDef Name column width (row size {rowSize}, {widths.Length} candidate "
                + $"layouts) for '{metadata.GetString(definition.Name)}'.");
    }

    // Re-reads the WRITTEN bytes and requires the target's name index to be exactly the out-of-range value, its
    // declaring type name to still be readable (attribution is what the tests are about), and no other method's
    // name to have been disturbed. This is what makes "the name is unreadable" a measurement, not an assumption.
    private static void Verify(byte[] image, int rowNumber, uint value, string declaringTypeName)
    {
        using var stream = new MemoryStream(image, writable: false);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();

        var handle = MetadataTokens.MethodDefinitionHandle(rowNumber);
        var definition = metadata.GetMethodDefinition(handle);

        if ((uint)MetadataTokens.GetHeapOffset(definition.Name) != value)
        {
            throw new InvalidOperationException(
                $"The patch did not take: row {rowNumber}'s Name index reads "
                + $"0x{MetadataTokens.GetHeapOffset(definition.Name):X}, expected 0x{value:X}.");
        }

        var declaring = metadata.GetString(metadata.GetTypeDefinition(definition.GetDeclaringType()).Name);
        if (declaring != declaringTypeName)
        {
            throw new InvalidOperationException(
                $"The patch hit the wrong row: its declaring type is '{declaring}', expected '{declaringTypeName}'.");
        }

        var unreadable = metadata.MethodDefinitions.Count(h => !CanReadName(metadata, h));
        if (unreadable != 1)
        {
            throw new InvalidOperationException(
                $"Expected exactly one unreadable method name after patching, found {unreadable}. The corruption "
                + "must be scoped to a single method or the tests built on it prove nothing.");
        }
    }

    private static bool CanReadName(MetadataReader metadata, MethodDefinitionHandle handle)
    {
        try
        {
            return metadata.GetString(metadata.GetMethodDefinition(handle).Name).Length >= 0;
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }

    private static uint Read(byte[] image, int offset, int width) =>
        width == 2 ? BitConverter.ToUInt16(image, offset) : BitConverter.ToUInt32(image, offset);

    private static void Write(byte[] image, int offset, int width, uint value)
    {
        if (width == 2) BitConverter.GetBytes((ushort)value).CopyTo(image, offset);
        else BitConverter.GetBytes(value).CopyTo(image, offset);
    }
    #endregion

    #region Fields
    // ECMA-335 II.22.26: RVA (4) + ImplFlags (2) + Flags (2) precede the Name column in every MethodDef row.
    private const int FixedColumnWidth = 8;

    // A heap index is 2 bytes until its heap exceeds 64 KB, then 4 — which of the two applies is confirmed per
    // image rather than assumed.
    private static readonly int[] IndexWidths = [2, 4];

    // The spike's own value, used when the column really is 4 bytes wide. Kept positive as a signed 32-bit
    // integer for the same reason FatHeaderPatcher keeps its CodeSize positive.
    private const uint OutOfRangeWideIndex = 0x7000_0000;
    #endregion
}
