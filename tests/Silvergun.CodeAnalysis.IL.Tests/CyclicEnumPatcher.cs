namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

/// <summary>
/// Builds the self-referential-enum fixture (<c>docs/agent/tasks/self-referential-enum-stack-overflow.md</c>,
/// <c>docs/agent/measurements/ilspy-provider-spike.md</c> §7) at <b>test time</b>, the same way
/// <see cref="Silvergun.Tests.Shared.FatHeaderPatcher"/> builds the unreadable-body fixture: it copies a real,
/// project-built assembly and edits exactly one metadata column per subject enum. No crafted binary is
/// committed, so the fixture cannot rot against a recompile and there is no opaque blob in the repo.
/// <para>
/// <b>What an enum's underlying type actually is.</b> ECMA-335 II.14.3: an enum's underlying type is the type
/// of its single instance field, <c>value__</c>. Nothing in the format requires that field to be a primitive,
/// so <c>value__ : valuetype E</c> — the enum itself — is representable, and CCI preserves the cycle rather
/// than resolving it. Roslyn will not emit it, which is why the spike hand-wrote IL.
/// </para>
/// <para>
/// <b>How this produces it without an IL assembler and without resizing anything.</b> The compiler already
/// emits the exact signature blob needed: every literal member of <c>enum E</c> is a static field of type
/// <c>E</c>, whose <c>FIELD</c> signature is <c>ELEMENT_TYPE_VALUETYPE</c> + <c>E</c>'s <c>TypeDef</c> token.
/// The patch is therefore a single <b>blob-heap index</b> written over <c>value__</c>'s <c>Signature</c>
/// column in the <c>Field</c> table (ECMA-335 II.22.15: <c>Flags(2) | Name | Signature</c>) — pointing it at
/// that already-present blob. No heap grows, no stream header or section size changes, and the blob itself is
/// never edited, so the only difference between the clean and patched images is one index per subject.
/// </para>
/// <para>
/// Every step is verified and hard-errors rather than silently producing an unpatched copy: the column offset
/// and its width are confirmed by reading the row back and requiring both indices to round-trip to the values
/// <c>MetadataReader</c> reports, <c>value__</c> must start out as a primitive, the donor blob must decode to
/// the intended <c>TypeDef</c>, and the written image is re-read and re-decoded before it is returned. A
/// fixture that quietly failed to take would read as "the analyzer survived the cycle" when no cycle was
/// present.
/// </para>
/// </summary>
public static class CyclicEnumPatcher
{
    #region Methods
    /// <summary>
    /// Writes <paramref name="targetPath"/> as a copy of <paramref name="sourcePath"/> in which each
    /// <c>Subject</c> enum's underlying type is the <c>UnderlyingEnum</c> enum — pass the same name for both
    /// to make an enum its own underlying type, or a pair of entries pointing at each other for a two-step
    /// cycle. Type names are the bare metadata names (no namespace). Returns the target path.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Any subject or donor is missing or ambiguous, <c>value__</c> is not already primitive-typed, the
    /// <c>Field</c> row layout cannot be confirmed, or the written image does not decode to the requested
    /// cycle.
    /// </exception>
    public static string WriteCopyWithCyclicEnums(
        string sourcePath, string targetPath, IReadOnlyList<(string Subject, string UnderlyingEnum)> cycles)
    {
        if (cycles is null || cycles.Count == 0)
            throw new InvalidOperationException("No cycles requested; the patcher must never produce an unpatched copy.");

        var image = File.ReadAllBytes(sourcePath);

        // All edits are planned against the pristine image and applied afterwards: the plan reads the metadata
        // through a MetadataReader, and mutating the buffer underneath one would invalidate it.
        var edits = Plan(image, cycles);
        foreach (var (offset, width, value) in edits)
            Write(image, offset, width, value);

        Verify(image, cycles);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(targetPath))!);
        File.WriteAllBytes(targetPath, image);
        return targetPath;
    }

    /// <summary>
    /// The <c>value__</c> field signature bytes of <paramref name="enumName"/> in the assembly at
    /// <paramref name="assemblyPath"/> — the evidence a test uses to show the patch took (a clean enum reads
    /// <c>06 08</c> for <c>int32</c>; a patched one reads <c>06 11 xx</c>).
    /// </summary>
    public static byte[] UnderlyingTypeSignature(string assemblyPath, string enumName)
    {
        using var stream = File.OpenRead(assemblyPath);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();

        return metadata.GetBlobBytes(metadata.GetFieldDefinition(ValueField(metadata, enumName)).Signature);
    }

    // One (fileOffset, width, blobIndex) edit per requested cycle.
    private static IReadOnlyList<(int Offset, int Width, uint Value)> Plan(
        byte[] image, IReadOnlyList<(string Subject, string UnderlyingEnum)> cycles)
    {
        using var stream = new MemoryStream(image, writable: false);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();

        var tableStart = pe.PEHeaders.MetadataStartOffset + metadata.GetTableMetadataOffset(TableIndex.Field);
        var rowSize = metadata.GetTableRowSize(TableIndex.Field);

        return cycles.Select(cycle =>
        {
            var subject = ValueField(metadata, cycle.Subject);
            var donor = DonorSignature(metadata, cycle.UnderlyingEnum);

            // The subject must START as a primitive: patching something already valuetype-typed would mean the
            // fixture proves nothing about introducing the cycle.
            var current = metadata.GetBlobReader(metadata.GetFieldDefinition(subject).Signature);
            current.ReadSignatureHeader();
            if (current.ReadByte() is var element && element != ElementTypeI4)
            {
                throw new InvalidOperationException(
                    $"'{cycle.Subject}.value__' has element type 0x{element:X2}, expected ELEMENT_TYPE_I4 (0x08). "
                    + "The patch subject must be an ordinary int-backed enum before it is made cyclic.");
            }

            var (nameWidth, signatureWidth) = ColumnWidths(metadata, image, tableStart, rowSize, subject);
            var offset = tableStart + (MetadataTokens.GetRowNumber(subject) - 1) * rowSize + FlagsColumnWidth + nameWidth;
            var value = (uint)MetadataTokens.GetHeapOffset(donor);

            if (signatureWidth == 2 && value > ushort.MaxValue)
            {
                throw new InvalidOperationException(
                    $"Blob index 0x{value:X} does not fit the {signatureWidth}-byte Signature column of the Field table.");
            }

            return (offset, signatureWidth, value);
        }).ToArray();
    }

    // The blob handle of a signature that reads FIELD ELEMENT_TYPE_VALUETYPE <enumName>, taken from a literal
    // member of that enum - the compiler emits exactly this shape for every enum member.
    private static BlobHandle DonorSignature(MetadataReader metadata, string enumName)
    {
        var type = TypeHandle(metadata, enumName);

        foreach (var handle in metadata.GetTypeDefinition(type).GetFields())
        {
            var field = metadata.GetFieldDefinition(handle);
            if (!field.Attributes.HasFlag(FieldAttributes.Static))
                continue;

            var blob = metadata.GetBlobReader(field.Signature);
            blob.ReadSignatureHeader();
            if (blob.ReadByte() != ElementTypeValueType)
                continue;
            if (blob.ReadTypeHandle() == type)
                return field.Signature;
        }

        throw new InvalidOperationException(
            $"'{enumName}' declares no literal member whose field signature is 'valuetype {enumName}', so there is "
            + "no donor blob to point value__ at. Give the enum at least one member.");
    }

    // The single instance field of an enum - value__, whose type IS the underlying type (ECMA-335 II.14.3).
    private static FieldDefinitionHandle ValueField(MetadataReader metadata, string enumName)
    {
        var fields = metadata.GetTypeDefinition(TypeHandle(metadata, enumName)).GetFields()
            .Where(h => !metadata.GetFieldDefinition(h).Attributes.HasFlag(FieldAttributes.Static))
            .ToArray();

        return fields.Length == 1
            ? fields[0]
            : throw new InvalidOperationException(
                $"Expected exactly one instance field (value__) on '{enumName}', found {fields.Length}.");
    }

    private static TypeDefinitionHandle TypeHandle(MetadataReader metadata, string typeName)
    {
        var matches = metadata.TypeDefinitions
            .Where(h => metadata.GetString(metadata.GetTypeDefinition(h).Name) == typeName)
            .ToArray();

        return matches.Length == 1
            ? matches[0]
            : throw new InvalidOperationException($"Expected exactly one type named '{typeName}', found {matches.Length}.");
    }

    // Confirms the Name/Signature column widths (each is 2 or 4 bytes depending on heap size) by reading the
    // probe row back at every layout consistent with the row size and requiring BOTH indices to round-trip to
    // what MetadataReader reports. A wrong offset would corrupt an unrelated column and make the fixture
    // meaningless, so an unconfirmable layout is a hard error rather than a guess.
    private static (int NameWidth, int SignatureWidth) ColumnWidths(
        MetadataReader metadata, byte[] image, int tableStart, int rowSize, FieldDefinitionHandle probe)
    {
        var field = metadata.GetFieldDefinition(probe);
        var row = tableStart + (MetadataTokens.GetRowNumber(probe) - 1) * rowSize;

        foreach (var nameWidth in HeapIndexWidths)
        {
            foreach (var signatureWidth in HeapIndexWidths)
            {
                if (FlagsColumnWidth + nameWidth + signatureWidth != rowSize)
                    continue;
                if (Read(image, row + FlagsColumnWidth, nameWidth) != (uint)MetadataTokens.GetHeapOffset(field.Name))
                    continue;
                if (Read(image, row + FlagsColumnWidth + nameWidth, signatureWidth) != (uint)MetadataTokens.GetHeapOffset(field.Signature))
                    continue;

                return (nameWidth, signatureWidth);
            }
        }

        throw new InvalidOperationException(
            $"Could not confirm the Field table row layout (row size {rowSize}) for '{metadata.GetString(field.Name)}'.");
    }

    // Re-reads the WRITTEN bytes and requires every subject's value__ to decode to the requested enum. This is
    // what makes "the fixture is cyclic" a measurement rather than an assumption.
    private static void Verify(byte[] image, IReadOnlyList<(string Subject, string UnderlyingEnum)> cycles)
    {
        using var stream = new MemoryStream(image, writable: false);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();

        foreach (var (subject, underlying) in cycles)
        {
            var blob = metadata.GetBlobReader(metadata.GetFieldDefinition(ValueField(metadata, subject)).Signature);
            blob.ReadSignatureHeader();

            if (blob.ReadByte() != ElementTypeValueType || blob.ReadTypeHandle() != TypeHandle(metadata, underlying))
            {
                throw new InvalidOperationException(
                    $"The patch did not take: '{subject}.value__' does not decode to 'valuetype {underlying}'.");
            }
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
    // ECMA-335 II.22.15: Field is Flags (a 2-byte bit mask), Name (a #Strings index) and Signature (a #Blob
    // index). A heap index is 2 bytes until its heap exceeds 64 KB, then 4 - which of the two applies is
    // confirmed per image rather than assumed.
    private const int FlagsColumnWidth = 2;
    private static readonly int[] HeapIndexWidths = [2, 4];

    // ECMA-335 II.23.1.16 element types, as raw signature bytes. SignatureTypeCode is deliberately not used
    // for the valuetype case: its TypeHandle member is 0x40, a synthetic value meaning "class or valuetype",
    // not the 0x11 that actually appears in the blob.
    private const byte ElementTypeI4 = 0x08;
    private const byte ElementTypeValueType = 0x11;
    #endregion
}
