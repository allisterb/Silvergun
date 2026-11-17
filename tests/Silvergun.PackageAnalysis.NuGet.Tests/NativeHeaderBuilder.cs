namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Buffers.Binary;
using System.Text;

/// <summary>
/// Hand-written, minimal PE / ELF / Mach-O headers for <see cref="NativeBinaryDetector"/> tests (native-binaries-1).
/// Only the fields the detector (and the BCL <c>PEReader</c>) read are populated; everything else is zero. No
/// compiled fixtures: every binary here is a byte array built in code.
/// </summary>
internal static class NativeHeaderBuilder
{
    #region Methods: PE
    internal const ushort MachineI386 = 0x014C, MachineAmd64 = 0x8664, MachineArm64 = 0xAA64;
    internal const ushort CharExecutable = 0x0002, CharDll = 0x2000;

    /// <summary>
    /// A PE image: DOS header (e_lfanew 0x40), "PE\0\0", COFF header, a PE32 (or PE32+ when <paramref name="pe32Plus"/>)
    /// optional header with 16 data directories, and ONE <c>.text</c> section at RVA 0x1000 / file 0x200. When
    /// <paramref name="corFlags"/> is non-null a 72-byte CLR header is placed at the section start (data directory 14)
    /// with those flags and a 16-byte metadata directory right after it, so <c>PEHeaders.CorHeader</c> is non-null.
    /// </summary>
    internal static byte[] Pe(ushort machine, ushort characteristics, bool pe32Plus, uint? corFlags = null)
    {
        var bytes = new byte[0x400];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        W32(bytes, 0x3C, 0x40, le: true);
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(bytes, 0x40);

        const int coff = 0x44;
        var optSize = pe32Plus ? 240 : 224;
        W16(bytes, coff + 0, machine, le: true);
        W16(bytes, coff + 2, 1, le: true);                              // NumberOfSections
        W16(bytes, coff + 16, (ushort)optSize, le: true);               // SizeOfOptionalHeader
        W16(bytes, coff + 18, characteristics, le: true);

        const int opt = coff + 20;
        W16(bytes, opt + 0, pe32Plus ? (ushort)0x20B : (ushort)0x10B, le: true);
        W32(bytes, opt + 32, 0x1000, le: true);                         // SectionAlignment
        W32(bytes, opt + 36, 0x200, le: true);                          // FileAlignment
        W32(bytes, opt + 56, 0x2000, le: true);                         // SizeOfImage
        W32(bytes, opt + 60, 0x200, le: true);                          // SizeOfHeaders
        W16(bytes, opt + 68, 3, le: true);                              // Subsystem: console
        var dirs = opt + (pe32Plus ? 112 : 96);
        W32(bytes, dirs - 4, 16, le: true);                             // NumberOfRvaAndSizes
        if (corFlags is { } flags)
        {
            W32(bytes, dirs + 14 * 8, 0x1000, le: true);                // CLI header RVA
            W32(bytes, dirs + 14 * 8 + 4, 72, le: true);                // ... size
        }

        var section = opt + optSize;
        Encoding.ASCII.GetBytes(".text").CopyTo(bytes, section);
        W32(bytes, section + 8, 0x200, le: true);                       // VirtualSize
        W32(bytes, section + 12, 0x1000, le: true);                     // VirtualAddress
        W32(bytes, section + 16, 0x200, le: true);                      // SizeOfRawData
        W32(bytes, section + 20, 0x200, le: true);                      // PointerToRawData
        W32(bytes, section + 36, 0x60000020, le: true);                 // code | execute | read

        if (corFlags is { } cor)
        {
            const int c = 0x200;
            W32(bytes, c + 0, 72, le: true);                            // cb
            W16(bytes, c + 4, 2, le: true);                             // MajorRuntimeVersion
            W16(bytes, c + 6, 5, le: true);
            W32(bytes, c + 8, 0x1048, le: true);                        // MetaData RVA (right after this header)
            W32(bytes, c + 12, 0x10, le: true);                         // MetaData size
            W32(bytes, c + 16, cor, le: true);                          // Flags
        }
        return bytes;
    }

    internal const uint CorILOnly = 0x1, CorILLibrary = 0x4, CorStrongNameSigned = 0x8;
    #endregion

    #region Nested types
    /// <summary>
    /// A copy of the real IL-only fixture assembly (<c>Silvergun.CodeAnalysis.IL.Tests.Fixture</c>) with its COR20 header
    /// patched in memory, so the metadata it carries is genuinely readable ("BSJB") — hand-building metadata is not worth
    /// it. COR20 layout: Flags at +16, MetaData directory at +8, ManagedNativeHeader directory at +64.
    /// </summary>
    internal static class ManagedPe
    {
        internal static byte[] Bytes => System.IO.File.ReadAllBytes(typeof(Silvergun.CodeAnalysis.IL.Tests.Fixture.Shapes).Assembly.Location);

        /// <summary>
        /// The fixture with <paramref name="flags"/> and a ManagedNativeHeader directory of <paramref name="managedNativeHeader"/>.
        /// <paramref name="metadataAtCorHeader"/> repoints the MetaData directory's RVA at the COR20 header itself: inside
        /// the section, so the PE headers still parse, but not a metadata root.
        /// </summary>
        internal static byte[] Patch(uint flags, (uint Rva, uint Size) managedNativeHeader, bool metadataAtCorHeader = false)
        {
            var bytes = Bytes;
            int cor;
            uint corRva;
            using (var reader = new System.Reflection.PortableExecutable.PEReader(new System.IO.MemoryStream(bytes, writable: false)))
            {
                cor = reader.PEHeaders.CorHeaderStartOffset;
                corRva = (uint)reader.PEHeaders.PEHeader!.CorHeaderTableDirectory.RelativeVirtualAddress;
            }
            if (cor <= 0)
                throw new InvalidOperationException("the fixture assembly has no COR20 header.");

            W32(bytes, cor + 16, flags, le: true);
            W32(bytes, cor + 64, managedNativeHeader.Rva, le: true);
            W32(bytes, cor + 68, managedNativeHeader.Size, le: true);
            if (metadataAtCorHeader)
                W32(bytes, cor + 8, corRva, le: true);
            return bytes;
        }
    }
    #endregion

    #region Methods: ELF
    internal const ushort EtRel = 1, EtExec = 2, EtDyn = 3;
    internal const ushort EmX86 = 3, EmMips = 8, EmPpc64 = 0x15, EmArm = 0x28, EmX64 = 0x3E, EmArm64 = 0xB7;
    internal const uint PtLoad = 1, PtDynamic = 2, PtInterp = 3;

    /// <summary>
    /// An ELF header followed directly by one program header per entry of <paramref name="programHeaders"/> (its p_type).
    /// <paramref name="phnum"/>/<paramref name="phoff"/>/<paramref name="phentsize"/> override the honest values, to stage
    /// hostile headers.
    /// </summary>
    internal static byte[] Elf(
        bool is64, bool littleEndian, ushort type, ushort machine, uint[]? programHeaders = null,
        ushort? phnum = null, ulong? phoff = null, ushort? phentsize = null, byte? classByte = null, byte? dataByte = null)
    {
        programHeaders ??= [];
        var ehsize = is64 ? 64 : 52;
        var entsize = is64 ? 56 : 32;
        var bytes = new byte[ehsize + entsize * programHeaders.Length];
        bytes[0] = 0x7F;
        bytes[1] = (byte)'E';
        bytes[2] = (byte)'L';
        bytes[3] = (byte)'F';
        bytes[4] = classByte ?? (byte)(is64 ? 2 : 1);
        bytes[5] = dataByte ?? (byte)(littleEndian ? 1 : 2);
        bytes[6] = 1;                                                   // EI_VERSION
        W16(bytes, 16, type, littleEndian);
        W16(bytes, 18, machine, littleEndian);
        W32(bytes, 20, 1, littleEndian);                                // e_version
        var off = phoff ?? (ulong)(programHeaders.Length == 0 ? 0 : ehsize);
        if (is64)
        {
            W64(bytes, 32, off, littleEndian);
            W16(bytes, 52, (ushort)ehsize, littleEndian);
            W16(bytes, 54, phentsize ?? (ushort)entsize, littleEndian);
            W16(bytes, 56, phnum ?? (ushort)programHeaders.Length, littleEndian);
        }
        else
        {
            W32(bytes, 28, (uint)off, littleEndian);
            W16(bytes, 40, (ushort)ehsize, littleEndian);
            W16(bytes, 42, phentsize ?? (ushort)entsize, littleEndian);
            W16(bytes, 44, phnum ?? (ushort)programHeaders.Length, littleEndian);
        }
        for (var i = 0; i < programHeaders.Length; i++)
            W32(bytes, ehsize + i * entsize, programHeaders[i], littleEndian);
        return bytes;
    }
    #endregion

    #region Methods: Mach-O
    internal const uint MhObject = 1, MhExecute = 2, MhDylib = 6, MhBundle = 8, MhDylibStub = 9;
    internal const uint CpuX86 = 7, CpuX64 = 0x01000007, CpuArm64 = 0x0100000C, CpuPpc = 18, CpuPpc64 = 0x01000012;

    /// <summary>A thin Mach-O header (28 bytes, or 32 when 64-bit) in the given byte order.</summary>
    internal static byte[] MachO(bool is64, bool littleEndian, uint cpu, uint fileType)
    {
        var bytes = new byte[is64 ? 32 : 28];
        W32(bytes, 0, is64 ? 0xFEEDFACFu : 0xFEEDFACEu, littleEndian);
        W32(bytes, 4, cpu, littleEndian);
        W32(bytes, 12, fileType, littleEndian);
        return bytes;
    }

    /// <summary>
    /// A universal (fat) Mach-O: big-endian CAFEBABE (or CAFEBABF when <paramref name="fat64"/>), the slice count, one
    /// fat_arch record per slice, then each slice's bytes at a 0x100-aligned offset. <paramref name="countOverride"/>
    /// writes a different count than the slices supplied.
    /// </summary>
    internal static byte[] Universal(bool fat64, (uint Cpu, byte[] Slice)[] slices, uint? countOverride = null, ulong? firstOffsetOverride = null)
    {
        var entry = fat64 ? 32 : 20;
        var offsets = new ulong[slices.Length];
        var next = 0x100UL;
        for (var i = 0; i < slices.Length; i++)
        {
            offsets[i] = next;
            next += (ulong)((slices[i].Slice.Length + 0xFF) & ~0xFF);
            if (next == offsets[i])
                next += 0x100;
        }
        var bytes = new byte[Math.Max((int)next, 8 + entry * slices.Length)];
        W32(bytes, 0, fat64 ? 0xCAFEBABFu : 0xCAFEBABEu, le: false);
        W32(bytes, 4, countOverride ?? (uint)slices.Length, le: false);
        for (var i = 0; i < slices.Length; i++)
        {
            var at = 8 + i * entry;
            var offset = i == 0 && firstOffsetOverride is { } o ? o : offsets[i];
            W32(bytes, at, slices[i].Cpu, le: false);
            if (fat64)
            {
                W64(bytes, at + 8, offset, le: false);
                W64(bytes, at + 16, (ulong)slices[i].Slice.Length, le: false);
            }
            else
            {
                W32(bytes, at + 8, (uint)offset, le: false);
                W32(bytes, at + 12, (uint)slices[i].Slice.Length, le: false);
            }
            slices[i].Slice.CopyTo(bytes, (int)offsets[i]);
        }
        return bytes;
    }
    #endregion

    #region Methods: byte writers
    private static void W16(byte[] b, int at, ushort v, bool le)
    {
        if (le) BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at), v);
        else BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(at), v);
    }

    private static void W32(byte[] b, int at, uint v, bool le)
    {
        if (le) BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), v);
        else BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(at), v);
    }

    private static void W64(byte[] b, int at, ulong v, bool le)
    {
        if (le) BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(at), v);
        else BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(at), v);
    }
    #endregion
}
