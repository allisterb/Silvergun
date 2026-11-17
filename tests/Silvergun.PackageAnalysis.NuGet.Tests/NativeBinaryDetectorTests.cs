namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

using static NativeHeaderBuilder;

/// <summary>
/// <see cref="NativeBinaryDetector.Detect"/> over hand-written headers (native-binaries-1 acceptance): PE (native,
/// and the <see cref="NativeBinaryCode"/> of a CLR header — IL-only, ReadyToRun, mixed-mode, unreadable metadata — over
/// in-memory patches of a real assembly; truncated), ELF (32/64, LE/BE, ET_EXEC, ET_DYN with and without PT_INTERP, bad ident),
/// thin Mach-O (32/64, LE/BE), universal Mach-O (slices, Java class collision, static-library slice), short inputs, and
/// hostile counts/offsets — which must stay bounded and never throw.
/// </summary>
public sealed class NativeBinaryDetectorTests
{
    #region Methods: PE
    [Theory]
    [InlineData(MachineI386, false, "x86")]
    [InlineData(MachineAmd64, true, "x64")]
    [InlineData(MachineArm64, true, "arm64")]
    public void Detect_NativePeExecutable_IsPeExecutableWithItsArchitecture(ushort machine, bool pe32Plus, string arch)
    {
        var header = Detect(Pe(machine, CharExecutable, pe32Plus));

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.PE, NativeBinaryKind.Executable, arch, NativeBinaryCode.Native), header);
    }

    [Theory]
    [InlineData(MachineI386, false, "x86")]
    [InlineData(MachineAmd64, true, "x64")]
    [InlineData(MachineArm64, true, "arm64")]
    public void Detect_NativePeDll_IsPeSharedLibrary(ushort machine, bool pe32Plus, string arch)
    {
        // A DLL also carries IMAGE_FILE_EXECUTABLE_IMAGE; the Dll bit must win.
        var header = Detect(Pe(machine, CharDll | CharExecutable, pe32Plus));

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.PE, NativeBinaryKind.SharedLibrary, arch, NativeBinaryCode.Native), header);
    }

    [Fact]
    public void Detect_PeWithNeitherDllNorExecutableCharacteristic_IsOther()
    {
        var header = Detect(Pe(MachineAmd64, 0, pe32Plus: true));

        Assert.Equal(NativeBinaryKind.Other, header?.Kind);
        Assert.Equal(NativeBinaryFormat.PE, header?.Format);
    }

    [Fact]
    public void Detect_PeWithAnUnknownMachine_NamesTheMachineInHex()
    {
        var header = Detect(Pe(0x5064, CharExecutable, pe32Plus: true));

        Assert.Equal("pe-machine-0x5064", header?.Architecture);
    }

    // The real, on-disk IL-only fixture assembly (an AnyCPU netstandard2.0 library): returned with Code ILOnly for the
    // caller to drop when the CIL inventory owns it (review round 1: no longer null).
    [Fact]
    public void Detect_RealIlOnlyManagedAssembly_IsILOnly()
    {
        using var stream = File.OpenRead(typeof(Shapes).Assembly.Location);

        Assert.Equal(
            new NativeBinaryHeader(NativeBinaryFormat.PE, NativeBinaryKind.SharedLibrary, "x86", NativeBinaryCode.ILOnly),
            NativeBinaryDetector.Detect(stream));
    }

    // The fixture's own COR20 header, patched in memory: crossgen's shape (ILOnly cleared, ILLibrary | StrongNameSigned,
    // a ManagedNativeHeader directory) is ReadyToRun, not mixed-mode.
    [Fact]
    public void Detect_ClrHeaderWithAManagedNativeHeaderAndIlOnlyClear_IsReadyToRun()
    {
        var bytes = ManagedPe.Patch(flags: CorILLibrary | CorStrongNameSigned, managedNativeHeader: (0x2000, 0x50));

        Assert.Equal(NativeBinaryCode.ReadyToRun, Detect(bytes)?.Code);
    }

    // The ManagedNativeHeader decides R2R whatever ILOnly says.
    [Fact]
    public void Detect_ClrHeaderWithAManagedNativeHeaderAndIlOnlySet_IsReadyToRun()
    {
        var bytes = ManagedPe.Patch(flags: CorILOnly, managedNativeHeader: (0x2000, 0x50));

        Assert.Equal(NativeBinaryCode.ReadyToRun, Detect(bytes)?.Code);
    }

    // ILOnly clear and no R2R header: C++/CLI, managed AND native code.
    [Fact]
    public void Detect_ClrHeaderWithIlOnlyClearAndNoManagedNativeHeader_IsMixedMode()
    {
        var bytes = ManagedPe.Patch(flags: CorStrongNameSigned, managedNativeHeader: (0, 0));

        Assert.Equal(
            new NativeBinaryHeader(NativeBinaryFormat.PE, NativeBinaryKind.SharedLibrary, "x86", NativeBinaryCode.MixedMode),
            Detect(bytes));
    }

    // Control for the patching itself: the unchanged flags still read ILOnly after a round trip through Patch.
    [Fact]
    public void Detect_PatchedCopyWithTheOriginalFlags_IsStillILOnly()
    {
        var bytes = ManagedPe.Patch(flags: CorILOnly, managedNativeHeader: (0, 0));

        Assert.Equal(NativeBinaryCode.ILOnly, Detect(bytes)?.Code);
    }

    // A CLR header is one attacker-set structure: when the metadata it points at is not a metadata root ("BSJB"), the
    // file is not managed, whatever ILOnly says, so it reads Native, never ILOnly (which a .dll name would drop).
    [Theory]
    [InlineData(CorILOnly)]
    [InlineData(CorStrongNameSigned)]
    public void Detect_RealClrHeaderWhoseMetadataPointsAtJunk_IsNative(uint flags)
    {
        var bytes = ManagedPe.Patch(flags, managedNativeHeader: (0, 0), metadataAtCorHeader: true);

        Assert.Equal(NativeBinaryCode.Native, Detect(bytes)?.Code);
    }

    // The hand-built PE's CLR header points at 16 zero bytes, not metadata: Native for every flag combination.
    [Theory]
    [InlineData(CorILOnly, false, MachineI386, "x86")]
    [InlineData(CorILOnly | CorStrongNameSigned, true, MachineAmd64, "x64")]
    [InlineData(CorStrongNameSigned, false, MachineI386, "x86")]
    public void Detect_SyntheticClrHeaderWithoutReadableMetadata_IsNative(uint corFlags, bool pe32Plus, ushort machine, string arch)
    {
        var header = Detect(Pe(machine, CharDll | CharExecutable, pe32Plus, corFlags));

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.PE, NativeBinaryKind.SharedLibrary, arch, NativeBinaryCode.Native), header);
    }

    // "MZ" followed by something that is not a PE: the magic matched, the header did not parse.
    [Theory]
    [InlineData(4)]       // MZ + 2 bytes: past the 4-byte floor, no DOS header
    [InlineData(64)]      // a whole DOS header whose e_lfanew (0) points back at "MZ", not "PE\0\0"
    [InlineData(0x50)]    // e_lfanew valid, file ends inside the COFF header
    [InlineData(0x100)]   // file ends inside the optional header
    public void Detect_TruncatedMz_IsMalformedPe(int length)
    {
        var full = length == 64 ? ZeroLfanew() : Pe(MachineAmd64, CharExecutable, pe32Plus: true);

        var header = Detect(full[..length]);

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.PE, NativeBinaryKind.Malformed, null, NativeBinaryCode.Native), header);

        static byte[] ZeroLfanew()
        {
            var b = new byte[64];
            b[0] = (byte)'M';
            b[1] = (byte)'Z';
            return b;
        }
    }

    [Fact]
    public void Detect_MzWithLfanewPastEndOfFile_IsMalformedPe()
    {
        var bytes = Pe(MachineAmd64, CharExecutable, pe32Plus: true)[..64];
        bytes[0x3C] = 0xFF;
        bytes[0x3D] = 0xFF;
        bytes[0x3E] = 0xFF;
        bytes[0x3F] = 0x7F;

        Assert.Equal(NativeBinaryKind.Malformed, Detect(bytes)?.Kind);
    }

    // A text file that merely starts with "MZ" is still probed as a PE (by design: header, not name) and reads Malformed.
    [Fact]
    public void Detect_TextStartingWithMz_IsMalformedPe_AndDoesNotThrow()
    {
        var header = Detect(Encoding.ASCII.GetBytes("MZ is a fine pair of initials for a readme line.\n"));

        Assert.Equal(NativeBinaryFormat.PE, header?.Format);
        Assert.Equal(NativeBinaryKind.Malformed, header?.Kind);
    }
    #endregion

    #region Methods: ELF
    [Theory]
    [InlineData(false, true, EmX86, "x86")]
    [InlineData(false, false, EmMips, "mips")]
    [InlineData(true, true, EmX64, "x64")]
    [InlineData(true, false, EmPpc64, "ppc64")]
    public void Detect_ElfEtExec_IsExecutable_InEveryClassAndByteOrder(bool is64, bool le, ushort machine, string arch)
    {
        var header = Detect(Elf(is64, le, EtExec, machine));

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.Elf, NativeBinaryKind.Executable, arch, NativeBinaryCode.Native), header);
    }

    // ET_DYN with a PT_INTERP program header is a PIE executable (e.g. Playwright's node), not a library.
    [Theory]
    [InlineData(false, true)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(true, false)]
    public void Detect_ElfEtDynWithInterpreter_IsExecutable(bool is64, bool le)
    {
        var header = Detect(Elf(is64, le, EtDyn, EmArm64, [PtLoad, PtLoad, PtInterp, PtDynamic]));

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.Elf, NativeBinaryKind.Executable, "arm64", NativeBinaryCode.Native), header);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(true, false)]
    public void Detect_ElfEtDynWithoutInterpreter_IsSharedLibrary(bool is64, bool le)
    {
        var header = Detect(Elf(is64, le, EtDyn, EmArm, [PtLoad, PtLoad, PtDynamic]));

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.Elf, NativeBinaryKind.SharedLibrary, "arm", NativeBinaryCode.Native), header);
    }

    [Fact]
    public void Detect_ElfEtDynWithNoProgramHeadersAtAll_IsSharedLibrary()
    {
        Assert.Equal(NativeBinaryKind.SharedLibrary, Detect(Elf(true, true, EtDyn, EmX64))?.Kind);
    }

    [Fact]
    public void Detect_ElfRelocatableObject_IsOther()
    {
        Assert.Equal(NativeBinaryKind.Other, Detect(Elf(true, true, EtRel, EmX64))?.Kind);
    }

    [Fact]
    public void Detect_ElfWithAnUnknownMachine_NamesTheMachineInDecimal()
    {
        Assert.Equal("elf-machine-4660", Detect(Elf(true, true, EtExec, 0x1234))?.Architecture);
    }

    [Theory]
    [InlineData((byte)0, (byte)1)]
    [InlineData((byte)3, (byte)1)]
    [InlineData((byte)2, (byte)0)]
    [InlineData((byte)2, (byte)3)]
    public void Detect_ElfWithABadClassOrDataByte_IsMalformed(byte classByte, byte dataByte)
    {
        var header = Detect(Elf(true, true, EtExec, EmX64, classByte: classByte, dataByte: dataByte));

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.Elf, NativeBinaryKind.Malformed, null, NativeBinaryCode.Native), header);
    }

    [Theory]
    [InlineData(false, 51)]
    [InlineData(true, 63)]
    [InlineData(true, 8)]
    public void Detect_ElfShorterThanItsHeader_IsMalformed(bool is64, int length)
    {
        var header = Detect(Elf(is64, true, EtExec, EmX64)[..length]);

        Assert.Equal(NativeBinaryKind.Malformed, header?.Kind);
        Assert.Equal(NativeBinaryFormat.Elf, header?.Format);
    }
    #endregion

    #region Methods: ELF, hostile program-header tables
    // phnum 0xFFFF is honoured only up to 512 entries: an interpreter at index 511 is seen...
    [Fact]
    public void Detect_ElfWithPhnum0xFFFF_ReadsTheFirst512Entries()
    {
        var bytes = Elf(true, true, EtDyn, EmX64, ProgramHeaders(count: 600, interpAt: 511), phnum: 0xFFFF);

        Assert.Equal(NativeBinaryKind.Executable, Detect(bytes)?.Kind);
    }

    // ... and one at index 512 is not: the table read is bounded, so the file reads as a shared library.
    [Fact]
    public void Detect_ElfWithPhnum0xFFFF_DoesNotReadPastEntry512()
    {
        var bytes = Elf(true, true, EtDyn, EmX64, ProgramHeaders(count: 600, interpAt: 512), phnum: 0xFFFF);

        Assert.Equal(NativeBinaryKind.SharedLibrary, Detect(bytes)?.Kind);
    }

    [Theory]
    [InlineData(true, 0x10000UL)]                 // past EOF
    [InlineData(true, 0x7FFFFFFFFFFFFFFFUL)]      // long.MaxValue
    [InlineData(true, 0xFFFFFFFFFFFFFFFFUL)]      // > long.MaxValue
    [InlineData(false, 0xFFFFFFFFUL)]             // 32-bit, past EOF
    public void Detect_ElfWithPhoffPastEndOfFile_IsSharedLibrary_WithoutThrowing(bool is64, ulong phoff)
    {
        var bytes = Elf(is64, true, EtDyn, EmX64, [PtInterp], phoff: phoff);

        var header = Detect(bytes);

        Assert.Equal(NativeBinaryKind.SharedLibrary, header?.Kind);
    }

    // phentsize must be exactly 32 or 56; anything else is rejected outright (no interpreter assumed), not read at that
    // stride. PT_INTERP is entry 0 at phoff, so ANY stride would find it: SharedLibrary here proves the rejection.
    [Theory]
    [InlineData(true, (ushort)0)]
    [InlineData(true, (ushort)3)]
    [InlineData(true, (ushort)4)]
    [InlineData(true, (ushort)55)]
    [InlineData(true, (ushort)57)]
    [InlineData(true, (ushort)64)]
    [InlineData(true, (ushort)0xFFFF)]
    [InlineData(false, (ushort)31)]
    [InlineData(false, (ushort)33)]
    [InlineData(false, (ushort)0xFFFF)]
    public void Detect_ElfWithAPhentsizeOtherThan32Or56_IsRejected_AsSharedLibrary(bool is64, ushort phentsize)
    {
        var header = Detect(Elf(is64, true, EtDyn, EmX64, [PtInterp, PtLoad], phentsize: phentsize));

        Assert.Equal(NativeBinaryKind.SharedLibrary, header?.Kind);
    }

    // Maximal phentsize x maximal phnum (a ~32 MB ask) is rejected on the phentsize, before any table read.
    [Fact]
    public void Detect_ElfWithMaximalPhentsizeAndPhnum_IsRejected_WithoutThrowing()
    {
        var header = Detect(Elf(true, true, EtDyn, EmX64, [PtInterp, PtLoad], phnum: 0xFFFF, phentsize: 0xFFFF));

        Assert.Equal(NativeBinaryKind.SharedLibrary, header?.Kind);
    }

    // The 512-entry cap holds for the 32-bit stride too.
    [Fact]
    public void Detect_Elf32WithPhnum0xFFFF_DoesNotReadPastEntry512()
    {
        Assert.Equal(NativeBinaryKind.Executable,
            Detect(Elf(false, true, EtDyn, EmX86, ProgramHeaders(count: 600, interpAt: 511), phnum: 0xFFFF))?.Kind);
        Assert.Equal(NativeBinaryKind.SharedLibrary,
            Detect(Elf(false, true, EtDyn, EmX86, ProgramHeaders(count: 600, interpAt: 512), phnum: 0xFFFF))?.Kind);
    }

    // An entry whose stride runs past the end is simply not seen.
    [Fact]
    public void Detect_ElfWhoseProgramHeaderTableIsTruncated_DoesNotThrow()
    {
        var bytes = Elf(true, true, EtDyn, EmX64, [PtLoad, PtInterp]);
        var cut = bytes[..(64 + 56 + 2)];   // the second entry's p_type is half there

        Assert.Equal(NativeBinaryKind.SharedLibrary, Detect(cut)?.Kind);
    }
    #endregion

    #region Methods: thin Mach-O
    [Theory]
    [InlineData(true, true, CpuArm64, MhExecute, NativeBinaryKind.Executable, "arm64")]
    [InlineData(true, true, CpuX64, MhDylib, NativeBinaryKind.SharedLibrary, "x64")]
    [InlineData(true, false, CpuPpc64, MhDylib, NativeBinaryKind.SharedLibrary, "ppc64")]
    [InlineData(true, false, CpuPpc64, MhExecute, NativeBinaryKind.Executable, "ppc64")]
    [InlineData(false, true, CpuX86, MhExecute, NativeBinaryKind.Executable, "x86")]
    [InlineData(false, true, CpuX86, MhBundle, NativeBinaryKind.SharedLibrary, "x86")]
    [InlineData(false, false, CpuPpc, MhExecute, NativeBinaryKind.Executable, "ppc")]
    [InlineData(false, false, CpuPpc, MhDylibStub, NativeBinaryKind.SharedLibrary, "ppc")]
    [InlineData(true, true, CpuX64, MhObject, NativeBinaryKind.Other, "x64")]
    public void Detect_ThinMachO_ReadsKindAndCpuInEitherByteOrder(
        bool is64, bool le, uint cpu, uint fileType, NativeBinaryKind kind, string arch)
    {
        var header = Detect(MachO(is64, le, cpu, fileType));

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.MachO, kind, arch, NativeBinaryCode.Native), header);
    }

    [Fact]
    public void Detect_ThinMachOWithAnUnknownCpu_NamesTheCpuInHex()
    {
        Assert.Equal("macho-cpu-0xabc", Detect(MachO(true, true, 0xABC, MhExecute))?.Architecture);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(15)]
    public void Detect_ThinMachOShorterThanSixteenBytes_IsMalformed(int length)
    {
        var header = Detect(MachO(true, true, CpuArm64, MhExecute)[..length]);

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.MachO, NativeBinaryKind.Malformed, null, NativeBinaryCode.Native), header);
    }
    #endregion

    #region Methods: universal Mach-O
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Detect_UniversalWithTwoSlices_JoinsTheArchitectures_AndTakesTheFirstSlicesKind(bool fat64)
    {
        var bytes = Universal(fat64,
        [
            (CpuX64, MachO(true, true, CpuX64, MhExecute)),
            (CpuArm64, MachO(true, true, CpuArm64, MhDylib)),
        ]);

        var header = Detect(bytes);

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.MachOUniversal, NativeBinaryKind.Executable, "x64+arm64", NativeBinaryCode.Native), header);
    }

    [Fact]
    public void Detect_UniversalWhoseFirstSliceIsADylib_IsSharedLibrary()
    {
        var bytes = Universal(false,
        [
            (CpuArm64, MachO(true, true, CpuArm64, MhDylib)),
            (CpuX64, MachO(true, true, CpuX64, MhExecute)),
        ]);

        Assert.Equal(NativeBinaryKind.SharedLibrary, Detect(bytes)?.Kind);
    }

    [Fact]
    public void Detect_UniversalWithABigEndianSlice_ReadsTheSlice()
    {
        var bytes = Universal(false, [(CpuPpc, MachO(false, false, CpuPpc, MhExecute))]);

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.MachOUniversal, NativeBinaryKind.Executable, "ppc", NativeBinaryCode.Native), Detect(bytes));
    }

    [Fact]
    public void Detect_UniversalWithRepeatedCpus_ListsEachCpuOnce()
    {
        var bytes = Universal(false,
        [
            (CpuArm64, MachO(true, true, CpuArm64, MhExecute)),
            (CpuArm64, MachO(true, true, CpuArm64, MhExecute)),
        ]);

        Assert.Equal("arm64", Detect(bytes)?.Architecture);
    }

    // A static library's universal wrapper: the slice is an "!<arch>" archive, not a Mach-O.
    [Fact]
    public void Detect_UniversalWrappingAnArArchive_IsOther()
    {
        var archive = Encoding.ASCII.GetBytes("!<arch>\n/               0           0     0     0       4         `\n");
        var bytes = Universal(false, [(CpuX64, archive), (CpuArm64, archive)]);

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.MachOUniversal, NativeBinaryKind.Other, "x64+arm64", NativeBinaryCode.Native), Detect(bytes));
    }

    // A Java class file shares CAFEBABE; its next word is minor/major version (major >= 45), never a slice count.
    [Theory]
    [InlineData(0, 45)]     // JDK 1.1
    [InlineData(0, 52)]     // Java 8
    [InlineData(0, 65)]     // Java 21
    [InlineData(3, 45)]     // JDK 1.0.2 (minor 3)
    public void Detect_JavaClassFile_IsNull(int minor, int major)
    {
        var bytes = new byte[64];
        bytes[0] = 0xCA; bytes[1] = 0xFE; bytes[2] = 0xBA; bytes[3] = 0xBE;
        bytes[4] = (byte)(minor >> 8); bytes[5] = (byte)minor;
        bytes[6] = (byte)(major >> 8); bytes[7] = (byte)major;

        Assert.Null(Detect(bytes));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(33u)]
    [InlineData(0xFFFFFFFFu)]
    [InlineData(0x80000000u)]
    public void Detect_UniversalWithASliceCountOutsideOneTo32_IsNull_WithoutThrowing(uint count)
    {
        var bytes = Universal(false, [(CpuX64, MachO(true, true, CpuX64, MhExecute))], countOverride: count);

        Assert.Null(Detect(bytes));
    }

    // 32 slices claimed, one present: the fat_arch table runs off the end of the file.
    [Fact]
    public void Detect_UniversalWhoseSliceTableIsTruncated_IsMalformed()
    {
        var bytes = Universal(false, [(CpuX64, MachO(true, true, CpuX64, MhExecute))], countOverride: 32)[..64];

        Assert.Equal(new NativeBinaryHeader(NativeBinaryFormat.MachOUniversal, NativeBinaryKind.Malformed, null, NativeBinaryCode.Native), Detect(bytes));
    }

    [Theory]
    [InlineData(false, 0xFFFFFFF0UL)]
    [InlineData(true, 0x7FFFFFFFFFFFFFFFUL)]
    [InlineData(true, 0xFFFFFFFFFFFFFFFFUL)]
    public void Detect_UniversalWhoseFirstSliceOffsetIsPastEndOfFile_IsMalformedKind_WithoutThrowing(bool fat64, ulong offset)
    {
        var bytes = Universal(fat64, [(CpuX64, MachO(true, true, CpuX64, MhExecute))], firstOffsetOverride: offset);

        var header = Detect(bytes);

        Assert.Equal(NativeBinaryFormat.MachOUniversal, header?.Format);
        Assert.Equal(NativeBinaryKind.Malformed, header?.Kind);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(7)]
    public void Detect_UniversalMagicWithoutACount_IsNull(int length)
    {
        var bytes = Universal(false, [(CpuX64, MachO(true, true, CpuX64, MhExecute))])[..length];

        Assert.Null(Detect(bytes));
    }
    #endregion

    #region Methods: not a native binary
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public void Detect_FilesShorterThanFourBytes_AreNull(int length)
    {
        // Even when those bytes are the start of a real magic.
        Assert.Null(Detect(Elf(true, true, EtExec, EmX64)[..length]));
        Assert.Null(Detect(Pe(MachineAmd64, CharExecutable, true)[..length]));
    }

    [Fact]
    public void Detect_ExactlyMz_IsNull()
    {
        Assert.Null(Detect([(byte)'M', (byte)'Z']));
    }

    [Theory]
    [InlineData("Hello, world.\n")]
    [InlineData("<?xml version=\"1.0\"?><package/>")]
    [InlineData("#!/bin/sh\nexec node \"$@\"\n")]
    public void Detect_TextFiles_AreNull(string text)
    {
        Assert.Null(Detect(Encoding.UTF8.GetBytes(text)));
    }

    [Fact]
    public void Detect_ZipArchive_IsNull()
    {
        Assert.Null(Detect([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00]));
    }

    [Fact]
    public void Detect_ReadsFromTheStartOfTheStream_WhateverItsPosition()
    {
        using var stream = new MemoryStream(Elf(true, true, EtExec, EmX64));
        stream.Position = stream.Length;

        Assert.Equal(NativeBinaryKind.Executable, NativeBinaryDetector.Detect(stream)?.Kind);
    }

    // Does not throw on random-ish input beginning with each magic (a cheap fuzz over every branch).
    [Fact]
    public void Detect_PseudoRandomBytesAfterEachMagic_NeverThrows()
    {
        byte[][] magics =
        [
            [(byte)'M', (byte)'Z'],
            [0x7F, (byte)'E', (byte)'L', (byte)'F'],
            [0xCE, 0xFA, 0xED, 0xFE],
            [0xFE, 0xED, 0xFA, 0xCF],
            [0xCA, 0xFE, 0xBA, 0xBE],
            [0xCA, 0xFE, 0xBA, 0xBF],
        ];
        var random = new Random(20261117);
        foreach (var magic in magics)
            for (var i = 0; i < 200; i++)
            {
                var bytes = new byte[random.Next(magic.Length, 600)];
                random.NextBytes(bytes);
                magic.CopyTo(bytes, 0);
                if (magic[0] == 0xCA && bytes.Length >= 8)
                {
                    bytes[4] = bytes[5] = bytes[6] = 0;   // a fat count in 1..32 so the slice path runs
                    bytes[7] = (byte)random.Next(1, 33);
                }

                var ex = Record.Exception(() => Detect(bytes));

                Assert.True(ex is null, $"magic {Convert.ToHexString(magic)}, input {Convert.ToHexString(bytes)}: {ex}");
            }
    }
    #endregion

    #region Methods: helpers
    private static NativeBinaryHeader? Detect(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        return NativeBinaryDetector.Detect(stream);
    }

    private static uint[] ProgramHeaders(int count, int interpAt) =>
        [.. Enumerable.Range(0, count).Select(i => i == interpAt ? PtInterp : PtLoad)];
    #endregion
}
