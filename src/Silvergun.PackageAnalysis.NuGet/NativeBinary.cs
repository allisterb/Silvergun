namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

/// <summary>Container format of a <see cref="NativeBinary"/>, identified by its header bytes, never by its name.</summary>
public enum NativeBinaryFormat { PE, Elf, MachO, MachOUniversal }

/// <summary>
/// What a <see cref="NativeBinary"/>'s header says it is. An ELF <c>ET_DYN</c> with a program interpreter is a
/// position-independent executable, not a library. <see cref="Malformed"/>: the magic matched but the header did not parse.
/// Known residual: a static PIE (<c>-static-pie</c>, some Go/musl builds) has no interpreter and reads as SharedLibrary.
/// </summary>
public enum NativeBinaryKind { Executable, SharedLibrary, Other, Malformed }

/// <summary>
/// What code a PE carries. ELF and Mach-O are always <see cref="Native"/>. <see cref="ReadyToRun"/>: precompiled native
/// code the runtime may run in place of the IL (crossgen clears ILOnly). <see cref="MixedMode"/>: ILOnly clear without an
/// R2R header (C++/CLI). <see cref="ILOnly"/>: managed only, listed solely when the file is outside the CIL inventory
/// (not named .dll/.exe), so it is not silently unanalysed. A CLR header whose metadata cannot be read is Native.
/// Known residual: a native PE with a forged ILOnly header and valid stub metadata, named .dll/.exe, reads ILOnly and is
/// left to the CIL inventory (imports/entry point are not checked).
/// </summary>
public enum NativeBinaryCode { Native, MixedMode, ReadyToRun, ILOnly }

/// <summary>
/// The .NET host marker in a <see cref="NativeBinary"/>: the host's fixed 32-byte bundle signature (present once in
/// every SDK apphost template measured, 3.1-10.0) and the 8-byte bundle-header offset before it.
/// <see cref="AppHost"/>: offset 0, a launcher that starts a managed app beside it. <see cref="SingleFileBundle"/>: a
/// non-zero offset, so managed assemblies are packed INSIDE this native file, where the CIL analysis does not see them.
/// <see cref="HostTemplate"/>: the unpatched app-path placeholder is still present (an SDK template or singlefilehost
/// shipped as a file). Set only on <see cref="NativeBinaryCode.Native"/> binaries: managed files can hold the signature
/// as data (Microsoft.NET.HostModel.dll). Attacker-forgeable bytes: a fact for triage, never grounds to suppress
/// anything. Old JSON reads <see cref="None"/>, which there means "not checked", not "no marker".
/// </summary>
public enum DotNetHost { None, AppHost, SingleFileBundle, HostTemplate }

/// <summary>
/// Whether <see cref="PackageCapabilityReport.NativeBinaries"/> is the whole answer. Old JSON predates the field and
/// reads <see cref="Unavailable"/>: an empty list from it is not "ships no native code".
/// </summary>
public enum NativeBinaryScanStatus
{
    /// <summary>Not run. Not produced by <see cref="PackageScanner.Scan"/>.</summary>
    NotRun,

    /// <summary>Every contained file's header was read; the list is complete (possibly empty).</summary>
    Completed,

    /// <summary>Some files could not be read (see <see cref="PackageCapabilityReport.NativeBinaryScanUnavailableReason"/>):
    /// listed binaries are real, absence is not evidence.</summary>
    Unavailable,
}

/// <summary>
/// A binary shipped in a package that carries native code or escapes the CIL inventory (see <see cref="NativeBinaryCode"/>):
/// PE, ELF or Mach-O, found by header in ANY contained file, whatever its name or extension. A fact for agents and reviewers, not a verdict: it gates nothing. Native code is
/// opaque to the CIL analysis, so this is where a package's unanalysed executable content is named.
/// </summary>
public sealed record NativeBinary(
    string RelativePath,            // package-relative path, escaped (YaraPathSafety.Escape) at construction
    NativeBinaryFormat Format,
    NativeBinaryKind Kind,
    string? Architecture,           // e.g. "x64", "arm64"; universal Mach-O joins slices with '+'; null when Malformed
    NativeBinaryCode Code,          // Native, or for a PE with a CLR header: MixedMode / ReadyToRun / ILOnly
    PackageItemRole Role,
    long Size,
    string Sha256,                  // lowercase hex
    DotNetHost DotNetHost = DotNetHost.None,   // additive; old JSON => None
    int? BundledFiles = null);      // SingleFileBundle only: the bundle header's file count, null if unreadable

/// <summary>A parsed native header; see <see cref="NativeBinaryDetector.Detect"/>.</summary>
internal readonly record struct NativeBinaryHeader(NativeBinaryFormat Format, NativeBinaryKind Kind, string? Architecture, NativeBinaryCode Code);

/// <summary>
/// Identifies PE, ELF and Mach-O binaries by header. Reads a bounded number of bytes. IL-only managed PEs are returned
/// with <see cref="NativeBinaryCode.ILOnly"/> for the caller to drop when the CIL analysis owns them; Java class files,
/// which share the universal Mach-O magic, return null.
/// </summary>
internal static class NativeBinaryDetector
{
    #region Methods
    /// <summary>The native header of <paramref name="stream"/> (seekable), or null when it is not a native binary.
    /// Throws only on I/O failure.</summary>
    internal static NativeBinaryHeader? Detect(Stream stream)
    {
        var head = ReadAt(stream, 0, 64);
        if (head.Length < 4)
            return null;
        if (head[0] == 'M' && head[1] == 'Z')
            return Pe(stream);
        if (head.AsSpan(0, 4).SequenceEqual(elfMagic))
            return Elf(stream, head);

        var be = BinaryPrimitives.ReadUInt32BigEndian(head);
        var le = BinaryPrimitives.ReadUInt32LittleEndian(head);
        return le is MhMagic or MhMagic64 ? MachO(head, littleEndian: true)
            : be is MhMagic or MhMagic64 ? MachO(head, littleEndian: false)
            : be is FatMagic or FatMagic64 ? Universal(stream, head, be == FatMagic64)
            : null;
    }

    private static NativeBinaryHeader? Pe(Stream stream)
    {
        PEHeaders headers;
        NativeBinaryCode code;
        try
        {
            stream.Position = 0;
            using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            headers = reader.PEHeaders;
            code = headers.CorHeader is not { } cor || !HasReadableMetadata(reader) ? NativeBinaryCode.Native
                : cor.ManagedNativeHeaderDirectory.Size != 0 ? NativeBinaryCode.ReadyToRun
                : (cor.Flags & CorFlags.ILOnly) != 0 ? NativeBinaryCode.ILOnly
                : NativeBinaryCode.MixedMode;
        }
        catch (Exception ex) when (ex is not IOException and not UnauthorizedAccessException)
        {
            return Malformed(NativeBinaryFormat.PE);
        }

        var c = headers.CoffHeader.Characteristics;
        var kind = c.HasFlag(Characteristics.Dll) ? NativeBinaryKind.SharedLibrary
            : c.HasFlag(Characteristics.ExecutableImage) ? NativeBinaryKind.Executable
            : NativeBinaryKind.Other;
        return new(NativeBinaryFormat.PE, kind, PeMachine(headers.CoffHeader.Machine), code);
    }

    // A CLR header alone is one attacker-set structure; managed means its metadata actually reads.
    private static bool HasReadableMetadata(PEReader reader)
    {
        try
        {
            return reader.HasMetadata && reader.GetMetadataReader() is not null;
        }
        catch (Exception ex) when (ex is not IOException and not UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static NativeBinaryHeader Elf(Stream stream, byte[] head)
    {
        var is64 = head[4] == 2;
        var le = head[5] == 1;
        if (head[4] is not (1 or 2) || head[5] is not (1 or 2) || head.Length < (is64 ? 64 : 52))
            return Malformed(NativeBinaryFormat.Elf);

        var kind = U16(head, 16, le) switch
        {
            2 => NativeBinaryKind.Executable,
            3 => HasInterpreter(stream, head, is64, le) ? NativeBinaryKind.Executable : NativeBinaryKind.SharedLibrary,
            _ => NativeBinaryKind.Other,
        };
        return new(NativeBinaryFormat.Elf, kind, ElfMachine(U16(head, 18, le)), NativeBinaryCode.Native);
    }

    // Whether a PT_INTERP program header exists: what tells a PIE executable from a shared library (both ET_DYN).
    private static bool HasInterpreter(Stream stream, byte[] head, bool is64, bool le)
    {
        var offset = is64 ? U64(head, 32, le) : U32(head, 28, le);
        var size = (int)U16(head, is64 ? 54 : 42, le);
        var count = Math.Min((int)U16(head, is64 ? 56 : 44, le), MaxProgramHeaders);
        if (size != (is64 ? ElfPhdrSize64 : ElfPhdrSize32) || count == 0 || offset > long.MaxValue)
            return false;

        var table = ReadAt(stream, (long)offset, size * count);
        return Enumerable.Range(0, table.Length / size).Any(i => U32(table, i * size, le) == PtInterp);
    }

    private static NativeBinaryHeader MachO(byte[] head, bool littleEndian)
    {
        if (head.Length < 16)
            return Malformed(NativeBinaryFormat.MachO);

        var kind = U32(head, 12, littleEndian) switch
        {
            2 => NativeBinaryKind.Executable,
            6 or 8 or 9 => NativeBinaryKind.SharedLibrary,   // dylib, bundle, dylib stub
            _ => NativeBinaryKind.Other,
        };
        return new(NativeBinaryFormat.MachO, kind, MachOCpu(U32(head, 4, littleEndian)), NativeBinaryCode.Native);
    }

    // A fat (universal) Mach-O: the slice count, then one record per slice. A Java class file shares CAFEBABE, but its
    // next word is its version (major >= 45), so a count outside 1..MaxFatSlices is not a universal binary.
    private static NativeBinaryHeader? Universal(Stream stream, byte[] head, bool is64)
    {
        var count = head.Length < 8 ? 0u : U32(head, 4, false);
        if (count is 0 or > MaxFatSlices)
            return null;

        var entry = is64 ? 32 : 20;
        var table = ReadAt(stream, 8, entry * (int)count);
        if (table.Length < entry * count)
            return Malformed(NativeBinaryFormat.MachOUniversal);

        var slices = Enumerable.Range(0, (int)count).Select(i => i * entry).ToArray();
        var first = is64 ? U64(table, 8, false) : U32(table, 8, false);
        // The kind is the first slice's. A slice that is not a Mach-O (a static library's "!<arch>" archive) is Other.
        var thin = first > long.MaxValue ? Array.Empty<byte>() : ReadAt(stream, (long)first, 16);
        var kind = thin.Length < 4 ? NativeBinaryKind.Malformed
            : BinaryPrimitives.ReadUInt32LittleEndian(thin) is MhMagic or MhMagic64 ? MachO(thin, true).Kind
            : BinaryPrimitives.ReadUInt32BigEndian(thin) is MhMagic or MhMagic64 ? MachO(thin, false).Kind
            : NativeBinaryKind.Other;
        var arch = string.Join('+', slices.Select(o => MachOCpu(U32(table, o, false))).Distinct());
        return new(NativeBinaryFormat.MachOUniversal, kind, arch, NativeBinaryCode.Native);
    }

    private static NativeBinaryHeader Malformed(NativeBinaryFormat format) => new(format, NativeBinaryKind.Malformed, null, NativeBinaryCode.Native);

    private static string PeMachine(Machine m) => m switch
    {
        Machine.I386 => "x86",
        Machine.Amd64 => "x64",
        Machine.Arm64 => "arm64",
        Machine.Arm or Machine.ArmThumb2 or Machine.Thumb => "arm",
        _ => $"pe-machine-0x{(ushort)m:x4}",
    };

    private static string ElfMachine(uint m) => m switch
    {
        3 => "x86",
        0x3E => "x64",
        0x28 => "arm",
        0xB7 => "arm64",
        0xF3 => "riscv",
        0x08 => "mips",
        0x14 => "ppc",
        0x15 => "ppc64",
        0x16 => "s390x",
        0x102 => "loongarch64",
        _ => $"elf-machine-{m}",
    };

    private static string MachOCpu(uint cpu) => cpu switch
    {
        7 => "x86",
        0x01000007 => "x64",
        12 => "arm",
        0x0100000C => "arm64",
        0x0200000C => "arm64_32",
        18 => "ppc",
        0x01000012 => "ppc64",
        _ => $"macho-cpu-0x{cpu:x}",
    };

    // Up to `count` bytes at `offset`; shorter (possibly empty) at end of stream.
    internal static byte[] ReadAt(Stream stream, long offset, int count)
    {
        if (offset >= stream.Length || count <= 0)
            return [];
        stream.Position = offset;
        var buffer = new byte[(int)Math.Min(count, stream.Length - offset)];
        return buffer[..stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false)];
    }

    private static uint U16(byte[] b, int at, bool le) =>
        le ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(at));

    private static uint U32(byte[] b, int at, bool le) =>
        le ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(at));

    private static ulong U64(byte[] b, int at, bool le) =>
        le ? BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(at));
    #endregion

    #region Fields
    private const uint MhMagic = 0xFEEDFACE, MhMagic64 = 0xFEEDFACF, FatMagic = 0xCAFEBABE, FatMagic64 = 0xCAFEBABF;
    private const uint PtInterp = 3;
    private const int ElfPhdrSize32 = 32, ElfPhdrSize64 = 56;
    private const int MaxProgramHeaders = 512, MaxFatSlices = 32;
    private static readonly byte[] elfMagic = [0x7F, (byte)'E', (byte)'L', (byte)'F'];
    #endregion
}

/// <summary>
/// One pass over a detected binary: its SHA-256 and its <see cref="DotNetHost"/> marker. The marker can sit megabytes
/// in (a singlefilehost-based bundle at ~7 MB), so it is searched over the whole file in the read the hash needs anyway.
/// </summary>
internal static class DotNetHostScanner
{
    #region Methods
    /// <summary>Hashes <paramref name="stream"/> from the start and classifies its .NET host marker. Throws only on I/O failure.</summary>
    internal static (string Sha256, DotNetHost Host, int? BundledFiles) HashAndScan(Stream stream)
    {
        stream.Position = 0;
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize + Overlap);
        var (carry, origin, signatureAt, placeholder) = (0, 0L, -1L, false);
        try
        {
            int read;
            while ((read = stream.Read(buffer, carry, BufferSize)) > 0)
            {
                sha.AppendData(buffer, carry, read);
                var window = buffer.AsSpan(0, carry + read);
                if (signatureAt < 0 && window.IndexOf(bundleSignature) is var at and >= 0)
                    signatureAt = origin + at;
                if (!placeholder)
                    placeholder = window.IndexOf(appPathPlaceholder) >= 0;

                // Keep a tail so a marker straddling two reads is still found.
                carry = Math.Min(Overlap, window.Length);
                window[^carry..].CopyTo(buffer);
                origin += window.Length - carry;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        var hash = Convert.ToHexStringLower(sha.GetHashAndReset());
        var headerOffset = signatureAt >= 8 ? BinaryPrimitives.ReadInt64LittleEndian(NativeBinaryDetector.ReadAt(stream, signatureAt - 8, 8)) : 0;
        return signatureAt < 0 ? (hash, placeholder ? DotNetHost.HostTemplate : DotNetHost.None, null)
            : headerOffset == 0 ? (hash, placeholder ? DotNetHost.HostTemplate : DotNetHost.AppHost, null)
            : (hash, DotNetHost.SingleFileBundle, BundledFileCount(stream, signatureAt, headerOffset));
    }

    // The bundle header starts (major u32, minor u32, file count i32); null unless it is there and plausible. The bundler
    // appends it after the host, so a header at or before the signature is not a real one.
    private static int? BundledFileCount(Stream stream, long signatureAt, long headerOffset)
    {
        if (headerOffset <= signatureAt || headerOffset > stream.Length - 12)
            return null;
        var header = NativeBinaryDetector.ReadAt(stream, headerOffset, 12);
        var major = BinaryPrimitives.ReadUInt32LittleEndian(header);
        var count = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8));
        return major is >= 1 and <= MaxBundleMajor && count is >= 0 and <= MaxBundledFiles ? count : null;
    }
    #endregion

    #region Fields
    private const int BufferSize = 1 << 20, Overlap = 63;   // Overlap: the longest marker (64) minus one
    private const uint MaxBundleMajor = 64;
    private const int MaxBundledFiles = 1_000_000;

    // The host's bundle signature constant (dotnet/runtime HostModel). Measured 2026-11-18: once in each SDK apphost
    // template 3.1.100-10.0.101, and in every apphost/bundle in the corpus. It is NOT the SHA-256 of ".net core bundle".
    private static readonly byte[] bundleSignature =
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    // The apphost's unpatched app-path slot: SHA-256("foobar") as hex, overwritten with the app's dll name when patched.
    private static readonly byte[] appPathPlaceholder = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"u8.ToArray();
    #endregion
}
