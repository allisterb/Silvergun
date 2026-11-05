namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

using Silvergun.CodeAnalysis.IL.Tests.AliasedPdbFixture;
using Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

using Xunit;

/// <summary>
/// ADR 0022 Stage 1, review round 1 C1 (<c>docs/agent/tasks/cci-assertions-stage1.md</c>): a <c>.pdb</c> beside an
/// assembly was a second untrusted parser on the load path. A portable PDB whose alias import names an AssemblyRef row
/// with an undefined content type (flags <c>| 0x0400</c>, content type 2) drove the DiaSymReader converter, a separate
/// compilation the CCI <c>Debug</c> alias does not cover, into a live <c>Debug.Assert(false)</c>: the reviewer measured
/// <c>0x80131623</c> (FailFast) from <c>AssemblyDisassembler.Create</c>, and exit 0 for the unpatched control.
/// <para>
/// <b>Fixture.</b> <c>Silvergun.CodeAnalysis.IL.Tests.AliasedPdbFixture</c>: one method, compiled with an
/// <c>extern alias</c> over an aliased reference, so its portable PDB carries one AliasAssemblyReference import, and a
/// source-named local (<see cref="AliasedReader.LocalName"/>) that Model reports only when the PDB was read. Each test
/// copies the dll and pdb to its own temp directory and patches the copy there, in this process, with
/// System.Reflection.Metadata only; nothing of CCI touches a patched file in this host.
/// </para>
/// <para>
/// <b>Every load runs in a child</b> (the PathologicalSignatureProbe's <c>pdb-load</c> verb, <see cref="PdbProbe"/>): a
/// regression is a FailFast, which would kill this host. Pinned, each against its unpatched control:
/// <list type="bullet">
/// <item><description>Silvergun's path (<see cref="AssemblyDisassembler.Create"/>) reads no PDB at all: it loads the
/// patched pair, and even a clean PDB's source names do not appear.</description></item>
/// <item><description>Defense in depth: the upstream loader with PDBs on (<c>Loader(host, readPdbs: true)</c>) also
/// completes on the patched pair; the PDB is dropped rather than fatal.</description></item>
/// <item><description><c>Loader(host)</c> still reads PDBs by default (the clean pair's source names appear).</description></item>
/// <item><description>A garbage PDB beside a good assembly changes nothing on Silvergun's path.</description></item>
/// </list>
/// </para>
/// </summary>
public sealed class PdbReaderRegressionTests : IDisposable
{
    #region Constructors
    public PdbReaderRegressionTests() => directory = Directory.CreateTempSubdirectory("silvergun-pdb-regression-").FullName;
    #endregion

    #region Methods
    // ---- premises ------------------------------------------------------------------------------------------------

    [Fact]
    public void Premise_TheFixturesPdbIsBesideIt_AndHoldsAnAliasAssemblyReferenceImport()
    {
        Assert.True(File.Exists(FixturePdb), $"'{FixturePdb}' was not copied next to this test assembly.");
        Assert.True(AliasImports(FixturePdb) >= 1, "The fixture's portable PDB holds no AliasAssemblyReference import: the extern alias did not reach it.");
    }

    /// <summary>The patch sets exactly the content-type bits of the one AssemblyRef row, to 2, and changes no other byte.</summary>
    [Fact]
    public void Premise_ThePatch_SetsContentType2OnTheAliasedReference_AndNothingElse()
    {
        var clean = Pair("clean", patch: false);
        var patched = Pair("patched", patch: true);

        Assert.Equal(0, ContentType(clean, AliasedReference));
        Assert.Equal(2, ContentType(patched, AliasedReference));
        var (a, b) = (File.ReadAllBytes(clean), File.ReadAllBytes(patched));
        Assert.Equal(a.Length, b.Length);
        Assert.Single(Enumerable.Range(0, a.Length), i => a[i] != b[i]);
        Assert.Equal(File.ReadAllBytes(Path.ChangeExtension(clean, "pdb")), File.ReadAllBytes(Path.ChangeExtension(patched, "pdb")));
    }

    // ---- Silvergun's path ----------------------------------------------------------------------------------------

    /// <summary>
    /// (a) <see cref="AssemblyDisassembler.Create"/> on the patched pair (and on the clean control): the child exits 0,
    /// the load succeeds with no reader assertion, and no PDB source name appears, because no PDB is read.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Disassembler_OnTheAliasedPair_Succeeds_WithoutReadingThePdb(bool patch)
    {
        var result = Probe(Pair(patch ? "patched" : "clean", patch), "disassembler");

        AssertCompleted(result);
        Assert.Contains("LOADED True", Lines(result));
        Assert.Contains("READER-ASSERTIONS 0", Lines(result));
        Assert.Contains($"SOURCE-LOCAL {AliasedReader.LocalName} False", Lines(result));
    }

    /// <summary>
    /// (c) A garbage <c>.pdb</c> beside a good assembly (random bytes; random bytes after a portable PDB's or a Windows
    /// PDB's signature) does not affect <see cref="AssemblyDisassembler.Create"/>: it succeeds with no reader assertion.
    /// </summary>
    [Theory]
    [InlineData(Garbage.Random)]
    [InlineData(Garbage.PortableSignature)]
    [InlineData(Garbage.WindowsSignature)]
    public void Disassembler_WithAGarbagePdbBesideAGoodAssembly_IsUnaffected(Garbage garbage)
    {
        var result = Probe(GarbagePair(garbage), "disassembler");

        AssertCompleted(result);
        Assert.Contains("LOADED True", Lines(result));
        Assert.Contains("READER-ASSERTIONS 0", Lines(result));
        Assert.Contains("RECORDED 0", Lines(result));
    }

    // ---- the upstream loader: defense in depth -------------------------------------------------------------------

    /// <summary>
    /// (b) <c>new Loader(host, readPdbs: true).LoadAssembly</c> on the patched pair completes in the child: the converter,
    /// built without DEBUG, throws instead of FailFasting, and the loader's catch drops the PDB, so the patched pair's
    /// source names are gone while the clean control's are read.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void LoaderReadingPdbs_OnTheAliasedPair_Completes_DroppingOnlyTheCorruptPdb(bool patch, bool namesRead)
    {
        var result = Probe(Pair(patch ? "patched" : "clean", patch), "loader-pdbs");

        AssertCompleted(result);
        Assert.Contains("LOADED True", Lines(result));
        Assert.Contains($"SOURCE-LOCAL {AliasedReader.LocalName} {namesRead}", Lines(result));
    }

    /// <summary>Twin of (c) on the upstream loader with PDBs on: a garbage PDB is dropped, never fatal.</summary>
    [Theory]
    [InlineData(Garbage.Random)]
    [InlineData(Garbage.PortableSignature)]
    [InlineData(Garbage.WindowsSignature)]
    public void LoaderReadingPdbs_WithAGarbagePdb_Completes(Garbage garbage)
    {
        var result = Probe(GarbagePair(garbage), "loader-pdbs");

        AssertCompleted(result);
        Assert.Contains("LOADED True", Lines(result));
    }

    /// <summary>
    /// <c>Loader(host)</c> still reads PDBs by default (the upstream behaviour the new <c>readPdbs</c> parameter must not
    /// change): over the clean pair, the PDB's source name of the local appears. Observed in a child like the rest, since
    /// a raw <c>Loader</c> in this host would race <see cref="AssemblyDisassembler"/>'s serialized loads on Analysis.Net's
    /// static state.
    /// </summary>
    [Fact]
    public void LoaderWithTheOneArgumentConstructor_StillReadsThePdb()
    {
        var result = Probe(Pair("clean", patch: false), "loader-default");

        AssertCompleted(result);
        Assert.Contains($"SOURCE-LOCAL {AliasedReader.LocalName} True", Lines(result));
    }

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch { /* best-effort temp cleanup */ }
    }

    // A copy of the fixture's dll + pdb in its own subdirectory, the dll patched when asked.
    private string Pair(string name, bool patch)
    {
        var target = Directory.CreateDirectory(Path.Combine(directory, name)).FullName;
        var dll = Path.Combine(target, Path.GetFileName(FixtureDll));
        File.Copy(FixtureDll, dll);
        File.Copy(FixturePdb, Path.ChangeExtension(dll, "pdb"));
        if (patch)
            SetContentType2(dll, AliasedReference);
        return dll;
    }

    // The clean fixture dll beside a garbage pdb of 4 KiB (seeded, so a failure reproduces).
    private string GarbagePair(Garbage garbage)
    {
        var target = Directory.CreateDirectory(Path.Combine(directory, $"garbage-{garbage}")).FullName;
        var dll = Path.Combine(target, Path.GetFileName(FixtureDll));
        File.Copy(FixtureDll, dll);
        var bytes = new byte[4096];
        new Random(2026).NextBytes(bytes);
        byte[] signature = garbage switch
        {
            Garbage.PortableSignature => [0x42, 0x53, 0x4A, 0x42],   // "BSJB", the metadata signature a portable PDB starts with
            Garbage.WindowsSignature => [.. Encoding.ASCII.GetBytes("Microsoft C/C++ MSF 7.00"), 0x0D, 0x0A, 0x1A, 0x44, 0x53, 0x00, 0x00, 0x00],
            _ => [],
        };
        signature.CopyTo(bytes, 0);
        File.WriteAllBytes(Path.ChangeExtension(dll, "pdb"), bytes);
        return dll;
    }

    // ORs 0x0400 into the Flags column (after four 2-byte version columns) of the AssemblyRef row named reference.
    private static void SetContentType2(string path, string reference)
    {
        int offset;
        using (var stream = File.OpenRead(path))
        using (var pe = new PEReader(stream))
        {
            var md = pe.GetMetadataReader();
            var handle = md.AssemblyReferences.Single(h => md.GetString(md.GetAssemblyReference(h).Name) == reference);
            offset = pe.PEHeaders.MetadataStartOffset + md.GetTableMetadataOffset(TableIndex.AssemblyRef)
                + (MetadataTokens.GetRowNumber(handle) - 1) * md.GetTableRowSize(TableIndex.AssemblyRef) + 8;
        }
        var bytes = File.ReadAllBytes(path);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset)) | 0x0400u);
        File.WriteAllBytes(path, bytes);
    }

    private static int ContentType(string path, string reference)
    {
        using var stream = File.OpenRead(path);
        using var pe = new PEReader(stream);
        var md = pe.GetMetadataReader();
        var flags = md.AssemblyReferences.Select(md.GetAssemblyReference).Single(r => md.GetString(r.Name) == reference).Flags;
        return ((int)flags & 0x0E00) >> 9;
    }

    private static int AliasImports(string pdbPath)
    {
        using var stream = File.OpenRead(pdbPath);
        using var provider = MetadataReaderProvider.FromPortablePdbStream(stream);
        var pdb = provider.GetMetadataReader();
        return pdb.ImportScopes.Select(pdb.GetImportScope).SelectMany(s => s.GetImports()).Count(i => i.Kind == ImportDefinitionKind.AliasAssemblyReference);
    }

    private static ProbeResult Probe(string assembly, string mode) =>
        ChildProcessProbe.Run(ProbeExe, TimeSpan.FromSeconds(60), PdbProbe.Verb, assembly, mode, AliasedReader.LocalName);

    private static void AssertCompleted(ProbeResult result)
    {
        Assert.True(result.ExitedCleanly, $"The pdb-load probe did not exit cleanly - {result.Describe()}");
        Assert.Contains("DONE", Lines(result));
    }

    private static string[] Lines(ProbeResult result) => result.StandardOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
    #endregion

    #region Fields
    private const string AliasedReference = "Silvergun.CodeAnalysis.IL.Tests.IndicatorCapFixture";

    private static readonly string FixtureDll = Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.AliasedPdbFixture.dll");

    private static readonly string FixturePdb = Path.ChangeExtension(FixtureDll, "pdb");

    private static readonly string ProbeExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe");

    private readonly string directory;
    #endregion

    #region Child types
    public enum Garbage { Random, PortableSignature, WindowsSignature }
    #endregion
}
