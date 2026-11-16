namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

using Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

using Xunit;

/// <summary>
/// <c>docs/agent/tasks/hidden-payloads-1.md</c> review rounds 1-2 (C1, C2, W2, W-a, W-b, W-e): hostile RVA field data and
/// AssemblyRef resources. Mutually recursive value types and an AssemblyRef resource loop entered from outside the scanned
/// row were an uncatchable stack overflow, so every assembly here is scanned in a CHILD process (<see cref="ObfuscationProbe"/>) and the test asserts on its exit
/// code and output; nothing is loaded or run.
/// </summary>
public sealed class HiddenPayloadsHostileTests : IDisposable
{
    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    #region Methods — C1 RVA field types
    [Fact]
    public void Scan_MutuallyRecursiveStructFieldWithRvaData_CompletesWithoutFinding()
    {
        var raw = new RawAssembly("RecursiveStructs");
        var a = raw.Type("N", "A", ValueType(raw), StructAttributes);
        var bHandle = raw.NextType();
        raw.Field("b", FieldAttributes.Public, t => t.Type(bHandle, isValueType: true));
        raw.Type("N", "B", ValueType(raw), StructAttributes);
        raw.Field("a", FieldAttributes.Public, t => t.Type(a, isValueType: true));
        raw.Type("N", "Holder", raw.Object);
        var data = raw.Field("Data", FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA, t => t.Type(a, isValueType: true));
        raw.FieldRva(data, raw.MappedData(HiddenPayloadsTests.PeHeader(96)));

        var scan = Scan(raw.Save(directory));

        Assert.True(scan.Result.ExitedCleanly, $"A mutually recursive struct field must not crash the scan - {scan.Result.Describe()}");
        Assert.Contains("DONE", scan.Lines);
        Assert.Empty(scan.Findings);
    }

    [Theory]
    [InlineData("EnumData")]
    [InlineData("GenericData")]
    public void Scan_RvaFieldOfEnumOrGenericInstanceType_IsSkippedWhileASizedStructIsRead(string skipped)
    {
        var raw = new RawAssembly("RvaFieldTypes" + skipped);
        var pe = HiddenPayloadsTests.PeHeader(96);

        var enumType = raw.Type("N", "E", raw.TypeRef(raw.Runtime, "System", "Enum"), TypeAttributes.Public | TypeAttributes.Sealed);
        raw.Field("value__", FieldAttributes.Public | FieldAttributes.SpecialName | FieldAttributes.RTSpecialName, t => t.Int32());

        var generic = raw.Type("N", "G`1", ValueType(raw), StructAttributes);
        raw.GenericParameter(generic, "T", 0);
        raw.Field("value", FieldAttributes.Public, t => t.GenericTypeParameter(0));

        var sized = raw.Type("N", "S", ValueType(raw), StructAttributes);
        raw.Layout(sized, 96);

        raw.Type("N", "Holder", raw.Object);
        const FieldAttributes mapped = FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA;
        var skippedField = skipped == "EnumData"
            ? raw.Field(skipped, mapped, t => t.Type(enumType, isValueType: true))
            : raw.Field(skipped, mapped, t => t.GenericInstantiation(generic, 1, isValueType: true).AddArgument().Int32());
        raw.FieldRva(skippedField, raw.MappedData(pe));
        var sizedField = raw.Field("SizedData", mapped, t => t.Type(sized, isValueType: true));
        raw.FieldRva(sizedField, raw.MappedData(pe));

        var scan = Scan(raw.Save(directory));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        var finding = Assert.Single(scan.Findings);
        Assert.Equal(("EncodedExecutable", "Windows PE", "FieldData", "SizedData"), (finding[0], finding[1], finding[2], finding[4]));
    }
    #endregion

    #region Methods — W2 RVA blocks
    [Fact]
    public void Scan_ManyFieldsAliasingOneBlockWithNoLoader_GiveExactlyOneFinding()
    {
        var raw = new RawAssembly("AliasedBlock");
        var sized = raw.Type("N", "S", ValueType(raw), StructAttributes);
        raw.Layout(sized, 96);
        raw.Type("N", "Holder", raw.Object);
        var offset = raw.MappedData(HiddenPayloadsTests.PeHeader(96));
        for (var i = 0; i < 6; i++)
            raw.FieldRva(raw.Field($"F{i}", FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA, t => t.Type(sized, isValueType: true)), offset);

        var scan = Scan(raw.Save(directory));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        var finding = Assert.Single(scan.Findings);
        Assert.Equal("FieldData", finding[2]);
    }

    [Fact]
    public void Scan_BlobOverTheCap_ReportsOnlyTheBytesRead()
    {
        var raw = new RawAssembly("BigBlock");
        var size = ObfuscationAnalysis.MaxBlobBytes + 4000;
        var big = raw.Type("N", "Big", ValueType(raw), StructAttributes);
        raw.Layout(big, size);
        raw.Type("N", "Holder", raw.Object);
        var field = raw.Field("Data", FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA, t => t.Type(big, isValueType: true));
        raw.FieldRva(field, raw.MappedData(HiddenPayloadsTests.PeHeader(size)));

        var scan = Scan(raw.Save(directory));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        var finding = Assert.Single(scan.Findings);
        Assert.Equal(ObfuscationAnalysis.MaxBlobBytes.ToString(), finding[5]);
    }
    #endregion

    #region Methods — C2 resources implemented by an AssemblyRef
    [Fact]
    public void Scan_ResourceImplementedByAnAbsentAssembly_CompletesWithoutFinding()
    {
        var raw = new RawAssembly("MissingSiblingResource");
        raw.Type("N", "Holder", raw.Object);
        var sibling = raw.AssemblyRef("Missing.Sibling");

        var scan = Scan(raw.Save(directory, md => md.AddManifestResource(ManifestResourceAttributes.Public, md.GetOrAddString("sibling.bin"), sibling, 0)));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        Assert.Contains("DONE", scan.Lines);
        Assert.Empty(scan.Findings);
    }

    [Fact]
    public void Scan_ResourceImplementedByAPresentAssemblyWithAPe_IsNotResolved()
    {
        EmitWithResource("Sibling.Present", "payload.bin", HiddenPayloadsTests.PeHeader(96));
        var raw = new RawAssembly("PresentSiblingResource");
        raw.Type("N", "Holder", raw.Object);
        var sibling = raw.AssemblyRef("Sibling.Present");

        var scan = Scan(raw.Save(directory, md => md.AddManifestResource(ManifestResourceAttributes.Public, md.GetOrAddString("payload.bin"), sibling, 0)));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        Assert.Empty(scan.Findings);
    }

    // The cycles below do NOT pass through the row being scanned: CCI's own guard (resRef == originalReference) already
    // stops A->A and A<->B, so only a loop entered from outside (A->B->C->B, A->B->B) tests the "never resolve an
    // AssemblyRef row" fix.
    [Fact]
    public void Scan_ResourceLeadingIntoALoopNotThroughItself_CompletesWithoutFinding()
    {
        SaveLooper("LoopA", "LoopB");
        SaveLooper("LoopB", "LoopC");
        SaveLooper("LoopC", "LoopB");

        var scan = Scan(Path.Combine(directory, "LoopA.dll"));

        Assert.True(scan.Result.ExitedCleanly, $"A resource row leading into a B<->C loop must not recurse - {scan.Result.Describe()}");
        Assert.Contains("DONE", scan.Lines);
        Assert.Empty(scan.Findings);
    }

    [Fact]
    public void Scan_ResourceLeadingIntoASelfReferencingAssembly_CompletesWithoutFinding()
    {
        SaveLooper("EntryA", "SelfB");
        SaveLooper("SelfB", "SelfB");

        var scan = Scan(Path.Combine(directory, "EntryA.dll"));

        Assert.True(scan.Result.ExitedCleanly, $"A resource row leading into a self-referencing assembly must not recurse - {scan.Result.Describe()}");
        Assert.Contains("DONE", scan.Lines);
        Assert.Empty(scan.Findings);
    }
    #endregion

    #region Methods — W-a, W-b RVA blobs
    [Fact]
    public void Scan_TwoRvasOfTheSameSize_AreEachReadAndClassified()
    {
        var raw = new RawAssembly("TwoRvas");
        var sized = raw.Type("N", "S", ValueType(raw), StructAttributes);
        raw.Layout(sized, 96);
        raw.Type("N", "Holder", raw.Object);
        const FieldAttributes mapped = FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA;
        raw.FieldRva(raw.Field("Benign", mapped, t => t.Type(sized, isValueType: true)), raw.MappedData(Enumerable.Range(1, 96).Select(i => (byte)(i * 3 % 200 + 1)).ToArray()));
        raw.FieldRva(raw.Field("Payload", mapped, t => t.Type(sized, isValueType: true)), raw.MappedData(HiddenPayloadsTests.PeHeader(96)));

        var scan = Scan(raw.Save(directory));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        var finding = Assert.Single(scan.Findings);
        Assert.Equal(("EncodedExecutable", "Payload"), (finding[0], finding[4]));
    }

    [Fact]
    public void Scan_RvaFieldTypedByAForeignTypeRef_IsNotRead()
    {
        var raw = new RawAssembly("ForeignTypedRva");
        var pe = HiddenPayloadsTests.PeHeader(96);
        var other = raw.AssemblyRef("Other.Lib");
        var foreign = raw.TypeRef(other, "Other", "Blob96");
        var sized = raw.Type("N", "S", ValueType(raw), StructAttributes);
        raw.Layout(sized, 96);
        raw.Type("N", "Holder", raw.Object);
        const FieldAttributes mapped = FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA;
        raw.FieldRva(raw.Field("ForeignData", mapped, t => t.Type(foreign, isValueType: true)), raw.MappedData(pe));
        raw.FieldRva(raw.Field("SizedData", mapped, t => t.Type(sized, isValueType: true)), raw.MappedData(pe));

        var scan = Scan(raw.Save(directory));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        var finding = Assert.Single(scan.Findings);
        Assert.Equal("SizedData", finding[4]);
    }

    [Fact]
    public void Scan_ManyMzDecoysWithFarPeOffset_DoNotStarveALaterResource()
    {
        var raw = new RawAssembly("MzDecoys");
        const FieldAttributes mapped = FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA;
        // Budget arithmetic (MaxBlobBytesPerAssembly = 16 MiB = 16,777,216): every decoy has its own size (so its own memo
        // key) of 65536+i, which puts "PE\0\0" at e_lfanew = 0xFFFC = 65532 inside every read. A reader that charged the
        // bytes skipped to reach it paid about 64 + 65536 per decoy: 300 x 65,600 = 19.7 MB, past the budget, so the later
        // resource went unread. Charging only the 4 signature bytes costs about 300 x 68 = 20 KB.
        const int decoys = 300;
        var types = Enumerable.Range(0, decoys).Select(i =>
        {
            var type = raw.Type("N", $"S{i}", ValueType(raw), StructAttributes);
            raw.Layout(type, 65536 + i);
            return type;
        }).ToArray();
        raw.Type("N", "Holder", raw.Object);
        var decoy = Enumerable.Range(1, 65536 + decoys).Select(i => (byte)(i * 7 % 250 + 1)).ToArray();
        decoy[0] = (byte)'M';
        decoy[1] = (byte)'Z';
        BitConverter.GetBytes(0xFFFC).CopyTo(decoy, 0x3C);   // 65532: the 4 bytes there are filler, not "PE\0\0"
        var offset = raw.MappedData(decoy);
        for (var i = 0; i < types.Length; i++)
            raw.FieldRva(raw.Field($"F{i}", mapped, t => t.Type(types[i], isValueType: true)), offset);
        var resources = new BlobBuilder();
        var pe = HiddenPayloadsTests.PeHeader(96);
        resources.WriteInt32(pe.Length);
        resources.WriteBytes(pe);

        var scan = Scan(raw.Save(directory, md => md.AddManifestResource(ManifestResourceAttributes.Public, md.GetOrAddString("payload.bin"), default(EntityHandle), 0), resources));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        var finding = Assert.Single(scan.Findings);
        Assert.Equal(("EncodedExecutable", "Resource", "payload.bin"), (finding[0], finding[2], finding[4]));
        Assert.Contains("TRUNCATED False", scan.Lines);
    }

    [Fact]
    public void Scan_MoreBlobReadsThanTheCap_SetsTruncatedAndCompletes()
    {
        var raw = new RawAssembly("ManyReads");
        const FieldAttributes mapped = FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA;
        const int count = 4097;   // MaxBlobReads is 4096, a private constant: one distinct (RVA, size) per field
        var types = Enumerable.Range(0, count).Select(i =>
        {
            var type = raw.Type("N", $"S{i}", ValueType(raw), StructAttributes);
            raw.Layout(type, 100 + i);
            return type;
        }).ToArray();
        raw.Type("N", "Holder", raw.Object);
        var offset = raw.MappedData(Enumerable.Range(1, 8192).Select(i => (byte)(i * 7 % 250 + 1)).ToArray());
        for (var i = 0; i < types.Length; i++)
            raw.FieldRva(raw.Field($"F{i}", mapped, t => t.Type(types[i], isValueType: true)), offset);

        var scan = Scan(raw.Save(directory));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        Assert.Contains("TRUNCATED True", scan.Lines);
        Assert.Empty(scan.Findings);
    }

    [Fact]
    public void Scan_ManyAliasedFieldsOfDistinctSizes_DoNotStarveALaterResource()
    {
        var raw = new RawAssembly("DecoyAliases");
        const FieldAttributes mapped = FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA;
        var types = Enumerable.Range(0, 64).Select(i =>
        {
            var type = raw.Type("N", $"S{i}", ValueType(raw), StructAttributes);
            raw.Layout(type, 60000 + i);
            return type;
        }).ToArray();
        raw.Type("N", "Holder", raw.Object);
        var offset = raw.MappedData(Enumerable.Range(1, 64 * 1024).Select(i => (byte)(i * 7 % 250 + 1)).ToArray());   // benign, and never a magic number
        for (var i = 0; i < types.Length; i++)
            raw.FieldRva(raw.Field($"F{i}", mapped, t => t.Type(types[i], isValueType: true)), offset);
        var resources = new BlobBuilder();
        var pe = HiddenPayloadsTests.PeHeader(96);
        resources.WriteInt32(pe.Length);
        resources.WriteBytes(pe);

        var scan = Scan(raw.Save(directory, md => md.AddManifestResource(ManifestResourceAttributes.Public, md.GetOrAddString("payload.bin"), default(EntityHandle), 0), resources));

        Assert.True(scan.Result.ExitedCleanly, scan.Result.Describe());
        var finding = Assert.Single(scan.Findings);
        Assert.Equal(("EncodedExecutable", "Resource", "payload.bin"), (finding[0], finding[2], finding[4]));
        Assert.Contains("TRUNCATED False", scan.Lines);
    }
    #endregion

    #region Methods — helpers
    private static readonly TypeAttributes StructAttributes =
        TypeAttributes.Public | TypeAttributes.SequentialLayout | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit;

    private static TypeReferenceHandle ValueType(RawAssembly raw) => raw.TypeRef(raw.Runtime, "System", "ValueType");

    // An assembly <name> whose only resource row is implemented by an AssemblyRef to <referenced>.
    private void SaveLooper(string name, string referenced)
    {
        var raw = new RawAssembly(name);
        raw.Type("N", "Holder", raw.Object);
        var reference = raw.AssemblyRef(referenced);
        raw.Save(directory, md => md.AddManifestResource(ManifestResourceAttributes.Public, md.GetOrAddString("loop.bin"), reference, 0));
    }

    // An assembly with one embedded resource, written beside the hostile ones (a PersistedAssemblyBuilder carries no
    // resources, so the resource blob and its row are added by hand).
    private void EmitWithResource(string name, string resource, byte[] data)
    {
        var builder = new PersistedAssemblyBuilder(new AssemblyName(name) { Version = new Version(1, 0, 0, 0) }, typeof(object).Assembly);
        builder.DefineDynamicModule(name).DefineType("Holder", TypeAttributes.Public | TypeAttributes.Class).CreateType();
        var metadata = builder.GenerateMetadata(out var il, out var fieldData);
        var resources = new BlobBuilder();
        resources.WriteInt32(data.Length);
        resources.WriteBytes(data);
        metadata.AddManifestResource(ManifestResourceAttributes.Public, metadata.GetOrAddString(resource), default(EntityHandle), 0);
        var image = new ManagedPEBuilder(
            new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(metadata), il, mappedFieldData: fieldData, managedResources: resources);
        var blob = new BlobBuilder();
        image.Serialize(blob);
        using var file = File.Create(Path.Combine(directory, name + ".dll"));
        blob.WriteContentTo(file);
    }

    private static Scanned Scan(string path)
    {
        var result = ChildProcessProbe.Run(ProbeExe, TimeSpan.FromSeconds(120), ObfuscationProbe.Verb, path);
        var lines = result.StandardOutput.Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
        return new Scanned(result, lines, [.. lines.Where(l => l.StartsWith("FINDING\t", StringComparison.Ordinal)).Select(l => l.Split('\t')[1..])]);
    }

    private sealed record Scanned(ProbeResult Result, string[] Lines, string[][] Findings);

    private static readonly string ProbeExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe");

    private readonly string directory = Directory.CreateTempSubdirectory("silvergun-hostile-").FullName;
    #endregion
}
