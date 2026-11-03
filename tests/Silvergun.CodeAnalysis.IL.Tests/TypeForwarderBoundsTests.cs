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

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The A1-TF bounds on <see cref="TypeForwarders.Read"/> (docs/agent/tasks/capslock-mechanism-fixtures-and-a1.md, A1-TF
/// and "A1-W2r5 and A1-TF: implemented"): an ExportedType table of more than 65,536 rows, or a kept row using a string
/// longer than 1,024 bytes — however many rows share it, or point into it at different offsets — is
/// <see cref="TypeForwarders.Unreadable"/>; within the bounds, shared strings decode as before, and real facades stay
/// readable. Every file is EMITTED (<see cref="EmittedAssembly"/>, forwarder rows added through its
/// <see cref="MetadataBuilder"/> overload) and only ever read through <see cref="TypeForwarders.Read"/> (or, for a
/// precondition, a raw <see cref="MetadataReader"/>) — never loaded.
/// </summary>
public sealed class TypeForwarderBoundsTests : IDisposable
{
    #region Constructors
    public TypeForwarderBoundsTests() => emitted = new EmittedAssembly();
    #endregion

    #region Methods
    // ---- the row bound -----------------------------------------------------------------------------------------------

    /// <summary>65,536 forwarder rows is the bound and is readable; 65,537 is <see cref="TypeForwarders.Unreadable"/>, never None.</summary>
    [Theory]
    [InlineData(65_536, true)]
    [InlineData(65_537, false)]
    public void Read_AnExportedTypeTableOfMoreThan65536Rows_IsUnreadable(int rows, bool readable)
    {
        var path = Forwarding($"rows-{rows}", metadata =>
        {
            var target = EmittedAssembly.Reference(metadata, "Target");
            for (var i = 0; i < rows; i++)
                EmittedAssembly.Forward(metadata, "N", "T", target);
        });

        var forwarders = TypeForwarders.Read(path);

        IReadOnlyList<string> expected = readable ? ["Target"] : [];
        Assert.Equal(readable, forwarders.IsReadable);
        Assert.Equal(expected, forwarders.Targets("N", "T"));
        Assert.Equal(readable ? 1 : 0, forwarders.Count);
    }

    // ---- the name bound ----------------------------------------------------------------------------------------------

    /// <summary>A forwarded namespace of exactly 1,024 bytes is readable (and found); 1,025 bytes is Unreadable.</summary>
    [Theory]
    [InlineData(1_024, true)]
    [InlineData(1_025, false)]
    public void Read_AForwardedNamespaceLongerThan1024Bytes_IsUnreadable(int length, bool readable)
    {
        var space = new string('n', length);
        var path = Forwarding($"name-{length}", metadata => EmittedAssembly.Forward(metadata, space, "T", EmittedAssembly.Reference(metadata, "Target")));

        var forwarders = TypeForwarders.Read(path);

        IReadOnlyList<string> expected = readable ? ["Target"] : [];
        Assert.Equal(readable, forwarders.IsReadable);
        Assert.Equal(expected, forwarders.Targets(space, "T"));
    }

    /// <summary>
    /// The bound holds per string, however many rows share it: 2,000 rows (distinct names) all using one 2,000-byte
    /// namespace — one heap string, one handle — are Unreadable.
    /// </summary>
    [Fact]
    public void Read_ManyRowsSharingOneStringOverTheBound_AreUnreadable()
    {
        var space = new string('s', 2_000);
        var path = Forwarding("shared-long", metadata =>
        {
            var target = EmittedAssembly.Reference(metadata, "Target");
            for (var i = 0; i < 2_000; i++)
                EmittedAssembly.Forward(metadata, space, $"T{i}", target);
        });

        Assert.Same(TypeForwarders.Unreadable, TypeForwarders.Read(path));
    }

    /// <summary>
    /// Rows pointing at DIFFERENT offsets inside one long heap string (suffix handles: the metadata writer stores each
    /// suffix of a 3,000-byte string inside it) are bounded by each handle's own string: suffixes of 2,000 bytes and more
    /// are Unreadable, while suffixes of at most 1,024 bytes into the same long string are readable and each found. The
    /// precondition reads the raw heap to show the suffixes really were merged into one string.
    /// </summary>
    [Theory]
    [InlineData(2_000, 2_999, false)]
    [InlineData(1, 1_024, true)]
    public void Read_SuffixHandlesIntoOneLongString_AreBoundedByEachSuffix(int shortest, int longest, bool readable)
    {
        const int whole = 3_000;
        var path = Forwarding($"suffix-{shortest}-{longest}", metadata =>
        {
            var target = EmittedAssembly.Reference(metadata, "Target");
            metadata.GetOrAddString(new string('a', whole));
            for (var length = shortest; length <= longest; length++)
                EmittedAssembly.Forward(metadata, new string('a', length), "T", target);
        });
        var rows = longest - shortest + 1;
        using (var pe = new PEReader(File.OpenRead(path)))
        {
            var reader = pe.GetMetadataReader();
            var namespaces = reader.ExportedTypes.Select(h => reader.GetExportedType(h).Namespace).ToArray();
            Assert.Equal(rows, namespaces.Distinct().Count());
            Assert.True(reader.GetHeapSize(HeapIndex.String) < whole + 1_024, "the suffixes were not merged into the one long string");
        }

        var forwarders = TypeForwarders.Read(path);

        Assert.Equal(readable, forwarders.IsReadable);
        Assert.Equal(readable ? rows : 0, forwarders.Count);
        if (readable)
            Assert.Equal(["Target"], forwarders.Targets(new string('a', longest), "T"));
    }

    // ---- the total budget (review nit N3) -------------------------------------------------------------------------------

    /// <summary>
    /// The DISTINCT strings kept rows use must total at most 4 MiB (4,194,304 bytes, each string's length without its
    /// terminator). Here 4,194 distinct namespaces, the first <paramref name="longer"/> of them 1,001 bytes and the rest
    /// 1,000, plus the shared name <c>T</c> (1 byte) and target <c>Target</c> (6): 297 longer ones total exactly the
    /// budget and are readable (every name found); 298 are one byte over and Unreadable.
    /// </summary>
    [Theory]
    [InlineData(297, true)]
    [InlineData(298, false)]
    public void Read_DistinctStringsTotallingMoreThanTheBudget_AreUnreadable(int longer, bool readable)
    {
        const int namespaces = 4_194;
        var spaces = Enumerable.Range(0, namespaces).Select(i => $"{i:D6}" + new string('n', (i < longer ? 1_001 : 1_000) - 6)).ToArray();
        Assert.Equal(4_194_304L + (longer - 297), spaces.Sum(s => (long)s.Length) + "T".Length + "Target".Length);
        var path = Forwarding($"budget-{longer}", metadata =>
        {
            var target = EmittedAssembly.Reference(metadata, "Target");
            foreach (var space in spaces)
                EmittedAssembly.Forward(metadata, space, "T", target);
        });

        var forwarders = TypeForwarders.Read(path);

        Assert.Equal(readable, forwarders.IsReadable);
        Assert.Equal(readable ? namespaces : 0, forwarders.Count);
        if (readable)
            Assert.All(new[] { spaces[0], spaces[longer], spaces[^1] }, s => Assert.Equal(["Target"], forwarders.Targets(s, "T")));
    }

    /// <summary>
    /// The control: the budget counts DISTINCT strings, not rows. 5,000 rows (distinct names) sharing one 1,000-byte
    /// namespace would be 5,000,000 bytes counted per row, over the budget; counted once, they are readable.
    /// </summary>
    [Fact]
    public void Read_ManyRowsSharingOneStringUnderTheBound_AreReadable_TheBudgetCountsDistinctStrings()
    {
        var space = new string('m', 1_000);
        Assert.True(5_000L * space.Length > 4_194_304);
        var path = Forwarding("budget-shared", metadata =>
        {
            var target = EmittedAssembly.Reference(metadata, "Target");
            for (var i = 0; i < 5_000; i++)
                EmittedAssembly.Forward(metadata, space, $"T{i}", target);
        });

        var forwarders = TypeForwarders.Read(path);

        Assert.True(forwarders.IsReadable);
        Assert.Equal(5_000, forwarders.Count);
        Assert.Equal(["Target"], forwarders.Targets(space, "T4999"));
    }

    /// <summary>
    /// Within the bounds, rows sharing short strings (one namespace handle, one name handle, one target) decode once and
    /// correctly: two names, the shared one forwarded to both targets.
    /// </summary>
    [Fact]
    public void Read_RowsSharingShortStrings_DecodeCorrectly()
    {
        var path = Forwarding("shared-short", metadata =>
        {
            var x = EmittedAssembly.Reference(metadata, "X");
            var y = EmittedAssembly.Reference(metadata, "Y");
            for (var i = 0; i < 100; i++)
            {
                EmittedAssembly.Forward(metadata, "N", "A", x);
                EmittedAssembly.Forward(metadata, "N", "B", x);
            }
            EmittedAssembly.Forward(metadata, "N", "A", y);
        });

        var forwarders = TypeForwarders.Read(path);

        Assert.True(forwarders.IsReadable);
        Assert.Equal(2, forwarders.Count);
        Assert.Equal(["X", "Y"], forwarders.Targets("N", "A"));
        Assert.Equal(["X"], forwarders.Targets("N", "B"));
        Assert.Empty(forwarders.Targets("N", "C"));
    }

    // ---- real facades ------------------------------------------------------------------------------------------------

    /// <summary>
    /// Real facades stay readable under the bounds, all within 65,536 rows and 1,024-byte names. Measured 2026-11-03: the
    /// reference pack's <c>netstandard.dll</c> forwards 2,458 coarse names (<c>System.Object</c> to <c>System.Runtime</c>), and
    /// the RUNTIME's <c>System.Runtime.dll</c> (next to CoreLib) forwards <c>System.Object</c> to CoreLib. The reference
    /// pack's own <c>System.Runtime.dll</c> DEFINES its types, so it is readable and forwards nothing — pinned too, so a
    /// bound that broke it would read as Unreadable here, not pass as empty.
    /// </summary>
    [Theory]
    [InlineData("reference", "netstandard.dll", true)]
    [InlineData("runtime", "System.Runtime.dll", true)]
    [InlineData("reference", "System.Runtime.dll", false)]
    public void Read_RealFacades_StayReadable(string pack, string file, bool forwards)
    {
        var directory = pack == "reference" ? ReferencePack() : Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var path = Path.Combine(directory, file);
        Assert.True(File.Exists(path), $"No {file} at '{path}'.");

        var forwarders = TypeForwarders.Read(path);

        Assert.True(forwarders.IsReadable, $"{path} is unreadable under the A1-TF bounds");
        Assert.Equal(forwards, forwarders.Count > 0);
        Assert.Equal(forwards, forwarders.Targets("System", "Object").Count > 0);
        if (pack == "reference" && forwards)
            Assert.True(forwarders.Count > 1_000, $"{path} forwards only {forwarders.Count} names");
    }

    public void Dispose() => emitted.Dispose();

    // An emitted assembly holding one marker type, with the forwarder rows `rows` adds.
    private string Forwarding(string name, Action<MetadataBuilder> rows) =>
        emitted.Save(name, module => module.DefineType("Bounds.Marker", TypeAttributes.Public | TypeAttributes.Class).CreateType(), rows);

    // The reference pack directory (packs/Microsoft.NETCore.App.Ref/<version>/ref/net<major>.0) of the running runtime's
    // major version, found from the runtime directory (dotnet/shared/Microsoft.NETCore.App/<version>). Fails loudly.
    private static string ReferencePack()
    {
        var runtime = new DirectoryInfo(Path.GetDirectoryName(typeof(object).Assembly.Location)!);
        var dotnet = runtime.Parent?.Parent?.Parent ?? throw new InvalidOperationException($"No dotnet root above '{runtime.FullName}'.");
        var major = Environment.Version.Major;
        var packs = new DirectoryInfo(Path.Combine(dotnet.FullName, "packs", "Microsoft.NETCore.App.Ref"));
        var pack = packs.Exists
            ? packs.GetDirectories($"{major}.*").Select(d => (Directory: d, Version: Version.TryParse(d.Name, out var v) ? v : null))
                .Where(d => d.Version is not null).OrderByDescending(d => d.Version).Select(d => d.Directory).FirstOrDefault()
            : null;
        var reference = pack is null ? null : Path.Combine(pack.FullName, "ref", $"net{major}.0");
        return reference is not null && Directory.Exists(reference)
            ? reference
            : throw new InvalidOperationException($"No Microsoft.NETCore.App.Ref {major}.x reference pack under '{packs.FullName}'.");
    }
    #endregion

    #region Fields
    private readonly EmittedAssembly emitted;
    #endregion
}
