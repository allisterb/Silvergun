namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Xunit;

using static SingleFileBundleBuilder;

/// <summary>
/// native-binaries-3: <see cref="SingleFileBundle.Extract"/> over synthetic bundles built in code, and
/// <see cref="DotNetHostScanner.Scan"/>'s <see cref="DotNetHostScan.BundleHeaderOffset"/>. Layouts v1 (no 40-byte block,
/// no compressed size), v2-5 and v6 (raw deflate); byte-exact round trips; disk names (plain kept, unsafe ones indexed,
/// nothing outside outDir); and every limit and failure, each with a reason and no partial file.
/// </summary>
public sealed class SingleFileBundleTests : IDisposable
{
    #region Constructors
    public SingleFileBundleTests()
    {
        outDir = Path.Combine(tree.Root, "out");
    }
    #endregion

    #region Methods: layouts and round trips
    [Fact]
    public void Extract_V6StoredAndCompressedEntries_AreWrittenByteForByte()
    {
        var stored = Noise(5000, seed: 1);
        var compressed = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("compressible text ", 2000)));
        var entries = new Entry[] { new("a.dll", stored), new("b.dll", compressed, Compress: true), new("e.json", []) };

        var (extracted, failed, charged) = Extract(entries);

        Assert.Empty(failed);
        Assert.Equal(new[] { "a.dll", "b.dll", "e.json" }, extracted.Select(e => e.Name).ToArray());
        Assert.Equal(stored, File.ReadAllBytes(PathOf(extracted, "a.dll")));
        Assert.Equal(compressed, File.ReadAllBytes(PathOf(extracted, "b.dll")));
        Assert.Empty(File.ReadAllBytes(PathOf(extracted, "e.json")));
        Assert.Equal(stored.Length + compressed.Length, charged);
    }

    // The compressed entry really is smaller in the bundle (so the test exercises inflation, not a stored copy).
    [Fact]
    public void Build_ACompressedEntry_IsStoredSmallerThanItsSize()
    {
        var bytes = new byte[50_000];

        Assert.True(Deflate(bytes).Length < bytes.Length / 10);
    }

    // v1 has neither the 40-byte deps/runtimeconfig block nor a compressed size; v2-5 have the block only; v6+ both.
    // Reading any of them with another version's layout would misplace every entry after the first field.
    [Theory]
    [InlineData(1u)]
    [InlineData(2u)]
    [InlineData(3u)]
    [InlineData(4u)]
    [InlineData(5u)]
    [InlineData(6u)]
    [InlineData(64u)]
    public void Extract_EachVersionsLayout_IsRead(uint major)
    {
        var one = Noise(300, seed: 2);
        var two = Noise(700, seed: 3);
        var entries = new List<Entry> { new("One.dll", one), new("two.deps.json", two, Type: 3) };
        if (major >= 6)
            entries.Add(new("Three.dll", two, Compress: true));

        var (extracted, failed, _) = Extract(entries, major);

        Assert.Empty(failed);
        Assert.Equal(entries.Select(e => e.Name).ToArray(), extracted.Select(e => e.Name).ToArray());
        Assert.Equal(one, File.ReadAllBytes(PathOf(extracted, "One.dll")));
        Assert.Equal(two, File.ReadAllBytes(PathOf(extracted, "two.deps.json")));
        if (major >= 6)
            Assert.Equal(two, File.ReadAllBytes(PathOf(extracted, "Three.dll")));
    }

    // Nothing is decided by the manifest's type byte: every value, valid or not, is extracted the same way.
    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)1)]
    [InlineData((byte)2)]
    [InlineData((byte)5)]
    [InlineData((byte)200)]
    public void Extract_TheTypeByte_DoesNotMatter(byte type)
    {
        var bytes = Noise(64, seed: type);

        var (extracted, failed, _) = Extract([new("x.bin", bytes, Type: type)]);

        Assert.Empty(failed);
        Assert.Equal(bytes, File.ReadAllBytes(Assert.Single(extracted).FullPath));
    }

    // An entry ending exactly at the header offset is inside the bundle (the last entry of every honest bundle here).
    [Fact]
    public void Extract_AnEntryEndingExactlyAtTheHeader_IsExtracted()
    {
        var bytes = Noise(128, seed: 4);
        var (bundle, headerOffset) = Build(Noise(16, seed: 5), [new("last.bin", bytes)]);

        var (extracted, failed, _) = ExtractBytes(bundle, headerOffset);

        Assert.Empty(failed);
        Assert.Equal(16, headerOffset - bytes.Length);
        Assert.Equal(bytes, File.ReadAllBytes(Assert.Single(extracted).FullPath));
    }

    // Two entries may share data: offsets are not required to be disjoint.
    [Fact]
    public void Extract_TwoEntriesPointingAtTheSameData_AreBothExtracted()
    {
        var bytes = Noise(256, seed: 6);
        var (bundle, headerOffset) = Build([], [new("a.bin", bytes), new("b.bin", []) { Offset = 0, Size = bytes.Length }]);

        var (extracted, failed, charged) = ExtractBytes(bundle, headerOffset);

        Assert.Empty(failed);
        Assert.All(extracted, e => Assert.Equal(bytes, File.ReadAllBytes(e.FullPath)));
        Assert.Equal(2L * bytes.Length, charged);
    }
    #endregion

    #region Methods: disk names
    [Theory]
    [InlineData("X.dll")]
    [InlineData("System.Private.CoreLib.dll")]
    [InlineData("a-b_c.d")]
    [InlineData("9.json")]
    [InlineData("noextension")]
    [InlineData("COM10.dll")]           // not a device name
    [InlineData("CONSOLE.dll")]         // the stem is CONSOLE, not CON
    public void Extract_APlainName_IsKept(string name)
    {
        var (extracted, _, _) = Extract([new(name, Noise(32, seed: 7))]);

        var entry = Assert.Single(extracted);
        Assert.Equal(Path.Combine(outDir, name), entry.FullPath);
    }

    [Fact]
    public void Extract_APlainNameOf128Chars_IsKept_129IsIndexed()
    {
        var at128 = "a" + new string('b', 123) + ".dll";
        var at129 = "a" + new string('b', 124) + ".dll";
        Assert.Equal((128, 129), (at128.Length, at129.Length));

        var (extracted, _, _) = Extract([new(at128, [1]), new(at129, [2])]);

        Assert.Equal(Path.Combine(outDir, at128), extracted[0].FullPath);
        Assert.Equal(Path.Combine(outDir, "_00001.bin"), extracted[1].FullPath);
        Assert.Equal(at129, extracted[1].Name);
    }

    // Each unsafe name, at index 3 behind three plain entries, is written as _00003.bin; its raw name is still returned.
    [Theory]
    [MemberData(nameof(UnsafeNames))]
    public void Extract_AnUnsafeName_GetsAnIndexName(string name)
    {
        var bytes = Noise(48, seed: 8);

        var (extracted, failed, _) = Extract([new("p0.dll", [0]), new("p1.dll", [1]), new("p2.dll", [2]), new(name, bytes)]);

        Assert.Empty(failed);
        Assert.Equal(4, extracted.Count);
        Assert.Equal(name, extracted[3].Name);
        Assert.Equal(Path.Combine(outDir, "_00003.bin"), extracted[3].FullPath);
        Assert.Equal(bytes, File.ReadAllBytes(extracted[3].FullPath));
    }

    public static TheoryData<string> UnsafeNames() =>
    [
        "",
        "a/b.dll",
        @"a\b.dll",
        "..",
        "../x.dll",
        @"..\x.dll",
        "/abs.dll",
        @"C:\x.dll",
        "C:x.dll",
        ".hidden",
        "CON.dll",
        "con",
        "Lpt9.txt",
        "nul.tar.gz",
        "COM1",
        "aux.",
        "x" + Rlo + "lld.exe",
        "x" + (char)0x01 + ".dll",
        "x" + (char)0x200B + ".dll",               // zero-width space
        "x" + (char)0xE9 + ".dll",                 // a non-ASCII letter
        "_lead.dll",
        "trail.",
        "trail.dll.",
        "a b.dll",
        "a:b.dll",
        "a*b.dll",
        "-dash.dll",
        new string('c', 129),
    ];

    // Case-insensitively used names are indexed: the first keeps its name, later ones (any case) do not.
    [Fact]
    public void Extract_CaseDuplicateNames_LaterOnesAreIndexed()
    {
        var (extracted, failed, _) = Extract([new("A.dll", [1]), new("a.DLL", [2]), new("A.dll", [3])]);

        Assert.Empty(failed);
        Assert.Equal(
            new[] { "A.dll", "_00001.bin", "_00002.bin" },
            extracted.Select(e => Path.GetFileName(e.FullPath)).ToArray());
        Assert.Equal(new byte[] { 2 }, File.ReadAllBytes(extracted[1].FullPath));
        Assert.Equal(new byte[] { 3 }, File.ReadAllBytes(extracted[2].FullPath));
    }

    // Every hostile name in one bundle: each file lands directly in outDir, and nothing else is written anywhere under
    // the tree (or beside it, for the traversal names).
    [Fact]
    public void Extract_HostileNames_NeverWriteOutsideOutDir()
    {
        var token = "sg-escape-" + Guid.NewGuid().ToString("N") + ".dll";
        var names = UnsafeNames().Cast<object[]>().Select(r => (string)r[0]).Concat([
            "../" + token, @"..\" + token, "../../" + token, "out/../" + token, Path.Combine(tree.Root, token)]).ToArray();

        var (extracted, failed, _) = Extract(names.Select((n, i) => new Entry(n, [(byte)i])).ToArray());

        Assert.Empty(failed);
        Assert.Equal(names.Length, extracted.Count);
        Assert.All(extracted, e => Assert.Equal(outDir, Path.GetDirectoryName(e.FullPath)));
        var outside = Directory.GetFiles(tree.Root, "*", SearchOption.AllDirectories)
            .Where(f => Path.GetDirectoryName(f) != outDir && f != HostPath).ToArray();
        Assert.Empty(outside);
        Assert.False(File.Exists(Path.Combine(tree.Root, token)));
        Assert.False(File.Exists(Path.Combine(Path.GetDirectoryName(tree.Root)!, token)));
    }

    // An index name can never collide with a plain one: a plain name never starts with '_'.
    [Fact]
    public void Extract_APlainNameShapedLikeAnIndexName_IsItselfIndexed()
    {
        var (extracted, failed, _) = Extract([new("_00001.bin", [1]), new("a/b", [2])]);

        Assert.Empty(failed);
        Assert.Equal(new[] { "_00000.bin", "_00001.bin" }, extracted.Select(e => Path.GetFileName(e.FullPath)).ToArray());
        Assert.Equal(new byte[] { 2 }, File.ReadAllBytes(extracted[1].FullPath));
    }
    #endregion

    #region Methods: per-entry failures
    [Theory]
    [InlineData(-1L, null, null)]
    [InlineData(long.MinValue, null, null)]
    [InlineData(null, -1L, null)]
    [InlineData(null, null, -1L)]
    public void Extract_ANegativeOffsetOrSize_FailsThatEntry(long? offset, long? size, long? compressedSize)
    {
        var bad = new Entry("bad.dll", Noise(64, seed: 9), Compress: compressedSize is not null)
            { Offset = offset, Size = size, CompressedSize = compressedSize };

        var (extracted, failed, charged) = Extract([bad, new("good.dll", [7])]);

        AssertFailedAlone(extracted, failed, "bad.dll", "negative offset or size");
        Assert.Equal(1, charged);
    }

    [Theory]
    [InlineData(1)]                     // one byte past the header offset
    [InlineData(1000)]
    public void Extract_DataPastTheHeaderOffset_FailsThatEntry(int past)
    {
        var data = Noise(64, seed: 10);
        // Layout: prefix, good.dll's 64 bytes, bad.dll's 64 bytes, manifest. Moving bad.dll's offset `past` bytes on
        // makes its data end `past` bytes into the manifest.
        var bad = new Entry("bad.dll", data) { Offset = PrefixLength + 64 + past };

        var (extracted, failed, _) = Extract([new("good.dll", data), bad]);

        AssertFailedAlone(extracted, failed, "bad.dll", "lies outside the bundle");
    }

    [Theory]
    [InlineData(long.MaxValue, 64L)]
    [InlineData(0L, long.MaxValue)]
    [InlineData(long.MaxValue, long.MaxValue)]
    public void Extract_HugeOffsetOrSize_FailsWithoutOverflow(long offset, long size)
    {
        var bad = new Entry("bad.dll", Noise(64, seed: 11)) { Offset = offset, Size = size };

        var (extracted, failed, _) = Extract([bad, new("good.dll", [7])]);

        AssertFailedAlone(extracted, failed, "bad.dll", "outside the bundle");
    }

    // A compressed entry is bounds-checked on its COMPRESSED extent.
    [Fact]
    public void Extract_ACompressedExtentPastTheHeader_FailsThatEntry()
    {
        var data = Noise(64, seed: 12);
        var bad = new Entry("bad.dll", data, Compress: true) { CompressedSize = 10_000 };

        var (extracted, failed, _) = Extract([new("good.dll", [7]), bad]);

        AssertFailedAlone(extracted, failed, "bad.dll", "lies outside the bundle");
    }

    // 256 MiB + 1 declared, from 10 stored bytes: the per-entry cap answers before the ratio or inflation is tried.
    [Fact]
    public void Extract_AnEntryOverThePerEntryCap_FailsThatEntry()
    {
        var bad = new Entry("big.dll", [], Compress: true) { Stored = new byte[10], Size = (256L << 20) + 1 };

        var (extracted, failed, _) = Extract([bad, new("good.dll", [7])]);

        AssertFailedAlone(extracted, failed, "big.dll", "exceeds the per-entry limit of 268435456");
    }

    // Exactly 256 MiB passes the per-entry cap (and then fails on the ratio, which is what proves it passed the cap).
    [Fact]
    public void Extract_AnEntryOfExactlyThePerEntryCap_PassesThatCheck()
    {
        var bad = new Entry("big.dll", [], Compress: true) { Stored = new byte[10], Size = 256L << 20 };

        var (_, failed, _) = Extract([bad]);

        var reason = Assert.Single(failed).Reason;
        Assert.DoesNotContain("per-entry", reason, StringComparison.Ordinal);
        Assert.Contains("ratio limit 200", reason, StringComparison.Ordinal);
    }

    // The budget is charged entry by entry: the first entries that fit are extracted, every later one fails.
    [Theory]
    [InlineData(250L, 2)]
    [InlineData(200L, 2)]               // exactly two entries' worth
    [InlineData(199L, 1)]
    [InlineData(400L, 4)]
    [InlineData(0L, 0)]
    public void Extract_TheBudget_ExtractsTheFirstEntriesThatFit(long budget, int expected)
    {
        var entries = Enumerable.Range(0, 4).Select(i => new Entry($"e{i}.bin", Noise(100, seed: 20 + i))).ToArray();

        var (extracted, failed, charged) = Extract(entries, budget: budget);

        Assert.Equal(entries.Take(expected).Select(e => e.Name), extracted.Select(e => e.Name));
        Assert.Equal(entries.Skip(expected).Select(e => e.Name), failed.Select(f => f.Name));
        Assert.All(failed, f => Assert.Contains("exceeds the remaining bundle extraction budget", f.Reason, StringComparison.Ordinal));
        Assert.Equal(100L * expected, charged);
        Assert.Equal(expected, FilesInOutDir().Length);
    }

    // A failed (over-budget) entry does not consume budget: a later, smaller entry still fits.
    [Fact]
    public void Extract_AnOverBudgetEntry_DoesNotStopASmallerLaterOne()
    {
        var (extracted, failed, charged) = Extract([new("big.bin", new byte[300]), new("small.bin", new byte[50])], budget: 100);

        Assert.Equal("big.bin", Assert.Single(failed).Name);
        Assert.Equal("small.bin", Assert.Single(extracted).Name);
        Assert.Equal(50, charged);
    }

    // Ratio 200 exactly is allowed; one byte more is not. The deflate stream is padded so CompressedSize is 100.
    [Fact]
    public void Extract_AnExpansionOfExactly200x_IsExtracted()
    {
        var zeros = new byte[20_000];

        var (extracted, failed, _) = Extract([Padded("z.bin", zeros, 100)]);

        Assert.Empty(failed);
        Assert.Equal(zeros, File.ReadAllBytes(Assert.Single(extracted).FullPath));
    }

    [Fact]
    public void Extract_AnExpansionOver200x_FailsThatEntry()
    {
        var bad = Padded("z.bin", new byte[20_000], 100) with { Size = 20_001 };

        var (extracted, failed, _) = Extract([bad, new("good.dll", [7])]);

        AssertFailedAlone(extracted, failed, "z.bin", "expands 100 to 20001 bytes (ratio limit 200)");
    }

    // A reserved deflate block type (BFINAL=1, BTYPE=11): the inflater throws, the partial file is deleted, and the
    // entries after it are still extracted.
    [Fact]
    public void Extract_InvalidDeflateData_FailsThatEntry_AndLeavesNoFile()
    {
        var garbage = new byte[] { 0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        var bad = new Entry("bad.dll", new byte[100], Compress: true) { Stored = garbage };

        var (extracted, failed, charged) = Extract([bad, new("good.dll", [7])]);

        AssertFailedAlone(extracted, failed, "bad.dll", "the entry could not be inflated");
        Assert.Equal(100 + 1, charged);             // charged on attempt: the failing entry's declared 100 too
    }

    // Deflate data that ends early (truncated mid-stream) inflates short.
    [Fact]
    public void Extract_TruncatedDeflateData_FailsThatEntry()
    {
        var data = Noise(4000, seed: 13);
        var deflated = Deflate(data);
        var bad = new Entry("bad.dll", data, Compress: true) { Stored = deflated[..(deflated.Length / 2)] };

        var (extracted, failed, _) = Extract([bad, new("good.dll", [7])]);

        AssertFailedAlone(extracted, failed, "bad.dll", "the entry could not be inflated");
    }

    // The inflater reads exactly CompressedSize bytes from the entry's offset. Here the real deflate stream runs on past
    // the declared extent (into the rest of its own data, then good.dll and the manifest): it must not be followed
    // there, so the entry inflates short and fails, with no file.
    [Theory]
    [InlineData(2)]                     // half the stream declared
    [InlineData(10)]                    // a tenth
    public void Extract_ACompressedSizeShorterThanTheDeflateStream_FailsThatEntry(int fraction)
    {
        var data = Noise(4000, seed: 30);                    // incompressible: output tracks input, so a cut is visible
        var deflated = Deflate(data);
        var bad = new Entry("short.dll", data, Compress: true) { CompressedSize = deflated.Length / fraction };

        var (extracted, failed, charged) = Extract([bad, new("good.dll", [7])]);

        AssertFailedAlone(extracted, failed, "short.dll", "the entry could not be inflated");
        Assert.Equal(data.Length + 1, charged);     // charged on attempt
    }

    // The control: the same entry with its true CompressedSize, followed by the same bytes, extracts.
    [Fact]
    public void Extract_TheSameEntryWithItsTrueCompressedSize_IsExtracted()
    {
        var data = Noise(4000, seed: 30);

        var (extracted, failed, _) = Extract([new("short.dll", data, Compress: true), new("good.dll", [7])]);

        Assert.Empty(failed);
        Assert.Equal(data, File.ReadAllBytes(PathOf(extracted, "short.dll")));
    }

    // Compressible data whose final deflate block is needed: declaring all but its last few bytes fails too.
    [Fact]
    public void Extract_ACompressedSizeMissingTheStreamsTail_FailsThatEntry()
    {
        var data = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Range(0, 3000).Select(i => $"{i},")));
        var deflated = Deflate(data);
        var bad = new Entry("tail.dll", data, Compress: true) { CompressedSize = deflated.Length - 8 };

        var (extracted, failed, _) = Extract([bad, new("good.dll", [7])]);

        AssertFailedAlone(extracted, failed, "tail.dll", "the entry could not be inflated");
    }

    // A compressed extent ending exactly at the header offset (the last entry, nothing after it but the manifest) is read
    // whole: the bound is the extent, not one byte less.
    [Fact]
    public void Extract_ACompressedExtentEndingExactlyAtTheHeader_IsExtracted()
    {
        var data = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("last entry ", 400)));
        var (bundle, headerOffset) = Build(Noise(PrefixLength, seed: 31), [new("a.bin", [1, 2, 3]), new("last.dll", data, Compress: true)]);
        Assert.Equal(PrefixLength + 3 + Deflate(data).Length, headerOffset);   // last.dll's extent ends at the header

        var (extracted, failed, _) = ExtractBytes(bundle, headerOffset);

        Assert.Empty(failed);
        Assert.Equal(data, File.ReadAllBytes(PathOf(extracted, "last.dll")));
    }

    // The declared size must equal what inflates: one byte short or one byte long are both failures.
    [Theory]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(1000)]
    [InlineData(-1000)]
    public void Extract_ADeclaredSizeThatIsNotTheInflatedSize_FailsThatEntry(int delta)
    {
        var data = Noise(4000, seed: 17);           // incompressible, so no delta can trip the ratio check instead
        var bad = new Entry("bad.dll", data, Compress: true) { Size = data.Length + delta };

        var (extracted, failed, charged) = Extract([bad, new("good.dll", [7])]);

        AssertFailedAlone(extracted, failed, "bad.dll", "bytes produced, the manifest says " + (data.Length + delta));
        Assert.Equal(data.Length + delta + 1, charged);   // charged its declared size on attempt
    }
    #endregion

    #region Methods: charging on attempt (review C1), maxEntries, indices, per-entry IO failures
    // C1: one shared compressed extent that inflates to 1000 bytes, referenced by six entries that each declare 1500.
    // Each attempt is charged 1500 BEFORE inflating, so a 4000 budget allows floor(4000/1500) = 2 attempts; the other
    // four fail on the budget without being inflated, and so does a valid 1001-byte entry after them (1000 left).
    // Under the old rule (charge only on success) every one of them would have been inflated, and the valid one extracted.
    [Fact]
    public void Extract_FailingEntriesSharingAnExtent_AreChargedOnAttempt_SoTheBudgetBoundsTheWork()
    {
        var data = Noise(1000, seed: 40);
        var deflated = Deflate(data);
        var shared = Enumerable.Range(0, 6).Select(i => i == 0
            ? new Entry("e0", data, Compress: true) { Size = 1500 }
            : new Entry($"e{i}", [], Compress: true) { Stored = [], Offset = PrefixLength, CompressedSize = deflated.Length, Size = 1500 });
        var valid = Noise(1001, seed: 41);

        var (extracted, failed, charged, attempted) = ExtractFull([.. shared, new("valid.bin", valid)], budget: 4000);

        Assert.Empty(extracted);
        Assert.Equal(3000, charged);
        Assert.Equal(7, attempted);
        Assert.Equal(Enumerable.Range(0, 7), failed.Select(f => f.Index));
        Assert.All(failed.Take(2), f => Assert.Equal("the entry could not be inflated: 1000 bytes produced, the manifest says 1500", f.Reason));
        Assert.All(failed.Skip(2).Take(4), f => Assert.Equal("1500 bytes exceeds the remaining bundle extraction budget (1000)", f.Reason));
        Assert.Equal("1001 bytes exceeds the remaining bundle extraction budget (1000)", failed[6].Reason);
        Assert.Empty(FilesInOutDir());
    }

    // A failing entry consumes budget: with room for exactly one 100-byte entry, a failing first entry leaves none for
    // the valid second one (which alone would fit).
    [Fact]
    public void Extract_AFailingEntry_ConsumesBudget()
    {
        var bad = new Entry("bad.dll", new byte[100], Compress: true) { Stored = [0x07, 0xFF, 0xFF, 0xFF] };
        var good = new Entry("good.bin", Noise(100, seed: 42));

        var (extracted, failed, charged) = Extract([bad, good], budget: 150);

        Assert.Empty(extracted);
        Assert.Equal(100, charged);
        Assert.StartsWith("the entry could not be inflated", failed[0].Reason, StringComparison.Ordinal);
        Assert.Equal("100 bytes exceeds the remaining bundle extraction budget (50)", failed[1].Reason);

        // The control: the same valid entry alone fits.
        Assert.Single(Extract([good], budget: 150).Extracted);
    }

    // Entries before maxEntries are attempted; the rest are ONE summary failure (empty name, Index -1).
    [Theory]
    [InlineData(4, 4)]
    [InlineData(0, 0)]
    [InlineData(-5, 0)]
    [InlineData(9, 9)]
    public void Extract_MaxEntries_AttemptsOnlyThatMany_AndSummarisesTheRest(int maxEntries, int expected)
    {
        var entries = Enumerable.Range(0, 10).Select(i => new Entry($"e{i}.bin", [(byte)i])).ToArray();

        var (extracted, failed, charged, attempted) = ExtractFull(entries, maxEntries: maxEntries);

        Assert.Equal(expected, attempted);
        Assert.Equal(Enumerable.Range(0, expected), extracted.Select(e => e.Index));
        Assert.Equal(expected, charged);
        var summary = Assert.Single(failed);
        Assert.Equal((string.Empty, -1), (summary.Name, summary.Index));
        Assert.Equal($"{10 - expected} entr(ies) past the package-wide limit on bundle entries were not extracted", summary.Reason);
        Assert.Equal(expected, FilesInOutDir().Length);
    }

    [Theory]
    [InlineData(10)]
    [InlineData(int.MaxValue)]
    public void Extract_MaxEntriesAtOrAboveTheCount_HasNoSummary(int maxEntries)
    {
        var entries = Enumerable.Range(0, 10).Select(i => new Entry($"e{i}.bin", [(byte)i])).ToArray();

        var (extracted, failed, _, attempted) = ExtractFull(entries, maxEntries: maxEntries);

        Assert.Equal((10, 10), (extracted.Count, attempted));
        Assert.Empty(failed);
    }

    // Budget failures inside the attempted range count as attempts (they used an entry slot), and the summary follows.
    [Fact]
    public void Extract_MaxEntriesAndBudget_TogetherKeepEveryEntryAccountedFor()
    {
        var entries = Enumerable.Range(0, 6).Select(i => new Entry($"e{i}.bin", Noise(10, seed: 50 + i))).ToArray();

        var (extracted, failed, charged, attempted) = ExtractFull(entries, budget: 20, maxEntries: 4);

        Assert.Equal(4, attempted);
        Assert.Equal(new[] { 0, 1 }, extracted.Select(e => e.Index));
        Assert.Equal(new[] { 2, 3, -1 }, failed.Select(f => f.Index));
        Assert.Equal(20, charged);
        Assert.Contains("2 entr(ies) past the package-wide limit", failed[^1].Reason, StringComparison.Ordinal);
    }

    // Every extracted and failed entry carries its manifest index; a manifest failure is Index -1.
    [Fact]
    public void Extract_EntriesCarryTheirManifestIndex()
    {
        var bad = new Entry("bad", [1]) { Offset = -1 };

        var (extracted, failed, _) = Extract([new("a", [1]), bad, new("a/b", [2]), new("c", [3])]);

        Assert.Equal(new[] { 0, 2, 3 }, extracted.Select(e => e.Index));
        Assert.Equal(1, Assert.Single(failed).Index);
        Assert.Equal(-1, Assert.Single(ExtractBytes([1, 2, 3], 1).Failed).Index);
    }

    // A per-entry IO failure (here a directory already sitting at the entry's disk name) is that entry's failure, named
    // by exception type; extraction continues, the obstacle is left alone, and the entry was charged.
    [Fact]
    public void Extract_APerEntryIoFailure_FailsThatEntry_AndExtractionContinues()
    {
        Directory.CreateDirectory(Path.Combine(outDir, "X.dll"));

        var (extracted, failed, charged) = Extract([new("X.dll", Noise(64, seed: 60)), new("Y.dll", [9])]);

        var failure = Assert.Single(failed);
        Assert.Equal(("X.dll", 0), (failure.Name, failure.Index));
        Assert.Matches("^(IOException|UnauthorizedAccessException) while extracting the entry$", failure.Reason);
        Assert.Equal("Y.dll", Assert.Single(extracted).Name);
        Assert.True(Directory.Exists(Path.Combine(outDir, "X.dll")));
        Assert.Equal(64 + 1, charged);
    }
    #endregion

    #region Methods: manifest failures (one failure with an empty name, nothing written)
    // Every cut of a valid v6 manifest, from 0 bytes to one short of whole.
    [Fact]
    public void Extract_AManifestTruncatedAnywhere_IsOneWholeBundleFailure()
    {
        var (bundle, headerOffset) = Build(Noise(32, seed: 14),
            [new("a.dll", Noise(40, seed: 15)), new("b.dll", Noise(400, seed: 16), Compress: true)]);
        var cuts = 0;
        for (var end = (int)headerOffset; end < bundle.Length; end++, cuts++)
        {
            var (extracted, failed, charged) = ExtractBytes(bundle[..end], headerOffset);

            Assert.Empty(extracted);
            var failure = Assert.Single(failed);
            Assert.Equal(string.Empty, failure.Name);
            Assert.StartsWith("the bundle manifest could not be read: ", failure.Reason, StringComparison.Ordinal);
            Assert.Equal(0, charged);
            Assert.False(Directory.Exists(outDir), $"cut at {end}: the output directory was created");
        }
        Assert.True(cuts > 100, $"only {cuts} cuts");
        // The whole manifest does extract (so every failure above was the cut).
        Assert.Equal(2, ExtractBytes(bundle, headerOffset).Extracted.Count);
    }

    [Theory]
    [InlineData(4097)]
    [InlineData(int.MaxValue)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Extract_AnEntryCountOutOfRange_IsOneWholeBundleFailure(int count)
    {
        var (bundle, headerOffset) = Build([], [new("a.dll", [1])], count: count);

        AssertManifestFailure(ExtractBytes(bundle, headerOffset), $"{count} entries (limit 4096)");
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(65u)]
    [InlineData(uint.MaxValue)]
    public void Extract_AMajorVersionOutOfRange_IsOneWholeBundleFailure(uint major)
    {
        var (bundle, headerOffset) = Build([], [new("a.dll", [1])], major: major);

        AssertManifestFailure(ExtractBytes(bundle, headerOffset), $"unsupported bundle version {major}");
    }

    [Fact]
    public void Extract_ANameOver4096Bytes_IsOneWholeBundleFailure()
    {
        var name = new string('n', 4097);

        AssertManifestFailure(Extract([new("ok.dll", [1]), new(name, [2])]), "a 4097-byte string (limit 4096)");
    }

    [Fact]
    public void Extract_ANameOfExactly4096Bytes_IsReadAndIndexed()
    {
        var name = new string('n', 4096);

        var (extracted, failed, _) = Extract([new(name, [2])]);

        Assert.Empty(failed);
        Assert.Equal(name, Assert.Single(extracted).Name);
        Assert.Equal("_00000.bin", Path.GetFileName(extracted[0].FullPath));
    }

    // The byte length counts, not the char length: 2049 two-byte UTF-8 chars are 4098 bytes.
    [Fact]
    public void Extract_ANameOver4096Utf8Bytes_IsOneWholeBundleFailure()
    {
        var name = new string((char)0xE9, 2049);

        AssertManifestFailure(Extract([new(name, [2])]), "a 4098-byte string (limit 4096)");
    }

    [Fact]
    public void Extract_ABundleIdOver4096Bytes_IsOneWholeBundleFailure()
    {
        var (bundle, headerOffset) = Build([], [new("a.dll", [1])], bundleId: new string('i', 4097));

        AssertManifestFailure(ExtractBytes(bundle, headerOffset), "a 4097-byte string (limit 4096)");
    }

    // A 7-bit length prefix longer than 5 bytes is malformed.
    [Fact]
    public void Extract_ALengthPrefixOver5Bytes_IsOneWholeBundleFailure()
    {
        var raw = new byte[] { 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 };

        AssertManifestFailure(Extract([new("a.dll", [1]) { RawName = raw }]), "malformed string length");
    }

    // 5 bytes encoding a value with bit 31 set: negative as an int, never a length.
    [Fact]
    public void Extract_A5BytePrefixDecodingNegative_IsOneWholeBundleFailure()
    {
        var raw = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x0F };

        AssertManifestFailure(Extract([new("a.dll", [1]) { RawName = raw }]), "a -1-byte string (limit 4096)");
    }

    // A fifth prefix byte above 0x0F overflows a 32-bit length (BinaryReader rejects it); before the fix these wrapped to
    // lengths 0 and 5 and were read. `tail` is the 5 name bytes the wrapped length 5 would have consumed.
    [Theory]
    [InlineData(new byte[] { 0x80, 0x80, 0x80, 0x80, 0x10 }, "")]
    [InlineData(new byte[] { 0x85, 0x80, 0x80, 0x80, 0x10 }, "a.dll")]
    [InlineData(new byte[] { 0x85, 0x80, 0x80, 0x80, 0x7F }, "a.dll")]
    public void Extract_AFifthPrefixByteOver0x0F_InAName_IsOneWholeBundleFailure(byte[] prefix, string tail)
    {
        var raw = prefix.Concat(Encoding.ASCII.GetBytes(tail)).ToArray();

        AssertManifestFailure(Extract([new("a.dll", [1]) { RawName = raw }]), "malformed string length");
    }

    [Theory]
    [InlineData(new byte[] { 0x80, 0x80, 0x80, 0x80, 0x10 }, "")]
    [InlineData(new byte[] { 0x85, 0x80, 0x80, 0x80, 0x10 }, "bndid")]
    public void Extract_AFifthPrefixByteOver0x0F_InTheBundleId_IsOneWholeBundleFailure(byte[] prefix, string tail)
    {
        var raw = prefix.Concat(Encoding.ASCII.GetBytes(tail)).ToArray();
        var (bundle, headerOffset) = Build([], [new("a.dll", [1])], rawBundleId: raw);

        AssertManifestFailure(ExtractBytes(bundle, headerOffset), "malformed string length");
    }

    // The fifth byte's last legal values: 0x00 is a valid (non-minimal) prefix; 0x01..0x0F are well-formed but encode
    // lengths of 2^28 and more, so they fail on the length limit, not as malformed.
    [Theory]
    [InlineData((byte)0x01, "a 268435456-byte string")]
    [InlineData((byte)0x07, "a 1879048192-byte string")]
    [InlineData((byte)0x0F, "a -268435456-byte string")]
    public void Extract_AFifthPrefixByteUpTo0x0F_IsWellFormed_AndFailsOnlyOnTheLength(byte fifth, string reason)
    {
        var raw = new byte[] { 0x80, 0x80, 0x80, 0x80, fifth };

        var result = Extract([new("a.dll", [1]) { RawName = raw }]);

        AssertManifestFailure(result, reason);
        Assert.DoesNotContain("malformed", Assert.Single(result.Failed).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Extract_AFifthPrefixByteOf0x00_InTheBundleId_IsRead()
    {
        var raw = new byte[] { 0x85, 0x80, 0x80, 0x80, 0x00 }.Concat("bndid"u8.ToArray()).ToArray();
        var (bundle, headerOffset) = Build([], [new("a.dll", [1])], rawBundleId: raw);

        var (extracted, failed, _) = ExtractBytes(bundle, headerOffset);

        Assert.Empty(failed);
        Assert.Equal("a.dll", Assert.Single(extracted).Name);
    }

    // A long-but-valid (5-byte, non-minimal) prefix for a short name is still read correctly.
    [Fact]
    public void Extract_ANonMinimalPrefixForAShortName_IsRead()
    {
        var raw = new byte[] { 0x85, 0x80, 0x80, 0x80, 0x00 }.Concat("a.dll"u8.ToArray()).ToArray();

        var (extracted, failed, _) = Extract([new("ignored", [9]) { RawName = raw }]);

        Assert.Empty(failed);
        Assert.Equal("a.dll", Assert.Single(extracted).Name);
    }

    [Theory]
    [InlineData(-1L)]
    [InlineData(long.MinValue)]
    public void Extract_ANegativeHeaderOffset_IsOneWholeBundleFailure(long headerOffset)
    {
        var (bundle, _) = Build([], [new("a.dll", [1])]);

        AssertManifestFailure(ExtractBytes(bundle, headerOffset), "the manifest region is");
    }

    [Theory]
    [InlineData(0L)]                    // at EOF
    [InlineData(1L)]
    [InlineData(long.MaxValue / 2)]
    public void Extract_AHeaderOffsetAtOrPastTheEnd_IsOneWholeBundleFailure(long pastEnd)
    {
        var (bundle, _) = Build([], [new("a.dll", [1])]);

        AssertManifestFailure(ExtractBytes(bundle, bundle.Length + pastEnd), "the manifest region is");
    }

    // The manifest region is everything from the header to EOF: 16 MiB is allowed (trailing bytes after a valid manifest
    // are not read), 16 MiB + 1 is not.
    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    public void Extract_TheManifestRegionCap_Is16MiB(int over, bool extracts)
    {
        var (bundle, headerOffset) = Build([], [new("a.dll", [1])]);
        var padded = new byte[headerOffset + (16 << 20) + over];
        bundle.CopyTo(padded, 0);

        var result = ExtractBytes(padded, headerOffset);

        if (extracts)
            Assert.Equal("a.dll", Assert.Single(result.Extracted).Name);
        else
            AssertManifestFailure(result, $"the manifest region is {(16 << 20) + 1} bytes (limit {16 << 20})");
    }

    // An empty bundle (count 0) is not a failure: nothing to extract.
    [Fact]
    public void Extract_AnEmptyBundle_ExtractsNothingAndFailsNothing()
    {
        var (extracted, failed, charged) = Extract([]);

        Assert.Empty(extracted);
        Assert.Empty(failed);
        Assert.Equal(0, charged);
    }
    #endregion

    #region Methods: DotNetHostScanner.Scan's BundleHeaderOffset
    [Fact]
    public void Scan_ABundleWithAPlausibleHeader_ReportsTheHeaderOffset()
    {
        var bytes = Hosted(NativeHeaderBuilder.Pe(NativeHeaderBuilder.MachineAmd64, NativeHeaderBuilder.CharExecutable, pe32Plus: true),
            [new("a.dll", [1]), new("b.dll", [2])]);
        var headerOffset = BitConverter.ToInt64(bytes, 0x400);

        var scan = ScanBytes(bytes);

        Assert.Equal(DotNetHost.SingleFileBundle, scan.Host);
        Assert.Equal(2, scan.BundledFiles);
        Assert.Equal(headerOffset, scan.BundleHeaderOffset);
        Assert.True(headerOffset > 0x400 + 8 + 32);
    }

    [Fact]
    public void Scan_ABundleWithAnImplausibleHeader_HasNoHeaderOffset()
    {
        var bytes = DotNetHostScannerTests.Image(8192, signatureAt: 1000, headerOffset: 5000);
        DotNetHostScannerTests.Header(bytes, 5000, major: 65, minor: 0, count: 3);

        var scan = ScanBytes(bytes);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)null, -1L), (scan.Host, scan.BundledFiles, scan.BundleHeaderOffset));
    }

    [Fact]
    public void Scan_AHeaderBeforeTheSignature_HasNoHeaderOffset()
    {
        var bytes = DotNetHostScannerTests.Image(8192, signatureAt: 6000, headerOffset: 100);
        DotNetHostScannerTests.Header(bytes, 100, major: 6, minor: 0, count: 3);

        Assert.Equal(-1, ScanBytes(bytes).BundleHeaderOffset);
    }

    [Fact]
    public void Scan_AnAppHostATemplateAndNoMarker_HaveNoHeaderOffset()
    {
        var apphost = DotNetHostScannerTests.Image(4096, signatureAt: 1000, headerOffset: 0);
        var template = DotNetHostScannerTests.Image(4096, signatureAt: 1000, headerOffset: 0);
        DotNetHostScannerTests.Placeholder.CopyTo(template, 2000);

        Assert.Equal((DotNetHost.AppHost, -1L), (ScanBytes(apphost).Host, ScanBytes(apphost).BundleHeaderOffset));
        Assert.Equal((DotNetHost.HostTemplate, -1L), (ScanBytes(template).Host, ScanBytes(template).BundleHeaderOffset));
        Assert.Equal((DotNetHost.None, -1L), (ScanBytes(new byte[4096]).Host, ScanBytes(new byte[4096]).BundleHeaderOffset));
    }

    // HashAndScan is Scan without the offset.
    [Fact]
    public void HashAndScan_IsScanWithoutTheOffset()
    {
        var bytes = Hosted(new byte[256], [new("a.dll", [1])]);
        var scan = ScanBytes(bytes);

        using var stream = new MemoryStream(bytes, writable: false);
        Assert.Equal((scan.Sha256, scan.Host, scan.BundledFiles), DotNetHostScanner.HashAndScan(stream));
    }

    [Fact]
    public void TheBuildersSignature_IsTheScannersSignature()
    {
        Assert.Equal(DotNetHostScannerTests.Signature, Signature);
    }
    #endregion

    #region Methods: helpers
    public void Dispose() => tree.Dispose();

    private (IReadOnlyList<ExtractedBundleEntry> Extracted, IReadOnlyList<UnextractedBundleEntry> Failed, long Charged) Extract(
        IReadOnlyList<Entry> entries, uint major = 6, long budget = long.MaxValue)
    {
        var (bundle, headerOffset) = Build(Noise(PrefixLength, seed: 99), entries, major);
        return ExtractBytes(bundle, headerOffset, budget);
    }

    private (IReadOnlyList<ExtractedBundleEntry> Extracted, IReadOnlyList<UnextractedBundleEntry> Failed, long Charged) ExtractBytes(
        byte[] bundle, long headerOffset, long budget = long.MaxValue)
    {
        var (extracted, failed, charged, _) = ExtractFull(bundle, headerOffset, budget);
        return (extracted, failed, charged);
    }

    private (IReadOnlyList<ExtractedBundleEntry> Extracted, IReadOnlyList<UnextractedBundleEntry> Failed, long Charged, int Attempted) ExtractFull(
        byte[] bundle, long headerOffset, long budget = long.MaxValue, int maxEntries = int.MaxValue)
    {
        File.WriteAllBytes(HostPath, bundle);
        return SingleFileBundle.Extract(HostPath, headerOffset, outDir, budget, maxEntries);
    }

    private (IReadOnlyList<ExtractedBundleEntry> Extracted, IReadOnlyList<UnextractedBundleEntry> Failed, long Charged, int Attempted) ExtractFull(
        IReadOnlyList<Entry> entries, long budget = long.MaxValue, int maxEntries = int.MaxValue)
    {
        var (bundle, headerOffset) = Build(Noise(PrefixLength, seed: 99), entries);
        return ExtractFull(bundle, headerOffset, budget, maxEntries);
    }

    // The named entry failed with the reason; "good.dll" (when present) was extracted; no file exists for the failure.
    private void AssertFailedAlone(
        IReadOnlyList<ExtractedBundleEntry> extracted, IReadOnlyList<UnextractedBundleEntry> failed, string name, string reason)
    {
        var failure = Assert.Single(failed);
        Assert.Equal(name, failure.Name);
        Assert.Contains(reason, failure.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(extracted, e => e.Name == name);
        Assert.Equal(extracted.Select(e => e.FullPath).Order(), FilesInOutDir().Order());
        Assert.False(File.Exists(Path.Combine(outDir, name)));
    }

    private void AssertManifestFailure(
        (IReadOnlyList<ExtractedBundleEntry> Extracted, IReadOnlyList<UnextractedBundleEntry> Failed, long Charged) result, string reason)
    {
        Assert.Empty(result.Extracted);
        var failure = Assert.Single(result.Failed);
        Assert.Equal(string.Empty, failure.Name);
        Assert.StartsWith("the bundle manifest could not be read: ", failure.Reason, StringComparison.Ordinal);
        Assert.Contains(reason, failure.Reason, StringComparison.Ordinal);
        Assert.Equal(0, result.Charged);
        Assert.False(Directory.Exists(outDir));
    }

    private string[] FilesInOutDir() => Directory.Exists(outDir) ? Directory.GetFiles(outDir) : [];

    private static string PathOf(IReadOnlyList<ExtractedBundleEntry> extracted, string name) =>
        Assert.Single(extracted, e => e.Name == name).FullPath;

    // `bytes` deflated, then zero-padded to exactly `compressedSize` stored bytes (the inflater stops at the final block).
    private static Entry Padded(string name, byte[] bytes, int compressedSize)
    {
        var deflated = Deflate(bytes);
        Assert.True(deflated.Length <= compressedSize, $"deflate gave {deflated.Length} bytes");
        return new Entry(name, bytes, Compress: true) { Stored = [.. deflated, .. new byte[compressedSize - deflated.Length]] };
    }

    private static DotNetHostScan ScanBytes(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        return DotNetHostScanner.Scan(stream);
    }

    private static byte[] Noise(int size, int seed)
    {
        var bytes = new byte[size];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private string HostPath => Path.Combine(tree.Root, "host.bin");
    #endregion

    #region Fields
    private readonly TempTree tree = new();
    private readonly string outDir;

    // The bytes Extract's bundles carry before the first entry's data.
    private const int PrefixLength = 24;

    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so this source never carries it raw.
    private const char Rlo = (char)0x202E;
    #endregion
}
