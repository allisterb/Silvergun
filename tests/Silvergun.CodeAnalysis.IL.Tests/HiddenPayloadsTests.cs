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
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <c>docs/agent/tasks/hidden-payloads-1.md</c>: hidden payloads beyond whole constants — base64 inside longer constants,
/// folded <c>string.Concat</c> of static fields, RVA field data, embedded resources, plus image/text recognition and the
/// additive JSON model. Every assembly is EMITTED at test time (<see cref="PersistedAssemblyBuilder"/>, as
/// <see cref="EmittedAssembly"/> does), read as metadata only and never loaded or run. Payloads are inert header shapes of
/// a few dozen bytes.
/// </summary>
public sealed class HiddenPayloadsTests : IClassFixture<AssemblyAnalyzerFixture>, IDisposable
{
    // The class fixture initializes the Silvergun runtime (logging) once; it is otherwise unused here.
    public HiddenPayloadsTests(AssemblyAnalyzerFixture runtimeInitialized) => _ = runtimeInitialized;

    public void Dispose() => emitted.Dispose();

    #region Methods — substrings (BF10)
    [Fact]
    public void Analyze_EncodedCommandInsideLongerConstant_ReportsUtf16TextSubstring()
    {
        var run = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host 'hello world'"));
        var report = AnalyzeConstants("powershell -NoP -W Hidden -Enc " + run);

        var finding = Assert.Single(report.Findings);
        Assert.Equal(HiddenContentKind.EncodedText, finding.Kind);
        Assert.Equal("UTF-16LE text", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.Substring, finding.Source);
        Assert.Equal(run.Length, finding.EncodedLength);
        Assert.Equal("Holder", finding.CallerType);
        Assert.Equal("M0", finding.CallerMethod);
    }

    [Fact]
    public void Analyze_Base64PeInsideLongerConstant_ReportsExecutableSubstring()
    {
        var run = Convert.ToBase64String(PeHeader());
        var report = AnalyzeConstants("data:application/octet-stream;base64," + run);

        Assert.Contains(report.Findings, f => f.Kind == HiddenContentKind.EncodedExecutable && f.DetectedAs == "Windows PE"
            && f.Source == HiddenContentSource.Substring && f.EncodedLength == run.Length);
    }

    [Fact]
    public void Analyze_Base64PngInsideLongerConstant_ReportsImageSubstring()
    {
        var report = AnalyzeConstants("icon: " + Convert.ToBase64String(WithMagic(PngMagic, 32)) + ";");

        var finding = Assert.Single(report.Findings);
        Assert.Equal(HiddenContentKind.EncodedImage, finding.Kind);
        Assert.Equal("PNG", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.Substring, finding.Source);
    }

    [Fact]
    public void Analyze_KeyEqualsBase64Png_ReportsImageSubstring()
    {
        var run = Convert.ToBase64String(WithMagic(PngMagic, 32));

        var finding = Assert.Single(AnalyzeConstants("icon=" + run).Findings);

        Assert.Equal(HiddenContentKind.EncodedImage, finding.Kind);
        Assert.Equal("PNG", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.Substring, finding.Source);
        Assert.Equal(run.Length, finding.EncodedLength);
    }

    [Fact]
    public void Analyze_EncEqualsBase64Utf16Text_ReportsTextSubstring()
    {
        var run = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host 'hello world'"));

        var finding = Assert.Single(AnalyzeConstants("-Enc=" + run).Findings);

        Assert.Equal(HiddenContentKind.EncodedText, finding.Kind);
        Assert.Equal("UTF-16LE text", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.Substring, finding.Source);
        Assert.Equal(run.Length, finding.EncodedLength);
    }

    [Fact]
    public void Analyze_PaddedRunFollowedDirectlyByText_SplitsAtThePadding()
    {
        var run = Convert.ToBase64String(PeHeader(127));   // 127 bytes: two '=' of padding
        Assert.EndsWith("==", run);

        var report = AnalyzeConstants("x " + run + "tail");

        Assert.Contains(report.Findings, f => f.Kind == HiddenContentKind.EncodedExecutable && f.DetectedAs == "Windows PE"
            && f.Source == HiddenContentSource.Substring && f.EncodedLength == run.Length);
    }

    [Theory]
    [InlineData("if (alpha == beta) then (gamma == delta) so be it, fine")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaa==bbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    public void Analyze_MidStringDoubleEquals_ProducesNoFinding(string constant) =>
        Assert.Empty(AnalyzeConstants(constant).Findings);

    [Fact]
    public void Analyze_SubstringDecodingToUnrecognisedBytes_ProducesNoFinding()
    {
        var bytes = Enumerable.Range(0, 48).Select(i => (byte)(0x80 + (i * 13) % 0x7F)).ToArray();
        var run = Convert.ToBase64String(bytes);
        Assert.True(run.Length >= ObfuscationAnalysis.MinEncodedLength);

        var report = AnalyzeConstants("run -Enc " + run + " now");

        Assert.Empty(report.Findings);
    }

    [Theory]
    [InlineData("type AbstractSingletonProxyFactoryBeanImplXYZ was resolved")]
    [InlineData("config: /usr/local/share/applications/mimeinfo/a (see docs)")]
    public void Analyze_Base64ShapedIdentifierOrPathRun_ProducesNoFinding(string constant)
    {
        // The test only means something if the run really is decodable; otherwise it would be silent for a trivial reason.
        var run = Regex.Matches(constant, "[A-Za-z0-9+/=]{24,}").Single().Value;
        Assert.Equal(0, run.Length % 4);
        Assert.NotEmpty(Convert.FromBase64String(run));

        var report = AnalyzeConstants(constant);

        Assert.Empty(report.Findings);
    }

    [Fact]
    public void Analyze_RunShorterThanMinimum_IsNotAnalysedAsSubstring()
    {
        var run = Convert.ToBase64String(WithMagic(PngMagic, 12));   // 16 chars < MinEncodedLength
        Assert.True(run.Length < ObfuscationAnalysis.MinEncodedLength);

        Assert.Empty(AnalyzeConstants("icon: " + run + " and more text to pass the length bar").Findings);
    }
    #endregion

    #region Methods — text
    [Fact]
    public void Analyze_WholeBase64OfUtf8Text_ReportsUtf8Text()
    {
        var report = AnalyzeConstants(Convert.ToBase64String(Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog")));

        var finding = Assert.Single(report.Findings);
        Assert.Equal(HiddenContentKind.EncodedText, finding.Kind);
        Assert.Equal("UTF-8 text", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.Constant, finding.Source);
    }

    [Fact]
    public void Analyze_WholeBase64OfUtf16Text_ReportsUtf16Text()
    {
        var report = AnalyzeConstants(Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host 'hi'")));

        var finding = Assert.Single(report.Findings);
        Assert.Equal(HiddenContentKind.EncodedText, finding.Kind);
        Assert.Equal("UTF-16LE text", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.Constant, finding.Source);
    }

    [Fact]
    public void Analyze_HexTextOfExactlyMinimumBytes_IsText()
    {
        var report = AnalyzeConstants(Convert.ToHexString(Encoding.ASCII.GetBytes("0123456789abcdef")).ToLowerInvariant());

        Assert.Contains(report.Findings, f => f.Kind == HiddenContentKind.EncodedText && f.DetectedAs == "UTF-8 text");
    }

    [Fact]
    public void Analyze_HexTextOneByteUnderMinimum_IsNotText()
    {
        var report = AnalyzeConstants(Convert.ToHexString(Encoding.ASCII.GetBytes("0123456789abcde")).ToLowerInvariant());

        Assert.DoesNotContain(report.Findings, f => f.Kind == HiddenContentKind.EncodedText);
    }

    [Fact]
    public void Analyze_ShortDecodedText_IsNotText()
    {
        // 12 bytes of text as hex: 24 chars, the shortest candidate, but under the 16-byte text minimum.
        var report = AnalyzeConstants(Convert.ToHexString(Encoding.ASCII.GetBytes("hello world!")).ToLowerInvariant());

        Assert.DoesNotContain(report.Findings, f => f.Kind == HiddenContentKind.EncodedText);
    }

    [Fact]
    public void Analyze_Utf16WithNonAsciiChar_IsNotText()
    {
        var report = AnalyzeConstants(Convert.ToBase64String(Encoding.Unicode.GetBytes("Café au lait, s'il vous plait")));

        Assert.DoesNotContain(report.Findings, f => f.Kind == HiddenContentKind.EncodedText);
    }

    [Fact]
    public void Analyze_InvalidUtf8_IsNotText()
    {
        var bytes = Enumerable.Repeat(new byte[] { 0xC3, 0x28 }, 12).SelectMany(b => b).ToArray();

        Assert.DoesNotContain(AnalyzeConstants(Convert.ToBase64String(bytes)).Findings, f => f.Kind == HiddenContentKind.EncodedText);
    }

    [Fact]
    public void Analyze_TextWithNul_IsNotText()
    {
        var bytes = Encoding.ASCII.GetBytes("hello world, this has a\0 NUL inside");

        Assert.DoesNotContain(AnalyzeConstants(Convert.ToBase64String(bytes)).Findings, f => f.Kind == HiddenContentKind.EncodedText);
    }

    [Fact]
    public void Analyze_MostlyControlBytes_IsNotText()
    {
        var bytes = Enumerable.Range(0, 24).Select(i => (byte)(i % 4 == 0 ? 'a' : 0x01)).ToArray();

        Assert.DoesNotContain(AnalyzeConstants(Convert.ToBase64String(bytes)).Findings, f => f.Kind == HiddenContentKind.EncodedText);
    }
    #endregion

    #region Methods — images
    [Theory]
    [MemberData(nameof(ImagePayloads))]
    public void Analyze_Base64Image_ReportsImageWithFormat(string format, byte[] bytes)
    {
        var report = AnalyzeConstants(Convert.ToBase64String(bytes));

        var finding = Assert.Single(report.Findings);
        Assert.Equal(HiddenContentKind.EncodedImage, finding.Kind);
        Assert.Equal(format, finding.DetectedAs);
        Assert.Equal(HiddenContentSource.Constant, finding.Source);
    }

    [Fact]
    public void Analyze_IconWithZeroEntries_IsNotAnIcon() =>
        Assert.DoesNotContain(AnalyzeConstants(Convert.ToBase64String(Icon(0, 64))).Findings, f => f.Kind == HiddenContentKind.EncodedImage);

    [Fact]
    public void Analyze_IconWithMoreThanSixtyFourEntries_IsNotAnIcon() =>
        Assert.DoesNotContain(AnalyzeConstants(Convert.ToBase64String(Icon(65, 6 + 16 * 65))).Findings, f => f.Kind == HiddenContentKind.EncodedImage);

    [Fact]
    public void Analyze_IconWithSixtyFourEntries_IsAnIcon() =>
        Assert.Contains(AnalyzeConstants(Convert.ToBase64String(Icon(64, 6 + 16 * 64))).Findings, f => f.Kind == HiddenContentKind.EncodedImage && f.DetectedAs == "ICO");

    [Fact]
    public void Analyze_IconWhoseEntriesDoNotFit_IsNotAnIcon() =>
        Assert.DoesNotContain(AnalyzeConstants(Convert.ToBase64String(Icon(1, 20))).Findings, f => f.Kind == HiddenContentKind.EncodedImage);

    [Fact]
    public void Analyze_RiffThatIsNotWebP_IsNotAnImage()
    {
        var bytes = WithMagic("RIFF"u8.ToArray().Concat(new byte[4]).Concat("WAVE"u8.ToArray()).ToArray(), 32);

        Assert.DoesNotContain(AnalyzeConstants(Convert.ToBase64String(bytes)).Findings, f => f.Kind == HiddenContentKind.EncodedImage);
    }

    [Fact]
    public void Analyze_ExecutableMagicWinsOverImage()
    {
        // A PE is classified before images: an "MZ" blob is never an image whatever follows.
        var report = AnalyzeConstants(Convert.ToBase64String(PeHeader()));

        Assert.All(report.Findings.Where(f => f.Source == HiddenContentSource.Constant), f => Assert.NotEqual(HiddenContentKind.EncodedImage, f.Kind));
        Assert.Contains(report.Findings, f => f.Kind == HiddenContentKind.EncodedExecutable);
    }
    #endregion

    #region Methods — folding (BF12b)
    [Fact]
    public void Analyze_TwoOnceStoredFieldsConcatenated_FoldsToExecutable()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);

        var report = AnalyzeFold([a, b], (il, f) => { il.Emit(OpCodes.Ldsfld, f[0]); il.Emit(OpCodes.Ldsfld, f[1]); il.Emit(OpCodes.Call, Concat(2)); });

        var finding = Assert.Single(report.Findings, f => f.Kind == HiddenContentKind.EncodedExecutable);
        Assert.Equal(HiddenContentSource.Folded, finding.Source);
        Assert.Equal("Windows PE", finding.DetectedAs);
        Assert.Equal("Folder", finding.CallerType);
        Assert.Equal("Use", finding.CallerMethod);
        Assert.Equal(a.Length + b.Length, finding.EncodedLength);
    }

    [Fact]
    public void Analyze_FieldStoredTwice_DoesNotFold()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);

        var report = AnalyzeFold([a, b], (il, f) => { il.Emit(OpCodes.Ldsfld, f[0]); il.Emit(OpCodes.Ldsfld, f[1]); il.Emit(OpCodes.Call, Concat(2)); }, storeFirstTwice: true);

        Assert.DoesNotContain(report.Findings, f => f.Source == HiddenContentSource.Folded);
    }

    [Fact]
    public void Analyze_ThreeArgumentConcat_Folds()
    {
        var parts = SplitN(Convert.ToBase64String(PeHeader()), 3);

        var report = AnalyzeFold(parts, (il, f) => { foreach (var field in f) il.Emit(OpCodes.Ldsfld, field); il.Emit(OpCodes.Call, Concat(3)); });

        Assert.Contains(report.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.EncodedExecutable);
    }

    [Fact]
    public void Analyze_FourArgumentConcat_Folds()
    {
        var parts = SplitN(Convert.ToBase64String(PeHeader()), 4);

        var report = AnalyzeFold(parts, (il, f) => { foreach (var field in f) il.Emit(OpCodes.Ldsfld, field); il.Emit(OpCodes.Call, Concat(4)); });

        Assert.Contains(report.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.EncodedExecutable);
    }

    [Fact]
    public void Analyze_NestedConcat_Folds()
    {
        var parts = SplitN(Convert.ToBase64String(PeHeader()), 3);

        var report = AnalyzeFold(parts, (il, f) =>
        {
            il.Emit(OpCodes.Ldsfld, f[0]);
            il.Emit(OpCodes.Ldsfld, f[1]);
            il.Emit(OpCodes.Call, Concat(2));
            il.Emit(OpCodes.Ldsfld, f[2]);
            il.Emit(OpCodes.Call, Concat(2));
        });

        Assert.Contains(report.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.EncodedExecutable);
    }

    [Fact]
    public void Analyze_LiteralConcatenatedWithField_Folds()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);

        var report = AnalyzeFold([b], (il, f) => { il.Emit(OpCodes.Ldstr, a); il.Emit(OpCodes.Ldsfld, f[0]); il.Emit(OpCodes.Call, Concat(2)); });

        Assert.Contains(report.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.EncodedExecutable);
    }

    [Fact]
    public void Analyze_ConcatOfLiteralsOnly_Folds()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);

        var report = AnalyzeFold([], (il, _) => { il.Emit(OpCodes.Ldstr, a); il.Emit(OpCodes.Ldstr, b); il.Emit(OpCodes.Call, Concat(2)); });

        Assert.Contains(report.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.EncodedExecutable);
    }

    [Fact]
    public void Analyze_BranchTargetBetweenTheLoads_DefeatsTheFold()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);

        // ldsfld A; br L; L: ldsfld B; Concat. The stack is cleared at L, so the Concat has one known argument at most.
        var report = AnalyzeFold([a, b], (il, f) =>
        {
            var target = il.DefineLabel();
            il.Emit(OpCodes.Ldsfld, f[0]);
            il.Emit(OpCodes.Br, target);
            il.MarkLabel(target);
            il.Emit(OpCodes.Ldsfld, f[1]);
            il.Emit(OpCodes.Call, Concat(2));
        });

        Assert.DoesNotContain(report.Findings, f => f.Source == HiddenContentSource.Folded);
    }

    [Fact]
    public void Analyze_AnotherOperationBetweenTheLoads_DefeatsTheFold()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);

        // ldsfld A; nop; ldsfld B; Concat: any other operation clears the abstract stack.
        var report = AnalyzeFold([a, b], (il, f) =>
        {
            il.Emit(OpCodes.Ldsfld, f[0]);
            il.Emit(OpCodes.Nop);
            il.Emit(OpCodes.Ldsfld, f[1]);
            il.Emit(OpCodes.Call, Concat(2));
        });

        Assert.DoesNotContain(report.Findings, f => f.Source == HiddenContentSource.Folded);
    }

    [Fact]
    public void Analyze_FoldedHighEntropyResult_FallsBackToHighEntropyBlob()
    {
        var bytes = Enumerable.Range(0, 96).Select(i => (byte)(0x80 + (i * 37) % 0x7F)).ToArray();
        var (a, b) = Split(Convert.ToBase64String(bytes), 30);

        var report = AnalyzeFold([a, b], (il, f) => { il.Emit(OpCodes.Ldsfld, f[0]); il.Emit(OpCodes.Ldsfld, f[1]); il.Emit(OpCodes.Call, Concat(2)); });

        Assert.Contains(report.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.HighEntropyBlob);
    }
    #endregion

    #region Methods — field data (BF12c)
    [Fact]
    public void Analyze_ByteArrayInitialiserWithPeHeader_ReportsExecutableFieldDataOnCctor()
    {
        var data = PeHeader(96);

        var report = AnalyzeFieldData(data);

        var finding = Assert.Single(report.Findings);
        Assert.Equal(HiddenContentKind.EncodedExecutable, finding.Kind);
        Assert.Equal("Windows PE", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.FieldData, finding.Source);
        Assert.Equal("Dropper", finding.CallerType);
        Assert.Equal(".cctor", finding.CallerMethod);
        Assert.Equal(data.Length, finding.EncodedLength);
    }

    [Fact]
    public void Analyze_FieldDataLoadedByTwoMethods_IsAttributedToBoth()
    {
        var report = AnalyzeFieldData(PeHeader(96), extraLoader: true);

        Assert.Equal(new[] { ".cctor", "Reload" }, report.Findings.Select(f => f.CallerMethod).Order(StringComparer.Ordinal));
        Assert.All(report.Findings, f => Assert.Equal(HiddenContentSource.FieldData, f.Source));
    }

    [Fact]
    public void Analyze_FieldDataNoMethodLoads_IsAttributedToDeclaringTypeAndFieldName()
    {
        var report = AnalyzeFieldData(PeHeader(96), withInitialiser: false);

        var finding = Assert.Single(report.Findings);
        Assert.Equal("Dropper", finding.CallerType);
        Assert.Equal("Payload", finding.CallerMethod);
    }

    [Fact]
    public void Analyze_FieldDataStartingWithMzButNoPeHeader_ProducesNothing()
    {
        var data = new byte[96];
        data[0] = (byte)'M';
        data[1] = (byte)'Z';
        for (var i = 2; i < data.Length; i++)
            data[i] = (byte)(i % 7 + 1);

        Assert.Empty(AnalyzeFieldData(data).Findings);
    }

    [Fact]
    public void Analyze_FieldDataWithPeOffsetPastTheEnd_ProducesNothing()
    {
        var data = PeHeader(96);
        BitConverter.GetBytes(94).CopyTo(data, 0x3C);   // "PE\0\0" would straddle the end

        Assert.Empty(AnalyzeFieldData(data).Findings);
    }

    [Fact]
    public void Analyze_FieldDataWithPeSignatureWellInsideTheBlob_IsAPe()
    {
        var data = new byte[160];
        data[0] = (byte)'M';
        data[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(data, 0x3C);
        "PE\0\0"u8.CopyTo(data.AsSpan(0x80));

        var finding = Assert.Single(AnalyzeFieldData(data).Findings);

        Assert.Equal(HiddenContentKind.EncodedExecutable, finding.Kind);
        Assert.Equal("Windows PE", finding.DetectedAs);
        Assert.Equal(data.Length, finding.EncodedLength);
    }

    [Fact]
    public void Analyze_FieldDataWithMissingPeSignatureAtOffset_ProducesNothing()
    {
        var data = new byte[160];
        data[0] = (byte)'M';
        data[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(data, 0x3C);   // nothing but zeros at 0x80

        Assert.Empty(AnalyzeFieldData(data).Findings);
    }

    [Fact]
    public void Analyze_FieldDataWithWrongPeSignature_ProducesNothing()
    {
        var data = PeHeader(96);
        data[0x40] = (byte)'X';

        Assert.Empty(AnalyzeFieldData(data).Findings);
    }

    [Fact]
    public void Analyze_FieldDataPng_ReportsImageFieldData()
    {
        var report = AnalyzeFieldData(WithMagic(PngMagic, 40));

        var finding = Assert.Single(report.Findings);
        Assert.Equal(HiddenContentKind.EncodedImage, finding.Kind);
        Assert.Equal("PNG", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.FieldData, finding.Source);
    }

    [Fact]
    public void Analyze_OrdinaryLookupTable_ProducesNothing()
    {
        var table = Enumerable.Range(1, 64).Select(i => (byte)(i * i % 251)).ToArray();

        Assert.Empty(AnalyzeFieldData(table).Findings);
    }

    [Fact]
    public void Analyze_FieldDataUtf8Literal_IsNotReportedAsText()
    {
        // Field data is checked by magic number only: text and entropy are ordinary there.
        Assert.Empty(AnalyzeFieldData(Encoding.UTF8.GetBytes("This is an ordinary readable literal blob.")).Findings);
    }
    #endregion

    #region Methods — resources (BF12d)
    [Fact]
    public void Analyze_ResourceWithPeBytes_ReportsExecutableResource()
    {
        var data = PeHeader(96);

        var report = AnalyzeResources(("payload.bin", data));

        var finding = Assert.Single(report.Findings);
        Assert.Equal(HiddenContentKind.EncodedExecutable, finding.Kind);
        Assert.Equal("Windows PE", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.Resource, finding.Source);
        Assert.Equal("<resource>", finding.CallerType);
        Assert.Equal("payload.bin", finding.CallerMethod);
        Assert.Equal(data.Length, finding.EncodedLength);
        Assert.True(finding.Entropy > 0);
    }

    [Fact]
    public void Analyze_BenignTextResource_ProducesNothing() =>
        Assert.Empty(AnalyzeResources(("readme.txt", Encoding.UTF8.GetBytes("Just some ordinary documentation text for the package."))).Findings);

    [Fact]
    public void Analyze_MzResourceWithoutPeHeader_ProducesNothing()
    {
        var data = new byte[96];
        data[0] = (byte)'M';
        data[1] = (byte)'Z';

        Assert.Empty(AnalyzeResources(("blob", data)).Findings);
    }

    [Fact]
    public void Analyze_SeveralResources_EachIsClassifiedAndNamed()
    {
        var report = AnalyzeResources(
            ("a.png", WithMagic(PngMagic, 32)),
            ("b.zip", WithMagic([0x50, 0x4B, 0x03, 0x04], 32)),
            ("c.txt", Encoding.ASCII.GetBytes("plain")),
            ("d.dll", PeHeader(96)));

        Assert.Equal(
            new[] { ("a.png", HiddenContentKind.EncodedImage), ("b.zip", HiddenContentKind.EncodedArchive), ("d.dll", HiddenContentKind.EncodedExecutable) },
            report.Findings.Select(f => (f.CallerMethod, f.Kind)).Order());
        Assert.All(report.Findings, f => Assert.Equal(HiddenContentSource.Resource, f.Source));
    }

    [Fact]
    public void Analyze_ResourceNameWithControlAndBidiChars_IsEscaped()
    {
        var name = "pay" + (char)0x202E + "load\n.bin";

        var finding = Assert.Single(AnalyzeResources((name, PeHeader(96))).Findings);

        Assert.Equal(UntrustedText.Escape(name), finding.CallerMethod);
        Assert.DoesNotContain((char)0x202E, finding.CallerMethod);
        Assert.DoesNotContain('\n', finding.CallerMethod);
    }

    [Fact]
    public void Analyze_ResourceInExternalFile_IsSkippedWithoutFailing()
    {
        // A real PE beside the dll under the name the File row gives: were the row's data read, it would be a finding.
        File.WriteAllBytes(Path.Combine(emitted.Directory, "side.bin"), PeHeader(96));

        var result = AnalyzeAssembly(builder =>
        {
            var module = builder.DefineDynamicModule("ext");
            Holder(module);
        }, metadata =>
        {
            var file = metadata.AddAssemblyFile(metadata.GetOrAddString("side.bin"), metadata.GetOrAddBlob(new byte[20]), containsMetadata: false);
            metadata.AddManifestResource(ManifestResourceAttributes.Public, metadata.GetOrAddString("external.bin"), file, 0);
        }, new BlobBuilder());

        Assert.Empty(result.Findings);
    }
    #endregion

    #region Methods — review round 1: folding
    [Fact]
    public void Analyze_ConcatChain_KeepsOnlyTheFinalFold()
    {
        var full = Convert.ToBase64String(PeHeader(96));   // 128 chars, no padding: every 4-char step decodes to a PE
        var pieces = Enumerable.Range(0, 24).Select(i => full.Substring(32 + 4 * i, 4)).ToArray();

        var report = AnalyzeFold([], (il, _) =>
        {
            il.Emit(OpCodes.Ldstr, full[..32]);
            foreach (var piece in pieces)
            {
                il.Emit(OpCodes.Ldstr, piece);
                il.Emit(OpCodes.Call, Concat(2));
            }
        });

        var folded = Assert.Single(report.Findings, f => f.Source == HiddenContentSource.Folded);
        Assert.Equal(HiddenContentKind.EncodedExecutable, folded.Kind);
        Assert.Equal(full.Length, folded.EncodedLength);
    }

    [Fact]
    public void Analyze_ConcatResultOverMaxFoldedChars_IsNotFolded()
    {
        var pe = Convert.ToBase64String(PeHeader(96));
        string Padded(int total) => pe + new string('A', total - pe.Length);   // a PE header, then zero bytes

        // Control: exactly MaxFoldedChars after the concatenation folds; four more chars do not.
        var atLimit = AnalyzeFold([], (il, _) => { il.Emit(OpCodes.Ldstr, Padded(ObfuscationAnalysis.MaxFoldedChars - 4)); il.Emit(OpCodes.Ldstr, "AAAA"); il.Emit(OpCodes.Call, Concat(2)); });
        var over = AnalyzeFold([], (il, _) => { il.Emit(OpCodes.Ldstr, Padded(ObfuscationAnalysis.MaxFoldedChars)); il.Emit(OpCodes.Ldstr, "AAAA"); il.Emit(OpCodes.Call, Concat(2)); });

        Assert.Contains(atLimit.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.EncodedExecutable);
        Assert.DoesNotContain(over.Findings, f => f.Source == HiddenContentSource.Folded);
    }

    [Fact]
    public void Analyze_FoldsBeyondTheModuleBudget_SetTruncated()
    {
        // Each Concat(A, A) builds 1 Mi chars; the budget is 8 Mi, so the ninth fold is the one refused.
        Assert.Equal(8L * 1024 * 1024, ObfuscationAnalysis.MaxFoldedCharsPerModule);
        var half = new string('A', ObfuscationAnalysis.MaxFoldedChars / 2);

        ObfuscationReport Folds(int count) => AnalyzeFold([], (il, _) =>
        {
            for (var i = 0; i < count; i++)
            {
                il.Emit(OpCodes.Ldstr, half);
                il.Emit(OpCodes.Ldstr, half);
                il.Emit(OpCodes.Call, Concat(2));
                il.Emit(OpCodes.Pop);
            }
            il.Emit(OpCodes.Ldnull);
        });

        Assert.False(Folds(8).Truncated);
        Assert.True(Folds(9).Truncated);
    }

    [Fact]
    public void Analyze_FoldedTextWithRecognisedRun_IsReportedAsFolded()
    {
        var run = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host 'hello world'"));
        var (first, second) = Split(run, 30);

        var report = AnalyzeFold(["-enc ", first, second], (il, f) => { foreach (var field in f) il.Emit(OpCodes.Ldsfld, field); il.Emit(OpCodes.Call, Concat(3)); });

        Assert.Contains(report.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.EncodedText && f.DetectedAs == "UTF-16LE text");
        Assert.DoesNotContain(report.Findings, f => f.Source == HiddenContentSource.Substring);
    }

    [Fact]
    public void Analyze_ConcatOfObjects_IsNotFolded()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);
        var concatObjects = typeof(string).GetMethod(nameof(string.Concat), [typeof(object), typeof(object)])!;

        var report = AnalyzeFold([a, b], (il, f) => { il.Emit(OpCodes.Ldsfld, f[0]); il.Emit(OpCodes.Ldsfld, f[1]); il.Emit(OpCodes.Call, concatObjects); });

        Assert.DoesNotContain(report.Findings, f => f.Source == HiddenContentSource.Folded);
    }

    [Fact]
    public void Analyze_ConcatOfAStringArray_IsNotFolded()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);
        var concatArray = typeof(string).GetMethod(nameof(string.Concat), [typeof(string[])])!;

        var report = AnalyzeFold([a, b], (il, f) => { il.Emit(OpCodes.Ldsfld, f[0]); il.Emit(OpCodes.Ldsfld, f[1]); il.Emit(OpCodes.Call, concatArray); });

        Assert.DoesNotContain(report.Findings, f => f.Source == HiddenContentSource.Folded);
    }

    [Fact]
    public void Analyze_SwitchTargetBetweenTheLoads_DefeatsTheFold()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);

        // ldc 0; switch (L); ldsfld A; L: ldsfld B; Concat. The switch itself comes BEFORE the first load, so only the
        // stack reset at its target L stops A and B being folded.
        var report = AnalyzeFold([a, b], (il, f) =>
        {
            var target = il.DefineLabel();
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Switch, new[] { target });
            il.Emit(OpCodes.Ldsfld, f[0]);
            il.MarkLabel(target);
            il.Emit(OpCodes.Ldsfld, f[1]);
            il.Emit(OpCodes.Call, Concat(2));
        });

        Assert.DoesNotContain(report.Findings, f => f.Source == HiddenContentSource.Folded);
    }
    #endregion

    #region Methods — review round 1: runs and ICO
    [Fact]
    public void Analyze_PathOrPlusPrefixJoinedToBase64Run_StillFindsThePayload()
    {
        var run = Convert.ToBase64String(PlainPe(96));
        Assert.DoesNotContain('/', run);
        Assert.DoesNotContain('+', run);

        var report = AnalyzeConstants("see path/" + run + " end", "see a+" + run + " end");

        foreach (var method in new[] { "M0", "M1" })
        {
            var finding = Assert.Single(report.Findings, f => f.CallerMethod == method);
            Assert.Equal(HiddenContentKind.EncodedExecutable, finding.Kind);
            Assert.Equal(HiddenContentSource.Substring, finding.Source);
            Assert.Equal(run.Length, finding.EncodedLength);
        }
    }

    [Fact]
    public void Analyze_PathOrPlusPrefixJoinedToRealisticDosHeaderRun_StillFindsThePayload()
    {
        // e_maxalloc = 0xFFFF puts "//8A" in the base64, as every compiled PE has: the retry must not cut at THAT '/'.
        var bytes = PlainPe(96);
        new byte[] { 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0xFF, 0xFF }.CopyTo(bytes, 2);
        var run = Convert.ToBase64String(bytes);
        Assert.StartsWith("TVqQAAMAAAAEAAAA//8A", run);

        var report = AnalyzeConstants("see path/" + run + " end", "see a+" + run + " end", "see x/y/" + run + " end");

        foreach (var method in new[] { "M0", "M1", "M2" })
        {
            var finding = Assert.Single(report.Findings, f => f.CallerMethod == method);
            Assert.Equal(HiddenContentKind.EncodedExecutable, finding.Kind);
            Assert.Equal(HiddenContentSource.Substring, finding.Source);
            Assert.Equal(run.Length, finding.EncodedLength);
        }
    }

    [Fact]
    public void Analyze_FoldWhoseOuterConcatIsTooLong_KeepsTheInnerFold()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);

        var report = AnalyzeFold([a, b], (il, f) =>
        {
            il.Emit(OpCodes.Ldsfld, f[0]);
            il.Emit(OpCodes.Ldsfld, f[1]);
            il.Emit(OpCodes.Call, Concat(2));
            il.Emit(OpCodes.Ldstr, new string('x', ObfuscationAnalysis.MaxFoldedChars));
            il.Emit(OpCodes.Call, Concat(2));
        });

        Assert.Contains(report.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.EncodedExecutable);
    }

    [Fact]
    public void Analyze_FoldWhoseOuterConcatHasAnUnknownArgument_KeepsTheInnerFold()
    {
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);

        // F0 is stored twice, so it is unknown: the outer Concat yields no value and must not swallow the inner fold.
        var report = AnalyzeFold(["unknown", a, b], (il, f) =>
        {
            il.Emit(OpCodes.Ldsfld, f[1]);
            il.Emit(OpCodes.Ldsfld, f[2]);
            il.Emit(OpCodes.Call, Concat(2));
            il.Emit(OpCodes.Ldsfld, f[0]);
            il.Emit(OpCodes.Call, Concat(2));
        }, storeFirstTwice: true);

        Assert.Contains(report.Findings, f => f.Source == HiddenContentSource.Folded && f.Kind == HiddenContentKind.EncodedExecutable);
    }

    [Fact]
    public void Analyze_UshortCounterTableAsFieldData_IsNotAnIcon()
    {
        var table = Enumerable.Range(0, 40).SelectMany(i => BitConverter.GetBytes((ushort)i)).ToArray();   // 00 00 01 00 02 00 ...

        Assert.DoesNotContain(AnalyzeFieldData(table).Findings, f => f.Kind == HiddenContentKind.EncodedImage);
    }

    [Fact]
    public void Analyze_MinimalIconAsFieldData_IsAnIcon()
    {
        var finding = Assert.Single(AnalyzeFieldData(Icon(1, 40)).Findings);

        Assert.Equal(HiddenContentKind.EncodedImage, finding.Kind);
        Assert.Equal("ICO", finding.DetectedAs);
        Assert.Equal(HiddenContentSource.FieldData, finding.Source);
    }
    #endregion

    #region Methods — JSON model
    [Fact]
    public void ToJson_ConstantSourceFinding_HasNoSourceProperty()
    {
        var json = ReportOf(new ObfuscationFinding(HiddenContentKind.EncodedExecutable, "Windows PE", "T", "M", 100, 5.0)).ToJson();

        Assert.DoesNotContain("\"Source\"", json);
        Assert.Matches(new Regex("\"Kind\"\\s*:\\s*\"EncodedExecutable\""), json);
    }

    [Theory]
    [InlineData(HiddenContentSource.Substring)]
    [InlineData(HiddenContentSource.Folded)]
    [InlineData(HiddenContentSource.FieldData)]
    [InlineData(HiddenContentSource.Resource)]
    public void ToJson_NonDefaultSource_WritesNameAndRoundTrips(HiddenContentSource source)
    {
        var report = ReportOf(new ObfuscationFinding(HiddenContentKind.EncodedText, "UTF-16LE text", "T", "M", 64, 4.5, source));

        var json = report.ToJson();
        var restored = ObfuscationReport.FromJson(json);

        Assert.Matches(new Regex($"\"Source\"\\s*:\\s*\"{source}\""), json);
        Assert.NotNull(restored);
        Assert.Equal(report.Findings, restored!.Findings);
        Assert.Equal(source, restored.Findings.Single().Source);
    }

    [Fact]
    public void FromJson_FindingWrittenBeforeSourceExisted_DeserializesAsConstant()
    {
        const string json = """
            {"AssemblyName":"A","AssemblyPath":"p","AnalyzedAt":"1970-01-01T00:00:00+00:00","Findings":[
              {"Kind":"EncodedArchive","DetectedAs":"zip","CallerType":"T","CallerMethod":"M","EncodedLength":40,"Entropy":4.2}]}
            """;

        var finding = Assert.Single(ObfuscationReport.FromJson(json)!.Findings);

        Assert.Equal(HiddenContentSource.Constant, finding.Source);
        Assert.Equal(HiddenContentKind.EncodedArchive, finding.Kind);
    }

    [Fact]
    public void ToJson_TruncatedFalse_OmitsTheProperty() =>
        Assert.DoesNotContain("Truncated", ReportOf().ToJson());

    [Fact]
    public void ToJson_TruncatedTrue_WritesItAndRoundTrips()
    {
        var report = ReportOf() with { Truncated = true };

        var json = report.ToJson();

        Assert.Matches(new Regex("\"Truncated\"\\s*:\\s*true"), json);
        Assert.True(ObfuscationReport.FromJson(json)!.Truncated);
        Assert.False(ObfuscationReport.FromJson(ReportOf().ToJson())!.Truncated);
    }

    [Fact]
    public void Enums_AreAppendOnly()
    {
        Assert.Equal(
            new[] { HiddenContentKind.EncodedExecutable, HiddenContentKind.EncodedArchive, HiddenContentKind.HighEntropyBlob, HiddenContentKind.EncodedText, HiddenContentKind.EncodedImage },
            Enum.GetValues<HiddenContentKind>().OrderBy(k => (int)k));
        Assert.Equal(
            new[] { HiddenContentSource.Constant, HiddenContentSource.Substring, HiddenContentSource.Folded, HiddenContentSource.FieldData, HiddenContentSource.Resource },
            Enum.GetValues<HiddenContentSource>().OrderBy(k => (int)k));
        Assert.Equal(0, (int)HiddenContentSource.Constant);
        Assert.Equal(3, (int)HiddenContentKind.EncodedText);
        Assert.Equal(4, (int)HiddenContentKind.EncodedImage);
    }
    #endregion

    #region Methods — determinism and robustness
    [Fact]
    public void Analyze_AssemblyWithEverySource_IsDeterministicAndOrdered()
    {
        var run = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host 'hello world'"));
        var (a, b) = Split(Convert.ToBase64String(PeHeader()), 30);
        var path = SaveEverySource(run, a, b);

        var first = AnalyzeFile(path);
        var second = AnalyzeFile(path);

        Assert.True(first.Findings.Select(f => f.Source).Distinct().Count() == 5,
            $"expected all five sources, got: {string.Join(",", first.Findings.Select(f => f.Source).Distinct())}");
        Assert.Equal(first.Findings, second.Findings);
        Assert.Equal(
            first.Findings.OrderBy(f => f.CallerType, StringComparer.Ordinal).ThenBy(f => f.CallerMethod, StringComparer.Ordinal)
                .ThenBy(f => f.DetectedAs, StringComparer.Ordinal).ThenBy(f => f.Kind).ThenBy(f => f.Source),
            first.Findings);
        Assert.Equal(first.Findings.Count, first.Findings.Distinct().Count());
    }

    [Fact]
    public void Analyze_ConstantsAssembly_IsStableAcrossRuns()
    {
        var path = emitted.Save(NextName(), module => Holder(module, "abc", Convert.ToBase64String(PeHeader()), "x " + Convert.ToBase64String(WithMagic(PngMagic, 32))));

        Assert.Equal(AnalyzeFile(path).Findings, AnalyzeFile(path).Findings);
    }
    #endregion

    #region Methods — emit helpers
    private ObfuscationReport AnalyzeConstants(params string[] values) => AnalyzeFile(emitted.Save(NextName(), module => Holder(module, values)));

    // A type "Holder" with one static string method M{i} per value: ldstr value; ret.
    private static void Holder(ModuleBuilder module, params string[] values)
    {
        var type = module.DefineType("Holder", TypeAttributes.Public | TypeAttributes.Class);
        for (var i = 0; i < values.Length; i++)
        {
            var il = type.DefineMethod($"M{i}", MethodAttributes.Public | MethodAttributes.Static, typeof(string), Type.EmptyTypes).GetILGenerator();
            il.Emit(OpCodes.Ldstr, values[i]);
            il.Emit(OpCodes.Ret);
        }
        type.CreateType();
    }

    // A type "Folder" whose .cctor stores each value into static field F{i} with ldstr;stsfld (optionally storing F0 a
    // second time), and a static method "Use" whose body is emitted by <body> (then ret).
    private ObfuscationReport AnalyzeFold(string[] values, Action<ILGenerator, FieldBuilder[]> body, bool storeFirstTwice = false) =>
        AnalyzeFile(emitted.Save(NextName(), module =>
        {
            var type = module.DefineType("Folder", TypeAttributes.Public | TypeAttributes.Class);
            var fields = values.Select((_, i) => type.DefineField($"F{i}", typeof(string), FieldAttributes.Public | FieldAttributes.Static)).ToArray();
            var init = type.DefineTypeInitializer().GetILGenerator();
            for (var i = 0; i < values.Length; i++)
            {
                init.Emit(OpCodes.Ldstr, values[i]);
                init.Emit(OpCodes.Stsfld, fields[i]);
            }
            if (storeFirstTwice)
            {
                init.Emit(OpCodes.Ldstr, "overwritten");
                init.Emit(OpCodes.Stsfld, fields[0]);
            }
            init.Emit(OpCodes.Ret);

            var use = type.DefineMethod("Use", MethodAttributes.Public | MethodAttributes.Static, typeof(string), Type.EmptyTypes).GetILGenerator();
            body(use, fields);
            use.Emit(OpCodes.Ret);
            type.CreateType();
        }));

    // A type "Dropper" with an RVA field "Payload" holding <data>; its .cctor (unless disabled) fills a static byte[] with
    // the InitializeArray idiom (ldtoken Payload), and an optional second method loads the same token.
    private ObfuscationReport AnalyzeFieldData(byte[] data, bool withInitialiser = true, bool extraLoader = false) =>
        AnalyzeFile(emitted.Save(NextName(), module =>
        {
            var type = module.DefineType("Dropper", TypeAttributes.Public | TypeAttributes.Class);
            var payload = type.DefineInitializedData("Payload", data, FieldAttributes.Public | FieldAttributes.Static);
            var table = type.DefineField("Table", typeof(byte[]), FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.InitOnly);
            if (withInitialiser)
                EmitInitializeArray(type.DefineTypeInitializer().GetILGenerator(), payload, table, data.Length);
            if (extraLoader)
                EmitInitializeArray(type.DefineMethod("Reload", MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes).GetILGenerator(), payload, table, data.Length);
            type.CreateType();
        }));

    private static void EmitInitializeArray(ILGenerator il, FieldBuilder payload, FieldBuilder table, int length)
    {
        il.Emit(OpCodes.Ldc_I4, length);
        il.Emit(OpCodes.Newarr, typeof(byte));
        il.Emit(OpCodes.Dup);
        il.Emit(OpCodes.Ldtoken, payload);
        il.Emit(OpCodes.Call, typeof(RuntimeHelpers).GetMethod(nameof(RuntimeHelpers.InitializeArray), [typeof(Array), typeof(RuntimeFieldHandle)])!);
        il.Emit(OpCodes.Stsfld, table);
        il.Emit(OpCodes.Ret);
    }

    private ObfuscationReport AnalyzeResources(params (string Name, byte[] Data)[] resources)
    {
        var blob = new BlobBuilder();
        return AnalyzeAssembly(
            builder => Holder(builder.DefineDynamicModule("res")),
            metadata =>
            {
                foreach (var (name, data) in resources)
                {
                    var offset = blob.Count;
                    blob.WriteInt32(data.Length);
                    blob.WriteBytes(data);
                    metadata.AddManifestResource(ManifestResourceAttributes.Public, metadata.GetOrAddString(name), default(EntityHandle), (uint)offset);
                }
            },
            blob);
    }

    // Emits an assembly whose metadata gets extra rows from <addRows>; <resources> becomes its managed-resource blob.
    private ObfuscationReport AnalyzeAssembly(Action<PersistedAssemblyBuilder> define, Action<MetadataBuilder> addRows, BlobBuilder resources)
    {
        var name = NextName();
        var builder = new PersistedAssemblyBuilder(new AssemblyName(name), typeof(object).Assembly);
        define(builder);
        var metadata = builder.GenerateMetadata(out var il, out var fieldData);
        addRows(metadata);
        var image = new ManagedPEBuilder(
            new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(metadata),
            il,
            mappedFieldData: fieldData,
            managedResources: resources);
        var blob = new BlobBuilder();
        image.Serialize(blob);
        var path = Path.Combine(emitted.Directory, name + ".dll");
        using (var file = File.Create(path))
            blob.WriteContentTo(file);
        return AnalyzeFile(path);
    }

    // One assembly carrying a finding of every HiddenContentSource.
    private string SaveEverySource(string run, string foldA, string foldB)
    {
        var name = NextName();
        var builder = new PersistedAssemblyBuilder(new AssemblyName(name), typeof(object).Assembly);
        var module = builder.DefineDynamicModule(name);
        var type = module.DefineType("Mixed", TypeAttributes.Public | TypeAttributes.Class);

        var whole = type.DefineMethod("Whole", MethodAttributes.Public | MethodAttributes.Static, typeof(string), Type.EmptyTypes).GetILGenerator();
        whole.Emit(OpCodes.Ldstr, Convert.ToBase64String(WithMagic(PngMagic, 32)));
        whole.Emit(OpCodes.Ret);

        var inside = type.DefineMethod("Inside", MethodAttributes.Public | MethodAttributes.Static, typeof(string), Type.EmptyTypes).GetILGenerator();
        inside.Emit(OpCodes.Ldstr, "powershell -Enc " + run);
        inside.Emit(OpCodes.Ret);

        var fa = type.DefineField("A", typeof(string), FieldAttributes.Public | FieldAttributes.Static);
        var fb = type.DefineField("B", typeof(string), FieldAttributes.Public | FieldAttributes.Static);
        var payload = type.DefineInitializedData("Payload", PeHeader(96), FieldAttributes.Public | FieldAttributes.Static);
        var table = type.DefineField("Table", typeof(byte[]), FieldAttributes.Public | FieldAttributes.Static);
        var init = type.DefineTypeInitializer().GetILGenerator();
        init.Emit(OpCodes.Ldstr, foldA);
        init.Emit(OpCodes.Stsfld, fa);
        init.Emit(OpCodes.Ldstr, foldB);
        init.Emit(OpCodes.Stsfld, fb);
        EmitInitializeArray(init, payload, table, 96);

        var use = type.DefineMethod("Use", MethodAttributes.Public | MethodAttributes.Static, typeof(string), Type.EmptyTypes).GetILGenerator();
        use.Emit(OpCodes.Ldsfld, fa);
        use.Emit(OpCodes.Ldsfld, fb);
        use.Emit(OpCodes.Call, Concat(2));
        use.Emit(OpCodes.Ret);
        type.CreateType();

        var metadata = builder.GenerateMetadata(out var il, out var fieldData);
        var resources = new BlobBuilder();
        resources.WriteInt32(96);
        resources.WriteBytes(PeHeader(96));
        metadata.AddManifestResource(ManifestResourceAttributes.Public, metadata.GetOrAddString("payload.bin"), default(EntityHandle), 0);
        var image = new ManagedPEBuilder(
            new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(metadata), il, mappedFieldData: fieldData, managedResources: resources);
        var blob = new BlobBuilder();
        image.Serialize(blob);
        var path = Path.Combine(emitted.Directory, name + ".dll");
        using (var file = File.Create(path))
            blob.WriteContentTo(file);
        return path;
    }

    private static ObfuscationReport AnalyzeFile(string path)
    {
        var load = AssemblyAnalyzer.Load(path);
        Assert.True(load.IsSuccess, load.Message);
        using var analyzer = load.Value;
        var result = new ObfuscationAnalysis(analyzer).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }

    private string NextName() => $"HiddenPayloads{++counter}";

    private static MethodInfo Concat(int arity) =>
        typeof(string).GetMethod(nameof(string.Concat), [.. Enumerable.Repeat(typeof(string), arity)])!;
    #endregion

    #region Methods — payload helpers
    public static TheoryData<string, byte[]> ImagePayloads() => new()
    {
        { "PNG", WithMagic(PngMagic, 32) },
        { "JPEG", WithMagic([0xFF, 0xD8, 0xFF, 0xE0], 32) },
        { "GIF", WithMagic("GIF89a"u8.ToArray(), 32) },
        { "GIF", WithMagic("GIF87a"u8.ToArray(), 32) },
        { "WebP", WithMagic("RIFF"u8.ToArray().Concat(new byte[4]).Concat("WEBP"u8.ToArray()).ToArray(), 32) },
        { "ICO", Icon(1, 32) },
    };

    // <magic> followed by non-trivial filler bytes (none of which can start another magic), padded to <length>.
    private static byte[] WithMagic(byte[] magic, int length)
    {
        var bytes = new byte[Math.Max(length, magic.Length)];
        magic.CopyTo(bytes, 0);
        for (var i = magic.Length; i < bytes.Length; i++)
            bytes[i] = (byte)(i * 5 % 61 + 1);
        return bytes;
    }

    // An ICO header with <entries> declared directory entries, padded with zeros to <length>.
    private static byte[] Icon(int entries, int length)
    {
        var bytes = new byte[length];
        bytes[2] = 1;
        BitConverter.GetBytes((ushort)entries).CopyTo(bytes, 4);
        // Each entry that fits: 16x16, one plane, 32 bits, image data right after the directory.
        for (var i = 0; i < entries && 6 + 16 * (i + 1) <= length; i++)
        {
            var entry = 6 + 16 * i;
            bytes[entry] = bytes[entry + 1] = 16;
            BitConverter.GetBytes((ushort)1).CopyTo(bytes, entry + 4);
            BitConverter.GetBytes((ushort)32).CopyTo(bytes, entry + 6);
            BitConverter.GetBytes((uint)(6 + 16 * entries)).CopyTo(bytes, entry + 12);
        }
        return bytes;
    }

    // As PeHeader, but zero filler, so its base64 holds no '/' or '+'.
    private static byte[] PlainPe(int length)
    {
        var bytes = new byte[length];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(0x40).CopyTo(bytes, 0x3C);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(0x40));
        return bytes;
    }

    // An inert PE-header shape: "MZ", e_lfanew = 0x40, "PE\0\0" there, non-trivial filler elsewhere. Not runnable.
    internal static byte[] PeHeader(int length = 128)
    {
        var bytes = new byte[length];
        for (var i = 0; i < bytes.Length; i++)
            bytes[i] = (byte)(i * 7 % 113 + 1);
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(0x40).CopyTo(bytes, 0x3C);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(0x40));
        return bytes;
    }

    private static (string, string) Split(string text, int at) => (text[..at], text[at..]);

    private static string[] SplitN(string text, int parts) =>
        [.. Enumerable.Range(0, parts).Select(i => text[(text.Length * i / parts)..(text.Length * (i + 1) / parts)])];

    private static ObfuscationReport ReportOf(params ObfuscationFinding[] findings) =>
        new("A", "p", DateTimeOffset.UnixEpoch, findings);
    #endregion

    #region Fields
    internal static readonly byte[] PngMagic = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    private readonly EmittedAssembly emitted = new();
    private int counter;
    #endregion
}
