namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.MsBuild;

using Xunit;

/// <summary>
/// <see cref="MsBuildExpander"/> on its own (MCP task S4): known properties become anchors, package definitions expand
/// (every candidate, a self reference empty), the path functions are evaluated, anything else stays as text and marks the
/// value unresolved, <c>%XX</c> is unescaped after expansion, paths normalize with their climbs, and package text cannot
/// forge an anchor.
/// </summary>
public sealed class MsBuildExpanderTests
{
    #region Methods
    [Theory]
    [InlineData("$(MSBuildThisFileDirectory)x/y.dll", MsBuildAnchor.Package, "build/x/y.dll", 0)]
    [InlineData("$(MSBuildThisFileFullPath)", MsBuildAnchor.Package, "build/Acme.Tool.targets", 0)]
    [InlineData("$(PkgAcme_Tool)tools/t.exe", MsBuildAnchor.Package, "tools/t.exe", 0)]
    [InlineData("$(MSBuildProjectDirectory)/../.claude/skills/", MsBuildAnchor.Project, ".claude/skills", 1)]
    [InlineData("relative/dir", MsBuildAnchor.Project, "relative/dir", 0)]
    [InlineData("$(SolutionDir)", MsBuildAnchor.Solution, "", 0)]
    [InlineData("$(USERPROFILE)\\.cursor\\mcp.json", MsBuildAnchor.Home, ".cursor/mcp.json", 0)]
    [InlineData("$(HOME)/.claude.json", MsBuildAnchor.Home, ".claude.json", 0)]
    [InlineData("~/x", MsBuildAnchor.Home, "x", 0)]
    [InlineData("%APPDATA%\\Code\\User", MsBuildAnchor.AppData, "Code/User", 0)]
    [InlineData("$(LOCALAPPDATA)x", MsBuildAnchor.LocalAppData, "x", 0)]
    [InlineData("$(TEMP)drop", MsBuildAnchor.Temp, "drop", 0)]
    [InlineData("$(windir)\\System32", MsBuildAnchor.System, "System32", 0)]
    [InlineData("$(OutputPath)a/./b/../c", MsBuildAnchor.Output, "a/c", 0)]
    [InlineData("$(OutDir)../../x", MsBuildAnchor.Output, "x", 2)]
    [InlineData("$(IntermediateOutputPath)stamp", MsBuildAnchor.Intermediate, "stamp", 0)]
    [InlineData("$(NuGetPackageRoot)other/1.0.0", MsBuildAnchor.NuGetPackages, "other/1.0.0", 0)]
    [InlineData("$(MSBuildExtensionsPath)x", MsBuildAnchor.MsBuild, "x", 0)]
    [InlineData("$(DOTNET_HOST_PATH)", MsBuildAnchor.Dotnet, "", 0)]
    [InlineData("/etc/passwd", MsBuildAnchor.Absolute, "etc/passwd", 0)]
    [InlineData("C:\\Windows\\x", MsBuildAnchor.Absolute, "C:/Windows/x", 0)]
    public void Expand_AKnownStart_IsItsAnchor(string value, MsBuildAnchor anchor, string path, int climbs)
    {
        var path0 = Single(Expander(), value);

        Assert.Equal(anchor, path0.Anchor);
        Assert.Equal(path, path0.Path);
        Assert.Equal(climbs, path0.Climbs);
        Assert.False(path0.Unresolved, path0.Display);
    }

    [Theory]
    [InlineData("$(OutputPath)x", false)]
    [InlineData("$(IntermediateOutputPath)x", false)]
    [InlineData("$(OutputPath)../x", true)]
    [InlineData("$(MSBuildProjectDirectory)x", true)]
    [InlineData("$(TEMP)x", true)]
    [InlineData("$(Unknown)x", null)]
    public void OutsideOutput_IsFalseOnlyUnderTheOutputWithoutClimbingOut_AndNullWhenUnknown(string value, bool? outside) =>
        Assert.Equal(outside, Single(Expander(), value).OutsideOutput);

    [Fact]
    public void Display_ShowsTheAnchorAndItsClimbs() =>
        Assert.Equal("{project}/../../a/b", Single(Expander(), "$(ProjectDir)../../a/b").Display);

    [Theory]
    [InlineData("$(Unknown)/x")]
    [InlineData("$(SolutionDir)%(Meta.Identity)")]
    [InlineData("$(SolutionDir)$([System.DateTime]::Now.Ticks)")]
    [InlineData("$(SolutionDir)@(NoSuchItem)")]
    [InlineData("$(SolutionDir)$(Unknown)")]
    public void Expand_AnythingItCannotResolve_StaysAsText_AndIsUnresolved(string value)
    {
        var candidates = Expander().Expand(value, File);

        Assert.True(candidates.All(c => c.Unresolved), string.Join(" | ", candidates));
        Assert.True(Single(Expander(), value).Unresolved);
    }

    [Theory]
    [InlineData("$(Configuration)/$(TargetFramework)/x")]
    [InlineData("$(SolutionDir)$(MSBuildProjectName).txt")]
    public void Expand_AScalarProperty_IsAPathSegment_NotUnresolved(string value) =>
        Assert.False(Single(Expander(), value).Unresolved);

    [Fact]
    public void Expand_APackageProperty_ExpandsToEachDefinition()
    {
        var expander = Expander(properties: new() { ["Dir"] = [("$(SolutionDir).claude", File), ("$(OutputPath)safe", "build/other.props")] });

        var paths = Paths(expander, "$(Dir)/skills");

        // The latest definition first: MSBuild keeps the last one whose condition holds (S4 review C6).
        Assert.Equal(["{output}/safe/skills", "{solution}/.claude/skills"], paths.Select(p => p.Display));
    }

    [Fact]
    public void Expand_ADefinitionInAnotherFile_TakesThatFilesDirectory()
    {
        var expander = Expander(properties: new() { ["ToolDir"] = [("$(MSBuildThisFileDirectory)../tools/", "buildTransitive/net8.0/Acme.Tool.props")] });

        Assert.Equal("buildTransitive/tools/t.exe", Single(expander, "$(ToolDir)t.exe").Path);
    }

    [Fact]
    public void Expand_AtMostEightCandidates()
    {
        var eight = Enumerable.Range(0, 8).Select(i => ($"a{i}", File)).ToList();
        var expander = Expander(properties: new() { ["P"] = eight, ["Q"] = [.. eight.Select(e => ("b" + e.Item1, File))] });

        var candidates = expander.Expand("$(P)/$(Q)", File);

        Assert.InRange(candidates.Count, 1, MsBuildExpander.MaxCandidates);
    }

    [Fact]
    public void Expand_ASelfReference_IsEmpty_AndAMutualOneTerminates()
    {
        var expander = Expander(properties: new()
        {
            ["Self"] = [("$(Self)x", File)],
            ["A"] = [("$(B)a", File)],
            ["B"] = [("$(A)b", File)],
        });

        Assert.Equal(new[] { ("x", false) }, expander.Expand("$(Self)", File));
        Assert.Equal(new[] { ("ba", false) }, expander.Expand("$(A)", File));
    }

    [Fact]
    public void Expand_PastTheDepthLimit_StaysUnresolved()
    {
        var properties = Enumerable.Range(1, 12).ToDictionary(i => $"P{i}", i => new List<(string, string)> { ($"$(P{i - 1})", File) }, StringComparer.OrdinalIgnoreCase);
        properties["P0"] = [("end", File)];
        var expander = new MsBuildExpander("Acme.Tool", properties, new Dictionary<string, List<(string, string)>>());

        Assert.True(expander.Expand("$(P12)", File).All(c => c.Unresolved));
        Assert.Equal(new[] { ("end", false) }, expander.Expand("$(P5)", File));
    }

    [Fact]
    public void Expand_AnItem_ExpandsToItsIncludes_AndATransformToItsBody()
    {
        var expander = Expander(items: new() { ["Skill"] = [("$(MSBuildThisFileDirectory)a.md", File), ("$(MSBuildThisFileDirectory)b.md", File)] });

        Assert.Equal(["{package}/build/a.md", "{package}/build/b.md"], Paths(expander, "@(Skill)").Select(p => p.Display));
        foreach (var transform in new[] { "@(Skill->'$(SolutionDir).claude/skills/%(Filename)%(Extension)')", "@(Skill -> '$(SolutionDir).claude/skills/%(Filename)%(Extension)')" })
        {
            var paths = Paths(expander, transform);
            // Even a source's own %(Filename) is a gap: MSBuild gives ".." for Include="..." (S4 review round 2, C1, measured).
            Assert.All(paths, p => Assert.True(p.Unresolved, p.Display));
            Assert.All(paths, p => Assert.Null(p.OutsideOutput));
            Assert.All(paths, p => Assert.True(p.Display.StartsWith("{solution}/.claude/skills/", StringComparison.Ordinal), $"{transform}: {p.Display}"));
        }
    }

    [Theory]
    [InlineData("$([MSBuild]::NormalizeDirectory($(SolutionDir), '.claude', 'skills'))", "{solution}/.claude/skills")]
    [InlineData("$([MSBuild]::NormalizePath('$(MSBuildProjectDirectory)', '..', '.mcp.json'))", "{project}/../.mcp.json")]
    [InlineData("$([MSBuild]::EnsureTrailingSlash('$(SolutionDir).cursor'))", "{solution}/.cursor")]
    [InlineData("$([System.IO.Path]::Combine($(MSBuildProjectDirectory), '..', '.vscode', 'mcp.json'))", "{project}/../.vscode/mcp.json")]
    [InlineData("$([System.IO.Path]::Combine('ignored', $(SolutionDir), 'AGENTS.md'))", "{solution}/AGENTS.md")]
    [InlineData("$([System.IO.Path]::GetFullPath('$(OutputPath)x'))", "{output}/x")]
    public void Expand_ThePathFunctions_AreEvaluated(string value, string display)
    {
        var path = Single(Expander(), value);

        Assert.Equal(display, path.Display);
        Assert.False(path.Unresolved);
    }

    [Theory]
    [InlineData("$(SolutionDir)%2Eclaude%2Fskills", "{solution}/.claude/skills")]
    [InlineData("$(SolutionDir)a%3Bb", "{solution}/a;b")]
    public void Normalize_UnescapesPercentEscapes_AfterExpansion(string value, string display) =>
        Assert.Equal(display, Single(Expander(), value).Display);

    /// <summary>Unescape decodes each %XX once (either hex case); a '%' not followed by two hex digits stays as it is.</summary>
    [Theory]
    [InlineData("Out%44ir", "OutDir")]
    [InlineData("%41dditional%50roperties", "AdditionalProperties")]
    [InlineData("%61b%2f", "ab/")]
    [InlineData("%2541", "%41")]
    [InlineData("OutDi%72", "OutDir")]
    [InlineData("%(Meta)", "%(Meta)")]
    [InlineData("a%4", "a%4")]
    [InlineData("%zz%", "%zz%")]
    [InlineData("plain", "plain")]
    [InlineData("", "")]
    public void Unescape_DecodesEachEscapeOnce(string text, string expected) => Assert.Equal(expected, MsBuildExpander.Unescape(text));

    [Fact]
    public void Expand_AnEscapedPropertyReference_IsNotExpanded()
    {
        var path = Single(Expander(), "%24(OutputPath)x");

        Assert.Equal(MsBuildAnchor.Project, path.Anchor);
        Assert.True(path.Unresolved);
    }

    [Theory]
    [InlineData("dotnet \"$(MSBuildThisFileDirectory)../lib/net8.0/Tool.dll\"", "dotnet")]
    [InlineData("\"$(MSBuildThisFileDirectory)tool.exe\" --x", "{package}/build/tool.exe")]
    [InlineData("$(MSBuildThisFileDirectory)tool.exe --x", "{package}/build/tool.exe")]
    [InlineData("   ", null)]
    public void Program_IsTheFirstWord(string command, string? program) =>
        Assert.Equal(program, MsBuildExpander.Program(Expander().Expand(command, File)[0].Text));

    [Fact]
    public void AnchoredPaths_FindEachAnchoredPathInACommand_QuotedOrNot()
    {
        var text = Expander().Expand("a \"$(MSBuildThisFileDirectory)x y.dll\" $(SolutionDir).mcp.json&&$(TEMP)z", File)[0].Text;

        var paths = MsBuildExpander.AnchoredPaths(text, false).Select(p => p.Display).ToList();

        Assert.Equal(["{package}/build/x y.dll", "{solution}/.mcp.json", "{temp}/z"], paths);
    }

    [Fact]
    public void Expand_ASmallBudget_IsSpent_AndLeavesTheValueUnresolved()
    {
        var expander = new MsBuildExpander("Acme.Tool", new Dictionary<string, List<(string, string)>>(), new Dictionary<string, List<(string, string)>>(), budgetChars: 4);

        var candidates = expander.Expand("$(SolutionDir).claude/skills", File);

        Assert.True(expander.BudgetSpent);
        Assert.All(candidates, c => Assert.True(c.Unresolved));
    }

    [Fact]
    public void Expand_AnExpansionOverTheCharCap_IsCut_AndUnresolved()
    {
        var expander = Expander(properties: new() { ["Big"] = [(new string('a', MsBuildExpander.MaxExpandedChars), File)] });

        var candidate = Assert.Single(expander.Expand("$(Big)$(Big)", File));

        Assert.Equal(MsBuildExpander.MaxExpandedChars, candidate.Text.Length);
        Assert.True(candidate.Unresolved);
        // The cut is counted, so the pass is incomplete (S4 review round 2, C3); once per candidate, however often it is hit.
        Assert.Equal(1, expander.Cuts);
    }

    [Fact]
    public void Expand_ALiteralOverTheCharCap_IsCut_Counted_AndUnresolved()
    {
        var expander = Expander();

        var candidate = Assert.Single(expander.Expand("echo " + new string('x', 17_000) + " > .claude/skills/a.md", File));

        Assert.Equal(MsBuildExpander.MaxExpandedChars, candidate.Text.Length);
        Assert.True(candidate.Unresolved);
        Assert.Equal(1, expander.Cuts);
    }

    [Fact]
    public void Expand_AValueUnderTheCharCap_IsNoCut()
    {
        var expander = Expander();

        var candidate = Assert.Single(expander.Expand(new string('x', MsBuildExpander.MaxExpandedChars), File));

        Assert.False(candidate.Unresolved);
        Assert.Equal(0, expander.Cuts);
    }

    /// <summary>A long list grows one candidate in place: its cost is linear, so it stays within one value's budget (S4 review round 2, W1).</summary>
    [Fact]
    public void Expand_AListOf300OutputPaths_ResolvesWithinTheValuesBudget()
    {
        var expander = Expander();
        var value = string.Join(';', Enumerable.Range(0, 300).Select(i => $"$(OutDir)p{i}"));

        var paths = Paths(expander, value);

        Assert.Equal(300, paths.Count);
        Assert.All(paths, p => Assert.False(p.OutsideOutput, p.Display));
        Assert.Equal(0, expander.Cuts);
        Assert.False(expander.BudgetSpent);
    }

    /// <summary>
    /// The reviewer's "copy2": eight 16K-char candidates followed by 15K one-char references. Each reference appends to
    /// every candidate in place; it must not copy them (S4 review round 2, W1).
    /// </summary>
    [Fact]
    public void Expand_ManyShortReferencesAfterEightFullCandidates_IsCheap()
    {
        var expander = Expander(properties: new()
        {
            ["M"] = [.. Enumerable.Range(0, 8).Select(i => (new string((char)('a' + i), MsBuildExpander.MaxExpandedChars), File))],
            ["Z"] = [("a", File)],
        });
        var value = "$(M)" + string.Concat(Enumerable.Repeat("$(Z)", 15_000));

        var before = GC.GetAllocatedBytesForCurrentThread();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var candidates = expander.Expand(value, File);
        clock.Stop();
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(2), $"expanding took {clock.Elapsed}");
        Assert.True(allocated < 64L * 1024 * 1024, $"expanding allocated {allocated / 1024 / 1024} MB");
        Assert.Equal(MsBuildExpander.MaxCandidates, candidates.Count);
        Assert.All(candidates, c => Assert.True(c.Unresolved));
    }

    // ---- forgery: U+E000 is the expander's own anchor bracket ----

    [Theory]
    [InlineData("Output")]
    [InlineData("output")]
    [InlineData("Intermediate")]
    [InlineData("Package")]
    public void Expand_PackageTextHoldingTheMark_CannotForgeAnAnchor(string anchor)
    {
        var forged = MsBuildTest.Mark + anchor + MsBuildTest.Mark + "/x";

        var candidates = Expander().Expand(forged, File);
        var path = MsBuildExpander.Normalize(candidates[0].Text, candidates[0].Unresolved);

        Assert.DoesNotContain(MsBuildTest.Mark.ToString(), candidates[0].Text);
        Assert.Equal(MsBuildAnchor.Project, path.Anchor);
        Assert.NotEqual(false, path.OutsideOutput);
    }

    [Fact]
    public void Expand_APropertyDefinitionHoldingTheMark_CannotForgeAnAnchor()
    {
        var expander = Expander(properties: new() { ["Forged"] = [(MsBuildTest.Mark + "Output" + MsBuildTest.Mark, File)] });

        var path = Single(expander, "$(Forged)/../.mcp.json");

        Assert.True(path.Anchor != MsBuildAnchor.Output, $"a package definition forged {path.Display}");
    }

    [Fact]
    public void Expand_AnItemIncludeHoldingTheMark_CannotForgeAnAnchor()
    {
        var expander = Expander(items: new() { ["Forged"] = [(MsBuildTest.Mark + "Output" + MsBuildTest.Mark + "/x", File)] });

        var path = Single(expander, "@(Forged)");

        Assert.True(path.Anchor != MsBuildAnchor.Output, $"a package item forged {path.Display}");
    }

    // ---- S4 review round 1 ----

    [Fact]
    public void Expand_AValueOverTheCharCap_IsNotExpanded_AndIsACut()
    {
        var expander = Expander();
        var value = "$(SolutionDir)" + new string('a', MsBuildExpander.MaxValueChars);

        var candidate = Assert.Single(expander.Expand(value, File));

        // Re-pinned in S4 review round 5 (C1): an over-long text is a short gap (not its raw text, which could carry the
        // anchor mark, and not "", which a list drops so a write reads as writing nowhere); literal tokens are matched on
        // the raw value elsewhere.
        Assert.Equal(MsBuildAnchor.Unknown, MsBuildExpander.Normalize(candidate.Text, candidate.Unresolved).Anchor);
        Assert.True(candidate.Unresolved);
        Assert.Equal(1, expander.Cuts);
    }

    [Fact]
    public void Expand_AValueOverTheCharCapHoldingTheMark_ReturnsNoMark_AndForgesNoAnchor()
    {
        var expander = Expander();
        var value = MsBuildTest.Mark + "Output" + MsBuildTest.Mark + new string('a', MsBuildExpander.MaxValueChars);

        var candidate = Assert.Single(expander.Expand(value, File));

        Assert.DoesNotContain(MsBuildTest.Mark.ToString(), candidate.Text);
        Assert.True(candidate.Unresolved);
        Assert.NotEqual(MsBuildAnchor.Output, MsBuildExpander.Normalize(candidate.Text, candidate.Unresolved).Anchor);
    }

    [Fact]
    public void Expand_ADefinitionOverTheCharCap_IsNotExpanded_AndLeavesTheReferenceUnresolved()
    {
        var expander = Expander(properties: new() { ["D"] = [(MsBuildTest.Mark + "Output" + MsBuildTest.Mark + new string('a', MsBuildExpander.MaxValueChars), File)] });

        var path = Single(expander, "$(D)/x");

        Assert.NotEqual(MsBuildAnchor.Output, path.Anchor);
        Assert.Null(path.OutsideOutput);
        Assert.Equal(1, expander.Cuts);
    }

    /// <summary>An over-long value is still charged (S4 review round 4, C2): a budget smaller than one call is spent by it.</summary>
    [Fact]
    public void Expand_AValueOverTheCharCap_IsChargedAgainstTheBudget()
    {
        var expander = new MsBuildExpander("Acme.Tool", WithComparer(null), WithComparer(null), budgetChars: 1);

        var candidate = Assert.Single(expander.Expand(new string('a', MsBuildExpander.MaxValueChars + 1), File));

        Assert.True(candidate.Unresolved);
        Assert.True(expander.BudgetSpent);
    }

    [Fact]
    public void Expand_AValueAtTheCharCap_IsExpanded()
    {
        var expander = Expander();
        var value = "$(SolutionDir)" + new string('a', MsBuildExpander.MaxValueChars - "$(SolutionDir)".Length);

        var path = Single(expander, value);

        // Expanded (its anchor found), but the result is over MaxExpandedChars and cut to it, and that cut is now counted
        // and leaves it unresolved (S4 review round 2, C3; supersedes the round-1 "no value cut").
        Assert.Equal(MsBuildAnchor.Solution, path.Anchor);
        Assert.True(path.Unresolved);
        Assert.True(expander.Cuts >= 1, $"{expander.Cuts} cuts");
    }

    [Theory]
    [InlineData("$(", 30_000)]
    [InlineData("$('", 20_000)]
    [InlineData("@(", 30_000)]
    [InlineData("%(", 30_000)]
    [InlineData("$([MSBuild]::NormalizePath(", 2_000)]
    public void Expand_ManyUnclosedReferencesUnderTheCap_IsLinear(string unit, int repeats)
    {
        var value = string.Concat(Enumerable.Repeat(unit, repeats));
        Assert.True(value.Length <= MsBuildExpander.MaxValueChars, $"{value.Length} chars");

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var candidates = Expander().Expand(value, File);
        clock.Stop();

        Assert.NotEmpty(candidates);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(2), $"expanding {value.Length} chars took {clock.Elapsed}");
    }

    [Fact]
    public void Expand_NineDistinctDefinitions_KeepsTheLatestEight_AndTheLastSaysItIsCut()
    {
        var nine = Enumerable.Range(0, 9).Select(i => ($"$(OutputPath)a{i}", File)).ToList();
        var expander = Expander(properties: new() { ["D"] = nine });

        var candidates = expander.Expand("$(D)", File);

        Assert.Equal(MsBuildExpander.MaxCandidates, candidates.Count);
        Assert.Equal(1, expander.Cuts);
        Assert.False(candidates[0].Unresolved);
        Assert.EndsWith("a8", candidates[0].Text, StringComparison.Ordinal);
        Assert.True(candidates[^1].Unresolved);
        Assert.Null(MsBuildExpander.Normalize(candidates[^1].Text, candidates[^1].Unresolved).OutsideOutput);
    }

    [Fact]
    public void Expand_AProductPastEightCandidates_IsACut_AndItsLastIsUnresolved()
    {
        var three = Enumerable.Range(0, 3).Select(i => ($"x{i}", File)).ToList();
        var expander = Expander(properties: new() { ["P"] = three, ["Q"] = three });

        var candidates = expander.Expand("$(P)$(Q)", File);

        Assert.Equal(MsBuildExpander.MaxCandidates, candidates.Count);
        Assert.True(expander.Cuts > 0);
        Assert.True(candidates[^1].Unresolved);
    }

    /// <summary>
    /// Reserved is MSBuild's explicit list, not every <c>MSBuild*</c>: <c>MSBuildProjectExtensionsPath</c>,
    /// <c>MSBuildExtensionsPath</c>(32/64) and <c>MSBuildSDKsPath</c> can be set (S4 review round 2, C2, measured).
    /// </summary>
    [Theory]
    [InlineData("OutputPath", true, false)]
    [InlineData("outdir", true, false)]
    [InlineData("IntermediateOutputPath", true, false)]
    [InlineData("SolutionDir", true, false)]
    [InlineData("Configuration", true, false)]
    [InlineData("TargetFramework", true, false)]
    [InlineData("HOME", true, false)]
    [InlineData("MSBuildProjectExtensionsPath", true, false)]
    [InlineData("msbuildextensionspath", true, false)]
    [InlineData("MSBuildExtensionsPath32", true, false)]
    [InlineData("MSBuildExtensionsPath64", true, false)]
    [InlineData("MSBuildSDKsPath", true, false)]
    [InlineData("MSBuildProjectDirectory", false, true)]
    [InlineData("MSBuildProjectFile", false, true)]
    [InlineData("MSBuildProjectFullPath", false, true)]
    [InlineData("MSBuildProjectName", false, true)]
    [InlineData("MSBuildProjectExtension", false, true)]
    [InlineData("MSBuildThisFile", false, true)]
    [InlineData("MSBuildThisFileDirectory", false, true)]
    [InlineData("MSBuildThisFileFullPath", false, true)]
    [InlineData("MSBuildBinPath", false, true)]
    [InlineData("msbuildtoolspath", false, true)]
    [InlineData("MSBuildToolsVersion", false, true)]
    [InlineData("MSBuildStartupDirectory", false, true)]
    [InlineData("RestoreSources", false, false)]
    [InlineData("SkillDir", false, false)]
    public void Overrides_IsEveryKnownPropertyButMSBuildsReservedOnes(string name, bool overrides, bool reserved)
    {
        Assert.Equal(overrides, MsBuildExpander.Overrides(name));
        Assert.Equal(reserved, MsBuildExpander.Reserved(name));
    }

    [Fact]
    public void Expand_APackageRedefinitionOfAnAnchor_AddsItsValueAfterTheAnchor()
    {
        var expander = Expander(properties: new() { ["OutputPath"] = [("$(MSBuildProjectDirectory)/../.claude/skills/", File)] });

        Assert.Equal(["{output}", "{project}/../.claude/skills"], Paths(expander, "$(OutputPath)").Select(p => p.Display));
    }

    [Fact]
    public void Expand_APackageRedefinitionOfAScalar_AddsItsValue()
    {
        var expander = Expander(properties: new() { ["Configuration"] = [("../../.claude", File)] });

        var paths = Paths(expander, "$(OutputPath)$(Configuration)/skills");

        Assert.Equal(["{output}/$(Configuration)/skills", "{output}/../../.claude/skills"], paths.Select(p => p.Display));
        Assert.Equal([false, true], paths.Select(p => p.OutsideOutput));
    }

    [Theory]
    [InlineData("MSBuildProjectDirectory", "$(MSBuildProjectDirectory)/x", "{project}/x")]
    [InlineData("MSBuildThisFileDirectory", "$(MSBuildThisFileDirectory)x", "{package}/build/x")]
    [InlineData("MSBuildBinPath", "$(MSBuildBinPath)x", "{msBuild}/x")]
    [InlineData("MSBuildToolsPath", "$(MSBuildToolsPath)x", "{msBuild}/x")]
    [InlineData("MSBuildStartupDirectory", "$(MSBuildStartupDirectory)x", "{project}/x")]
    public void Expand_APackageRedefinitionOfAReservedProperty_IsIgnored(string name, string value, string display)
    {
        var expander = Expander(properties: new() { [name] = [("$(SolutionDir).claude", File)] });

        Assert.Equal(display, Single(expander, value).Display);
    }

    /// <summary>These can be set, measured on MSBuild: a package's value is a candidate after the anchor (S4 review round 2, C2).</summary>
    [Theory]
    [InlineData("MSBuildProjectExtensionsPath", "{intermediate}/x")]
    [InlineData("MSBuildExtensionsPath", "{msBuild}/x")]
    [InlineData("MSBuildExtensionsPath32", "{msBuild}/x")]
    [InlineData("MSBuildExtensionsPath64", "{msBuild}/x")]
    [InlineData("MSBuildSDKsPath", "{msBuild}/x")]
    public void Expand_APackageRedefinitionOfASettableMSBuildProperty_AddsItsValueAfterTheAnchor(string name, string anchored)
    {
        var expander = Expander(properties: new() { [name] = [("$(SolutionDir).claude/", File)] });

        var paths = Paths(expander, "$(" + name + ")x");

        Assert.Equal([anchored, "{solution}/.claude/x"], paths.Select(p => p.Display));
        Assert.All(paths, p => Assert.False(p.Unresolved, p.Display));
        Assert.True(paths[1].OutsideOutput);
    }

    [Fact]
    public void Normalize_AClimbOverAnUnresolvedSegment_IsUnresolved()
    {
        var output = MsBuildTest.Mark + "Output" + MsBuildTest.Mark;

        var path = MsBuildExpander.Normalize(output + "/$(Y)/../../.claude", unresolved: false);

        Assert.True(path.Unresolved);
        Assert.Null(path.OutsideOutput);
    }

    /// <summary>
    /// MSBuild gives <c>%(Filename)</c> = <c>..</c> for <c>Include="..."</c>, and an escaped <c>%2F</c> survives in it: even
    /// a source's own file name is a gap (S4 review round 2, C1, measured on MSBuild; supersedes the round-1 "is a name").
    /// </summary>
    [Theory]
    [InlineData("Solution", "/.claude/skills/%(Filename)%(Extension)")]
    [InlineData("Solution", "/.claude/skills/%(Skill.Filename)%(Skill.Extension)")]
    [InlineData("Solution", "/.claude/skills/%(filename).bak")]
    [InlineData("Output", "/%(Filename)")]
    [InlineData("Output", "/%(S.Filename)%(S.Extension)")]
    public void Normalize_ASourcesOwnFileNameMetadata_IsAGap(string anchor, string rest)
    {
        var path = MsBuildExpander.Normalize(MsBuildTest.Mark + anchor + MsBuildTest.Mark + rest, unresolved: false);

        Assert.True(path.Unresolved, path.Display);
        Assert.Null(path.OutsideOutput);
    }

    [Theory]
    [InlineData("/%(Rel)")]
    [InlineData("/%(S.RecursiveDir)x")]
    [InlineData("/%(Identity)")]
    public void Normalize_OtherMetadata_IsAGap(string rest)
    {
        var path = MsBuildExpander.Normalize(MsBuildTest.Mark + "Output" + MsBuildTest.Mark + rest, unresolved: false);

        Assert.True(path.Unresolved, path.Display);
        Assert.Null(path.OutsideOutput);
    }

    // ---- S4 review round 3 ----

    /// <summary>A name a task sets to a value Silvergun cannot see may be anything: its built-in reading is never the only one (C1).</summary>
    [Theory]
    [InlineData("OutDir")]
    [InlineData("outdir")]
    public void Expand_ADroppedKnownProperty_WithNoDefinition_IsAlsoUnresolved(string dropped)
    {
        var expander = DroppedExpander([dropped]);

        var paths = Paths(expander, "$(OutDir)skills");

        Assert.Contains(paths, p => p.Display == "{output}/skills" && !p.Unresolved);
        Assert.Contains(paths, p => p.Unresolved && p.OutsideOutput is null);
    }

    [Fact]
    public void Expand_ADroppedReservedProperty_StaysAPureAnchor()
    {
        var expander = DroppedExpander(["MSBuildProjectDirectory"]);

        var path = Single(expander, "$(MSBuildProjectDirectory)/x");

        Assert.Equal("{project}/x", path.Display);
        Assert.False(path.Unresolved);
    }

    [Fact]
    public void Expand_ADroppedUnknownProperty_WithNoDefinition_IsUnresolved()
    {
        var path = Single(DroppedExpander(["SkillDir"]), "$(SkillDir)x");

        Assert.True(path.Unresolved);
        Assert.Null(path.OutsideOutput);
    }

    /// <summary>
    /// Two values of 16,000 references each spend at most their own budget: once spent, a value charges the package
    /// nothing more, so a later small value still resolves (W1). Each big value is one cut.
    /// </summary>
    [Theory]
    // Z undefined: each $(Z) is unexpanded text, so the value's cut comes from the 16K MaxExpandedChars cap on its
    // candidate, not from its value budget (S4 review round 4, S3). Kept: it still checks one cut per value.
    [InlineData(false, MsBuildExpander.DefaultBudgetChars)]
    [InlineData(true, MsBuildExpander.DefaultBudgetChars)]
    // Three times one value's budget: room for two spent values only if a spent value stops charging the package.
    [InlineData(true, 3 * MsBuildExpander.MaxValueBudgetChars)]
    public void Expand_TwoValuesThatSpendTheirOwnBudget_LeaveALaterSmallValueResolved(bool zDefined, long budgetChars)
    {
        var properties = new Dictionary<string, List<(string Value, string File)>>(StringComparer.OrdinalIgnoreCase) { ["D"] = [("$(SolutionDir).claude/", File)] };
        if (zDefined)
            properties["Z"] = [("a", File)];
        var expander = new MsBuildExpander("Acme.Tool", properties, WithComparer(null), budgetChars);
        var big = string.Concat(Enumerable.Repeat("$(Z)", 16_000));

        Assert.All(expander.Expand(big, File), c => Assert.True(c.Unresolved));
        Assert.Equal(1, expander.Cuts);
        Assert.All(expander.Expand(big, File), c => Assert.True(c.Unresolved));
        Assert.Equal(2, expander.Cuts);
        var path = Single(expander, "$(D)skills");

        Assert.Equal("{solution}/.claude/skills", path.Display);
        Assert.False(path.Unresolved);
        Assert.False(expander.BudgetSpent);
        Assert.Equal(2, expander.Cuts);
    }

    // ---- S4 review round 4: a package that may set any property (C1) ----

    /// <summary>With the flag, every settable property may be anything: its known reading is never the only one.</summary>
    [Theory]
    [InlineData("$(OutDir)skills", "{output}/skills")]
    [InlineData("$(outputpath)skills", "{output}/skills")]
    [InlineData("$(IntermediateOutputPath)skills", "{intermediate}/skills")]
    [InlineData("$(MSBuildExtensionsPath)skills", "{msBuild}/skills")]
    public void Expand_WithAnyPropertySet_AKnownProperty_AlsoGetsAnUnresolvedCandidate(string value, string known)
    {
        var paths = Paths(AnyPropertyExpander(), value);

        Assert.Contains(paths, p => p.Display == known && !p.Unresolved);
        Assert.Contains(paths, p => p.Unresolved && p.OutsideOutput is null);
    }

    [Fact]
    public void Expand_WithAnyPropertySet_APackageDefinition_KeepsItsValue_AndAddsAnUnresolvedCandidate()
    {
        var expander = new MsBuildExpander("Acme.Tool", WithComparer(new() { ["D"] = [("$(SolutionDir).claude/", File)] }), WithComparer(null), anyProperty: true);

        var paths = Paths(expander, "$(D)skills");

        Assert.Contains(paths, p => p.Display == "{solution}/.claude/skills" && !p.Unresolved);
        Assert.Contains(paths, p => p.Unresolved && p.OutsideOutput is null);
    }

    [Fact]
    public void Expand_WithoutAnyPropertySet_AKnownProperty_IsItsAnchorOnly()
    {
        var path = Single(Expander(), "$(OutDir)skills");

        Assert.Equal("{output}/skills", path.Display);
        Assert.False(path.OutsideOutput);
    }

    [Theory]
    [InlineData("$(MSBuildProjectDirectory)/x", "{project}/x")]
    [InlineData("$(MSBuildThisFileDirectory)x", "{package}/build/x")]
    [InlineData("$(MSBuildBinPath)x", "{msBuild}/x")]
    [InlineData("$(MSBuildStartupDirectory)x", "{project}/x")]
    public void Expand_WithAnyPropertySet_AReservedProperty_StaysAPureAnchor(string value, string display)
    {
        var path = Single(AnyPropertyExpander(), value);

        Assert.Equal(display, path.Display);
        Assert.False(path.Unresolved);
    }

    [Fact]
    public void Expand_WithAnyPropertySet_AnUndefinedProperty_IsUnresolved()
    {
        var path = Single(AnyPropertyExpander(), "$(SkillDir)x");

        Assert.True(path.Unresolved);
        Assert.Null(path.OutsideOutput);
    }

    // ---- S4 review round 5: a value given up on is a gap (C1), and a package's own Pkg<Id> (W) ----

    /// <summary>
    /// "emptyhog" (C1): 4,500 references to an empty property spend the value's budget, so a later reference is never
    /// appended. Every candidate is unresolved, and none reads as a path inside the output.
    /// </summary>
    [Fact]
    public void Expand_AReferenceAfterTheValuesBudgetIsSpent_LeavesEveryCandidateUnresolved()
    {
        var expander = Expander(properties: new()
        {
            ["E"] = [("", File)],
            ["Hog"] = [(string.Concat(Enumerable.Repeat("$(E)", 4_500)), File)],
            ["D"] = [("$(MSBuildProjectDirectory)/../x/", File)],
        });

        var candidates = expander.Expand("$(Hog)$(D)", File);

        Assert.NotEmpty(candidates);
        Assert.All(candidates, c => Assert.True(c.Unresolved, c.Text));
        Assert.DoesNotContain(candidates.SelectMany(c => MsBuildExpander.Paths(c.Text, c.Unresolved)), p => p.OutsideOutput == false);
        Assert.True(expander.Cuts >= 1, $"{expander.Cuts} cuts");
    }

    [Fact]
    public void Expand_AReferenceAfterAFewEmptyReferences_Resolves()
    {
        var expander = Expander(properties: new()
        {
            ["E"] = [("", File)],
            ["Hog"] = [(string.Concat(Enumerable.Repeat("$(E)", 100)), File)],
            ["D"] = [("$(MSBuildProjectDirectory)/../x/", File)],
        });

        var path = Single(expander, "$(Hog)$(D)");

        Assert.Equal("{project}/../x", path.Display);
        Assert.False(path.Unresolved);
        Assert.True(path.OutsideOutput);
        Assert.Equal(0, expander.Cuts);
    }

    /// <summary>A value over the cap that would list paths (padded with ';') is one gap, never an empty list (C1).</summary>
    [Fact]
    public void Expand_AListOverTheCharCap_IsOneUnknownPath()
    {
        var expander = Expander();

        var path = Single(expander, "$(MSBuildProjectDirectory)/../evil" + new string(';', 70_000));

        Assert.Equal(MsBuildAnchor.Unknown, path.Anchor);
        Assert.True(path.Unresolved);
        Assert.Null(path.OutsideOutput);
    }

    [Fact]
    public void Expand_APackageDefinitionOfItsPkgProperty_AddsItsValueAfterThePackageRoot()
    {
        var expander = Expander(properties: new() { ["PkgAcme_Tool"] = [("$(MSBuildProjectDirectory)/../.claude", File)] });

        var paths = Paths(expander, "$(PkgAcme_Tool)/skills");

        Assert.Equal(["{package}/skills", "{project}/../.claude/skills"], paths.Select(p => p.Display));
        Assert.All(paths, p => Assert.False(p.Unresolved, p.Display));
    }

    [Fact]
    public void Expand_WithoutAPackageDefinition_ThePkgPropertyIsThePackageRoot()
    {
        var path = Single(Expander(), "$(PkgAcme_Tool)/skills");

        Assert.Equal("{package}/skills", path.Display);
        Assert.False(path.Unresolved);
        Assert.Equal("PkgAcme_Tool", Expander().PkgProperty);
    }

    [Fact]
    public void Expand_NeverThrows_OnUnbalancedOrOddSyntax()
    {
        foreach (var value in new[] { "$(", "$(a", "@(", "%(", "$()", "$([MSBuild]::NormalizePath(", "$([X]::Y('a', 'b'))", "$(a.b)", "$(''')", "@(x->')", "$([MSBuild]::NormalizePath(,,))" })
        {
            var candidates = Expander().Expand(value, File);
            Assert.NotEmpty(candidates);
            _ = MsBuildExpander.Paths(candidates[0].Text, candidates[0].Unresolved);
            _ = MsBuildExpander.Program(candidates[0].Text);
        }
    }
    #endregion

    #region Methods: helpers
    private static MsBuildExpander Expander(Dictionary<string, List<(string Value, string File)>>? properties = null, Dictionary<string, List<(string Value, string File)>>? items = null) =>
        new("Acme.Tool", WithComparer(properties), WithComparer(items));

    private static MsBuildExpander DroppedExpander(string[] dropped) =>
        new("Acme.Tool", WithComparer(null), WithComparer(null), dropped: new HashSet<string>(dropped, StringComparer.OrdinalIgnoreCase));

    private static MsBuildExpander AnyPropertyExpander() => new("Acme.Tool", WithComparer(null), WithComparer(null), anyProperty: true);

    private static Dictionary<string, List<(string Value, string File)>> WithComparer(Dictionary<string, List<(string Value, string File)>>? map) =>
        new(map ?? new(), StringComparer.OrdinalIgnoreCase);

    private static List<MsBuildPath> Paths(MsBuildExpander expander, string value) =>
        [.. expander.Expand(value, File).SelectMany(c => MsBuildExpander.Paths(c.Text, c.Unresolved))];

    private static MsBuildPath Single(MsBuildExpander expander, string value) => Assert.Single(Paths(expander, value));
    #endregion

    #region Fields
    private const string File = "build/Acme.Tool.targets";
    #endregion
}
