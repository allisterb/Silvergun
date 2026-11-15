namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

using Xunit;

/// <summary>
/// <c>scan-package --reachability --ssa</c> through the real CLI, in child processes (<c>docs/agent/tasks/ssa-facts-s5.md</c>
/// S5.3; acceptance criteria 1, 2, 3, 5 and 6). The child is the CLI apphost, so its graph worker is itself and runs the
/// real SSA phase.
/// <para>
/// One package, built once per class (<see cref="Packages"/>): <c>lib/net10.0/SilvergunSsaFixture.dll</c>, emitted with
/// <see cref="PersistedAssemblyBuilder"/>, whose <c>Own.Calls</c> holds a constant <c>Process.Start("cmd.exe")</c>, a
/// <c>Type.GetType("Own.Target").GetMethod("Run").Invoke(null, null)</c> chain onto its own <c>Own.Target.Run</c>, and a
/// <c>Process.Start</c> of a hostile constant (a quote, an RLO, a lone surrogate, ESC and BEL, a line feed, markup, a Tag
/// character, a zero-width space, a BOM, then 10 KB); and <c>lib/netstandard2.0/notmanaged.dll</c>, ten bytes that are
/// not a PE, so one folder is neither graph- nor SSA-analysed. Every run is <c>--no-vulns --no-yara</c>, offline, and cached
/// by its key. The validator runs (<c>--ssa</c> without <c>--reachability</c>) need no package.
/// </para>
/// </summary>
public sealed class SsaScanPackageCliTests : IClassFixture<SsaScanPackageCliTests.Packages>
{
    #region Constructors
    public SsaScanPackageCliTests(Packages packages) => this.packages = packages;
    #endregion

    #region Methods: the switch (D1)
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ScanPackage_SsaWithoutReachability_IsAParseError(bool json)
    {
        var (exit, stdout, error) = RunCli(["scan-package", "does-not-exist.nupkg", "--ssa", .. json ? new[] { "--json" } : []]);

        Assert.NotEqual(0, exit);
        Assert.Contains("--ssa needs --reachability: SSA facts are derived at the call sites the reachability pass finds.", error, StringComparison.Ordinal);
        Assert.DoesNotContain("Assessment", stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Reachability\"", stdout, StringComparison.Ordinal);
    }

    // With --reachability the validator passes; what fails then is the missing package, not the switch.
    [Fact]
    public void ScanPackage_SsaWithReachability_PassesTheValidator()
    {
        var (_, _, error) = RunCli(["scan-package", "does-not-exist.nupkg", "--reachability", "--ssa"]);

        Assert.DoesNotContain("--ssa needs --reachability", error, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: without --ssa (criterion 1)
    [Fact]
    public void ScanPackage_WithoutSsa_HasNoSsaKeyNoSectionAndNoNote()
    {
        var json = packages.Run("reach-json", "--json", "--reachability");
        var human = packages.Run("reach-human", "--reachability");

        Assert.All(FolderNodes(json), f => Assert.False(f.ContainsKey("Ssa"), f.ToJsonString()));
        Assert.DoesNotContain("\"Ssa\"", json.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("Argument values", human.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("SSA", human.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("SSA", human.Error, StringComparison.Ordinal);
        Assert.DoesNotContain("SSA", json.Error, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: --ssa is additive (criteria 2 and 6)
    // The JSON with --ssa is the JSON without it once each folder's Ssa object (and AnalyzedAt) is removed.
    [Fact]
    public void ScanPackage_Ssa_JsonOutsideTheSsaObjects_IsReachabilityAlones()
    {
        var without = JsonNode.Parse(packages.Run("reach-json", "--json", "--reachability").Output)!.AsObject();
        var with = JsonNode.Parse(packages.Run("ssa-json", "--json", "--reachability", "--ssa").Output)!.AsObject();

        var folders = with["Reachability"]!["Folders"]!.AsArray();
        Assert.Equal(2, folders.Count);
        Assert.All(folders, f => Assert.True(f!.AsObject().Remove("Ssa"), $"a folder has no Ssa object: {f.ToJsonString()}"));
        without.Remove("AnalyzedAt");
        with.Remove("AnalyzedAt");
        Assert.Equal(Normalize(without.ToJsonString()), Normalize(with.ToJsonString()));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(Normalize(without.ToJsonString())), JsonNode.Parse(Normalize(with.ToJsonString()))));
    }

    [Fact]
    public void ScanPackage_Ssa_ExitCodeFooterAndSnapshotUnchanged()
    {
        var without = packages.Run("reach-human", "--reachability");
        var with = packages.Run("ssa-human", "--reachability", "--ssa");
        var jsonWithout = packages.Run("reach-json", "--json", "--reachability");
        var jsonWith = packages.Run("ssa-json", "--json", "--reachability", "--ssa");

        Assert.Equal(without.Exit, with.Exit);
        Assert.Equal(jsonWithout.Exit, jsonWith.Exit);
        Assert.Equal(Footer(without.Output), Footer(with.Output));
        Assert.Equal(FooterHeadline.Of(without.Output), FooterHeadline.Of(with.Output));
        Assert.Equal(Normalize(File.ReadAllText(without.Snapshot!)), Normalize(File.ReadAllText(with.Snapshot!)));
    }

    [Fact]
    public void ScanPackage_Ssa_StrictExitCodeUnchanged()
    {
        var without = packages.Run("reach-strict", "--strict", "--reachability");
        var with = packages.Run("ssa-strict", "--strict", "--reachability", "--ssa");

        Assert.Equal(without.Exit, with.Exit);
    }

    // The human report with --ssa is the report without it plus the section (its title to the Assemblies section).
    [Fact]
    public void ScanPackage_Ssa_HumanReportUnchangedButTheSection()
    {
        var without = ReportLines(packages.Run("reach-human", "--reachability").Output);
        var with = ReportLines(packages.Run("ssa-human", "--reachability", "--ssa").Output);

        var start = with.FindIndex(l => l.Contains("Argument values (SSA-derived", StringComparison.Ordinal));
        var end = start < 0 ? -1 : with.FindIndex(start, l => l.Contains("Assemblies", StringComparison.Ordinal));
        Assert.True(start >= 0 && end > start, $"no section found (start {start}, end {end}):\n{string.Join("\n", with)}");
        Assert.Equal(without, with.Take(start).Concat(with.Skip(end)).ToList());
        Assert.Contains(with.Take(start), l => l.Contains("Reachability (informational", StringComparison.Ordinal));   // it follows reachability's
    }

    // stderr gains exactly one line, the SSA note, after reachability's, which is unchanged (D4).
    [Fact]
    public void ScanPackage_Ssa_StderrGainsOnlyTheSsaNote_AfterReachabilitys()
    {
        var without = StderrLines(packages.Run("reach-human", "--reachability").Error);
        var with = StderrLines(packages.Run("ssa-human", "--reachability", "--ssa").Error);

        var note = Assert.Single(with, l => l.StartsWith(SsaNotePrefix, StringComparison.Ordinal));
        Assert.Equal(without, with.Where(l => l != note).ToList());
        var reach = with.FindIndex(l => l.StartsWith(ReachNotePrefix, StringComparison.Ordinal));
        Assert.True(reach >= 0 && with.IndexOf(note) > reach, string.Join("\n", with));
        // The non-PE folder has no SSA, and it is the only incomplete one.
        Assert.Equal($"{SsaNotePrefix}1 folder(s) SSA did not fully analyse); see the report.", note);
    }
    #endregion

    #region Methods: what --ssa shows
    [Fact]
    public void ScanPackage_Ssa_Json_CarriesTheResolvedSites()
    {
        var run = packages.Run("ssa-json", "--json", "--reachability", "--ssa");

        var lib = Ssa(run, "lib/net10.0");
        Assert.Equal("Analyzed", lib["Outcome"]!.GetValue<string>());
        Assert.True(lib["Counts"]!["Analyzed"]!.GetValue<int>() >= 3, lib.ToJsonString());
        var calls = Sites(lib).Select(s => s["Call"]!.GetValue<string>()).ToArray();
        Assert.Contains("System.Diagnostics.Process.Start(\"cmd.exe\")", calls);
        var invoke = Assert.Single(Sites(lib), s => s["Call"]!.GetValue<string>().StartsWith("System.Reflection.MethodBase.Invoke(", StringComparison.Ordinal));
        Assert.Equal("ReflectionInvocation", invoke["Capability"]!.GetValue<string>());
        var target = invoke["Target"]!;
        Assert.Equal("Method", target["Kind"]!.GetValue<string>());
        Assert.Equal("Method \"Own.Target\" :: \"Run\"", target["Text"]!.GetValue<string>());
        Assert.True(target["CandidatesTotal"]!.GetValue<int>() >= 1, target.ToJsonString());
        Assert.Contains(target["Candidates"]!.AsArray(), c => c!.GetValue<string>().Contains("Own.Target", StringComparison.Ordinal) && c.GetValue<string>().Contains("Run", StringComparison.Ordinal));
        // The resolved reflection target sorts first.
        Assert.NotNull(Sites(lib).First()["Target"]);

        var bad = Ssa(run, "lib/netstandard2.0");
        Assert.Equal("NotRun", bad["Outcome"]!.GetValue<string>());
        Assert.False(string.IsNullOrEmpty(bad["Reason"]!.GetValue<string>()));
        Assert.Empty(Sites(bad));
    }

    // The hostile constant is listed with every character escaped, its 10 KB cut with the hash suffix outside the quotes.
    [Fact]
    public void ScanPackage_Ssa_HostileConstant_IsEscapedAndCut()
    {
        var run = packages.Run("ssa-json", "--json", "--reachability", "--ssa");

        var call = Assert.Single(Sites(Ssa(run, "lib/net10.0")).Select(s => s["Call"]!.GetValue<string>()), c => c.Contains("evil", StringComparison.Ordinal));
        Assert.Equal(ExpectedHostileCall(), call);
        foreach (var token in EscapedTokens)
            Assert.Contains(token, call, StringComparison.Ordinal);
        Assert.Matches("\"" + Regex.Escape(((char)0x2026).ToString()) + @"\[\+\d+ chars, sha256:[0-9a-f]{8}\]\)$", call);
        Assert.True(Clean(call), Visible(call));
    }

    [Fact]
    public void ScanPackage_Ssa_ShowsTheSection_WithTheResolvedValues()
    {
        var run = packages.Run("ssa-human", "--reachability", "--ssa");
        var json = packages.Run("ssa-json", "--json", "--reachability", "--ssa");
        var lines = ReportLines(run.Output);

        Assert.Contains(lines, l => l.Contains("Argument values (SSA-derived, informational; constants at sinks are common in benign packages)", StringComparison.Ordinal));
        Assert.Contains(lines, l => Regex.IsMatch(l, @"^\d+ site\(s\) with resolved values in 1 folder\(s\); 1 folder\(s\) SSA-incomplete$"));
        var cmd = Assert.Single(Sites(Ssa(json, "lib/net10.0")), s => s["Call"]!.GetValue<string>() == "System.Diagnostics.Process.Start(\"cmd.exe\")");
        Assert.Contains($"  ProcessExecution  System.Diagnostics.Process.Start(\"cmd.exe\")  in {cmd["Caller"]!.GetValue<string>()}", lines);
        Assert.Contains(lines, l => l.StartsWith("      acts on Method \"Own.Target\" :: \"Run\" (", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.StartsWith("  SSA incomplete: not analysed: NotRun: ", StringComparison.Ordinal));
        // The hostile line wraps at the report's width, so its escapes are looked for in the unwrapped text.
        var flat = Flat(run.Output);
        foreach (var token in EscapedTokens)
            Assert.Contains(token, flat, StringComparison.Ordinal);
    }

    // No raw hostile character reaches stdout or stderr, human or JSON (criterion 3).
    [Theory]
    [InlineData("ssa-human", "--reachability", "--ssa")]
    [InlineData("ssa-json", "--json", "--reachability", "--ssa")]
    [InlineData("ssa-human-rich", "--rich", "--reachability", "--ssa")]
    public void ScanPackage_Ssa_NoRawHostileCharacterReachesTheTerminal(string key, params string[] flags)
    {
        var run = packages.Run(key, flags);

        Assert.True(Clean(run.Output.Replace("\r", string.Empty).Replace("\n", string.Empty), allowEsc: flags.Contains("--rich")), Visible(run.Output));
        Assert.True(Clean(run.Error.Replace("\r", string.Empty).Replace("\n", string.Empty)), Visible(run.Error));
        // A lone surrogate was never written for the encoder to replace. (A redirected --rich run writes its glyphs in the
        // console's code page, not UTF-8, so its U+FFFDs are the decoder's: checked on the ASCII and JSON runs only.)
        var replaced = flags.Contains("--rich") ? -1 : run.Output.IndexOf((char)0xFFFD);
        Assert.True(replaced < 0, $"U+FFFD at {replaced}: {Visible(run.Output[Math.Max(0, replaced - 300)..Math.Min(run.Output.Length, replaced + 100)])}");
        Assert.Contains("evil", run.Output, StringComparison.Ordinal);   // the premise: the hostile site is shown
    }

    // Markup inside a constant is shown literally.
    [Fact]
    public void ScanPackage_Ssa_MarkupInAConstant_RendersLiterally()
    {
        Assert.Contains("z[red]x[/]", Flat(packages.Run("ssa-human", "--reachability", "--ssa").Output), StringComparison.Ordinal);
        Assert.Contains("z[red]x[/]", Flat(packages.Run("ssa-human-rich", "--rich", "--reachability", "--ssa").Output), StringComparison.Ordinal);
    }

    [Fact]
    public void ScanPackage_Ssa_TwoRuns_GiveTheSameSsaJson()
    {
        var first = packages.Run("ssa-json", "--json", "--reachability", "--ssa");
        var second = packages.Run("ssa-json-again", "--json", "--reachability", "--ssa");

        Assert.Equal(
            Normalize(JsonNode.Parse(first.Output)!["Reachability"]!.ToJsonString()),
            Normalize(JsonNode.Parse(second.Output)!["Reachability"]!.ToJsonString()));
    }
    #endregion

    #region Methods: helpers
    private static List<JsonObject> FolderNodes(CliRun run) =>
        [.. JsonNode.Parse(run.Output)!["Reachability"]!["Folders"]!.AsArray().Select(f => f!.AsObject())];

    private static JsonObject Ssa(CliRun run, string folder) =>
        Assert.Single(FolderNodes(run), f => f["Folder"]!.GetValue<string>() == folder)["Ssa"]!.AsObject();

    private static List<JsonNode> Sites(JsonObject ssa) => [.. ssa["Sites"]!.AsArray().Select(s => s!)];

    // What the worker keeps of the hostile constant (UntrustedText.EscapeBounded at the default 256 chars), shown as §3
    // says: quotes escaped, the suffix outside the closing quote.
    private static string ExpectedHostileCall()
    {
        var kept = Silvergun.UntrustedText.EscapeBounded(Packages.Hostile, 256, out _, out var cut);
        Assert.True(cut, "the premise: the hostile constant is cut");
        var at = kept.LastIndexOf((char)0x2026 + "[+", StringComparison.Ordinal);
        return "System.Diagnostics.Process.Start(\"" + kept[..at].Replace("\"", Bs + "\"", StringComparison.Ordinal) + "\"" + kept[at..] + ")";
    }

    // The Assessment section to the end, normalized.
    private static List<string> Footer(string output)
    {
        var lines = ReportLines(output);
        var at = lines.FindLastIndex(l => l.Contains("Assessment", StringComparison.Ordinal));
        Assert.True(at >= 0, $"no Assessment section:\n{output}");
        return [.. lines.Skip(at)];
    }

    private static List<string> ReportLines(string output) =>
        [.. Normalize(output).Split('\n').Select(l => l.TrimEnd('\r', ' ')).Where(l => !LogLine.IsMatch(l))];

    private static List<string> StderrLines(string error) =>
        [.. error.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0 && !LogLine.IsMatch(l)).Select(Normalize)];

    private static string Flat(string output) => output.Replace("\r", string.Empty).Replace("\n", string.Empty);

    private static string Normalize(string text) => Iso8601.Replace(ExtractionDir.Replace(text, "pkg-MASKED"), "TIMESTAMP");

    // No control (but ESC when the run may style its output), bidi, zero-width, BOM, Tag-block character or lone surrogate.
    private static bool Clean(string text, bool allowEsc = false)
    {
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                if (char.ConvertToUtf32(c, text[++i]) is >= 0xE0000 and <= 0xE007F)
                    return false;
                continue;
            }
            if (allowEsc && c == (char)0x1B)
                continue;
            if (char.IsSurrogate(c) || c < 0x20 || c is >= (char)0x7F and <= (char)0x9F || c == 0xAD
                || c is >= (char)0x200B and <= (char)0x200F || c is >= (char)0x2028 and <= (char)0x202E
                || c is >= (char)0x2060 and <= (char)0x2064 || c is >= (char)0x2066 and <= (char)0x2069 || c == 0xFEFF)
                return false;
        }
        return true;
    }

    private static string Visible(string text)
    {
        var sb = new StringBuilder();
        foreach (var c in text.Length > 4_000 ? text[..4_000] : text)
            sb.Append(c is >= ' ' and < (char)0x7F or '\n' ? c.ToString() : $"<U+{(int)c:X4}>");
        return sb.ToString();
    }

    private static (int Exit, string Stdout, string Error) RunCli(string[] args)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");

        using var process = Process.Start(psi)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(60_000))
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            Assert.Fail($"the CLI did not exit within 60 s: {string.Join(" ", args)}");
        }
        process.WaitForExit();
        return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
    }
    #endregion

    #region Nested types
    /// <summary>A CLI run: exit code, stdout, stderr, and the --snapshot file it wrote (human runs only).</summary>
    public sealed record CliRun(int Exit, string Output, string Error, string? Snapshot);

    /// <summary>The package, and every CLI run over it, cached by key. Deletes its files on dispose.</summary>
    public sealed class Packages : IDisposable
    {
        #region Constructors
        public Packages() =>
            Package = BuildNupkg("SilvergunSsaPkg", ("lib/net10.0/SilvergunSsaFixture.dll", EmitFixture()), ("lib/netstandard2.0/notmanaged.dll", NotManagedBytes));
        #endregion

        #region Properties
        public string Package { get; }

        /// <summary>
        /// The hostile constant: a quote, RLO, a lone high surrogate, ESC and BEL, a line feed, markup, a Tag character, a
        /// zero-width space and a BOM, then 10 KB, so it is cut.
        /// </summary>
        public static string Hostile { get; } =
            "evil\"q" + (char)0x202E + "x" + (char)0xD800 + "y" + (char)0x1B + "[31m" + (char)0x07 + (char)0x0A
            + "z[red]x[/]" + char.ConvertFromUtf32(0xE0041) + (char)0x200B + (char)0xFEFF + new string('A', 10_240);
        #endregion

        #region Methods
        /// <summary>
        /// The run of <c>scan-package {package} --no-vulns --no-yara {flags}</c> under <paramref name="key"/>. A run
        /// without --json also writes a --snapshot file.
        /// </summary>
        public CliRun Run(string key, params string[] flags)
        {
            var run = runs.GetOrAdd(key, _ => new Lazy<CliRun>(() => Start(flags))).Value;
            Assert.True(run.Exit >= 0, $"{key}: the CLI did not exit within {TimeoutMs} ms and was killed");
            Assert.True(run.Exit is 0 or 2 or 3, $"{key}: unexpected exit {run.Exit}\nstderr:\n{run.Error}\nstdout:\n{run.Output}");
            return run;
        }

        public void Dispose()
        {
            foreach (var file in new[] { Package }.Concat(snapshots))
                try { if (File.Exists(file)) File.Delete(file); } catch { /* best-effort temp cleanup */ }
        }

        private CliRun Start(string[] flags)
        {
            var snapshot = flags.Contains("--json") ? null : Path.Combine(Path.GetTempPath(), $"silvergun-ssa-{Guid.NewGuid():N}.json");
            if (snapshot is not null)
                snapshots.Add(snapshot);
            var psi = new ProcessStartInfo(CliExe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                UseShellExecute = false,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            foreach (var arg in new[] { "scan-package", Package, "--no-vulns", "--no-yara" }.Concat(flags)
                         .Concat(snapshot is null ? [] : new[] { "--snapshot", snapshot }))
                psi.ArgumentList.Add(arg);
            psi.Environment["NO_COLOR"] = "1";
            psi.Environment.Remove("DOTNET_STARTUP_HOOKS");

            using var process = Process.Start(psi)!;
            process.StandardInput.Close();
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(TimeoutMs))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                return new CliRun(-1, string.Empty, string.Empty, null);
            }
            process.WaitForExit();
            return new CliRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), snapshot);
        }

        // Own.Target (a constructor and a static Run) and Own.Calls (StartCmd, Reflect, Hostile). Shallow types only.
        private static byte[] EmitFixture()
        {
            var builder = new PersistedAssemblyBuilder(new AssemblyName("SilvergunSsaFixture"), typeof(object).Assembly);
            var module = builder.DefineDynamicModule("SilvergunSsaFixture");

            var target = module.DefineType("Own.Target", TypeAttributes.Public | TypeAttributes.Class);
            target.DefineDefaultConstructor(MethodAttributes.Public);
            Body(target.DefineMethod("Run", MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes), _ => { });
            target.CreateType();

            var calls = module.DefineType("Own.Calls", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
            // Process.Start("cmd.exe").
            Body(Static(calls, "StartCmd"), il =>
            {
                il.Emit(OpCodes.Ldstr, "cmd.exe");
                il.Emit(OpCodes.Call, typeof(Process).GetMethod(nameof(Process.Start), [typeof(string)])!);
                il.Emit(OpCodes.Pop);
            });
            // Type.GetType("Own.Target").GetMethod("Run").Invoke(null, null).
            Body(Static(calls, "Reflect"), il =>
            {
                il.Emit(OpCodes.Ldstr, "Own.Target");
                il.Emit(OpCodes.Call, typeof(Type).GetMethod(nameof(Type.GetType), [typeof(string)])!);
                il.Emit(OpCodes.Ldstr, "Run");
                il.Emit(OpCodes.Callvirt, typeof(Type).GetMethod(nameof(Type.GetMethod), [typeof(string)])!);
                il.Emit(OpCodes.Ldnull);
                il.Emit(OpCodes.Ldnull);
                il.Emit(OpCodes.Callvirt, typeof(MethodBase).GetMethod(nameof(MethodBase.Invoke), [typeof(object), typeof(object[])])!);
                il.Emit(OpCodes.Pop);
            });
            // Process.Start(<hostile>).
            Body(Static(calls, "Hostile"), il =>
            {
                il.Emit(OpCodes.Ldstr, Hostile);
                il.Emit(OpCodes.Call, typeof(Process).GetMethod(nameof(Process.Start), [typeof(string)])!);
                il.Emit(OpCodes.Pop);
            });
            calls.CreateType();

            using var stream = new MemoryStream();
            builder.Save(stream);
            return stream.ToArray();

            static MethodBuilder Static(TypeBuilder type, string name) =>
                type.DefineMethod(name, MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes);

            static void Body(MethodBuilder method, Action<ILGenerator> emit)
            {
                var il = method.GetILGenerator();
                emit(il);
                il.Emit(OpCodes.Ret);
            }
        }

        // A minimal valid .nupkg: the nuspec plus the given entries. Pure BCL zip.
        private static string BuildNupkg(string id, params (string Entry, byte[] Bytes)[] entries)
        {
            var nuspec = $"""
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="{NuspecNamespace}">
                  <metadata>
                    <id>{id}</id>
                    <version>1.0.0</version>
                    <authors>Silvergun Tests</authors>
                    <description>Argument-value facts test package (S5).</description>
                  </metadata>
                </package>
                """;

            var path = Path.Combine(Path.GetTempPath(), $"silvergun-ssa-{Guid.NewGuid():N}.nupkg");
            using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
            using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
            {
                Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
                foreach (var (entry, bytes) in entries)
                    Write(zip, entry, bytes);
            }
            return path;

            static void Write(ZipArchive zip, string name, byte[] bytes)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(bytes, 0, bytes.Length);
            }
        }
        #endregion

        #region Fields
        private readonly ConcurrentDictionary<string, Lazy<CliRun>> runs = new(StringComparer.Ordinal);

        private readonly ConcurrentBag<string> snapshots = [];

        private static readonly byte[] NotManagedBytes = [0x00, 0x01, 0x02, 0x03, 0x2A, 0x7F, 0x55, 0xAA, 0x13, 0x37];
        #endregion
    }
    #endregion

    #region Fields
    private readonly Packages packages;

    private const string Bs = @"\";

    private const string SsaNotePrefix = "scan-package: SSA facts INCOMPLETE (";

    private const string ReachNotePrefix = "scan-package: reachability INCOMPLETE (";

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";

    private const int TimeoutMs = 300_000;

    // The escapes the hostile constant must show (the worker's lossless escaping, then the summary's quote escape).
    private static readonly string[] EscapedTokens =
    [
        "evil" + Bs + "\"q",
        Bs + "u202ex",
        Bs + "uD800y",
        Bs + "x1b[31m" + Bs + "x07" + Bs + "nz[red]x[/]",
        Bs + "U000E0041" + Bs + "u200b" + Bs + "ufeffAAA",
    ];

    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    private static readonly Regex LogLine = new(@"^\[\d{2}:\d{2}:\d{2} [A-Z]{3}\]", RegexOptions.Compiled);

    private static readonly Regex ExtractionDir = new(@"pkg-[A-Za-z0-9_\-]+", RegexOptions.Compiled);

    private static readonly Regex Iso8601 = new(@"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)?", RegexOptions.Compiled);
    #endregion
}
