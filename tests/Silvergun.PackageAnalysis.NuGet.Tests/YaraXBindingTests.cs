#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Win32.SafeHandles;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// The YARA-X C API binding (ADR 0033 FINAL FORM / revision; task T2), against the real pinned <c>yara_x_capi.dll</c>:
/// compiling (with the reserved canary prefix refused; a source with errors keeps the rules in it that compiled and is
/// named, counted and summarised, per the T5 finding 1 decision; a source holding a NUL dropped whole), the canary (passing on compiled and
/// deserialized rules, failing on another ruleset's, and never surfacing in a result), and the scanner (one owning thread,
/// timeouts as a value with the scanner reusable after, errors as escaped bounded values, a callback fault as an error and
/// never as a clean scan, files opened by the caller through <c>\\?\</c>, and the memory-mapped path above
/// <see cref="Array.MaxLength"/>).
///
/// <para><b>Process-fatal hazard.</b> A Rust panic aborts the test host (0xC0000409). The only one observed came from one
/// scanner used by two threads at once, which the binding refuses (and which these tests never do: every cross-thread
/// test expects the refusal before any native call). Each test creates its own scanner on its own thread.</para>
/// </summary>
public sealed class YaraXBindingTests
{
    #region Methods: compile
    [Theory]
    [InlineData("rule SilvergunCanary_0123 { condition: true }")]
    [InlineData("rule silvergunCANARY_x { condition: true }")]
    [InlineData("rule ok { condition: true } // SILVERGUNCANARY_ in a comment")]
    [InlineData("rule ok { strings: $s = \"SilverGunCanary_\" condition: $s }")]
    public void Compile_ASourceUsingTheCanaryPrefixInAnyCase_IsRefused(string reserved)
    {
        YaraX.EnsureEngine();

        var rules = YaraXRules.Compile(YaraX.Sources("rule fine { condition: true }", reserved), out var failure);

        Assert.Null(rules);
        Assert.Contains("reserved canary prefix", failure, StringComparison.Ordinal);
    }

    // The UTF-8 marshaller hands the engine a NUL-terminated string, so a NUL would silently cut a source short: such a
    // source is the one exception to "rules that compiled are kept" (T5 finding 1). It never reaches the engine, is
    // dropped whole with a warning naming it, is listed as dropped, and the others still compile.
    [Fact]
    public void Compile_ASourceContainingANul_IsDropped_AndTheRestCompile()
    {
        YaraX.EnsureEngine();
        using var warnings = new WarningCapture();

        using var rules = YaraXRules.Compile(YaraX.Sources("rule kept { condition: true }", "rule cut { condition: true }\0rule hidden { condition: true }"), out var failure);

        Assert.True(rules is not null, failure);
        Assert.Equal(1, rules!.RuleCount);
        Assert.Equal(1, rules.SourceErrors);
        Assert.Contains(warnings.Warnings, w => w.Contains("dropped rule source test-1.yar: it contains a NUL character", StringComparison.Ordinal));
        Assert.Contains(warnings.Warnings, w => w.Contains("1 of 2 embedded rule source(s) were dropped and are NOT part of the ruleset: 'test-1.yar'", StringComparison.Ordinal));
        using var scanner = rules.CreateScanner(5);
        Assert.Equal(new[] { "kept" }, YaraX.Hits(scanner.Scan([0])));   // neither half of the NUL source got in
    }

    // T5 finding 1, decision 2026-10-22: YARA-X keeps the rules that compiled in a source with errors. The re-pinned
    // contract: only the failing rule is absent, the warning names the source with its error count and says the rest is
    // kept, the summary lists the source, and SourceErrors counts it (which is what makes the worker's ready refuse to
    // vouch for the ruleset, amendment G1).
    [Fact]
    public void Compile_ASourceThatDoesNotCompile_KeepsTheRestCompiling_AndIsCountedAndNamed()
    {
        YaraX.EnsureEngine();
        using var warnings = new WarningCapture();

        using var rules = YaraXRules.Compile(YaraX.Sources("rule broken { condition: no_such_identifier }", "rule a { condition: true } rule b { condition: false }"), out var failure);

        Assert.True(rules is not null, failure);
        Assert.Equal(2, rules!.RuleCount);
        Assert.Equal(1, rules.SourceErrors);
        Assert.Contains(warnings.Warnings, w => w.Contains("1 error(s) in rule source test-0.yar; the rules in it that compiled are kept", StringComparison.Ordinal));
        Assert.Contains(warnings.Warnings, w => w.Contains("1 of 2 embedded rule source(s) had compile errors; the rules in them that compiled are kept: 'test-0.yar'", StringComparison.Ordinal));
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("NOT part of the ruleset", StringComparison.Ordinal));
    }

    // Formerly Compile_ASourceThatDoesNotCompile_IsDroppedWhole_NotJustItsBadRule, the deliberate red of T5 round 1. The
    // decision kept YARA-X's semantics, so this now pins them: the good rule of the source with an error is KEPT (and
    // matches), the bad rule is absent, and the warning names that source rather than claiming it was dropped.
    [Fact]
    public void Compile_ASourceWithABadRule_KeepsItsGoodRules_AndOnlyTheBadRuleIsAbsent()
    {
        YaraX.EnsureEngine();
        using var warnings = new WarningCapture();

        using var rules = YaraXRules.Compile(YaraX.Sources(
            "rule from_failed_source { condition: true } rule broken { condition: no_such_identifier } rule after_the_error { condition: true }",
            "rule from_good_source { condition: true }"), out var failure);

        Assert.True(rules is not null, failure);
        using var scanner = rules!.CreateScanner(5);
        var hits = YaraX.Hits(scanner.Scan([0]));
        Assert.Equal(new[] { "after_the_error", "from_failed_source", "from_good_source" }, hits.Order(StringComparer.Ordinal));
        Assert.Equal(3, rules.RuleCount);
        Assert.Equal(1, rules.SourceErrors);
        Assert.Contains(warnings.Warnings, w => w.Contains("error(s) in rule source test-0.yar; the rules in it that compiled are kept", StringComparison.Ordinal));
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("test-1.yar", StringComparison.Ordinal));
    }

    // The error count is per source: the compiler's errors accumulate across add_source calls, and each source's warning
    // carries only its own (the difference), not the running total.
    [Fact]
    public void Compile_TheErrorCountInEachWarning_IsThatSourcesOwn()
    {
        YaraX.EnsureEngine();
        using var warnings = new WarningCapture();

        using var rules = YaraXRules.Compile(YaraX.Sources(
            "rule one_bad { condition: missing_a }",
            "rule good { condition: true }",
            "rule two_bad_x { condition: missing_b } rule two_bad_y { condition: missing_c }"), out var failure);

        Assert.True(rules is not null, failure);
        Assert.Equal(2, rules!.SourceErrors);
        Assert.Contains(warnings.Warnings, w => w.Contains("1 error(s) in rule source test-0.yar", StringComparison.Ordinal));
        Assert.Contains(warnings.Warnings, w => w.Contains("2 error(s) in rule source test-2.yar", StringComparison.Ordinal));
        Assert.Contains(warnings.Warnings, w => w.Contains("2 of 3 embedded rule source(s) had compile errors; the rules in them that compiled are kept: 'test-0.yar', 'test-2.yar'", StringComparison.Ordinal));
    }

    // A source's name is embedded-resource text, but it is still escaped wherever it is logged: a newline cannot forge a
    // second log line and a bidi override cannot reorder one.
    [Fact]
    public void Compile_TheWarningEscapesTheSourceName()
    {
        YaraX.EnsureEngine();
        using var warnings = new WarningCapture();
        var hostile = "evil\n[WRN] forged" + (char)0x202E + ".yar";

        using var rules = YaraXRules.Compile([(hostile, "rule bad { condition: nope }"), ("ok.yar", "rule ok { condition: true }")], out var failure);

        Assert.True(rules is not null, failure);
        var warning = Assert.Single(warnings.Warnings, w => w.Contains("error(s) in rule source", StringComparison.Ordinal));
        Assert.Contains("evil\\n[WRN] forged\\u202e.yar", warning, StringComparison.Ordinal);
        Assert.DoesNotContain('\n', warning);
        Assert.DoesNotContain((char)0x202E, warning);
        var summary = Assert.Single(warnings.Warnings, w => w.Contains("had compile errors", StringComparison.Ordinal));
        Assert.DoesNotContain('\n', summary);
        Assert.DoesNotContain((char)0x202E, summary);
    }

    // SourceErrors is "sources with compile errors PLUS sources dropped whole" — the number the worker's ready carries as
    // ruleSourceErrors.
    [Fact]
    public void Compile_SourceErrors_CountsSourcesWithErrorsPlusDroppedSources()
    {
        YaraX.EnsureEngine();
        using var warnings = new WarningCapture();

        using var rules = YaraXRules.Compile(YaraX.Sources(
            "rule bad { condition: nope }",
            "rule nul_source { condition: true }\0",
            "rule good { condition: true }",
            "rule also_bad { condition: nope_again }"), out var failure);

        Assert.True(rules is not null, failure);
        Assert.Equal(3, rules!.SourceErrors);
        Assert.Equal(1, rules.RuleCount);
    }

    [Fact]
    public void Compile_CleanSources_HaveNoSourceErrors()
    {
        using var rules = YaraX.Compile("rule a { condition: true }", "rule b { condition: false }");

        Assert.Equal(0, rules.SourceErrors);
    }

    // Amendment (n): compile fails when EVERY source had errors — also when the only "good" source was dropped for a NUL,
    // and also when a source with errors still contributed a rule that compiled.
    [Theory]
    [InlineData("rule bad { condition: nope }", "rule other_bad { condition: nope }")]
    [InlineData("rule bad { condition: nope }", "rule would_be_good { condition: true }\0")]
    [InlineData("rule kept_but_errored { condition: true } rule bad { condition: nope }", "rule other { condition: nope }")]
    public void Compile_WhenEverySourceHadErrorsOrWasDropped_Fails(string first, string second)
    {
        YaraX.EnsureEngine();

        Assert.Null(YaraXRules.Compile(YaraX.Sources(first, second), out var failure));
        Assert.Contains("no embedded YARA rule source compiled without errors", failure, StringComparison.Ordinal);
    }

    // YRX_DISABLE_INCLUDES: an include would read a file relative to the working directory. Here it names a real rule file
    // by absolute path; with includes disabled, that file's rule is never compiled in. The include is a compile error of
    // its source, warned about in the new wording and counted.
    [Fact]
    public void Compile_AnInclude_IsRefused_SoTheIncludedFileIsNeverRead()
    {
        YaraX.EnsureEngine();
        using var dir = new YaraXTempDir("include");
        var included = dir.Combine("included.yar");
        File.WriteAllText(included, "rule from_included_file { condition: true }");
        using var warnings = new WarningCapture();

        using var rules = YaraXRules.Compile(YaraX.Sources($"include \"{included.Replace("\\", "/")}\"", "rule plain { condition: true }"), out var failure);

        Assert.True(rules is not null, failure);
        Assert.Equal(1, rules!.RuleCount);
        Assert.Equal(1, rules.SourceErrors);
        using var scanner = rules.CreateScanner(5);
        Assert.Equal(new[] { "plain" }, YaraX.Hits(scanner.Scan([0])));
        Assert.Contains(warnings.Warnings, w => w.Contains("error(s) in rule source test-0.yar; the rules in it that compiled are kept", StringComparison.Ordinal)
            && w.Contains("include", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compile_NoSources_Fails()
    {
        YaraX.EnsureEngine();

        Assert.Null(YaraXRules.Compile([], out var failure));
        Assert.Contains("no embedded YARA rule sources", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void Compile_WhenNoSourceCompiles_Fails()
    {
        YaraX.EnsureEngine();

        Assert.Null(YaraXRules.Compile(YaraX.Sources("rule x { condition: nope }", "not yara at all"), out var failure));
        Assert.Contains("no embedded YARA rule source compiled without errors", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void RuleCount_ExcludesTheCanary()
    {
        using var rules = YaraX.Compile("rule one { condition: true } rule two { condition: true }", "rule three { condition: true }");

        Assert.Equal(3, rules.RuleCount);
    }
    #endregion

    #region Methods: the canary
    [Fact]
    public void CheckCanary_PassesOnFreshlyCompiledRules()
    {
        using var rules = YaraX.Compile("rule any_rule { condition: false }");
        using var scanner = rules.CreateScanner(5);

        Assert.Null(scanner.CheckCanary());
    }

    // The serialized blob does not carry the canary's marker, so the cache stores it alongside. Deserialized with ITS OWN
    // canary the rules pass; with another ruleset's canary they fail, which is what catches a cache entry whose blob and
    // canary do not belong together.
    [Fact]
    public void CheckCanary_OnDeserializedRules_PassesWithTheirOwnCanary_AndFailsWithAnothers()
    {
        using var a = YaraX.Compile("rule shared { condition: false }");
        using var b = YaraX.Compile("rule shared { condition: false }");
        var blob = a.Serialize(out var serializeFailure);
        Assert.True(blob is not null, serializeFailure);

        using var own = YaraXRules.Deserialize(blob, a.Canary, a.SourcesSha256, a.RuleCount, out var ownFailure);
        using var foreign = YaraXRules.Deserialize(blob, b.Canary, a.SourcesSha256, a.RuleCount, out var foreignFailure);
        Assert.True(own is not null, ownFailure);
        Assert.True(foreign is not null, foreignFailure);

        using (var scanner = own!.CreateScanner(5))
            Assert.Null(scanner.CheckCanary());
        using (var scanner = foreign!.CreateScanner(5))
            Assert.Equal("the canary rule did not match its marker", scanner.CheckCanary());
    }

    [Fact]
    public void Deserialize_WithTheWrongRuleCount_Fails()
    {
        using var rules = YaraX.Compile("rule one { condition: false }");
        var blob = rules.Serialize(out _)!;

        Assert.Null(YaraXRules.Deserialize(blob, rules.Canary, rules.SourcesSha256, rules.RuleCount + 1, out var failure));
        Assert.Contains("expected 2", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void Deserialize_Garbage_FailsAsAValue()
    {
        YaraX.EnsureEngine();
        var canary = YaraXCanary.Create();

        Assert.Null(YaraXRules.Deserialize(new byte[] { 1, 2, 3, 4, 5 }, canary, new string('0', 64), 1, out var failure));
        Assert.Contains("yrx_rules_deserialize failed", failure, StringComparison.Ordinal);
    }

    // The canary scans its marker: CheckCanary sees it, but no scan result ever does.
    [Fact]
    public void Scan_NeverReportsTheCanary_EvenOnItsOwnMarker()
    {
        var marker = YaraX.Marker();
        using var rules = YaraX.Compile(YaraX.MarkerRule("visible", marker));
        using var scanner = rules.CreateScanner(5);
        var both = rules.Canary.Marker.ToArray().Concat(marker).ToArray();

        Assert.Null(scanner.CheckCanary());
        Assert.Empty(YaraX.Hits(scanner.Scan(rules.Canary.Marker)));
        Assert.Equal(new[] { "visible" }, YaraX.Hits(scanner.Scan(both)));
    }

    [Fact]
    public void Strip_RemovesTheExactCanary_AndDropsLookalikesWithAWarning()
    {
        var canary = YaraXCanary.Create();
        var real = new YaraXHit("Win32_Something", "default", ["t"]);
        YaraXHit[] hits =
        [
            new(canary.RuleName, "default", []),
            real,
            new("SilvergunCanary_" + new string('0', 32), "default", []),   // the prefix, not this canary
            new("silvergunCANARY_" + canary.Id, "default", []),              // this canary's id, wrong case
            new("Another", "ns", []),
        ];
        using var warnings = new WarningCapture();

        var stripped = canary.Strip(hits);

        Assert.Equal(new[] { "Win32_Something", "Another" }, stripped.Select(h => h.Rule));
        var warning = Assert.Single(warnings.Warnings, w => w.Contains("reserved canary prefix", StringComparison.Ordinal));
        Assert.Contains("dropped 2 hit(s)", warning, StringComparison.Ordinal);
        Assert.DoesNotContain(canary.RuleName, warning, StringComparison.Ordinal);   // the real canary is not "foreign"
    }

    [Fact]
    public void Strip_WithNoReservedHits_ReturnsTheHitsUnchangedAndWarnsNothing()
    {
        var canary = YaraXCanary.Create();
        YaraXHit[] hits = [new("A", "default", []), new("B", "default", [])];
        using var warnings = new WarningCapture();

        Assert.Same(hits, canary.Strip(hits));
        Assert.Empty(warnings.Warnings);
    }

    [Fact]
    public void Canary_HasTheContractShape()
    {
        var a = YaraXCanary.Create();
        var b = YaraXCanary.Create();

        Assert.Matches("^SilvergunCanary_[0-9a-f]{32}$", a.RuleName);
        Assert.Equal(32, a.Marker.Length);
        Assert.NotEqual(a.RuleName, b.RuleName);
        Assert.False(a.Marker.SequenceEqual(b.Marker));
        Assert.Equal(a.Id, YaraXCanary.From(a.IdBytes(), a.Marker)!.Id);
        Assert.Null(YaraXCanary.From(new byte[15], a.Marker));
        Assert.Null(YaraXCanary.From(a.IdBytes(), new byte[31]));
    }
    #endregion

    #region Methods: the scanner
    [Fact]
    public void Scan_ReportsRuleNamespaceAndTags()
    {
        var marker = YaraX.Marker();
        using var rules = YaraX.Compile(YaraX.MarkerRule("tagged", marker, "first", "second"));
        using var scanner = rules.CreateScanner(5);

        var hit = Assert.Single(Assert.IsType<YaraXScanResult.Scanned>(scanner.Scan(marker)).Hits);

        Assert.Equal(("tagged", "default"), (hit.Rule, hit.Namespace));
        Assert.Equal(new[] { "first", "second" }, hit.Tags);
        Assert.Empty(YaraX.Hits(scanner.Scan([1, 2, 3])));   // a later scan does not see the earlier hits
    }

    // One scanner used by two threads at once aborted the host in every spike run; the binding refuses use from any
    // thread but the creator's, before any native call, and the scanner stays usable by its owner.
    [Fact]
    public void Scanner_UsedFromAnotherThread_Throws_AndStaysUsableByItsOwner()
    {
        var marker = YaraX.Marker();
        using var rules = YaraX.Compile(YaraX.MarkerRule("owned", marker));
        using var scanner = rules.CreateScanner(5);
        using var dir = new YaraXTempDir("thread");
        var path = dir.Combine("f.bin");
        File.WriteAllBytes(path, marker);
        using var file = File.OpenHandle(path);

        // A dedicated thread (not a Task, whose continuation could land anywhere): this test must stay on its own thread.
        Exception?[] errors = [];
        var other = new Thread(() => errors =
        [
            Record.Exception(() => scanner.Scan(marker)),
            Record.Exception(() => scanner.Scan(file)),
            Record.Exception(() => scanner.SetTimeout(3)),
            Record.Exception(() => scanner.CheckCanary()),
        ]);
        other.Start();
        other.Join();

        Assert.Equal(4, errors.Length);
        Assert.All(errors, e => Assert.Contains("only be used by the thread that created it", Assert.IsType<InvalidOperationException>(e).Message, StringComparison.Ordinal));
        Assert.Equal(new[] { "owned" }, YaraX.Hits(scanner.Scan(marker)));
        Assert.Null(scanner.CheckCanary());
    }

    // A second thread gets its own scanner over the same rules (the spike's control: two scanners, one rules object).
    [Fact]
    public async Task Rules_MayBackAScannerPerThread()
    {
        var marker = YaraX.Marker();
        using var rules = YaraX.Compile(YaraX.MarkerRule("shared", marker));

        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            using var scanner = rules.CreateScanner(5);
            return Enumerable.Range(0, 20).Select(_ => YaraX.Hits(scanner.Scan(marker)).Single()).ToArray();
        })));

        Assert.All(results, names => Assert.All(names, name => Assert.Equal("shared", name)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Scanner_RejectsATimeoutBelowOneSecond(int seconds)
    {
        using var rules = YaraX.Compile("rule r { condition: true }");

        Assert.Throws<ArgumentOutOfRangeException>(() => rules.CreateScanner(seconds));
        using var scanner = rules.CreateScanner(1);
        Assert.Throws<ArgumentOutOfRangeException>(() => scanner.SetTimeout(seconds));
        Assert.Null(scanner.CheckCanary());   // a rejected SetTimeout changed nothing
    }

    // The engine's timeout is a value, not an exception, and the scanner is reusable after it (spike Q2: ~209 timeouts,
    // every following call behaved). 64 KiB of zeros under the quadratic rule is minutes of work untimed.
    [Fact]
    public void Scan_PastTheTimeout_IsTimeout_AndTheNextScanOnTheSameScannerWorks()
    {
        var marker = YaraX.Marker();
        using var rules = YaraX.Compile(YaraX.SlowRule, YaraX.MarkerRule("after_timeout", marker));
        using var scanner = rules.CreateScanner(1);

        var clock = Stopwatch.StartNew();
        var slow = scanner.Scan(new byte[64 * 1024]);
        clock.Stop();

        Assert.IsType<YaraXScanResult.Timeout>(slow);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"the 1 s timeout took {clock.Elapsed}");
        Assert.Equal(new[] { "after_timeout" }, YaraX.Hits(scanner.Scan(marker)));
        Assert.Null(scanner.CheckCanary());
    }

    [Fact]
    public void ErrorMessages_AreEscapedAndBounded()
    {
        var hostile = "line1\nline2" + (char)0x202E + (char)0x07 + (char)0x200B + new string('x', 2000);

        var error = new YaraXScanResult.Error(hostile);

        Assert.True(error.Message.Length <= 512, $"{error.Message.Length} chars");
        Assert.StartsWith("line1\\nline2\\u202e\\x07\\u200b", error.Message, StringComparison.Ordinal);
        Assert.EndsWith("...", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(error.Message, c => c < ' ' || c is (char)0x202E or (char)0x200B);
    }

    // A handle the scanner cannot read from: the read fails and the file is an Error, never a clean Scanned.
    [Fact]
    public void Scan_OfAFileItCannotRead_IsAnError()
    {
        using var rules = YaraX.Compile("rule always { condition: true }");
        using var scanner = rules.CreateScanner(5);
        using var dir = new YaraXTempDir("unreadable");
        var path = dir.Combine("write-only.bin");
        File.WriteAllBytes(path, [1, 2, 3]);
        using var writeOnly = File.OpenHandle(path, FileMode.Open, FileAccess.Write);

        var error = Assert.IsType<YaraXScanResult.Error>(scanner.Scan(writeOnly));

        Assert.StartsWith("could not read the file: ", error.Message, StringComparison.Ordinal);
    }

    // A byte-range lock held by someone else makes the read fail: an Error, not a short or empty scan.
    [Fact]
    public void Scan_OfALockedFile_IsAnError()
    {
        using var rules = YaraX.Compile("rule always { condition: true }");
        using var scanner = rules.CreateScanner(5);
        using var dir = new YaraXTempDir("locked");
        var path = dir.Combine("locked.bin");
        File.WriteAllBytes(path, new byte[4096]);
        using var locker = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
        locker.Lock(0, 4096);
        using var reader = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

        var error = Assert.IsType<YaraXScanResult.Error>(scanner.Scan(reader));

        Assert.StartsWith("could not read the file: IOException", error.Message, StringComparison.Ordinal);
        locker.Unlock(0, 4096);
    }

    // A file that shrinks between the length check and the read: the read loop meets end-of-file early and throws, which
    // Scan(SafeFileHandle) turns into an Error (pinned by the two tests above). The race itself cannot be timed
    // deterministically from a test, so the loop is driven directly with a length larger than the file.
    [Fact]
    public void ReadAll_WhenTheFileEndsEarly_Throws_RatherThanReturningAShortBuffer()
    {
        using var dir = new YaraXTempDir("shrunk");
        var path = dir.Combine("shrunk.bin");
        File.WriteAllBytes(path, new byte[100]);
        using var file = File.OpenHandle(path);
        var readAll = typeof(YaraXScanner).GetMethod("ReadAll", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.True(readAll is not null, "YaraXScanner.ReadAll is gone; the shrinking-file guard is no longer reachable by this test.");

        var thrown = Assert.Throws<TargetInvocationException>(() => readAll!.Invoke(null, [file, 200]));

        Assert.Contains("changed while being read", Assert.IsType<IOException>(thrown.InnerException).Message, StringComparison.Ordinal);
    }

    // W5: a file that GREW while it was read (someone appended past the length the read was sized from) is not the file
    // that was scanned: the read loop re-checks the length after reading and throws. Driven directly with a length smaller
    // than the file, which is the state a grow-during-read leaves (the race itself cannot be timed from a test).
    [Fact]
    public void ReadAll_WhenTheFileIsLongerAfterReading_Throws_RatherThanReturningAPrefix()
    {
        using var dir = new YaraXTempDir("grown");
        var path = dir.Combine("grown.bin");
        File.WriteAllBytes(path, new byte[200]);
        using var file = File.OpenHandle(path);
        var readAll = typeof(YaraXScanner).GetMethod("ReadAll", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.True(readAll is not null, "YaraXScanner.ReadAll is gone; the grown-file guard is no longer reachable by this test.");

        var thrown = Assert.Throws<TargetInvocationException>(() => readAll!.Invoke(null, [file, 100]));

        Assert.Equal("the file is 200 bytes after reading 100; it changed while being read", Assert.IsType<IOException>(thrown.InnerException).Message);
    }

    // The control: the exact length reads the whole file.
    [Fact]
    public void ReadAll_OfExactlyTheFilesLength_ReturnsItsBytes()
    {
        using var dir = new YaraXTempDir("exact");
        var path = dir.Combine("exact.bin");
        var bytes = YaraX.Marker();
        File.WriteAllBytes(path, bytes);
        using var file = File.OpenHandle(path);
        var readAll = typeof(YaraXScanner).GetMethod("ReadAll", BindingFlags.NonPublic | BindingFlags.Static)!;

        Assert.Equal(bytes, (byte[])readAll.Invoke(null, [file, bytes.Length])!);
    }

    // No exception may cross the FFI boundary, and a callback that fails must fail the scan: hits could be missing, so it
    // is an Error, never a Scanned. Provoked without touching src by pointing the GC handle the match callback reads at an
    // object of the wrong type for the duration of one scan (the callback's cast then throws inside the engine's call).
    [Fact]
    public void Scan_WhenTheMatchCallbackFails_IsAnError_NeverAScanned()
    {
        var marker = YaraX.Marker();
        using var rules = YaraX.Compile(YaraX.MarkerRule("would_match", marker));
        using var scanner = rules.CreateScanner(5);
        var sink = SinkHandle(scanner);
        var original = sink.Target;

        YaraXScanResult result;
        sink.Target = new object();
        try
        {
            result = scanner.Scan(marker);
        }
        finally
        {
            sink.Target = original;
        }

        var error = Assert.IsType<YaraXScanResult.Error>(result);
        Assert.Contains("a match callback failed", error.Message, StringComparison.Ordinal);
        Assert.Equal(new[] { "would_match" }, YaraX.Hits(scanner.Scan(marker)));   // and the scanner recovers
    }

    // A non-matching scan never calls back, so the same fault leaves a clean scan clean.
    [Fact]
    public void Scan_WithAFaultyCallbackThatIsNeverCalled_IsScanned()
    {
        using var rules = YaraX.Compile(YaraX.MarkerRule("never", YaraX.Marker()));
        using var scanner = rules.CreateScanner(5);
        var sink = SinkHandle(scanner);
        var original = sink.Target;

        sink.Target = new object();
        try
        {
            Assert.Empty(YaraX.Hits(scanner.Scan([9, 9, 9])));
        }
        finally
        {
            sink.Target = original;
        }
    }

    // yara_x.h: the rules must outlive their scanners. The scanner holds a reference on the rules handle, so disposing the
    // rules first is safe and the scanner keeps working until it is disposed itself.
    [Fact]
    public void DisposingTheRulesBeforeTheScanner_KeepsTheScannerWorking()
    {
        var marker = YaraX.Marker();
        var rules = YaraX.Compile(YaraX.MarkerRule("outlived", marker));
        var scanner = rules.CreateScanner(5);

        rules.Dispose();

        Assert.Equal(new[] { "outlived" }, YaraX.Hits(scanner.Scan(marker)));
        Assert.Null(scanner.CheckCanary());
        scanner.Dispose();
    }
    #endregion

    #region Methods: files
    // A plain path to a real file named like a DOS device opens the DEVICE (spike: SUCCESS with no hits). The caller
    // opens the file through \\?\, and the scanner scans what the handle holds: the file's bytes.
    [Theory]
    [InlineData("NUL")]
    [InlineData("CON")]
    [InlineData("nul.txt")]
    [InlineData("con.yara")]
    [InlineData("COM1")]
    public void Scan_OfARealFileNamedLikeADevice_OpenedViaTheVerbatimPrefix_ScansTheFile(string name)
    {
        var marker = YaraX.Marker();
        using var rules = YaraX.Compile(YaraX.MarkerRule("device_named", marker));
        using var scanner = rules.CreateScanner(5);
        using var dir = new YaraXTempDir("devname");
        var verbatim = @"\\?\" + dir.Combine(name);
        File.WriteAllBytes(verbatim, [.. new byte[100], .. marker, .. new byte[100]]);

        using var file = File.OpenHandle(verbatim, FileMode.Open, FileAccess.Read, FileShare.Read);

        Assert.Equal(232, RandomAccess.GetLength(file));
        Assert.Equal(new[] { "device_named" }, YaraX.Hits(scanner.Scan(file)));
    }

    [Fact]
    public void Scan_OfAnEmptyFile_IsAScanWithNoHits()
    {
        using var rules = YaraX.Compile(YaraX.MarkerRule("never", YaraX.Marker()));
        using var scanner = rules.CreateScanner(5);
        using var dir = new YaraXTempDir("empty");
        var path = dir.Combine("empty.bin");
        File.WriteAllBytes(path, []);
        using var file = File.OpenHandle(path);

        Assert.Empty(YaraX.Hits(scanner.Scan(file)));
    }

    // Above Array.MaxLength the file cannot be read into one array, so it is scanned through a read-only memory-mapped
    // view. A sparse file costs no disk; the marker sits past 2 GiB, so only a scan that covered the whole mapping finds
    // it (and a non-mapped path could not even allocate the buffer: it would be an Error).
    [Fact]
    [Trait("Category", "Slow")]
    public void Scan_OfAFileAboveArrayMaxLength_UsesTheMappedViewAndCoversTheWholeFile()
    {
        var marker = YaraX.Marker();
        using var rules = YaraX.Compile(YaraX.MarkerRule("beyond_two_gib", marker));
        using var scanner = rules.CreateScanner(120);
        using var dir = new YaraXTempDir("mapped");
        var path = dir.Combine("sparse.bin");
        var length = (long)Array.MaxLength + 64 * 1024 * 1024;
        using (var create = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            WindowsFileSystem.SetSparse(create.SafeFileHandle);
            create.SetLength(length);
            create.Position = length - 4096;
            create.Write(marker);
        }

        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Assert.True(RandomAccess.GetLength(file) > Array.MaxLength);

        Assert.Equal(new[] { "beyond_two_gib" }, YaraX.Hits(scanner.Scan(file)));
    }
    #endregion

    #region Methods: helpers
    // The GC handle a scanner's match callback reads its sink through (YaraXScannerHandle.sink). GCHandle is a struct, but
    // its Target setter writes the shared handle-table slot, so setting it on this copy is seen by the callback.
    private static GCHandle SinkHandle(YaraXScanner scanner)
    {
        var handleField = typeof(YaraXScanner).GetField("handle", BindingFlags.NonPublic | BindingFlags.Instance);
        var sinkField = typeof(YaraXScannerHandle).GetField("sink", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.True(handleField is not null && sinkField is not null, "YaraXScanner.handle or YaraXScannerHandle.sink is gone; the callback-fault test cannot reach the callback's sink.");
        var sink = (GCHandle)sinkField!.GetValue(handleField!.GetValue(scanner))!;
        Assert.True(sink.IsAllocated);
        return sink;
    }
    #endregion
}
#endif
