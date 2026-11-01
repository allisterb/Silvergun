namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

using Microsoft.ApplicationInspector.RulesEngine;

using Xunit;

using EngineUtils = Microsoft.ApplicationInspector.Common.Utils;

/// <summary>
/// ADR 0035 decision 3 (S4): the embedded rulesets are compiled with RulesEngine's
/// <c>RuleSet.EnableNonBacktrackingRegex</c> switch, so every regex matches in linear time — except the few patterns
/// .NET cannot run NonBacktracking, which the engine's <c>Utils.StringToRegex</c> fallback silently rebuilds
/// backtracking. The ADR's guard is this test class, not runtime code:
/// <list type="bullet">
/// <item>(a) every embedded <c>regex</c>/<c>regexword</c> pattern constructs in its effective mode — NonBacktracking,
/// or the fallback's backtracking regex — and none comes out null (the fallback's second failure caches null and
/// disables the pattern for good, in silence: the scanner passes the engine no logger);</item>
/// <item>(b) every pattern that falls back is quantifier-free, so backtracking over it is O(n·k) by construction. Today
/// that is exactly SG0001 p0 and SG0002 p0–p2 (the Silvergun-owned lookaround literals), pinned below: a new pattern
/// that falls back fails here and must be reviewed;</item>
/// <item>(c) the SHARED processor the scanner actually uses carries <c>RegexOptions.NonBacktracking</c> on its compiled
/// regexes, apart from those four. Dropping the switch from <c>BuildProcessor</c> fails this.</item>
/// </list>
/// (d), the findings being unchanged, is the existing <see cref="SilvergunRulesetTests"/> and
/// <see cref="NuspecProseRedactionTests"/>, which pin real rule hits and run against the switched processor.
///
/// <para>The patterns are read the way <c>BuildProcessor</c> reads them (its own resource markers, read by reflection),
/// into a <see cref="RuleSet"/> with the same switch, and each is turned into the regex the engine builds with the
/// engine's own helpers (<c>Utils.RegexModifierToRegexOptions</c>, <c>Utils.StringToRegex</c>; a <c>regexword</c>
/// pattern is wrapped in <c>\b(…)\b</c> first). (c) cross-checks that reconstruction against the shared processor's
/// live regex cache (its keys are exactly that built pattern and those options), as the S3 measurement did.</para>
/// </summary>
public sealed class ScriptRuleNonBacktrackingGuardTests
{
    #region Constructors
    public ScriptRuleNonBacktrackingGuardTests() => Runtime.Initialize("Silvergun", "TESTS");
    #endregion

    #region Methods: (a) every pattern constructs in its effective mode
    [Fact]
    public void EveryEmbeddedRegexPattern_GetsTheNonBacktrackingModifier_AndConstructs()
    {
        var patterns = EmbeddedRegexPatterns();

        Assert.True(patterns.Count >= 30, $"expected the embedded rulesets' regex patterns, found only {patterns.Count}");
        Assert.All(patterns, p =>
        {
            Assert.Contains("nb", p.Modifiers, StringComparer.OrdinalIgnoreCase);   // the switch reached AddString
            Assert.True(p.Requested.HasFlag(RegexOptions.NonBacktracking), $"{p.Id}: the engine would not request NonBacktracking ({p.Requested})");
            Assert.True(p.Effective is not null, $"{p.Id}: the engine's StringToRegex returned null, so this pattern is silently disabled");
        });
    }

    // What "its effective mode" means, stated without the engine's helper: a pattern that comes back NonBacktracking
    // constructs that way; one that comes back backtracking genuinely cannot (NotSupportedException, the one exception
    // the fallback retries) and constructs without the flag, with every other option the rule asked for.
    [Fact]
    public void EveryEmbeddedRegexPattern_ConstructsInTheModeTheEngineGaveIt()
    {
        Assert.All(EmbeddedRegexPatterns(), p =>
        {
            if (p.Effective!.Options.HasFlag(RegexOptions.NonBacktracking))
            {
                Assert.Equal(p.Requested, p.Effective.Options);
                _ = new Regex(p.Built, p.Requested);
            }
            else
            {
                Assert.Throws<NotSupportedException>(() => new Regex(p.Built, p.Requested));
                Assert.Equal(p.Requested & ~RegexOptions.NonBacktracking, p.Effective.Options);
            }
        });
    }
    #endregion

    #region Methods: (b) the fallbacks are pinned, and quantifier-free
    [Fact]
    public void ThePatternsThatFallBackToBacktracking_AreExactlyThePinnedFour()
    {
        var fallbacks = EmbeddedRegexPatterns()
            .Where(p => !p.Effective!.Options.HasFlag(RegexOptions.NonBacktracking))
            .Select(p => p.Id)
            .Order(StringComparer.Ordinal);

        Assert.Equal(PinnedFallbacks, fallbacks);
    }

    [Fact]
    public void EveryPatternThatFallsBackToBacktracking_IsQuantifierFree()
    {
        var fallbacks = EmbeddedRegexPatterns().Where(p => !p.Effective!.Options.HasFlag(RegexOptions.NonBacktracking)).ToArray();

        Assert.NotEmpty(fallbacks);
        Assert.All(fallbacks, p => Assert.False(HasQuantifier(p.Built), $"{p.Id} falls back to backtracking and has a quantifier: {p.Built}"));
    }

    // The detector itself, so (b) cannot pass because it never finds anything: '*', '+', '{' and a '?' that is not a
    // group construct's '(?' are quantifiers; escaped ones are literals.
    [Theory]
    [InlineData("a*", true)]
    [InlineData("a+", true)]
    [InlineData("a{2}", true)]
    [InlineData("a?", true)]
    [InlineData("(ab)?", true)]
    [InlineData("a+?", true)]
    [InlineData(@"(?<![A-Za-z0-9-])(x\.com|y\.io)(?![A-Za-z0-9-])", false)]
    [InlineData(@"(?:a|b)(?=c)(?<=d)", false)]
    [InlineData(@"a\?b\*c\+d\{", false)]
    [InlineData(@"\\?", true)]
    public void HasQuantifier_RecognisesQuantifiersAndOnlyThem(string pattern, bool expected) =>
        Assert.Equal(expected, HasQuantifier(pattern));
    #endregion

    #region Methods: (c) the shared processor's compiled regexes are NonBacktracking
    // Regexes are compiled lazily, on first use, into each regex operation's cache, keyed by (built pattern, options).
    // Scanning ordinary script content through the shared scanner fills it; every entry must then have been requested
    // NonBacktracking, and must BE NonBacktracking unless it is one of the pinned fallbacks — which must still be a
    // real, non-null regex. Without the switch no entry carries the flag, and this fails.
    [Fact]
    public void TheSharedProcessor_CompilesItsRegexesNonBacktracking_ApartFromThePinnedFallbacks()
    {
        using var tree = new TempTree();
        var scanner = new ScriptRuleScanner();
        _ = scanner.ScanFile(tree.Write("tools/install.ps1", PackageFixture.MaliciousPs1), "tools/install.ps1");
        _ = scanner.ScanFile(tree.Write("build/x.targets", PackageFixture.MaliciousTargets), "build/x.targets");
        var patterns = EmbeddedRegexPatterns();
        var fallbackKeys = patterns.Where(p => PinnedFallbacks.Contains(p.Id)).Select(p => p.Built).ToHashSet(StringComparer.Ordinal);

        var cache = SharedRegexCache();

        Assert.NotEmpty(cache);
        Assert.All(cache, entry =>
        {
            Assert.True(patterns.Any(p => p.Built == entry.Built && p.Requested == entry.Options),
                $"the shared processor compiled a regex this test did not reconstruct: ({entry.Options}) {entry.Built}");
            Assert.True(entry.Options.HasFlag(RegexOptions.NonBacktracking), $"requested without NonBacktracking: {entry.Built}");
            Assert.True(entry.Regex is not null, $"a null (disabled) regex in the shared cache: {entry.Built}");
            Assert.True(entry.Regex!.Options.HasFlag(RegexOptions.NonBacktracking) || fallbackKeys.Contains(entry.Built),
                $"compiled backtracking but is not a pinned fallback: {entry.Built}");
        });
        Assert.Contains(cache, entry => entry.Regex!.Options.HasFlag(RegexOptions.NonBacktracking));
        Assert.Contains(cache, entry => fallbackKeys.Contains(entry.Built));   // the fallbacks were exercised too, and passed above
    }
    #endregion

    #region Methods: helpers
    // Every regex/regexword pattern of the embedded rulesets, loaded as BuildProcessor loads them (same resources, same
    // switch), with the options the engine requests for it and the regex its StringToRegex returns.
    private static IReadOnlyList<RegexPattern> EmbeddedRegexPatterns()
    {
        var markers = (string[])typeof(ScriptRuleScanner).GetField("RuleResourceMarkers", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
        var assembly = typeof(ScriptRuleScanner).Assembly;
        var rules = new RuleSet { EnableNonBacktrackingRegex = true };
        var resources = assembly.GetManifestResourceNames()
            .Where(n => markers.Any(n.Contains) && n.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Assert.NotEmpty(resources);
        foreach (var resource in resources)
        {
            using var reader = new StreamReader(assembly.GetManifestResourceStream(resource)!);
            rules.AddString(reader.ReadToEnd(), resource);
        }

        return rules.GetAppInspectorRules()
            .SelectMany(rule => SearchPatterns(rule).Select(p => (Id: $"{rule.Id} {p.Where}", p.Pattern)))
            .Where(p => p.Pattern.PatternType is PatternType.Regex or PatternType.RegexWord)
            .Select(p =>
            {
                var built = p.Pattern.PatternType == PatternType.RegexWord ? $"\\b({p.Pattern.Pattern})\\b" : p.Pattern.Pattern!;
                var modifiers = p.Pattern.Modifiers.ToList();
                var requested = EngineUtils.RegexModifierToRegexOptions(modifiers);
                return new RegexPattern(p.Id, built, modifiers, requested, EngineUtils.StringToRegex(built, requested, null));
            })
            .ToArray();
    }

    private static IEnumerable<(string Where, SearchPattern Pattern)> SearchPatterns(Rule rule) =>
        (rule.Patterns ?? []).SelectMany((p, i) =>
                new[] { ($"p{i}", p) }.Concat((p.Conditions ?? []).Where(c => c.Pattern is not null).Select((c, j) => ($"p{i}c{j}", c.Pattern!))))
            .Concat((rule.Conditions ?? []).Where(c => c.Pattern is not null).Select((c, j) => ($"c{j}", c.Pattern!)));

    // The shared processor's compiled-regex caches (one per regex operation), read by reflection: the processor's
    // analyzer, its operation delegates, and each one's RegexCache. Retried briefly, because other tests may be adding
    // to a cache while it is read.
    private static IReadOnlyList<(string Built, RegexOptions Options, Regex? Regex)> SharedRegexCache()
    {
        const BindingFlags instance = BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance;
        var lazy = typeof(ScriptRuleScanner).GetField("sharedProcessor", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
        var processor = (RuleProcessor?)lazy.GetType().GetProperty("Value")!.GetValue(lazy);
        Assert.NotNull(processor);
        var analyzer = typeof(RuleProcessor).GetField("_analyzer", instance)!.GetValue(processor)!;
        PropertyInfo? delegatesProperty = null;
        for (var type = analyzer.GetType(); type is not null && delegatesProperty is null; type = type.BaseType)
            delegatesProperty = type.GetProperty("Delegates", instance);
        Assert.NotNull(delegatesProperty);
        var delegates = (IDictionary)delegatesProperty!.GetValue(analyzer)!;

        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return delegates.Values.Cast<object>()
                    .Select(operation => operation.GetType().GetField("RegexCache", instance)?.GetValue(operation))
                    .OfType<IDictionary>()
                    .SelectMany(Entries)
                    .Select(entry => entry.Key is ValueTuple<string, RegexOptions> key
                        ? (key.Item1, key.Item2, (Regex?)entry.Value)
                        : throw new InvalidOperationException($"unexpected regex cache key type {entry.Key.GetType()}"))
                    .ToArray();
            }
            catch (InvalidOperationException) when (attempt < 5)
            {
                // a concurrent add during enumeration; read again
            }
        }
    }

    // IDictionary's own enumerator yields DictionaryEntry; the non-generic IEnumerable one of a generic dictionary does not.
    private static DictionaryEntry[] Entries(IDictionary dictionary)
    {
        var entries = new List<DictionaryEntry>();
        for (var enumerator = dictionary.GetEnumerator(); enumerator.MoveNext();)
            entries.Add(enumerator.Entry);
        return [.. entries];
    }

    // A quantifier anywhere: '*', '+', '{', or a '?' that does not open a group construct ("(?"). Escaped characters are
    // literals. Deliberately conservative: a '*' inside a character class counts too.
    private static bool HasQuantifier(string pattern)
    {
        for (var i = 0; i < pattern.Length; i++)
        {
            switch (pattern[i])
            {
                case '\\':
                    i++;
                    break;
                case '*' or '+' or '{':
                    return true;
                case '?' when i == 0 || pattern[i - 1] != '(' || (i >= 2 && pattern[i - 2] == '\\'):
                    return true;
            }
        }

        return false;
    }
    #endregion

    #region Nested types
    private sealed record RegexPattern(string Id, string Built, IReadOnlyList<string> Modifiers, RegexOptions Requested, Regex? Effective);
    #endregion

    #region Fields
    // SG0001 p0 and SG0002 p0-p2 (Resources/SilvergunRules/callback_domains.json): single-character negative lookarounds
    // around an alternation of fixed literals, which .NET cannot run NonBacktracking (ADR 0035 decision 3, S3).
    private static readonly string[] PinnedFallbacks = ["SG0001 p0", "SG0002 p0", "SG0002 p1", "SG0002 p2"];
    #endregion
}
