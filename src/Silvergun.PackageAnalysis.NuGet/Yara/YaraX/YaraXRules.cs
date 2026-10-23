#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

/// <summary>
/// A compiled YARA-X ruleset (<c>YRX_RULES</c>): the embedded rule sources plus this ruleset's own
/// <see cref="YaraXCanary"/> rule, compiled together by ONE compiler. Built by <see cref="Compile"/>, or rebuilt from a
/// serialized blob by <see cref="Deserialize"/>. A rules object may back any number of scanners, each used from one thread
/// (<see cref="CreateScanner"/>); it is destroyed only after the last of them.
/// </summary>
internal sealed unsafe class YaraXRules : IDisposable
{
    #region Constructors
    private YaraXRules(YaraXRulesHandle handle, YaraXCanary canary, string sourcesSha256, int ruleCount, int sourceErrors) =>
        (Handle, Canary, SourcesSha256, RuleCount, SourceErrors) = (handle, canary, sourcesSha256, ruleCount, sourceErrors);
    #endregion

    #region Properties
    /// <summary>This ruleset's canary rule (compiled into it).</summary>
    internal YaraXCanary Canary { get; }

    /// <summary>The rules cache key's content part: <see cref="SourcesSha256Of"/> of the sources compiled.</summary>
    internal string SourcesSha256 { get; }

    /// <summary>The number of compiled rules, NOT counting the canary.</summary>
    internal int RuleCount { get; }

    /// <summary>
    /// How many of the sources compiled had compile errors (their failing rules are absent) or were dropped whole: the
    /// worker's <c>ready.ruleSourceErrors</c> (amendment G1). 0 for a ruleset rebuilt by <see cref="Deserialize"/>, because
    /// the rules cache stores only rulesets that compiled with none (<see cref="YaraXRulesCache.Store"/>).
    /// </summary>
    internal int SourceErrors { get; }

    internal YaraXRulesHandle Handle { get; }
    #endregion

    #region Methods
    /// <summary>
    /// The sha256 (lower-case hex) of <paramref name="sources"/> in order, each name and text framed by its UTF-8 byte
    /// length, so no two different source lists can concatenate to the same input.
    /// </summary>
    internal static string SourcesSha256Of(IEnumerable<(string Name, string Text)> sources)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[sizeof(long)];
        foreach (var part in sources.SelectMany(s => new[] { s.Name, s.Text }))
        {
            var bytes = Encoding.UTF8.GetBytes(part);
            BinaryPrimitives.WriteInt64LittleEndian(length, bytes.LongLength);
            sha.AppendData(length);
            sha.AppendData(bytes);
        }
        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }

    /// <summary>
    /// Compiles <paramref name="sources"/> plus a fresh <see cref="YaraXCanary"/> with one compiler (<c>include</c>
    /// disabled). YARA-X semantics, accepted as they are (no two-pass compile; T5 finding 1): a source with compile errors
    /// keeps the rules in it that DID compile — before or after the error — and only its failing rules are absent; the
    /// compiler stays usable for the other sources. Each such source is warned about by name (escaped), with its error
    /// count. A source holding a NUL is the exception: it never reaches the engine and is dropped whole. The canary must
    /// compile cleanly, and at least one source must compile without errors (a ruleset in which every source failed is
    /// not trusted to be the ruleset). Sources that use the reserved canary prefix anywhere (case-insensitively) are
    /// refused outright, so no embedded rule can shadow or be mistaken for the canary. <c>null</c>, with an escaped,
    /// bounded <paramref name="failure"/>, when no usable ruleset was built.
    /// </summary>
    internal static YaraXRules? Compile(IReadOnlyList<(string Name, string Text)> sources, out string? failure)
    {
        YaraXNative.EnsureLoaded();
        if (sources.Count == 0)
            return Fail("there are no embedded YARA rule sources", out failure);
        if (sources.Any(s => s.Text.Contains(YaraXCanary.Prefix, StringComparison.OrdinalIgnoreCase)))
            return Fail($"the embedded YARA rules use the reserved canary prefix '{YaraXCanary.Prefix}'", out failure);

        var canary = YaraXCanary.Create();
        var created = YaraXNative.yrx_compiler_create(YaraXNative.DisableIncludes, out var compiler);
        using (compiler)
        {
            if (created != YaraXResult.Success || compiler.IsInvalid)
                return Fail($"yrx_compiler_create failed: {created}: {YaraXNative.LastError()}", out failure);

            int? errorsSoFar = 0;
            var withErrors = new List<string>();
            var dropped = new List<string>();
            foreach (var (name, text) in sources)
                switch (Add(compiler, name, text, ref errorsSoFar))
                {
                    case SourceOutcome.HadErrors: withErrors.Add(name); break;
                    case SourceOutcome.Dropped: dropped.Add(name); break;
                }

            if (withErrors.Count + dropped.Count == sources.Count)
                return Fail("no embedded YARA rule source compiled without errors", out failure);
            if (withErrors.Count > 0)
                Runtime.Warn("YARA-X: {0} of {1} embedded rule source(s) had compile errors; the rules in them that compiled are kept: {2}",
                    withErrors.Count, sources.Count, YaraPathSafety.Bounded(withErrors));
            if (dropped.Count > 0)
                Runtime.Warn("YARA-X: {0} of {1} embedded rule source(s) were dropped and are NOT part of the ruleset: {2}",
                    dropped.Count, sources.Count, YaraPathSafety.Bounded(dropped));
            if (Add(compiler, CanaryOrigin, canary.RuleSource, ref errorsSoFar) != SourceOutcome.Compiled)
                return Fail("the canary rule did not compile", out failure);

            var rules = YaraXNative.yrx_compiler_build(compiler);
            if (rules.IsInvalid)
            {
                var error = YaraXNative.LastError();
                rules.Dispose();
                return Fail($"yrx_compiler_build returned no rules: {error}", out failure);
            }

            return Wrap(rules, canary, SourcesSha256Of(sources), expectedRuleCount: null, withErrors.Count + dropped.Count, out failure);
        }
    }

    /// <summary>
    /// Rebuilds a ruleset from a <see cref="Serialize"/>d <paramref name="blob"/>. The caller MUST have verified the blob's
    /// integrity first: most single-byte corruptions deserialize without error (C API spike, 48 of 60). <c>null</c>, with
    /// <paramref name="failure"/>, when the engine rejects it or its rule count is not <paramref name="ruleCount"/>.
    /// </summary>
    internal static YaraXRules? Deserialize(ReadOnlySpan<byte> blob, YaraXCanary canary, string sourcesSha256, int ruleCount, out string? failure)
    {
        YaraXNative.EnsureLoaded();
        YaraXResult result;
        YaraXRulesHandle rules;
        fixed (byte* data = blob)
            result = YaraXNative.yrx_rules_deserialize(data, (nuint)blob.Length, out rules);

        if (result != YaraXResult.Success || rules.IsInvalid)
        {
            var error = YaraXNative.LastError();
            rules.Dispose();
            return Fail($"yrx_rules_deserialize failed: {result}: {error}", out failure);
        }

        return Wrap(rules, canary, sourcesSha256, ruleCount, sourceErrors: 0, out failure);
    }

    /// <summary>The ruleset as bytes for <see cref="Deserialize"/>, or <c>null</c> with <paramref name="failure"/>.</summary>
    internal byte[]? Serialize(out string? failure)
    {
        var result = YaraXNative.yrx_rules_serialize(Handle, out var buffer);
        var error = result != YaraXResult.Success ? YaraXNative.LastError() : null;
        try
        {
            if (result != YaraXResult.Success || buffer is null)
                return Fail<byte[]>($"yrx_rules_serialize failed: {result}: {error}", out failure);

            failure = null;
            return new ReadOnlySpan<byte>(buffer->data, checked((int)buffer->length)).ToArray();
        }
        finally
        {
            if (buffer is not null)
                YaraXNative.yrx_buffer_destroy(buffer);
        }
    }

    /// <summary>
    /// A scanner over these rules whose every scan is bounded by <paramref name="timeoutSeconds"/> (≥ 1). It may only be used
    /// from the calling thread; see <see cref="YaraXScanner"/>.
    /// </summary>
    internal YaraXScanner CreateScanner(int timeoutSeconds) => new(this, timeoutSeconds);

    public void Dispose() => Handle.Dispose();

    // Adds one source. `errorsSoFar` is the compiler's running error count (errors accumulate across sources, and only a
    // failed add adds any), so a failed add's own count is the difference. It is null while that count is unknown: once
    // the compiler's count could not be read, the running total is no longer known, and no later difference is computed
    // from a stale one (every add after it reads "1 or more" until the count is read again, which resynchronises it).
    private static SourceOutcome Add(YaraXCompilerHandle compiler, string origin, string text, ref int? errorsSoFar)
    {
        // The UTF-8 marshaller hands the engine a NUL-terminated string, so an embedded NUL would silently cut the source.
        if (text.Contains('\0'))
        {
            Runtime.Warn("YARA-X: dropped rule source {0}: it contains a NUL character.", YaraXText.Bounded(origin));
            return SourceOutcome.Dropped;
        }

        var result = YaraXNative.yrx_compiler_add_source_with_origin(compiler, text, origin);
        if (result == YaraXResult.Success)
            return SourceOutcome.Compiled;

        var error = YaraXNative.LastError() ?? "(no message)";
        var total = ErrorCount(compiler);
        var count = total is int t && errorsSoFar is int before && t > before ? (t - before).ToString(System.Globalization.CultureInfo.InvariantCulture) : "1 or more";
        errorsSoFar = total;
        Runtime.Warn("YARA-X: {0} error(s) in rule source {1}; the rules in it that compiled are kept. {2}: {3}",
            count, YaraXText.Bounded(origin), result, error);
        return SourceOutcome.HadErrors;
    }

    // The compiler's cumulative error count (the length of yrx_compiler_errors_json's array), or null when it cannot be read.
    private static int? ErrorCount(YaraXCompilerHandle compiler)
    {
        YaraXBuffer* buffer = null;
        try
        {
            if (YaraXNative.yrx_compiler_errors_json(compiler, out buffer) != YaraXResult.Success || buffer is null || buffer->length > MaxErrorsJsonBytes)
                return null;

            using var json = JsonDocument.Parse(new ReadOnlySpan<byte>(buffer->data, (int)buffer->length).ToArray());
            return json.RootElement.ValueKind == JsonValueKind.Array ? json.RootElement.GetArrayLength() : null;
        }
        catch (Exception)
        {
            return null;
        }
        finally
        {
            if (buffer is not null)
                YaraXNative.yrx_buffer_destroy(buffer);
        }
    }

    // Takes ownership of `rules`: returned inside the wrapper, or disposed. The canary is one of the rules, so a healthy
    // set holds at least two.
    private static YaraXRules? Wrap(YaraXRulesHandle rules, YaraXCanary canary, string sourcesSha256, int? expectedRuleCount, int sourceErrors, out string? failure)
    {
        var count = YaraXNative.yrx_rules_count(rules) - 1;
        if (count < 1 || (expectedRuleCount is int expected && count != expected))
        {
            rules.Dispose();
            return Fail($"the ruleset holds {count} rule(s) besides the canary{(expectedRuleCount is int e ? $", expected {e}" : "")}", out failure);
        }

        failure = null;
        return new YaraXRules(rules, canary, sourcesSha256, count, sourceErrors);
    }

    private static T? Fail<T>(string message, out string? failure) where T : class
    {
        failure = YaraXText.Bounded(message);
        return null;
    }

    private static YaraXRules? Fail(string message, out string? failure) => Fail<YaraXRules>(message, out failure);
    #endregion

    #region Fields
    private const string CanaryOrigin = "silvergun-canary";

    // The error report is only counted; one this large is not worth parsing for a warning's number.
    private const nuint MaxErrorsJsonBytes = 64 * 1024 * 1024;
    #endregion

    #region Child types
    // What adding one source did.
    private enum SourceOutcome
    {
        Compiled,
        HadErrors,   // YARA-X kept the rules in it that compiled
        Dropped,     // never reached the engine
    }
    #endregion
}
#endif
