// Portions adapted from OSSGadget (DefoggerTool.cs) — © Microsoft Corporation, MIT License.
// The executable magic-number tables, GetExecutableType classification, and the
// base64-decode-and-round-trip-verify technique are derived from that source. Copy authorized
// 2026-07-16. Source: reference/projects/OSSGadget-main/src/Shared.CLI/Tools/DefoggerTool.cs
namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Microsoft.Cci;

/// <summary>
/// Scans an assembly's IL string constants for hidden/encoded payloads — the "encode a payload so
/// scanners miss it, then decode and run it" pattern. It reads CCI directly from an
/// <see cref="AssemblyAnalyzer"/> (ADR 0009), enumerating every method's <see cref="IMethodBody.Operations"/>
/// for <c>ldstr</c> operands (an <see cref="OperationCode.Ldstr"/> whose <see cref="IOperation.Value"/> is the
/// loaded string), and for each sufficiently long constant that looks base64/hex it decodes, round-trip
/// verifies, and classifies the decoded bytes via magic numbers (adapted from OSSGadget's Defogger):
/// Windows PE / ELF / Mach-O / Java (<see cref="HiddenContentKind.EncodedExecutable"/>),
/// zip / gzip (<see cref="HiddenContentKind.EncodedArchive"/>). Long high-entropy encoded constants that
/// decode cleanly but match no signature are reported as <see cref="HiddenContentKind.HighEntropyBlob"/>.
/// Shannon entropy of the raw encoded constant is recorded on every finding as a secondary signal.
/// Detection classifies only — decoded archives are never extracted (RecursiveExtractor is out of scope).
/// Never throws: per-method / per-constant failures are skipped, not fatal (ADR 0005 threat model).
/// </summary>
public sealed class ObfuscationAnalysis(AssemblyAnalyzer assembly)
{
    #region Properties
    /// <summary>Minimum Shannon entropy (bits/char) for an encoded constant to count as a high-entropy blob.</summary>
    public static double MinEntropyThreshold { get; } = 4.0;

    /// <summary>Minimum length of an encoded constant to be considered a candidate (shorter strings are ignored).</summary>
    public static int MinEncodedLength { get; } = 24;
    #endregion

    #region Methods
    /// <summary>
    /// Enumerates <c>ldstr</c> constants across all method bodies, decode-and-classifies each candidate, and
    /// produces a serializable <see cref="ObfuscationReport"/>. Findings are deduplicated on the full tuple and
    /// ordered deterministically by (CallerType, CallerMethod, DetectedAs) with <see cref="StringComparer.Ordinal"/>.
    /// Never throws.
    /// </summary>
    public Result<ObfuscationReport> Analyze()
    {
        try
        {
            // Materialize inside the guard: enumerating assembly.Methods advances CCI's lazy type
            // resolution, which can throw on a corrupt/hostile module — the outer catch upholds the
            // never-throws contract even for a top-level enumeration failure.
            var findings = assembly.Methods
                .SelectMany(ScanMethod)
                .Distinct()
                .OrderBy(f => f.CallerType, StringComparer.Ordinal)
                .ThenBy(f => f.CallerMethod, StringComparer.Ordinal)
                .ThenBy(f => f.DetectedAs, StringComparer.Ordinal)
                .ThenBy(f => f.Kind)
                .ToArray();

            var report = new ObfuscationReport(
                assembly.AssemblyName,
                assembly.AssemblyPath,
                DateTimeOffset.UtcNow,
                findings);

            return Result.Success(report);

            // NOTE (deferred, nice-to-have): byte-array blobs from <PrivateImplementationDetails> /
            // RuntimeHelpers.InitializeArray (the .NET idiom for embedded data) are not scanned in this pass —
            // reaching the RVA-backed field data cleanly through the Analysis.Net model is not straightforward.
            // String constants deliver the core value; blob scanning can be added as a follow-up.
        }
        catch (Exception ex)
        {
            return Result.FailureWithError<ObfuscationReport>($"Failed to analyze {assembly.AssemblyName}.", ex);
        }
    }

    // Scans one method's CCI operations for ldstr constants and classifies each. Skips (never throws) any
    // method whose scan throws; per-constant failures are isolated in Classify. The caller type is best-effort
    // ("<unknown>" if unresolvable), matching the prior analysis-net semantics.
    private IReadOnlyList<ObfuscationFinding> ScanMethod(IMethodDefinition method)
    {
        try
        {
            var callerType = CallerType(method);
            var callerMethod = method.Name.Value;

            return method.Body.Operations
                .Where(op => op.OperationCode == OperationCode.Ldstr)
                .Select(op => op.Value as string)
                .Where(text => text is not null)
                .SelectMany(text => Classify(text!, callerType, callerMethod))
                .ToArray();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping obfuscation scan of method {0}: {1}", method.Name.Value, ex.Message);
            return [];
        }
    }

    // Best-effort namespace-qualified type name of the method's containing type ("<unknown>" if CCI cannot
    // resolve it), using the same TypeName helper CapabilityAnalysis uses.
    private static string CallerType(IMethodDefinition method)
    {
        try { return AssemblyAnalyzer.TypeName(method.ContainingTypeDefinition); }
        catch { return "<unknown>"; }
    }

    // Decode-and-classify a single string constant. A constant can be a valid encoding under more than one
    // scheme (lowercase hex is also valid base64), so BOTH applicable decodings are attempted and each decoded
    // byte sequence is classified against the magic-number table — the base64 alphabet is a superset of hex, so
    // testing only the first match would leave hex-encoded payloads unreachable. Magic-number findings from every
    // decoding are emitted (identical ones are deduped downstream by Distinct); the high-entropy fallback emits at
    // most one finding per constant. Any failure is caught so the constant is dropped without failing the analysis.
    private static IReadOnlyList<ObfuscationFinding> Classify(string text, string callerType, string callerMethod)
    {
        try
        {
            if (text.Length < MinEncodedLength)
                return [];

            var entropy = ShannonEntropy(text);

            // Every scheme whose pattern matches and that decodes to >= 2 bytes, in preference order (base64 first).
            (byte[] decoded, string scheme)[] candidates =
            [
                .. base64Regex.IsMatch(text) && TryDecodeBase64(text) is { Length: >= 2 } b64 ? [(b64, "base64")] : Array.Empty<(byte[], string)>(),
                .. hexRegex.IsMatch(text) && TryDecodeHex(text) is { Length: >= 2 } hex ? [(hex, "hex")] : Array.Empty<(byte[], string)>(),
            ];

            if (candidates.Length == 0)
                return [];

            // Magic-number findings from any decoding that matches a signature.
            var matches = candidates
                .Select(c => ContentType(c.decoded))
                .Where(m => m is not null)
                .Select(m => new ObfuscationFinding(m!.Value.Kind, m.Value.DetectedAs, callerType, callerMethod, text.Length, entropy))
                .ToArray();

            if (matches.Length > 0)
                return matches;

            // Decoded cleanly but matched no signature: report at most one high-entropy blob for the constant,
            // preferring the base64 interpretation when it applied.
            return entropy >= MinEntropyThreshold
                ? [new ObfuscationFinding(HiddenContentKind.HighEntropyBlob, $"high-entropy {candidates[0].scheme}",
                    callerType, callerMethod, text.Length, entropy)]
                : [];
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping obfuscation constant in {0}.{1}: {2}", callerType, callerMethod, ex.Message);
            return [];
        }
    }

    // Base64-decode with round-trip verification: re-encoding must reproduce the exact input, which rejects
    // strings that merely resemble base64 (Defogger technique). Returns null on failure.
    private static byte[]? TryDecodeBase64(string text)
    {
        try
        {
            var bytes = Convert.FromBase64String(text);
            return Convert.ToBase64String(bytes) == text ? bytes : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    // Hex-decode a string matched by hexRegex (optional "0x" prefix, even number of hex digits). All such
    // strings are valid encodings, so no round-trip is needed. Returns null on failure.
    private static byte[]? TryDecodeHex(string text)
    {
        var hex = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? text[2..] : text;
        if (hex.Length % 2 != 0)
            return null;

        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    // Classifies decoded bytes via magic numbers: executables first, then archives. Returns null if unrecognized.
    private static (HiddenContentKind Kind, string DetectedAs)? ContentType(byte[] bytes) =>
        StartsWith(bytes, windowsMagicNumber) ? (HiddenContentKind.EncodedExecutable, "Windows PE")
        : StartsWith(bytes, elfMagicNumber) ? (HiddenContentKind.EncodedExecutable, "ELF")
        : StartsWith(bytes, javaMagicNumber) ? (HiddenContentKind.EncodedExecutable, "Java class / Mach-O fat")
        : macMagicNumbers.Any(m => StartsWith(bytes, m)) ? (HiddenContentKind.EncodedExecutable, "Mach-O")
        : StartsWith(bytes, zipMagicNumber) ? (HiddenContentKind.EncodedArchive, "zip")
        : StartsWith(bytes, gzipMagicNumber) ? (HiddenContentKind.EncodedArchive, "gzip")
        : null;

    private static bool StartsWith(byte[] bytes, byte[] magic) =>
        bytes.Length >= magic.Length && bytes.AsSpan(0, magic.Length).SequenceEqual(magic);

    // Shannon entropy (bits per character) of the raw encoded constant.
    private static double ShannonEntropy(string text) =>
        text.GroupBy(c => c)
            .Select(g => (double)g.Count() / text.Length)
            .Sum(p => -p * Math.Log2(p));
    #endregion

    #region Fields
    // Whole-constant base64: base64 alphabet with optional trailing padding. Anchored so strings with
    // whitespace/punctuation (e.g. plain English) never match, keeping false positives down.
    private static readonly Regex base64Regex = new(
        @"^[A-Za-z0-9+/]+={0,2}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Whole-constant hex: optional "0x" prefix then an even run of hex digits.
    private static readonly Regex hexRegex = new(
        @"^(?:0x)?(?:[A-Fa-f0-9]{2})+$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Executable / archive magic numbers (adapted from OSSGadget DefoggerTool).
    private static readonly byte[] windowsMagicNumber = [0x4D, 0x5A];                   // "MZ"
    private static readonly byte[] elfMagicNumber = [0x7F, 0x45, 0x4C, 0x46];           // 0x7F "ELF"
    private static readonly byte[] javaMagicNumber = [0xCA, 0xFE, 0xBA, 0xBE];          // Java class / Mach-O fat
    private static readonly byte[] zipMagicNumber = [0x50, 0x4B, 0x03, 0x04];           // "PK\x03\x04"
    private static readonly byte[] gzipMagicNumber = [0x1F, 0x8B];                      // gzip

    private static readonly IReadOnlyList<byte[]> macMagicNumbers =
    [
        [0xFE, 0xED, 0xFA, 0xCE],   // 32-bit
        [0xFE, 0xED, 0xFA, 0xCF],   // 64-bit
        [0xCE, 0xFA, 0xED, 0xFE],   // 32-bit reverse byte order
        [0xCF, 0xFA, 0xED, 0xFE],   // 64-bit reverse byte order
    ];
    #endregion
}
