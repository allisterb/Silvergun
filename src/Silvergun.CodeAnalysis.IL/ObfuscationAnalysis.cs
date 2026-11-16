// Portions adapted from OSSGadget (DefoggerTool.cs) — © Microsoft Corporation, MIT License.
// The executable magic-number tables, GetExecutableType classification, and the
// base64-decode-and-round-trip-verify technique are derived from that source. Copy authorized
// 2026-07-16. Source: reference/projects/OSSGadget-main/src/Shared.CLI/Tools/DefoggerTool.cs
namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

using Microsoft.Cci;

using MetadataTokens = System.Reflection.Metadata.Ecma335.MetadataTokens;
using PEReader = System.Reflection.PortableExecutable.PEReader;
using PEReaderExtensions = System.Reflection.Metadata.PEReaderExtensions;

/// <summary>
/// Scans an assembly for hidden/encoded payloads — the "encode a payload so scanners miss it, then decode and run it"
/// pattern (<c>docs/agent/tasks/hidden-payloads-1.md</c>). It reads CCI directly from an <see cref="AssemblyAnalyzer"/>
/// (ADR 0009) and looks in five places (<see cref="HiddenContentSource"/>):
/// <list type="bullet">
/// <item>whole <c>ldstr</c> constants that look base64/hex: decoded, round-trip verified and classified;</item>
/// <item>base64/hex runs inside longer constants, reported only when their content is recognised;</item>
/// <item><c>string.Concat</c> of constants and once-stored static string fields, folded at the IL level;</item>
/// <item>RVA-mapped field data and embedded managed resources, by magic number only.</item>
/// </list>
/// Content is classified by magic number (adapted from OSSGadget's Defogger) as
/// <see cref="HiddenContentKind.EncodedExecutable"/>, <see cref="HiddenContentKind.EncodedArchive"/> or
/// <see cref="HiddenContentKind.EncodedImage"/>, or, for decoded text sources, as <see cref="HiddenContentKind.EncodedText"/>.
/// Long high-entropy whole or folded constants that decode cleanly but match nothing are
/// <see cref="HiddenContentKind.HighEntropyBlob"/>. Detection classifies only — nothing is extracted or run.
/// Never throws: per-method, per-field, per-resource and per-constant failures are skipped, not fatal (ADR 0005).
/// <para>
/// <b>Does NOT share <see cref="AssemblyAnalyzer.StringConstants"/> with <see cref="IndicatorAnalysis"/></b>
/// even though that seam exists and does the identical <c>ldstr</c> walk: <c>SafeNameTests.SafeName_BothConsumers_CallTheSharedSeam</c>
/// pins that this class's own compiled IL calls <see cref="AssemblyAnalyzer.SafeName"/> directly (a structural
/// guard against a private, divergence-prone copy of the fallback reappearing here). This scan also needs more of
/// each body than the seam gives (stores, tokens, calls), so it keeps its own guarded walk.
/// </para>
/// </summary>
public sealed class ObfuscationAnalysis(AssemblyAnalyzer assembly)
{
    #region Properties
    /// <summary>Minimum Shannon entropy (bits/char) for an encoded constant to count as a high-entropy blob.</summary>
    public static double MinEntropyThreshold { get; } = 4.0;

    /// <summary>Minimum length of an encoded constant or run to be considered a candidate (shorter strings are ignored).</summary>
    public static int MinEncodedLength { get; } = 24;

    /// <summary>Minimum decoded length for <see cref="HiddenContentKind.EncodedText"/>.</summary>
    public static int MinTextBytes { get; } = 16;

    /// <summary>Bytes read from one field's RVA data or one resource.</summary>
    public static int MaxBlobBytes { get; } = 64 * 1024;

    /// <summary>Bytes read from all field data and resources of one assembly; past it the rest are not read (<see cref="ObfuscationReport.Truncated"/>).</summary>
    public static long MaxBlobBytesPerAssembly { get; } = 16L * 1024 * 1024;

    /// <summary>Longest folded <c>string.Concat</c> result kept.</summary>
    public static int MaxFoldedChars { get; } = 1024 * 1024;

    /// <summary>Chars built by folding in one module; past it nothing more is folded (<see cref="ObfuscationReport.Truncated"/>).</summary>
    public static long MaxFoldedCharsPerModule { get; } = 8L * 1024 * 1024;
    #endregion

    #region Methods
    /// <summary>
    /// Scans constants, folded concatenations, field data and resources, and produces a serializable
    /// <see cref="ObfuscationReport"/>. Findings are deduplicated on the full tuple and ordered deterministically by
    /// (CallerType, CallerMethod, DetectedAs, Kind, Source) with <see cref="StringComparer.Ordinal"/>. Never throws.
    /// </summary>
    public Result<ObfuscationReport> Analyze()
    {
        try
        {
            // Materialize inside the guard: enumerating assembly.Methods advances CCI's lazy type resolution, which can
            // throw on a corrupt/hostile module — the outer catch upholds the never-throws contract even for a top-level
            // enumeration failure. Method bodies are NOT read by that enumeration (see AssemblyAnalyzer.Methods):
            // ScanMethod reads each one under its own guard, so one unreadable body loses only that method.
            var facts = new ModuleFacts(assembly.AssemblyPath);
            var constants = assembly.Methods.SelectMany(m => ScanMethod(m, facts)).ToArray();
            var known = facts.KnownFields();
            var findings = constants
                .Concat(facts.ConcatCallers.SelectMany(m => FoldMethod(m, known, facts)).ToArray())
                .Concat(ScanFieldData(facts))
                .Concat(ScanResources(facts))
                .Distinct()
                .OrderBy(f => f.CallerType, StringComparer.Ordinal)
                .ThenBy(f => f.CallerMethod, StringComparer.Ordinal)
                .ThenBy(f => f.DetectedAs, StringComparer.Ordinal)
                .ThenBy(f => f.Kind)
                .ThenBy(f => f.Source)
                .ToArray();

            return Result.Success(new ObfuscationReport(assembly.AssemblyName, assembly.AssemblyPath, DateTimeOffset.UtcNow, findings, facts.Truncated));
        }
        catch (Exception ex)
        {
            return Result.FailureWithError<ObfuscationReport>($"Failed to analyze {assembly.AssemblyName}.", ex);
        }
    }

    // Scans one method's operations: classifies each ldstr constant, and records into facts (only if the whole walk
    // succeeds) its ldstr;stsfld pairs, static stores, ldtoken'd fields and whether it calls string.Concat. Skips (never
    // throws) a method whose body cannot be read or whose scan throws.
    private static IReadOnlyList<ObfuscationFinding> ScanMethod(IMethodDefinition method, ModuleFacts facts)
    {
        // Guarded body read: assembly.Methods yields body-read CANDIDATES, so the dereference a hostile module can make
        // throw happens here, per method, and costs only this method.
        var read = AssemblyAnalyzer.TryReadBody(method);
        if (read.Body is null)
        {
            if (read.Error is { } error)
                Runtime.Warn("Skipping obfuscation scan of method {0}: {1}", AssemblyAnalyzer.SafeName(method), error);
            return [];
        }

        // The constants' findings do not depend on the fact reads below: a throwing stsfld/ldtoken/call read keeps the
        // findings so far and only skips committing this method's facts.
        var found = new List<ObfuscationFinding>();
        try
        {
            var callerType = CallerType(method);
            var callerMethod = method.Name.Value;
            var ops = read.Body.Operations.ToArray();
            var local = new MethodFacts();
            for (var i = 0; i < ops.Length; i++)
            {
                switch (ops[i])
                {
                    case { OperationCode: OperationCode.Ldstr, Value: string text }:
                        found.AddRange(Classify(text, callerType, callerMethod, HiddenContentSource.Constant, facts));
                        // A constant longer than MaxFoldedChars can never take part in a kept fold.
                        if (text.Length <= MaxFoldedChars && i + 1 < ops.Length && ops[i + 1] is { OperationCode: OperationCode.Stsfld, Value: IFieldReference target })
                            local.Constants.Add((FieldKey(target), text));
                        break;
                    case { OperationCode: OperationCode.Stsfld, Value: IFieldReference stored }:
                        local.Stores.Add(FieldKey(stored));
                        break;
                    case { OperationCode: OperationCode.Ldtoken, Value: IFieldReference token }:
                        local.Tokens.Add(FieldKey(token));
                        break;
                    case { OperationCode: OperationCode.Call, Value: IMethodReference callee } when ConcatArity(callee) > 0:
                        local.CallsConcat = true;
                        break;
                }
            }

            facts.Add(method, (callerType, callerMethod), local);
            return found;
        }
        catch (Exception ex)
        {
            // AssemblyAnalyzer.SafeName, not method.Name.Value: reading the name here can itself throw on a crafted
            // module, and that throw would escape this per-method guard and fail the whole analysis.
            Runtime.Warn("Skipping obfuscation scan of method {0}: {1}", AssemblyAnalyzer.SafeName(method), ex.Message);
            return found;
        }
    }

    // Pass 2 over a method that calls string.Concat: a straight-line abstract stack of known strings (ldstr, ldsfld of a
    // known field), cleared by any other operation and at every branch or handler target. Each Concat whose arguments
    // are all known builds a folded constant, charged to the module's fold budget; only the last Concat of a chain (one
    // no later Concat consumes) is kept and classified, with Source = Folded. The fold can over-claim (stores through
    // ldsflda or in unreadable bodies are not counted) but never gates, so that only costs precision.
    private static IReadOnlyList<ObfuscationFinding> FoldMethod(IMethodDefinition method, IReadOnlyDictionary<(string, string), string> known, ModuleFacts facts)
    {
        var read = AssemblyAnalyzer.TryReadBody(method);
        if (read.Body is null)
            return [];

        try
        {
            var ops = read.Body.Operations.ToArray();
            var targets = Targets(read.Body, ops);
            // Each entry: the known string (null if unknown) and, for a fold result, its index in folded.
            var stack = new List<(string? Text, int Fold)>();
            var folded = new List<string?>();
            foreach (var op in ops)
            {
                if (targets.Contains(op.Offset))
                    stack.Clear();
                switch (op)
                {
                    case { OperationCode: OperationCode.Ldstr, Value: string text }:
                        stack.Add((text, -1));
                        break;
                    case { OperationCode: OperationCode.Ldsfld, Value: IFieldReference field }:
                        stack.Add((known.GetValueOrDefault(FieldKey(field)), -1));
                        break;
                    case { OperationCode: OperationCode.Call, Value: IMethodReference callee } when ConcatArity(callee) is var n and > 0 && stack.Count >= n:
                        var args = stack.GetRange(stack.Count - n, n);
                        stack.RemoveRange(stack.Count - n, n);
                        var length = args.Sum(a => (long)(a.Text?.Length ?? 0));
                        var value = args.All(a => a.Text is not null) && length <= MaxFoldedChars && facts.ChargeFold(length)
                            ? string.Concat(args.Select(a => a.Text))
                            : null;
                        if (value is not null)
                        {
                            // A fold result consumed by a fold that succeeded is an intermediate: drop it so only the
                            // chain's end is kept. One consumed by a failed fold is the end of what is known, so it stays.
                            foreach (var arg in args.Where(a => a.Fold >= 0))
                                folded[arg.Fold] = null;
                            folded.Add(value);
                        }
                        stack.Add((value, value is null ? -1 : folded.Count - 1));
                        break;
                    default:
                        stack.Clear();
                        break;
                }
            }

            var kept = folded.OfType<string>().Distinct(StringComparer.Ordinal).ToArray();
            if (kept.Length == 0)
                return [];
            var callerType = CallerType(method);
            var callerMethod = method.Name.Value;
            return kept.SelectMany(text => Classify(text, callerType, callerMethod, HiddenContentSource.Folded, facts)).ToArray();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping obfuscation fold of method {0}: {1}", AssemblyAnalyzer.SafeName(method), ex.Message);
            return [];
        }
    }

    // Branch, switch and exception-handler targets: where a straight-line stack is not known to hold.
    private static HashSet<uint> Targets(IMethodBody body, IOperation[] ops)
    {
        var targets = new HashSet<uint>();
        foreach (var op in ops)
        {
            if (op.Value is uint target)
                targets.Add(target);
            else if (op.Value is uint[] cases)
                targets.UnionWith(cases);
        }
        foreach (var handler in body.OperationExceptionInformation ?? [])
        {
            targets.Add(handler.TryStartOffset);
            targets.Add(handler.HandlerStartOffset);
            targets.Add(handler.FilterDecisionStartOffset);
        }
        return targets;
    }

    // Every RVA-mapped field's data, by magic number, attributed to the methods that ldtoken it.
    private IReadOnlyList<ObfuscationFinding> ScanFieldData(ModuleFacts facts)
    {
        INamedTypeDefinition[] types;
        try
        {
            types = assembly.Module.GetAllTypes().ToArray();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping field-data scan of {0}: {1}", assembly.AssemblyName, ex.Message);
            return [];
        }
        return types.SelectMany(type => FieldsOf(type).SelectMany(field => ScanField(field, facts))).ToArray();
    }

    private static IReadOnlyList<IFieldDefinition> FieldsOf(INamedTypeDefinition type)
    {
        try
        {
            return type.Fields.ToArray();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping the fields of a type: {0}", ex.Message);
            return [];
        }
    }

    // One mapped field's data. Fields aliasing one block share one read and, unless something ldtokens them, one finding;
    // reads are charged to the assembly's blob budget.
    private static IReadOnlyList<ObfuscationFinding> ScanField(IFieldDefinition field, ModuleFacts facts)
    {
        try
        {
            if (!field.IsMapped || !SizedWithoutRecursion(field.Type))
                return [];
            var block = field.FieldMapping;
            // Keyed by the field's RVA, not the block's section-relative offset: section kinds are not unique (.data and
            // .datax; two sections named .text), so equal offsets in different sections would share a read.
            var rva = facts.FieldRva(field);
            var (blob, seen) = facts.Blob(rva is { } r ? (r, block.Size) : null, () => block.Data);
            if (blob is not { Content: { } content } read)
                return [];
            var key = FieldKey(field);
            var users = facts.TokenUsers(key);
            if (users.Count == 0 && seen)
                return [];
            var callers = users.Count > 0 ? users.Take(MaxCallersPerBlob) : [(key.Type, UntrustedText.Escape(key.Field))];
            return callers
                .Select(c => new ObfuscationFinding(content.Kind, content.DetectedAs, c.Type, c.Method, read.Length, read.Entropy, HiddenContentSource.FieldData))
                .ToArray();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping the data of a mapped field: {0}", ex.Message);
            return [];
        }
    }

    // Whether CCI can size a field of this type (GetFieldMapping) without TypeHelper.TypeAlignment's recursion, whose
    // only cycle guard is a struct containing itself directly: mutually recursive structs overflow the stack, which
    // cannot be caught. Only sized primitives and non-enum, non-generic definitions with an explicit ClassLayout size (as
    // every compiler-generated __StaticArrayInitTypeSize=N has) are admitted; references are rejected (see below).
    private static bool SizedWithoutRecursion(ITypeReference type)
    {
        // The codes GetFieldSizeIfPossibleToDoSoWithoutResolving answers directly, before looking at the type.
        if (type.TypeCode is PrimitiveTypeCode.Boolean or PrimitiveTypeCode.Char or PrimitiveTypeCode.Int8 or PrimitiveTypeCode.UInt8
            or PrimitiveTypeCode.Int16 or PrimitiveTypeCode.UInt16 or PrimitiveTypeCode.Int32 or PrimitiveTypeCode.UInt32
            or PrimitiveTypeCode.Int64 or PrimitiveTypeCode.UInt64 or PrimitiveTypeCode.IntPtr or PrimitiveTypeCode.UIntPtr
            or PrimitiveTypeCode.Float32 or PrimitiveTypeCode.Float64 or PrimitiveTypeCode.Pointer)
            return true;
        if (type is IModifiedTypeReference modified)
            type = modified.UnmodifiedType;
        // Anything else must be a non-enum definition with a ClassLayout size (as every compiler-generated
        // __StaticArrayInitTypeSize=N is). A reference (a TypeRef, a generic instance) is skipped: CCI sizes it 0 and then
        // finds the next RVA by linear scans of the FieldRVA and Method tables, per field, quadratic in a crafted module.
        return type is ITypeDefinition definition and not IGenericTypeInstanceReference && !definition.IsEnum && definition.SizeOf > 0;
    }

    // Every embedded managed resource, by magic number. Only a resource defined in this assembly's own resource section
    // is read: one implemented by a File (CCI opens it from disk) or an AssemblyRef (CCI loads that assembly from the
    // package's folder and recurses, unbounded on a cycle) is skipped without being resolved.
    private IReadOnlyList<ObfuscationFinding> ScanResources(ModuleFacts facts)
    {
        IResourceReference[] resources;
        try
        {
            resources = assembly.Module is IAssembly unit ? unit.Resources.ToArray() : [];
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping resource scan of {0}: {1}", assembly.AssemblyName, ex.Message);
            return [];
        }
        return resources.SelectMany(r => ScanResource(r, facts)).ToArray();
    }

    private static IReadOnlyList<ObfuscationFinding> ScanResource(IResourceReference reference, ModuleFacts facts)
    {
        try
        {
            // Local rows are IResource themselves; reading reference.Resource would resolve an AssemblyRef one.
            if (reference is not IResource resource || resource.IsInExternalFile)
                return [];
            var (blob, _) = facts.Blob(null, () => resource.Data);
            return blob is { Content: { } content } read
                ? [new ObfuscationFinding(content.Kind, content.DetectedAs, ResourceCaller, UntrustedText.Escape(reference.Name.Value),
                    read.Length, read.Entropy, HiddenContentSource.Resource)]
                : [];
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping an embedded resource: {0}", ex.Message);
            return [];
        }
    }

    // Best-effort namespace-qualified type name of the method's containing type ("<unknown>" if CCI cannot resolve it).
    private static string CallerType(IMethodDefinition method)
    {
        try { return AssemblyAnalyzer.TypeName(method.ContainingTypeDefinition); }
        catch { return "<unknown>"; }
    }

    // A field's identity across definitions and references: (declaring type name, field name).
    private static (string Type, string Field) FieldKey(IFieldReference field) =>
        (AssemblyAnalyzer.TypeName(field.ContainingType), field.Name.Value);

    // The string-parameter count of a platform string.Concat(string, ...) overload with 2–4 parameters, else 0.
    private static int ConcatArity(IMethodReference method) =>
        method.Name.Value == "Concat" && method.ContainingType.TypeCode == PrimitiveTypeCode.String
        && method.ParameterCount is >= 2 and <= 4 && method.Parameters.All(p => p.Type.TypeCode == PrimitiveTypeCode.String)
            ? method.ParameterCount
            : 0;

    // Decode-and-classify one string, memoised per (text, source) for the module. Any failure drops the string without
    // failing the analysis.
    private static IReadOnlyList<ObfuscationFinding> Classify(string text, string callerType, string callerMethod, HiddenContentSource source, ModuleFacts facts)
    {
        try
        {
            if (text.Length < MinEncodedLength)
                return [];
            return facts.Contents(text, source, () => Contents(text, source))
                .Select(c => new ObfuscationFinding(c.Kind, c.DetectedAs, callerType, callerMethod, c.Length, c.Entropy, c.Source))
                .ToArray();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping obfuscation constant in {0}.{1}: {2}", callerType, callerMethod, ex.Message);
            return [];
        }
    }

    // The whole text (with the high-entropy fallback), then each base64/hex run inside it, reported only when recognised:
    // Source = Substring for a constant's run, Folded for a folded text's (whose parts are not one ldstr). A "path/<b64>"
    // or "a+<b64>" prefix joins the run, so an unrecognised run is retried after each of its first MaxRunRetries '/' or
    // '+', left to right (a payload's own base64 holds them too: a PE's starts "TVqQAAMAAAAEAAAA//8A"), until one is.
    private static IReadOnlyList<Content> Contents(string text, HiddenContentSource source)
    {
        var found = new List<Content>(Whole(text, source));
        var runSource = source == HiddenContentSource.Folded ? HiddenContentSource.Folded : HiddenContentSource.Substring;
        foreach (var run in Runs(text).Where(r => r.Length < text.Length))
        {
            var recognised = Recognised(run, runSource);
            for (int cut = -1, tries = 0; recognised.Count == 0 && tries < MaxRunRetries; tries++)
            {
                cut = run.IndexOfAny(['/', '+'], cut + 1);
                if (cut < 0 || run.Length - cut - 1 < MinEncodedLength)
                    break;
                recognised = Recognised(run[(cut + 1)..], runSource);
            }
            found.AddRange(recognised);
        }
        return found;
    }

    private static IReadOnlyList<Content> Recognised(string run, HiddenContentSource source) =>
        Decodings(run)
            .Select(c => TextContent(c.Decoded))
            .Where(m => m is not null)
            .Select(m => new Content(m!.Value.Kind, m.Value.DetectedAs, run.Length, ShannonEntropy(run), source))
            .ToArray();

    // A whole text: every applicable decoding (lowercase hex is also valid base64, so both are tried) is classified;
    // with no recognised content, at most one high-entropy blob, preferring the base64 interpretation.
    private static IReadOnlyList<Content> Whole(string text, HiddenContentSource source)
    {
        var candidates = Decodings(text);
        if (candidates.Count == 0)
            return [];

        var entropy = ShannonEntropy(text);
        var matches = candidates
            .Select(c => TextContent(c.Decoded))
            .Where(m => m is not null)
            .Select(m => new Content(m!.Value.Kind, m.Value.DetectedAs, text.Length, entropy, source))
            .ToArray();
        if (matches.Length > 0)
            return matches;

        return entropy >= MinEntropyThreshold
            ? [new Content(HiddenContentKind.HighEntropyBlob, $"high-entropy {candidates[0].Scheme}", text.Length, entropy, source)]
            : [];
    }

    // Every scheme whose pattern matches and that decodes to >= 2 bytes, in preference order (base64 first).
    private static IReadOnlyList<(byte[] Decoded, string Scheme)> Decodings(string text) =>
    [
        .. base64Regex.IsMatch(text) && TryDecodeBase64(text) is { Length: >= 2 } b64 ? [(b64, "base64")] : Array.Empty<(byte[], string)>(),
        .. hexRegex.IsMatch(text) && TryDecodeHex(text) is { Length: >= 2 } hex ? [(hex, "hex")] : Array.Empty<(byte[], string)>(),
    ];

    // The maximal runs of base64-alphabet characters, with at most two '=' only as trailing padding (so "key=<b64>"
    // splits at the '='), at least MinEncodedLength long.
    private static IEnumerable<string> Runs(string text) =>
        runRegex.Matches(text).Select(m => m.Value).Where(r => r.Length >= MinEncodedLength);

    // Base64-decode with round-trip verification: re-encoding must reproduce the exact input, which rejects
    // strings that merely resemble base64 (Defogger technique). Returns null on failure.
    private static byte[]? TryDecodeBase64(string text)
    {
        // A length that is not a multiple of 4 never round-trips; checked first so such runs cost no exception.
        if (text.Length % 4 != 0)
            return null;
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

    // Decoded text content: magic numbers, then text. Null if unrecognised.
    private static (HiddenContentKind Kind, string DetectedAs)? TextContent(byte[] bytes) =>
        MagicContent(bytes, strictPe: false) ?? (TextKind(bytes) is { } text ? (HiddenContentKind.EncodedText, text) : null);

    // Raw blob content: magic numbers only, with a PE needing its "PE\0\0" header, since tables of ordinary data can
    // start with "MZ". Null if unrecognised.
    private static (HiddenContentKind Kind, string DetectedAs)? BlobContent(byte[] bytes) => MagicContent(bytes, strictPe: true);

    // Executables first, then archives, then images. Returns null if unrecognized.
    private static (HiddenContentKind Kind, string DetectedAs)? MagicContent(byte[] bytes, bool strictPe) =>
        StartsWith(bytes, windowsMagicNumber) && (!strictPe || HasPeHeader(bytes)) ? (HiddenContentKind.EncodedExecutable, "Windows PE")
        : StartsWith(bytes, elfMagicNumber) ? (HiddenContentKind.EncodedExecutable, "ELF")
        : StartsWith(bytes, javaMagicNumber) ? (HiddenContentKind.EncodedExecutable, "Java class / Mach-O fat")
        : macMagicNumbers.Any(m => StartsWith(bytes, m)) ? (HiddenContentKind.EncodedExecutable, "Mach-O")
        : StartsWith(bytes, zipMagicNumber) ? (HiddenContentKind.EncodedArchive, "zip")
        : StartsWith(bytes, gzipMagicNumber) ? (HiddenContentKind.EncodedArchive, "gzip")
        : ImageKind(bytes) is { } image ? (HiddenContentKind.EncodedImage, image)
        : null;

    // e_lfanew (offset 0x3C) points inside the bytes at "PE\0\0".
    private static bool HasPeHeader(byte[] bytes)
    {
        if (bytes.Length < 0x40)
            return false;
        var offset = BitConverter.ToInt32(bytes, 0x3C);
        return offset >= 0x40 && offset <= bytes.Length - 4 && bytes.AsSpan(offset, 4).SequenceEqual(peSignature);
    }

    private static string? ImageKind(byte[] bytes) =>
        StartsWith(bytes, pngMagicNumber) ? "PNG"
        : StartsWith(bytes, jpegMagicNumber) ? "JPEG"
        : StartsWith(bytes, gif87MagicNumber) || StartsWith(bytes, gif89MagicNumber) ? "GIF"
        : bytes.Length >= 12 && StartsWith(bytes, riffMagicNumber) && bytes.AsSpan(8, 4).SequenceEqual(webpMagicNumber) ? "WebP"
        : IsIcon(bytes) ? "ICO"
        : null;

    // ICO: reserved 0, type 1, then 1–64 directory entries of 16 bytes that fit in the bytes read, each with a zero
    // reserved byte, 0 or 1 planes, a real bit depth, and image data after the directory (so a ushort table 0, 1, 2, …
    // is not an icon).
    private static bool IsIcon(byte[] bytes)
    {
        if (bytes.Length < 6 || !StartsWith(bytes, icoMagicNumber))
            return false;
        var count = BitConverter.ToUInt16(bytes, 4);
        if (count is < 1 or > 64)
            return false;
        var directory = 6 + 16 * count;
        return bytes.Length >= directory && Enumerable.Range(0, count).All(i =>
        {
            var entry = 6 + 16 * i;
            return bytes[entry + 3] == 0
                && BitConverter.ToUInt16(bytes, entry + 4) <= 1
                && BitConverter.ToUInt16(bytes, entry + 6) is 0 or 1 or 4 or 8 or 16 or 24 or 32
                && BitConverter.ToUInt32(bytes, entry + 12) >= (uint)directory;
        });
    }

    // UTF-16LE (the PowerShell -EncodedCommand form) or strict UTF-8 text, at least MinTextBytes long.
    private static string? TextKind(byte[] bytes)
    {
        if (bytes.Length < MinTextBytes)
            return null;
        if (bytes.Length % 2 == 0 && Enumerable.Range(0, bytes.Length / 2).All(i => bytes[2 * i + 1] == 0 && IsPrintableAscii(bytes[2 * i])))
            return "UTF-16LE text";
        try
        {
            var text = strictUtf8.GetString(bytes);
            return !text.Contains('\0') && text.Count(c => !char.IsControl(c) || c is '\t' or '\r' or '\n') >= text.Length * 0.95
                ? "UTF-8 text"
                : null;
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static bool IsPrintableAscii(byte b) => b is >= 0x20 and <= 0x7E or 0x09 or 0x0A or 0x0D;

    private static bool StartsWith(byte[] bytes, byte[] magic) =>
        bytes.Length >= magic.Length && bytes.AsSpan(0, magic.Length).SequenceEqual(magic);

    // Shannon entropy (bits per character) of an encoded text.
    private static double ShannonEntropy(string text) =>
        text.GroupBy(c => c)
            .Select(g => (double)g.Count() / text.Length)
            .Sum(p => -p * Math.Log2(p));

    // Shannon entropy (bits per byte) of a blob; 0 for an empty one.
    private static double ShannonEntropy(byte[] bytes) =>
        bytes.Length == 0 ? 0 : bytes.GroupBy(b => b)
            .Select(g => (double)g.Count() / bytes.Length)
            .Sum(p => -p * Math.Log2(p));
    #endregion

    #region Fields
    private const string ResourceCaller = "<resource>";

    // Methods named per field-data finding: aliased blobs loaded from many methods do not multiply findings without bound.
    private const int MaxCallersPerBlob = 16;

    // Bytes of a blob read before recognition decides whether to read more.
    private const int BlobHeaderBytes = 64;

    // Blob reads per assembly (unkeyed and distinct-key ones): bounds the enumeration that decoys cost, beyond the byte
    // budget; past it the rest are not read (Truncated).
    private const int MaxBlobReads = 4096;

    // Cut positions ('/' or '+', from the left) at which an unrecognised run is retried.
    private const int MaxRunRetries = 8;

    private static readonly UTF8Encoding strictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    // Whole-constant base64: base64 alphabet with optional trailing padding. Anchored so strings with
    // whitespace/punctuation (e.g. plain English) never match, keeping false positives down.
    private static readonly Regex base64Regex = new(
        @"^[A-Za-z0-9+/]+={0,2}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // A base64 run inside a longer constant: '=' only as up to two trailing padding characters.
    private static readonly Regex runRegex = new(
        @"[A-Za-z0-9+/]+={0,2}", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Whole-constant hex: optional "0x" prefix then an even run of hex digits.
    private static readonly Regex hexRegex = new(
        @"^(?:0x)?(?:[A-Fa-f0-9]{2})+$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Executable / archive magic numbers (adapted from OSSGadget DefoggerTool).
    private static readonly byte[] windowsMagicNumber = [0x4D, 0x5A];                   // "MZ"
    private static readonly byte[] peSignature = [0x50, 0x45, 0x00, 0x00];              // "PE\0\0"
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

    // Image magic numbers.
    private static readonly byte[] pngMagicNumber = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private static readonly byte[] jpegMagicNumber = [0xFF, 0xD8, 0xFF];
    private static readonly byte[] gif87MagicNumber = "GIF87a"u8.ToArray();
    private static readonly byte[] gif89MagicNumber = "GIF89a"u8.ToArray();
    private static readonly byte[] riffMagicNumber = "RIFF"u8.ToArray();
    private static readonly byte[] webpMagicNumber = "WEBP"u8.ToArray();
    private static readonly byte[] icoMagicNumber = [0x00, 0x00, 0x01, 0x00];
    #endregion

    #region Child types
    // What one method's walk recorded; committed to ModuleFacts only when the walk finished.
    private sealed class MethodFacts
    {
        public List<((string Type, string Field) Key, string Text)> Constants { get; } = [];
        public List<(string Type, string Field)> Stores { get; } = [];
        public List<(string Type, string Field)> Tokens { get; } = [];
        public bool CallsConcat { get; set; }
    }

    // A recognised content, independent of where it was found.
    private readonly record struct Content(HiddenContentKind Kind, string DetectedAs, int Length, double Entropy, HiddenContentSource Source);

    // What one blob read gave: its content (null if unrecognised), the bytes read and their entropy.
    private sealed record BlobRead((HiddenContentKind Kind, string DetectedAs)? Content, int Length, double Entropy);

    // Module-wide state: pass 1's facts (static stores, ldstr;stsfld constants, ldtoken users, Concat callers), the
    // classification memo, and the blob and fold budgets.
    private sealed class ModuleFacts(string assemblyPath)
    {
        #region Properties
        public List<IMethodDefinition> ConcatCallers { get; } = [];

        /// <summary>Whether a blob or fold budget was spent, so some content was not read or folded.</summary>
        public bool Truncated { get; private set; }
        #endregion

        #region Methods
        public void Add(IMethodDefinition method, (string Type, string Method) caller, MethodFacts local)
        {
            foreach (var key in local.Stores)
                stores[key] = stores.GetValueOrDefault(key) + 1;
            // Pooled: CCI allocates a fresh string per ldstr read, so N fields stored from one constant share one copy.
            foreach (var (key, text) in local.Constants)
                constants[key] = pool.TryGetValue(text, out var pooled) ? pooled : pool[text] = text;
            foreach (var key in local.Tokens.Distinct())
            {
                if (!tokenUsers.TryGetValue(key, out var users))
                    tokenUsers[key] = users = [];
                users.Add(caller);
            }
            if (local.CallsConcat)
                ConcatCallers.Add(method);
        }

        // The static fields stored exactly once in the module, by an ldstr;stsfld pair.
        public IReadOnlyDictionary<(string, string), string> KnownFields() =>
            constants.Where(c => stores.GetValueOrDefault(c.Key) == 1).ToDictionary(c => c.Key, c => c.Value);

        public IReadOnlyList<(string Type, string Method)> TokenUsers((string, string) key) =>
            tokenUsers.TryGetValue(key, out var users) ? users : [];

        // The contents of (text, source), computed once per module.
        public IReadOnlyList<Content> Contents(string text, HiddenContentSource source, Func<IReadOnlyList<Content>> compute)
        {
            if (!contents.TryGetValue((text, source), out var found))
                contents[(text, source)] = found = compute();
            return found;
        }

        // Charges a fold of length chars to the module's budget; false (and Truncated) once it is spent.
        public bool ChargeFold(long length)
        {
            if (foldedChars + length > MaxFoldedCharsPerModule)
            {
                Truncated = true;
                return false;
            }
            foldedChars += length;
            return true;
        }

        // A mapped field's RVA from its FieldRVA row (System.Reflection.Metadata over the same file, read once), or null
        // when it cannot be read. A crafted field with two FieldRVA rows may get a different row here than in CCI's
        // read; that only mis-keys the memo for that field, a precision cost.
        public int? FieldRva(IFieldDefinition field)
        {
            fieldRvas ??= ReadFieldRvas(assemblyPath);
            return field is IMetadataObjectWithToken { TokenValue: var token } && token >> 24 == 0x04
                && fieldRvas.TryGetValue((int)(token & 0xFFFFFF), out var rva) ? rva : null;
        }

        // Reads a blob and classifies it, charging every byte kept to the assembly's budget. Only what recognition needs
        // is read first (BlobHeaderBytes; for an MZ, the 4 bytes at e_lfanew, skipping the rest; for an ICO, its
        // directory), and the rest (to MaxBlobBytes) only for recognised content, so an unrecognised decoy costs at most
        // about 1 KB.
        // A keyed blob is read once: a later request for the same key returns the first read, with seen = true.
        public (BlobRead? Read, bool Seen) Blob((int, uint)? key, Func<IEnumerable<byte>> data)
        {
            if (key is { } k && blobs.TryGetValue(k, out var known))
                return (known, true);
            if (++blobReads > MaxBlobReads)
            {
                Truncated = true;
                return (null, false);
            }
            var head = Take(data, BlobHeaderBytes);
            if (head is null)
                return (null, false);
            (HiddenContentKind Kind, string DetectedAs)? content = IsPortableExecutable(head, data) switch
            {
                true => (HiddenContentKind.EncodedExecutable, "Windows PE"),
                false => null,
                null => BlobContent(IcoDirectory(head, data) ?? head),
            };
            var bytes = content is null ? head : Take(data, MaxBlobBytes) ?? head;
            var read = new BlobRead(content, bytes.Length, ShannonEntropy(bytes));
            if (key is { } stored)
                blobs[stored] = read;
            return (read, false);
        }

        // Up to count bytes of data, charged to the budget; null (and Truncated) once the budget is spent.
        private byte[]? Take(Func<IEnumerable<byte>> data, int count)
        {
            var allowance = (int)Math.Min(count, MaxBlobBytesPerAssembly - blobBytes);
            if (allowance <= 0)
            {
                Truncated = true;
                return null;
            }
            var bytes = data().Take(allowance).ToArray();
            blobBytes += bytes.Length;
            if (allowance < count && bytes.Length == allowance)
                Truncated = true;
            return bytes;
        }

        // For a blob starting "MZ": whether e_lfanew points (within MaxBlobBytes) at "PE\0\0"; null when it does not start
        // "MZ". Only the 4 signature bytes are charged: what is skipped to reach them is enumerated, not kept, so a
        // far-e_lfanew decoy costs a few bytes of budget, like any other decoy (MaxBlobReads bounds the enumeration).
        private bool? IsPortableExecutable(byte[] head, Func<IEnumerable<byte>> data)
        {
            if (!StartsWith(head, windowsMagicNumber))
                return null;
            if (head.Length < 0x40)
                return false;
            var lfanew = BitConverter.ToInt32(head, 0x3C);
            return lfanew >= 0x40 && lfanew <= MaxBlobBytes - 4 && Charge(4)
                && data().Skip(lfanew).Take(4).SequenceEqual(peSignature);
        }

        // For a blob starting with ICO magic, its header through the entry directory (at most 1030 bytes); else null.
        private byte[]? IcoDirectory(byte[] head, Func<IEnumerable<byte>> data) =>
            head.Length >= 6 && StartsWith(head, icoMagicNumber) && BitConverter.ToUInt16(head, 4) is var count and >= 1 and <= 64
                && 6 + 16 * count > head.Length
                ? Take(data, 6 + 16 * count)
                : null;

        // Charges count bytes to the budget without reading them; false (and Truncated) once it is spent.
        private bool Charge(int count)
        {
            if (blobBytes + count > MaxBlobBytesPerAssembly)
            {
                Truncated = true;
                return false;
            }
            blobBytes += count;
            return true;
        }

        private static Dictionary<int, int> ReadFieldRvas(string path)
        {
            try
            {
                using var stream = File.OpenRead(path);
                using var pe = new PEReader(stream);
                var metadata = PEReaderExtensions.GetMetadataReader(pe);
                return metadata.FieldDefinitions
                    .Select(h => (Row: MetadataTokens.GetRowNumber(h), Rva: metadata.GetFieldDefinition(h).GetRelativeVirtualAddress()))
                    .Where(f => f.Rva > 0)
                    .ToDictionary(f => f.Row, f => f.Rva);
            }
            catch (Exception ex)
            {
                Runtime.Warn("Field RVAs unavailable for {0}: {1}", path, ex.Message);
                return [];
            }
        }
        #endregion

        #region Fields
        private readonly Dictionary<(string, string), int> stores = [];
        private readonly Dictionary<(string, string), string> constants = [];
        private readonly Dictionary<string, string> pool = new(StringComparer.Ordinal);
        private readonly Dictionary<(string, string), List<(string Type, string Method)>> tokenUsers = [];
        // Every distinct classified text, for the module's life: bounded by the #US heap plus the fold budget.
        private readonly Dictionary<(string, HiddenContentSource), IReadOnlyList<Content>> contents = [];
        private readonly Dictionary<(int, uint), BlobRead> blobs = [];
        private readonly string assemblyPath = assemblyPath;
        private Dictionary<int, int>? fieldRvas;
        private long blobBytes;
        private int blobReads;
        private long foldedChars;
        #endregion
    }
    #endregion
}
