namespace Silvergun.MCPServer;

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// The IL tools (task S3): a completed job's methods and string constants, served from the row files its child wrote, and one
/// method's CIL, listed by an inspect child per call and fenced (D6). Tokens join them to each other and to findings.
/// </summary>
public sealed partial class DrillTools
{
    #region Methods
    [McpServerTool(Name = ToolNames.ListMembers, Title = "List an assembly's methods", ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("The methods of one assembly of a completed job: token (pass it to disassemble), type, name, id (with its signature), "
        + "visibility, static, virtual and abstract (present only when true), special (constructor, typeInitializer, finalizer, pinvoke, nativeExport), body "
        + "and ilBytes, and counts of the findings that name the method (capabilities, indicators, hiddenContent; absent means "
        + "none). pass says how many assemblies were read. Paged: while truncated is true, call again with cursor set to next. "
        + UntrustedNote)]
    public CallToolResult ListMembers(
        [Description("The jobId from analyze_package.")] string jobId,
        [Description("The assembly, by its list_files path (the untrusted value).")] string assembly,
        [Description("Only methods whose type contains this, case-insensitive, as served (escaped: a backslash is doubled), e.g. \"Installer\".")] string? typePattern = null,
        [Description("The next value of the previous page; omit it for the first page.")] string? cursor = null)
    {
        var elapsed = Stopwatch.StartNew();
        if (string.IsNullOrEmpty(assembly) || TooLong(assembly) || TooLong(typePattern) || TooLong(cursor))
            return Invalid(ToolNames.ListMembers, elapsed, $"assembly is required; assembly, typePattern and cursor are at most {MaxArgumentChars} chars");
        var (entry, refusal) = Open(ToolNames.ListMembers, jobId, elapsed);
        if (entry is null)
            return refusal!;

        var list = entry.Index["members"]!.AsObject();
        bool Keep(JsonObject row) =>
            RowFile.UntrustedValue(row, "assembly") == assembly
            && (typePattern is not { Length: > 0 } || RowFile.UntrustedValue(row, "type")?.Contains(typePattern, StringComparison.OrdinalIgnoreCase) == true);
        var data = Data(entry);
        data["pass"] = list["pass"]!.DeepClone();
        // Every row is of the assembly asked for: it is not repeated.
        return Serve(ToolNames.ListMembers, entry, elapsed, JobProtocol.MembersFile, list,
            PageCursor.Query(entry.View.JobId, ToolNames.ListMembers, assembly, typePattern), cursor, Keep, row => { row.Remove("assembly"); row.Remove("pathForm"); }, data);
    }

    [McpServerTool(Name = ToolNames.SearchStrings, Title = "Search an analysed package's string constants", ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("The ldstr string constants of a completed job's assemblies, one row per distinct constant per method: value (cut at "
        + "1024 chars; length is the whole), callerToken (pass it to disassemble), callerType, callerMethod, offset (the first IL "
        + "offset) and occurrences. Strings built at run time, decrypted or downloaded are not here. Paged: while truncated is "
        + "true, call again with cursor set to next. " + UntrustedNote)]
    public CallToolResult SearchStrings(
        [Description("The jobId from analyze_package.")] string jobId,
        [Description("Only this assembly, by its list_files path.")] string? assembly = null,
        [Description("Only constants that contain this, case-insensitive, as served (escaped: a backslash is doubled).")] string? contains = null,
        [Description("The next value of the previous page; omit it for the first page.")] string? cursor = null)
    {
        var elapsed = Stopwatch.StartNew();
        if (TooLong(assembly) || TooLong(contains) || TooLong(cursor))
            return Invalid(ToolNames.SearchStrings, elapsed, $"assembly, contains and cursor are at most {MaxArgumentChars} chars");
        var (entry, refusal) = Open(ToolNames.SearchStrings, jobId, elapsed);
        if (entry is null)
            return refusal!;

        var list = entry.Index["strings"]!.AsObject();
        bool Keep(JsonObject row) =>
            (assembly is not { Length: > 0 } || RowFile.UntrustedValue(row, "assembly") == assembly)
            && (contains is not { Length: > 0 } || RowFile.UntrustedValue(row, "value")?.Contains(contains, StringComparison.OrdinalIgnoreCase) == true);
        var data = Data(entry);
        data["pass"] = list["pass"]!.DeepClone();
        return Serve(ToolNames.SearchStrings, entry, elapsed, JobProtocol.StringsFile, list,
            PageCursor.Query(entry.View.JobId, ToolNames.SearchStrings, assembly, contains), cursor, Keep, null, data);
    }

    [McpServerTool(Name = ToolNames.Disassemble, Title = "Disassemble a method", ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("One method's CIL, by its token (from list_members, search_strings, or a finding's callerTokens): a header, then one "
        + "IL_xxxx: opcode operand line per instruction from offset, then the exception handlers. A call into the package carries "
        + "the callee's token: a [0x06...] token can be disassembled in turn. The listing is in a second text block, between "
        + "<<<UNTRUSTED nonce=N>>> and <<<END UNTRUSTED nonce=N>>> lines, N being content.fence. While next is present, call again "
        + "with offset set to it. Each call starts a reader process. Nothing is executed. " + UntrustedNote)]
    public async Task<CallToolResult> Disassemble(
        [Description("The jobId from analyze_package.")] string jobId,
        [Description("The assembly, by its list_files path (the untrusted value).")] string assembly,
        [Description("The method's MethodDef token, e.g. \"0x06000012\".")] string token,
        [Description("The IL offset to start at, from the previous page's next. Default 0.")] long offset = 0,
        CancellationToken ct = default)
    {
        var elapsed = Stopwatch.StartNew();
        if (string.IsNullOrEmpty(assembly) || TooLong(assembly))
            return Invalid(ToolNames.Disassemble, elapsed, $"assembly is required, at most {MaxArgumentChars} chars");
        if (ParseToken(token) is not { } methodToken)
            return Invalid(ToolNames.Disassemble, elapsed, "token must be a MethodDef token, such as \"0x06000012\"");
        if (offset is < 0 or > uint.MaxValue)
            return Invalid(ToolNames.Disassemble, elapsed, "offset must be an IL offset, 0 or more");
        var (entry, refusal) = Open(ToolNames.Disassemble, jobId, elapsed);
        if (entry is null)
            return refusal!;

        var (row, full, status, problem, corrupt) = ExtractedFile.Resolve(entry.Dir, assembly);
        if (corrupt != RowProblem.None)
            return row is not null && status == ToolStatus.NotPermitted
                ? ToolEnvelope.Create(ToolNames.Disassemble, ToolStatus.NotPermitted, elapsed, Data(entry), message: problem + "; " + Discard(entry))
                : Unusable(ToolNames.Disassemble, entry, elapsed, corrupt, problem);
        if (row is not null && Text(row["kind"]) is { } kind && kind != "assembly" && kind != "notExtracted")
            return Invalid(ToolNames.Disassemble, elapsed, "that file is not an assembly; list_files with kind \"assembly\" lists them");
        if (full is null)
            return ToolEnvelope.Create(ToolNames.Disassemble, status, elapsed, Data(entry), message: problem);

        // The listing gets what the response leaves once its fields are carried twice (structured and text; S3 review W2), and
        // four fifths of that: neutralising forged fences adds at most a quarter.
        var data = Data(entry);
        data["assembly"] = row!["path"]!.DeepClone();
        var maxChars = Math.Clamp(
            Math.Min(McpLimits.BulkBudgetChars, McpLimits.ResponseBudgetChars - 2 * (RowFile.Chars(data) + ListingFieldsChars) - FenceChars) * 4 / 5,
            InspectProtocol.MinChars, McpLimits.BulkBudgetChars * 4 / 5);
        var (result, runStatus, failure) = await jobs.InspectAsync(new InspectRequest(InspectProtocol.Version, full, methodToken, (uint)offset, maxChars), ct);
        // A failed child's reason quotes its output, so it is untrusted (D10); Busy and Cancelled are Silvergun's own words.
        if (result?.Inspected is not { } listed)
            return runStatus == ToolStatus.Failed
                ? ToolEnvelope.Create(ToolNames.Disassemble, runStatus, elapsed, Data(entry), message: "the method could not be listed; reason says why", reason: failure)
                : ToolEnvelope.Create(ToolNames.Disassemble, runStatus, elapsed, Data(entry), message: failure);
        if (InspectedProblem(listed, (uint)offset, maxChars) is { } malformed)
            return ToolEnvelope.Create(ToolNames.Disassemble, ToolStatus.Failed, elapsed, Data(entry), message: $"the inspect process returned a malformed result ({malformed})");
        if (!listed.Found)
            return ToolEnvelope.Create(ToolNames.Disassemble, ToolStatus.NotFound, elapsed, Data(entry),
                message: "no method of this assembly has that token; list_members gives each method's token");
        // As read_file: an offset past the end is refused. The end itself is valid (the handlers' own page).
        if (listed.Body == CodeAnalysis.IL.MemberBody.Il && offset > listed.IlBytes)
            return Invalid(ToolNames.Disassemble, elapsed, $"offset is past the end of the method's IL, which is {listed.IlBytes} bytes");

        // The method's names are in the listing's header, not repeated here: a CJK name costs six chars a char as JSON (W2).
        var fence = new UntrustedFence(listed.Listing);
        data["token"] = MemberRows.Hex(methodToken);
        data["body"] = EnumName(listed.Body);
        data["ilBytes"] = listed.IlBytes;
        data["maxStack"] = listed.MaxStack;
        data["locals"] = listed.Locals;
        data["instructions"] = listed.Instructions;
        data["offset"] = offset;
        data["shown"] = listed.Shown;
        data["truncated"] = listed.Next is not null;
        if (listed.Next is { } next)
            data["next"] = next;
        if (listed.HandlersNotShown > 0)
            data["handlersNotShown"] = listed.HandlersNotShown;
        if (listed.ReaderAssertions > 0)
            data["readerAssertions"] = listed.ReaderAssertions;
        data["content"] = new JsonObject { ["fence"] = fence.Nonce, ["chars"] = fence.Content.Length };
        return ToolEnvelope.Create(ToolNames.Disassemble, ToolStatus.Succeeded, elapsed, data, bulk: fence.Block);
    }

    // "0x06000012" or its decimal form, when it is a MethodDef token.
    private static uint? ParseToken(string? token)
    {
        var text = token?.Trim();
        if (string.IsNullOrEmpty(text) || text.Length > 12)
            return null;
        var parsed = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? uint.TryParse(text[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var hex) ? hex : (uint?)null
            : uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var dec) ? dec : null;
        return parsed is { } t && t >> 24 == 0x06 && (t & 0xFFFFFF) != 0 ? t : null;
    }

    // Why an inspect child's result cannot be served: it is checked as any child output is (D2), and its text must already be
    // escaped for display, since it goes in the bulk block as it is.
    private static string? InspectedProblem(JobInspected r, uint offset, int maxChars)
    {
        static bool Name(string? s) => s is { Length: <= MaxListedNameChars } && ExtractedFile.IsDisplayable(s) && !s.Contains('\n');
        return r.Listing is null || r.Listing.Length > maxChars ? "the listing is missing or over its budget"
            : !ExtractedFile.IsDisplayable(r.Listing) ? "the listing holds unescaped text"
            : r.Found && !(Name(r.DeclaringType) && Name(r.Name) && Name(r.Id)) ? "a name is missing, too long, or unescaped"
            : r.Instructions < 0 || r.Shown < 0 || r.Shown > r.Instructions || r.Locals < 0 || r.MaxStack < 0 ? "a count is out of range"
            : !Enum.IsDefined(r.Body) ? "the body kind is not known"
            : r.Next is { } next && (next > r.IlBytes || next <= offset) ? "next does not move the listing on"
            : r.HandlersNotShown < 0 ? "a count is out of range"
            : null;
    }
    #endregion

    #region Fields
    // A listed method's type, name or id: the child bounds each to at most 1,024 chars and a cut suffix.
    private const int MaxListedNameChars = 1_100;
    // What the listing's other fields take beside jobId and assembly: token, counts, flags, next, the fence's nonce.
    private const int ListingFieldsChars = 600;
    // The envelope's own fields and the two fence lines.
    private const int FenceChars = 300;
    #endregion
}
