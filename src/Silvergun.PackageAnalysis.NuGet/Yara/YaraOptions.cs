// Ported from reference/projects/Yara/YaraModels.cs (Camel.DFIR.Toolkits.Models.YaraOptions) —
// user approved copying reference/ into src/ on 2026-07-17 (CLAUDE.md). Adapted for Silvergun: the
// original ToArgs() rendered a single shell string; here it emits an argument LIST so hostile filenames
// can never inject into a shell (ADR 0016 invocation safety), and it drops the unused external-variable
// and worker-thread options that Silvergun does not set.

namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// Optional flags for a classic <c>yara</c> CLI scan. All fields are nullable; only those that are set are
/// emitted. <see cref="AddTo"/> appends them to a process <c>ArgumentList</c> so the process is launched with
/// a real argument vector, never a shell string.
/// </summary>
public sealed class YaraOptions
{
    #region Properties
    public bool? Recurse { get; init; }            // -r            recursive directory scan
    public bool? PrintStrings { get; init; }       // -s            print matching strings (with offset)
    public bool? PrintMeta { get; init; }          // -m            print rule metadata
    public bool? PrintTags { get; init; }          // -g            print rule tags
    public bool? PrintNamespace { get; init; }     // -e            print rule namespace
    public bool? PrintNonMatching { get; init; }   // -n            print rules that did NOT match
    public bool? FastScan { get; init; }           // -f            fast mode (first match per rule)
    public bool? Compiled { get; init; }           // -C            rules file is compiled (yarac output)
    public bool? NoFollowSymlinks { get; init; }   // -N            do not follow symlinks
    public int? Timeout { get; init; }             // --timeout N   skip a file after N seconds
    public string? Tag { get; init; }              // -t TAG        only apply rules with this tag
    #endregion

    #region Methods
    /// <summary>Appends the set options to <paramref name="args"/> as individual argument tokens.</summary>
    public void AddTo(IList<string> args)
    {
        if (Recurse == true) args.Add("-r");
        if (PrintStrings == true) args.Add("-s");
        if (PrintMeta == true) args.Add("-m");
        if (PrintTags == true) args.Add("-g");
        if (PrintNamespace == true) args.Add("-e");
        if (PrintNonMatching == true) args.Add("-n");
        if (FastScan == true) args.Add("-f");
        if (Compiled == true) args.Add("-C");
        if (NoFollowSymlinks == true) args.Add("-N");
        if (Timeout is int t) args.Add($"--timeout={t}");   // yara 4.5 requires the =form for this long option
        if (Tag is { Length: > 0 } tag) { args.Add("-t"); args.Add(tag); }
    }

    /// <summary>The set options as a fresh argument list (convenience over <see cref="AddTo"/>).</summary>
    public List<string> ToArgs()
    {
        var args = new List<string>();
        AddTo(args);
        return args;
    }
    #endregion
}
