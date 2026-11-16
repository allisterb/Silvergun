namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

/// <summary>A value class at a sink site that names a behaviour (<c>docs/agent/tasks/recall-levers-1.md</c> §2).</summary>
/// <remarks><b>Append-only</b>: the names are written to JSON and pinned.</remarks>
public enum SsaSignal
{
    /// <summary>A shell or script host as the process's file.</summary>
    ShellInterpreter,
    /// <summary>Process arguments with an encoded command, a hidden window, a policy bypass, or a download-and-run idiom.</summary>
    StealthArguments,
    /// <summary>A virtual-memory P/Invoke asked for an executable page protection.</summary>
    ExecutableMemory,
    /// <summary>An environment variable whose name is shaped like a secret.</summary>
    SecretEnvironmentName,
}

/// <summary>
/// Which <see cref="SsaSignal"/>s one sink fact shows. Pure, deterministic, never throws. Reads only an Analyzed site's
/// Constant and OneOf values (a OneOf matches when any alternative does). The text read is the worker's escaped text:
/// a cut constant matches on its kept prefix, and a hash-only one never matches. No signal never means "benign": a
/// value that is not constant is not read at all.
/// </summary>
public static class SsaValueSignals
{
    #region Methods
    /// <summary>The signals of <paramref name="fact"/>, in enum order, each once.</summary>
    public static IReadOnlyList<SsaSignal> Of(SsaSinkFact fact)
    {
        try
        {
            if (fact is not { Status: SsaSiteStatus.Analyzed })
                return [];
            var (type, method) = Split(fact.Site.CalleeKey);
            var signals = new SortedSet<SsaSignal>();
            if (type is "System.Diagnostics.Process" && method == "Start" || type is "System.Diagnostics.ProcessStartInfo" && method is ".ctor" or "set_FileName")
            {
                if (Any(fact, 0, IsShell))
                    signals.Add(SsaSignal.ShellInterpreter);
                // The second argument is the arguments in the 2- and 5-argument overloads; in Start(string, string,
                // SecureString, string) it is a user name.
                if (method != "set_FileName" && fact.ArgumentCount is 2 or 5 && Any(fact, 1, IsStealth))
                    signals.Add(SsaSignal.StealthArguments);
            }
            if (type is "System.Diagnostics.ProcessStartInfo" && method == "set_Arguments" && Any(fact, 0, IsStealth))
                signals.Add(SsaSignal.StealthArguments);
            if (fact.Import is { } import && protectionArgument.TryGetValue(import, out var index) && AnyInt(fact, index, IsExecutable))
                signals.Add(SsaSignal.ExecutableMemory);
            if (type is "System.Environment" && method == "GetEnvironmentVariable" && Any(fact, 0, IsSecretName))
                signals.Add(SsaSignal.SecretEnvironmentName);
            return [.. signals];
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return [];
        }
    }

    // A classification key's type and method name: the method is the part after the last '.', or ".ctor".
    private static (string Type, string Method) Split(string key)
    {
        if (key.EndsWith("..ctor", StringComparison.Ordinal))
            return (key[..^6], ".ctor");
        var dot = key.LastIndexOf('.');
        return dot <= 0 ? (key, "") : (key[..dot], key[(dot + 1)..]);
    }

    // Each matcher sees a String constant's text and whether it was cut (then only its kept prefix).
    private static bool Any(SsaSinkFact fact, int index, Func<string, bool, bool> match) =>
        Strings(fact, index).Any(s => match(s.Text, s.Cut));

    // Int text is the worker's invariant decimal, signed or (for an unsigned constant) above long.MaxValue.
    private static bool AnyInt(SsaSinkFact fact, int index, Func<ulong, bool> match) =>
        index < fact.Arguments.Count && fact.Arguments[index] is { Kind: SsaValueKind.Constant or SsaValueKind.OneOf } value
        && value.Constants.Any(c => c.Kind == SsaConstantKind.Int
            && (long.TryParse(c.Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n) ? match(unchecked((ulong)n))
                : ulong.TryParse(c.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var u) && match(u)));

    // The readable text of a String argument's constants: a cut one's kept prefix, none for a hash-only one.
    private static IEnumerable<(string Text, bool Cut)> Strings(SsaSinkFact fact, int index) =>
        index < fact.Arguments.Count && fact.Arguments[index] is { Kind: SsaValueKind.Constant or SsaValueKind.OneOf } value
            ? value.Constants.Where(c => c.Kind == SsaConstantKind.String).Select(Readable).Where(r => r.Text is not null).Select(r => (r.Text!, r.Cut))
            : [];

    private static (string? Text, bool Cut) Readable(SsaConstant constant)
    {
        if (!constant.Cut)
            return (constant.Text, false);
        var suffix = constant.Text.LastIndexOf("…[+", StringComparison.Ordinal);
        return (suffix > 0 ? constant.Text[..suffix] : null, true);
    }

    // A cut file name is not whole, so it is never claimed to be a shell.
    private static bool IsShell(string file, bool cut)
    {
        if (cut)
            return false;
        var name = file.Trim().Trim('"');
        name = name[(name.LastIndexOfAny(['/', '\\']) + 1)..];
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            name = name[..^4];
        return shells.Contains(name);
    }

    // Matched on the text with the worker's tab, newline and return escapes read back as spaces (a command line splits on
    // tab; a -Command script's tokenizer also on newline and return). A cut text gets a word character after its prefix, so no word boundary is found at the cut.
    private static bool IsStealth(string arguments, bool cut) => stealth.IsMatch(Whitespaced(arguments) + (cut ? "_" : string.Empty));

    // The escaped text with \t, \n and \r as spaces, read left to right so an escaped backslash (\\) stays one char pair.
    private static string Whitespaced(string escaped)
    {
        var text = new StringBuilder(escaped.Length);
        for (var i = 0; i < escaped.Length; i++)
        {
            if (escaped[i] == '\\' && i + 1 < escaped.Length)
            {
                var next = escaped[++i];
                text.Append(next is 't' or 'n' or 'r' ? " " : $"\\{next}");
            }
            else
                text.Append(escaped[i]);
        }
        return text.ToString();
    }

    // PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY.
    private static bool IsExecutable(ulong protection) => (protection & 0xF0) != 0;

    private static bool IsSecretName(string name, bool cut) => secretName.IsMatch(name);
    #endregion

    #region Fields
    private static readonly HashSet<string> shells = new(
        ["powershell", "pwsh", "cmd", "bash", "sh", "zsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32"],
        StringComparer.OrdinalIgnoreCase);

    // The protection argument's index, per virtual-memory entry point.
    private static readonly Dictionary<string, int> protectionArgument = new(StringComparer.Ordinal)
    {
        ["VirtualAlloc"] = 3,
        ["VirtualAllocEx"] = 4,
        ["VirtualProtect"] = 2,
        ["VirtualProtectEx"] = 3,
    };

    private static readonly Regex stealth = new(
        @"(?<![\w-])(?:-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|-w(?:indowstyle)?\s+hidden\b|-exec(?:utionpolicy)?\s+bypass\b|iex\b|invoke-expression\b|downloadstring\b|downloadfile\b)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private static readonly Regex secretName = new(
        "TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    #endregion
}
