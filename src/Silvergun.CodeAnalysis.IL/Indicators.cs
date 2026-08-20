namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// Categories of network / sensitive-target indicator a string constant can carry. Unlike
/// <see cref="HiddenContentKind"/> (an encoding a payload was hidden under), a category here names what the
/// constant, once found, actually points <em>at</em> — the target half of RL's "collect and exfiltrate to
/// &lt;named target&gt;" taxonomy.
/// <para>
/// <b>Append-only</b>, for the same reason as <see cref="Capability"/> (ADR 0019 decision 5): new values go at
/// the end, existing ones are never reordered or renamed. JSON is written by name, so appending is safe.
/// </para>
/// </summary>
public enum IndicatorCategory
{
    /// <summary>Out-of-band interaction / request-catcher host (pipedream, Burp Collaborator, webhook.site, …).
    /// Cross-reference: <c>SG0001</c> in
    /// <c>src/Silvergun.PackageAnalysis.NuGet/Resources/SilvergunRules/callback_domains.json</c> carries the same
    /// concept for the NuGet scanner — update both when this list changes.</summary>
    CallbackDomain,

    /// <summary>Paste, anonymous file drop, or chat-webhook exfiltration sink (pastebin raw, transfer.sh,
    /// Discord/Slack/Telegram webhook endpoints, …). Cross-reference: <c>SG0002</c> in the same
    /// <c>callback_domains.json</c> — update both when this list changes.</summary>
    ExfilSink,

    /// <summary>Dynamic-DNS host used to front an otherwise-throwaway endpoint (ngrok, duckdns, no-ip,
    /// trycloudflare, localtunnel, …).</summary>
    DynamicDns,

    /// <summary>Raw-content code host commonly used to stage a second-stage payload
    /// (raw.githubusercontent.com, gist, gitee raw).</summary>
    RawCodeHost,

    /// <summary>A URL or bare literal naming a routable (public) IPv4/IPv6 address, with no DNS name.</summary>
    PublicIpLiteral,

    /// <summary>A URL or bare literal naming an RFC1918 / loopback / link-local IPv4 or IPv6 address.</summary>
    PrivateIpLiteral,

    /// <summary>A URL (has a scheme) whose host matched no category above.</summary>
    GenericUrl,

    /// <summary>An autorun registry path: …CurrentVersion\Run(Once), Winlogon\Shell, or Image File Execution
    /// Options (IFEO).</summary>
    AutorunRegistry,

    /// <summary>A well-known credential file/path: .aws/credentials, .ssh/id_*, a browser "Login Data" store,
    /// .npmrc, .git-credentials.</summary>
    CredentialPath,

    /// <summary>A string that parses as an assembly-qualified or namespace-qualified CLR type name — the
    /// reflection-mediated route (<c>Type.GetType("…")</c>) that is invisible to the reference-side call graph.
    /// Best-effort/heuristic: no attempt is made to confirm the name actually resolves to a loadable type.</summary>
    ReflectionTypeName,
}

/// <summary>
/// One aggregated network/sensitive-target indicator. <paramref name="Value"/> is the <em>normalised</em>
/// indicator (e.g. a lowercased bare host for a host-category finding) — not the whole constant it came from;
/// see <see cref="IndicatorAnalysis"/> for the exact normalisation per category. <paramref name="Excerpt"/> is a
/// hard-capped excerpt of the containing constant, kept only as short supporting context (constants are
/// attacker-authored and can be megabytes). <paramref name="Occurrences"/> counts how many <c>ldstr</c> constants
/// (in this caller) produced this same (Category, Value) pair — the finding itself is aggregated, not
/// enumerated. Carries only strings/enums — no Analysis.Net types (ADR 0001/0002).
/// </summary>
public sealed record IndicatorFinding(
    IndicatorCategory Category,
    string Value,          // the normalised indicator (host, path, registry key) - NOT the whole constant
    string Excerpt,        // bounded excerpt of the containing constant, hard-capped
    string CallerType,
    string CallerMethod,
    int Occurrences);

/// <summary>A serializable indicator report for a single analyzed assembly.</summary>
public sealed record IndicatorReport(
    string AssemblyName,
    string AssemblyPath,
    DateTimeOffset AnalyzedAt,
    IReadOnlyList<IndicatorFinding> Findings,
    bool Truncated)     // the distinct-indicator cap (IndicatorAnalysis.MaxDistinctIndicators) was hit
{
    #region Methods
    /// <summary>Serializes this report to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes an <see cref="IndicatorReport"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static IndicatorReport? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<IndicatorReport>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
