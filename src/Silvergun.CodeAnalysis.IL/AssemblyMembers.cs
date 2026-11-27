namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

/// <summary>What a method is from its metadata alone (MCP task S3). Not the reachability root class (<see cref="RootClass"/>).</summary>
public enum MemberSpecial { None, Constructor, TypeInitializer, Finalizer, PInvoke, NativeExport }

/// <summary>Whether a method has an IL body, and whether it could be read.</summary>
public enum MemberBody { Il, None, Unreadable }

/// <summary>One distinct <c>ldstr</c> constant of a method: its text, its first IL offset, and how often the method loads it.</summary>
public sealed record MethodString(string Text, uint Offset, int Occurrences);

/// <summary>
/// One method definition as <see cref="AssemblyMembers"/> reads it. <see cref="Type"/> and <see cref="Name"/> are named as
/// the scan analyses name a finding's caller; <see cref="Id"/> is its <see cref="CanonicalName"/> node id, with its
/// signature. <see cref="CalledApis"/> are the call sites named as <see cref="ApiCallFinding.CalledApi"/> is.
/// </summary>
public sealed record MemberFacts(
    uint Token,
    string Type,
    string Name,
    string Id,
    TypeMemberVisibility Visibility,
    bool IsStatic,
    bool IsVirtual,
    bool IsAbstract,
    MemberSpecial Special,
    MemberBody Body,
    uint IlBytes,
    IReadOnlySet<string> CalledApis,
    IReadOnlyList<MethodString> Strings);

/// <summary>How an <see cref="AssemblyMembers.Walk"/> went: bodies it could not read, and why it stopped early (null when it did not).</summary>
public sealed class MemberWalkStatus
{
    #region Properties
    public int Unreadable { get; set; }

    public string? Problem { get; set; }
    #endregion
}

/// <summary>
/// Every method definition of a CCI-loaded assembly with its metadata token, flags, call sites and string constants (MCP task
/// S3: <c>list_members</c>, <c>search_strings</c>, and a finding's caller token). Every read is guarded as the scan analyses
/// guard theirs: a hostile method costs that method's facts, never the assembly. Never throws.
/// </summary>
public static class AssemblyMembers
{
    #region Methods
    /// <summary>
    /// At most <paramref name="maxMembers"/> methods of <paramref name="assembly"/>, by token. <c>Unreadable</c> counts the
    /// bodies that could not be read; <c>Problem</c> says why the list stopped early (enumeration failed, or the cap). Holds
    /// every method's strings at once: for a small assembly; a whole package streams with <see cref="Walk"/>.
    /// </summary>
    public static (IReadOnlyList<MemberFacts> Members, int Unreadable, string? Problem) Read(AssemblyAnalyzer assembly, int maxMembers = DefaultMaxMembers)
    {
        var status = new MemberWalkStatus();
        var members = Walk(assembly, maxMembers, status).OrderBy(m => m.Token).ToList();
        return (members, status.Unreadable, status.Problem);
    }

    /// <summary>
    /// The methods of <paramref name="assembly"/>, one at a time in metadata order, each once, at most
    /// <paramref name="maxMembers"/>: a consumer that drops each method's strings when it has used them holds only one
    /// method's at a time (S3 review C1: CCI makes a new string for every <c>ldstr</c>). <paramref name="status"/> is filled in
    /// as the walk goes.
    /// </summary>
    public static IEnumerable<MemberFacts> Walk(AssemblyAnalyzer assembly, int maxMembers, MemberWalkStatus status)
    {
        IEnumerator<IMethodDefinition> methods;
        try
        {
            methods = assembly.Module.GetAllTypes().SelectMany(t => t.Methods).GetEnumerator();
        }
        catch (Exception ex)
        {
            status.Problem = Unenumerable(ex);
            yield break;
        }
        using (methods)
        {
            var seen = new HashSet<uint>();
            while (true)
            {
                IMethodDefinition method;
                try
                {
                    if (!methods.MoveNext())
                        yield break;
                    method = methods.Current;
                }
                catch (Exception ex)
                {
                    status.Problem = Unenumerable(ex);
                    yield break;
                }
                if (seen.Count >= maxMembers)
                {
                    status.Problem = $"the assembly has more than {maxMembers} methods; the rest were not read";
                    yield break;
                }
                if (Facts(method) is { } facts && seen.Add(facts.Token))
                {
                    if (facts.Body == MemberBody.Unreadable)
                        status.Unreadable++;
                    yield return facts;
                }
            }
        }
    }

    private static string Unenumerable(Exception ex) => $"the assembly's methods could not all be enumerated ({ex.GetType().Name})";

    /// <summary><paramref name="method"/>'s MethodDef token, or null when it has none (it did not come from a metadata table).</summary>
    public static uint? Token(IMethodDefinition method)
    {
        try
        {
            return method is IMetadataObjectWithToken { TokenValue: var token } && token != uint.MaxValue && token >> 24 == MethodDefTable ? token : null;
        }
        catch
        {
            return null;
        }
    }

    private static MemberFacts? Facts(IMethodDefinition method)
    {
        if (Token(method) is not { } token)
            return null;
        var name = AssemblyAnalyzer.SafeName(method);
        var isStatic = Guard(() => method.IsStatic);
        var isVirtual = Guard(() => method.IsVirtual);
        var read = AssemblyAnalyzer.TryReadBody(method);
        var (calls, strings) = read.Body is { } body ? Walk(body) : noBody;
        return new MemberFacts(
            token,
            Guard(() => AssemblyAnalyzer.TypeName(method.ContainingTypeDefinition), UnknownType),
            name,
            CciNames.Of(method).ToString(),
            Guard(() => method.Visibility, TypeMemberVisibility.Other),
            isStatic,
            isVirtual,
            Guard(() => method.IsAbstract),
            Special(method, name, isStatic, isVirtual),
            read.IsMissing ? MemberBody.None : read.IsUnreadable ? MemberBody.Unreadable : MemberBody.Il,
            read.Body is { } sized ? Guard(() => sized.Size) : 0,
            calls,
            strings);
    }

    // The body's call sites (as findings name them) and its distinct ldstr constants; one unreadable operation costs itself.
    private static (IReadOnlySet<string> Calls, IReadOnlyList<MethodString> Strings) Walk(IMethodBody body)
    {
        var calls = new HashSet<string>(StringComparer.Ordinal);
        var strings = new Dictionary<string, (uint Offset, int Count)>(StringComparer.Ordinal);
        try
        {
            foreach (var op in body.Operations)
                try
                {
                    if (op.OperationCode == OperationCode.Ldstr && op.Value is string text)
                        strings[text] = strings.TryGetValue(text, out var seen) ? (seen.Offset, seen.Count + 1) : (op.Offset, 1);
                    else if (CapabilityAnalysis.Callee(op) is { } callee)
                        calls.Add(callee.Api);
                }
                catch (Exception ex)
                {
                    Runtime.Debug("Skipping an operation while listing members: {0}", ex.GetType().Name);
                }
        }
        catch (Exception ex)
        {
            Runtime.Debug("Stopped reading a method's operations while listing members: {0}", ex.GetType().Name);
        }
        return (calls, [.. strings.OrderBy(s => s.Value.Offset).Select(s => new MethodString(s.Key, s.Value.Offset, s.Value.Count))]);
    }

    private static MemberSpecial Special(IMethodDefinition method, string name, bool isStatic, bool isVirtual) =>
        Guard(() => method.IsPlatformInvoke) ? MemberSpecial.PInvoke
        : Guard(() => method.Attributes?.Any(CapabilityAnalysis.IsUnmanagedCallersOnly) == true) ? MemberSpecial.NativeExport
        : name == ".cctor" && isStatic ? MemberSpecial.TypeInitializer
        : name == ".ctor" && !isStatic ? MemberSpecial.Constructor
        : name == "Finalize" && isVirtual && !isStatic && Guard(() => method.ParameterCount) == 0 ? MemberSpecial.Finalizer
        : MemberSpecial.None;

    // A metadata read a crafted module can make throw, as its fallback when it does. Shared with MethodListing.
    internal static T Guard<T>(Func<T> read, T fallback = default!)
    {
        try
        {
            return read();
        }
        catch
        {
            return fallback;
        }
    }
    #endregion

    #region Fields
    public const int DefaultMaxMembers = 250_000;

    private const uint MethodDefTable = 0x06;
    private const string UnknownType = "<unknown>";

    private static readonly (IReadOnlySet<string> Calls, IReadOnlyList<MethodString> Strings) noBody = (new HashSet<string>(), []);
    #endregion
}
