namespace Silvergun.PackageAnalysis.NuGet.Graph;

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// How R3 presents a reach (<c>docs/agent/tasks/reachability-r3.md</c>, "What is presented"), pinned to R2b's measured
/// verdicts (<c>docs/agent/tasks/reachability-r2b.md</c>, "Result (S4)"): NativeEntry at both labels and Finalizer at
/// Direct passed E1 and E2 on the signal capabilities, so only those cells are triggers. Everything else is information.
/// LoadTime is informational by the user's ruling (2026-11-07). Finalizer at Direct triggers only in lib and runtimes
/// folders: on build-time packages it fails E1 (user's ruling, 2026-11-11, after R3 S3). Changing a cell needs a new
/// measurement, not a code edit; narrowing where one triggers does not.
/// </summary>
internal static class ReachabilityPresentation
{
    #region Properties
    /// <summary>The presented root classes, in presentation order. PublicApi, PublicContract and Hidden are not presented.</summary>
    public static IReadOnlyList<RootClass> Classes { get; } =
        ImmutableArray.Create(RootClass.NativeEntry, RootClass.Finalizer, RootClass.TypeInitializer, RootClass.HostContract, RootClass.LoadTime);

    /// <summary>The capabilities R2b judged (presence at least 3).</summary>
    public static IReadOnlySet<Capability> SignalCapabilities { get; } = new[]
    {
        Capability.ProcessExecution, Capability.Registry, Capability.Network, Capability.NativeInterop, Capability.FileSystem,
    }.ToFrozenSet();
    #endregion

    #region Methods
    /// <summary>
    /// Whether a statement about <paramref name="cls"/> reaching <paramref name="capability"/> (null: unseen code), in a
    /// folder of <paramref name="role"/>, is a trigger.
    /// </summary>
    public static ReachStatementKind KindOf(RootClass cls, Capability? capability, bool direct, PackageItemRole role) =>
        capability is { } c && SignalCapabilities.Contains(c)
        && triggers.TryGetValue((cls, direct), out var roles) && (roles is null || roles.Contains(role))
            ? ReachStatementKind.Trigger
            : ReachStatementKind.Informational;

    /// <summary>
    /// The role a folder's statements are judged by: of <paramref name="folderRole"/> and <paramref name="memberRoles"/>,
    /// the one in which the most cells trigger, the folder's own on a tie.
    /// </summary>
    public static PackageItemRole TriggerRole(PackageItemRole folderRole, IEnumerable<PackageItemRole> memberRoles) =>
        memberRoles.Prepend(folderRole).MaxBy(r => triggers.Values.Count(roles => roles is null || roles.Contains(r)));

    /// <summary>Whether every cell is a trigger in <paramref name="a"/> exactly when it is in <paramref name="b"/>.</summary>
    public static bool SameKinds(PackageItemRole a, PackageItemRole b) =>
        triggers.Values.All(roles => roles is null || roles.Contains(a) == roles.Contains(b));

    /// <summary>The statement's wording, <paramref name="sink"/> naming what is reached.</summary>
    public static string Text(RootClass cls, string sink, bool direct) =>
        $"{subjects[cls]} {(direct ? "directly reaches" : "creates a delegate that reaches")} {sink}";

    /// <summary>What an unseen reach ended in, from its example's opacity kind and whether its last hop is own code.</summary>
    public static string Unseen(OpacityKind? kind, bool ownSink) => kind switch
    {
        OpacityKind.IndirectCall => "an indirect call (calli)",
        OpacityKind.Unresolved => "an unresolved call",
        OpacityKind.Ambiguous => "an ambiguous call",
        OpacityKind.BodyUnreadable => "an unreadable method body",
        { } other => $"an opacity site ({other})",
        null => ownSink ? "an internal call" : "an API the map marks unanalyzed",
    };
    #endregion

    #region Fields
    // The (class, Direct) cells that passed E1 and E2 in R2b, each with the folder roles it triggers in (null: any).
    private static readonly Dictionary<(RootClass Class, bool Direct), IReadOnlySet<PackageItemRole>?> triggers = new()
    {
        [(RootClass.NativeEntry, true)] = null,
        [(RootClass.NativeEntry, false)] = null,
        [(RootClass.Finalizer, true)] = new[] { PackageItemRole.Lib, PackageItemRole.Runtimes }.ToFrozenSet(),
    };

    private static readonly Dictionary<RootClass, string> subjects = new()
    {
        [RootClass.NativeEntry] = "a native entry point",
        [RootClass.Finalizer] = "a finalizer",
        [RootClass.TypeInitializer] = "a type initializer",
        [RootClass.HostContract] = "a build-host entry point (MSBuild task, analyzer, generator)",
        [RootClass.LoadTime] = "a module initializer",
    };
    #endregion
}
