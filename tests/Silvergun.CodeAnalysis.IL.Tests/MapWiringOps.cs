namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;

/// <summary>
/// Call-site shapes for capability-map <b>phase 2</b> (<c>docs/agent/tasks/capability-map.md</c>): the ones that
/// distinguish the retired legacy <c>StartsWith</c>-over-<c>Catalog</c> matcher from the live
/// <c>CapabilityMap.Default.Classify(ClassificationKey)</c> one. Every shape here exists because the two matchers
/// disagree about it, or because it pins a documented architect decision about the switch.
/// <para>
/// Lives in the <b>net10.0 test assembly</b> and is analyzed through the self-load pattern
/// (<c>CapabilityMapWiringTests.SelfFindings</c>), the same one <see cref="Net10OnlyGapOps"/> uses. That keeps
/// these shapes out of the shared netstandard2.0 fixture and the TFM matrix fixture, both of which carry exact
/// measured method/finding baselines that adding shapes would move. Analyzed statically, never executed — so
/// arguments need not be meaningful and no path here is ever opened.
/// </para>
/// </summary>
public static class MapWiringOps
{
    #region Methods
    /// <summary>
    /// MAP-ONLY: <see cref="GC.Collect()"/>. <c>System.GC</c> has no entry in the legacy catalog at all, so this
    /// can only be classified (<c>RuntimeControl</c>) by the map. Never called.
    /// </summary>
    public static int TriggersGarbageCollection()
    {
        GC.Collect();
        return GC.CollectionCount(0);
    }

    /// <summary>
    /// LEGACY-ONLY: <c>new FileNotFoundException(...)</c>. The legacy prefix <c>System.IO.File</c> matched
    /// <c>System.IO.FileNotFoundException</c> by <c>StartsWith</c> and reported it as <c>FileSystem</c>; the map
    /// has no entry for the exception type, so the finding is gone. An exception type is not a filesystem
    /// capability — the accepted false-positive removal at the head of the phase-2 known-delta table. Never called.
    /// </summary>
    public static Exception CreatesFileNotFoundException(string path) => new FileNotFoundException("nope", path);

    /// <summary>
    /// CARVE-OUT: <c>System.IO.Directory.GetCurrentDirectory</c> reads process state and touches no file, so the
    /// method entry overrides the <c>capability System.IO.Directory FileSystem</c> type entry and it classifies
    /// as <c>EnvironmentProbe</c>. Never called.
    /// </summary>
    public static string ProbesCurrentDirectory() => Directory.GetCurrentDirectory();

    /// <summary>
    /// The sibling the carve-out above is carved out OF: <c>Directory.Exists</c> reaches the type entry and stays
    /// <c>FileSystem</c>. Never called.
    /// </summary>
    public static bool ChecksDirectoryExists(string path) => Directory.Exists(path);

    /// <summary>
    /// CARVE-OUT: <em>looking up</em> a process is reconnaissance of the host, not execution, so
    /// <c>Process.GetCurrentProcess</c> classifies as <c>EnvironmentProbe</c> rather than inheriting
    /// <c>ProcessExecution</c> from the <c>System.Diagnostics.Process</c> type entry. Never called.
    /// </summary>
    public static Process ProbesCurrentProcess() => Process.GetCurrentProcess();

    /// <summary>
    /// The sibling: <c>Process.Start</c> reaches the type entry and stays <c>ProcessExecution</c>. Never called.
    /// </summary>
    public static Process? StartsProcess(string path) => Process.Start(path);

    /// <summary>
    /// SAFE: <c>System.IO.Path</c> is allowlisted (pure string manipulation), so <c>Path.Combine</c> yields no
    /// finding at all. <c>safe</c> is honoured by the matcher but has no finding-level effect yet — the absence
    /// of a finding is the same absence an unmatched key produces, which is exactly what phase 2 specifies.
    /// Never called.
    /// </summary>
    public static string CombinesPaths(string left, string right) => Path.Combine(left, right);

    /// <summary>
    /// The carve-out from that allowlist, in the other direction: <c>Path.GetTempFileName</c> creates a file, so
    /// its method entry beats <c>safe System.IO.Path</c> and it classifies as <c>FileSystem</c>. Never called.
    /// </summary>
    public static string CreatesTempFile() => Path.GetTempFileName();

    /// <summary>
    /// UNSPECIFIED: <c>unspecified System.Text.Json.*</c> re-opens the subtree that <c>safe System.Text.*</c>
    /// would otherwise swallow. <c>Unspecified</c> means "keep walking", not "sink", so — like <c>safe</c> — it
    /// produces no finding today. Never called.
    /// </summary>
    public static string SerializesJson(object value) => JsonSerializer.Serialize(value);

    /// <summary>
    /// CONTROL for the decision-2 pin in <see cref="Microsoft.Win32.Registry"/>: an ordinary call to a member of
    /// that catalogued type. Its key <c>Microsoft.Win32.Registry.ReadsValue</c> reaches the
    /// <c>capability Microsoft.Win32.Registry Registry</c> type entry and DOES produce a finding — without it,
    /// "the nested state machine's .ctor produces no finding" could equally mean the catalogued name never
    /// matched anything here in the first place. Never called.
    /// </summary>
    // CS0436: the fixture type deliberately shadows the real Microsoft.Win32.Registry facade — that collision is
    // the whole point (see CataloguedTypeStateMachineOps.cs). The compiler binds to the fixture, as intended.
#pragma warning disable CS0436
    public static string CallsCataloguedTypeMember(string name) => Microsoft.Win32.Registry.ReadsValue(name);
#pragma warning restore CS0436
    #endregion
}
