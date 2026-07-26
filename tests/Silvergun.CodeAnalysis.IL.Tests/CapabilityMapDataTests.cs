namespace Silvergun.CodeAnalysis.IL.Tests;

using System;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Integrity of the built-in map, <c>src/Silvergun.CodeAnalysis.IL/Resources/capabilities.cm</c>.
/// <para>
/// A typo'd entry never matches anything and never announces itself, so it silently disables a detection —
/// the worst failure mode for a security tool. These are the guards: the embedded file must parse with
/// <b>zero</b> rejects, every <see cref="Capability"/> must be reachable through it, and every behaviour the
/// legacy <see cref="CapabilityAnalysis.Catalog"/> detects must still be represented (the precondition for
/// phase 2's no-lost-findings gate).
/// </para>
/// <para>
/// The second half pins the blanket-safe audit's carve-outs (capability-map-seed.md §2). <c>safe</c>
/// terminates traversal, so widening a blanket-safe prefix over one of these would silently under-report.
/// </para>
/// </summary>
public sealed class CapabilityMapDataTests
{
    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Integrity
    // ---------------------------------------------------------------------------------------------------

    // The headline guard: a rejected line is an entry that does nothing at all.
    [Fact]
    public void Default_ParsesTheEmbeddedResourceWithNoRejectedLines()
    {
        var rejected = CapabilityMap.Default.Stats.RejectedLines;

        Assert.True(
            rejected.Count == 0,
            "Resources/capabilities.cm has lines the parser rejected — each one is an entry that silently "
                + $"detects nothing:{Environment.NewLine}  {string.Join(Environment.NewLine + "  ", rejected)}");
    }

    [Fact]
    public void Default_IsPopulatedWithCapabilitySafeAndUnspecifiedEntries()
    {
        var stats = CapabilityMap.Default.Stats;

        Assert.True(stats.CapabilityEntries > 0, "The built-in map has no capability entries.");
        Assert.True(stats.SafeEntries > 0, "The built-in map has no safe entries (the allowlist is missing).");
        Assert.True(stats.UnspecifiedEntries > 0, "The built-in map has no unspecified entries (carve-outs are missing).");
        Assert.Equal(stats.CapabilityEntries + stats.SafeEntries + stats.UnspecifiedEntries + stats.UnanalyzedEntries, stats.TotalEntries);
    }

    // Every value of the (append-only) Capability enum must be producible by the map. A value nothing can
    // ever yield is dead taxonomy; adding one without a map entry is the regression this catches.
    [Fact]
    public void Default_RepresentsEveryCapabilityInTheTaxonomy()
    {
        Assert.All(Enum.GetValues<Capability>(), capability =>
        {
            Assert.True(
                CapabilityMapKeys.Representative.TryGetValue(capability, out var key),
                $"No representative classification key is registered for {capability} (see CapabilityMapKeys).");

            var verdict = CapabilityMap.Default.Classify(key!);

            Assert.True(
                verdict == new CapabilityVerdict(CapabilityClass.Capability, capability),
                $"'{key}' should classify as Capability/{capability} but was {Describe(verdict)}.");
        });
    }

    // The phase 2 no-lost-findings gate's precondition, made concrete: for EVERY legacy catalog entry, a key
    // that entry matches today must classify to the SAME capability under the map. Asserted per entry rather
    // than as a count, so a gap names the API it lost.
    [Fact]
    public void Default_RepresentsEveryLegacyCatalogEntryWithTheSameCapability()
    {
        Assert.NotEmpty(CapabilityAnalysis.Catalog);

        Assert.All(CapabilityAnalysis.Catalog, api =>
        {
            var key = RepresentativeKey(api);
            var verdict = CapabilityMap.Default.Classify(key);

            Assert.True(
                verdict == new CapabilityVerdict(CapabilityClass.Capability, api.Capability),
                $"Legacy catalog entry '{api.TypePrefix}'/'{api.Method ?? "*"}' ({api.Capability}) is not represented "
                    + $"in the built-in map: '{key}' classified as {Describe(verdict)}.");
        });
    }

    // Spot-check of the same gate on the concrete APIs the fixture exercises, so the assertion does not rest
    // solely on the synthesized keys above.
    [Theory]
    [InlineData("System.IO.File.ReadAllText", Capability.FileSystem)]
    [InlineData("System.IO.FileStream..ctor", Capability.FileSystem)]
    [InlineData("System.IO.Directory.GetFiles", Capability.FileSystem)]
    [InlineData("System.Net.WebClient..ctor", Capability.Network)]
    [InlineData("System.Net.WebClient.DownloadString", Capability.Network)]
    [InlineData("System.Net.Sockets.Socket.Connect", Capability.Network)]
    [InlineData("System.Diagnostics.Process.Start", Capability.ProcessExecution)]
    [InlineData("Microsoft.Win32.Registry.GetValue", Capability.Registry)]
    [InlineData("System.Environment.GetEnvironmentVariable", Capability.EnvironmentProbe)]
    [InlineData("System.Environment.get_MachineName", Capability.EnvironmentProbe)]
    [InlineData("System.Reflection.Assembly.UnsafeLoadFrom", Capability.DynamicCodeLoading)]
    [InlineData("System.Activator.CreateInstanceFrom", Capability.DynamicCodeLoading)]
    [InlineData("System.Reflection.Emit.DynamicMethod..ctor", Capability.DynamicCodeLoading)]
    [InlineData("System.Linq.Expressions.Expression.Compile", Capability.DynamicCodeLoading)]
    [InlineData("System.Delegate.DynamicInvoke", Capability.ReflectionInvocation)]
    [InlineData("System.Reflection.MethodInfo.Invoke", Capability.ReflectionInvocation)]
    [InlineData("System.Runtime.InteropServices.Marshal.Copy", Capability.NativeInterop)]
    [InlineData("System.Security.Cryptography.Aes.Create", Capability.Cryptography)]
    public void Default_ClassifiesAKnownSensitiveApi(string key, Capability expected)
    {
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, expected), CapabilityMap.Default.Classify(key));
    }

    // Constructor keys carry a doubled dot ("Ns.Type..ctor") and the map seeds two of them explicitly.
    [Theory]
    [InlineData("System.IO.StreamWriter..ctor")]
    [InlineData("System.IO.StreamReader..ctor")]
    public void Default_ConstructorEntry_ClassifiesAsFileSystem(string key)
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem),
            CapabilityMap.Default.Classify(key));
    }

    // ...while the rest of those types is deliberately unclassified: a StreamWriter over a MemoryStream is
    // not file I/O. This is the tightening the map buys over the legacy StartsWith catalog.
    [Theory]
    [InlineData("System.IO.StreamWriter.Write")]
    [InlineData("System.IO.StreamReader.ReadToEnd")]
    public void Default_NonConstructorMembersOfStreamTypes_AreNotClassified(string key)
    {
        Assert.Equal(CapabilityVerdict.None, CapabilityMap.Default.Classify(key));
    }

    // The trailing dot in "System.Net.Sockets.*" is load-bearing: the bare namespace-shaped key is outside it.
    [Fact]
    public void Default_SubtreePrefixNearMiss_DoesNotMatch()
    {
        Assert.Equal(CapabilityVerdict.None, CapabilityMap.Default.Classify("System.Net.Sockets"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Default_NullOrBlankKey_ReturnsNone(string? key)
    {
        Assert.Equal(CapabilityVerdict.None, CapabilityMap.Default.Classify(key!));
    }

    [Fact]
    public void Default_IsASingletonThatNeverReparses()
    {
        Assert.Same(CapabilityMap.Default, CapabilityMap.Default);
    }

    // ---------------------------------------------------------------------------------------------------
    // Carve-outs from the blanket-safe audit (capability-map-seed.md §2). Each pins a decision that a
    // careless widening of a blanket-safe prefix would silently undo — and `safe` under-reports silently.
    // ---------------------------------------------------------------------------------------------------

    // `safe System.Text.*` would swallow System.Text.Json, a deserialization gadget vector. The longer
    // `unspecified System.Text.Json.*` prefix re-opens that subtree.
    [Theory]
    [InlineData("System.Text.Json.JsonSerializer.Deserialize")]
    [InlineData("System.Text.Json.JsonSerializer.Serialize")]
    [InlineData("System.Text.Json.Serialization.JsonConverter.Read")]
    public void Default_SystemTextJson_IsUnspecifiedRatherThanSwallowedBySafeSystemText(string key)
    {
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Unspecified, null), CapabilityMap.Default.Classify(key));
    }

    // ...while the rest of System.Text really is allowlisted — the carve-out must not have re-opened it.
    [Theory]
    [InlineData("System.Text.StringBuilder.Append")]
    [InlineData("System.Text.RegularExpressions.Regex.Match")]
    [InlineData("System.Text.Encoding.GetBytes")]
    public void Default_RestOfSystemText_IsSafe(string key)
    {
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), CapabilityMap.Default.Classify(key));
    }

    // The second System.Text carve-out: Regex.CompileToAssembly emits a .NET assembly to disk.
    [Fact]
    public void Default_RegexCompileToAssembly_IsDynamicCodeLoadingDespiteTheSafeSystemTextPrefix()
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.DynamicCodeLoading),
            CapabilityMap.Default.Classify("System.Text.RegularExpressions.Regex.CompileToAssembly"));
    }

    // Locale/region fingerprinting is textbook reconnaissance ("skip the CIS countries"), so these four leaf
    // getters are carved out of `safe System.Globalization.*`.
    [Theory]
    [InlineData("System.Globalization.CultureInfo.get_CurrentCulture")]
    [InlineData("System.Globalization.CultureInfo.get_CurrentUICulture")]
    [InlineData("System.Globalization.CultureInfo.get_InstalledUICulture")]
    [InlineData("System.Globalization.RegionInfo.get_CurrentRegion")]
    public void Default_GlobalizationLocaleProbes_AreEnvironmentProbe(string key)
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.EnvironmentProbe),
            CapabilityMap.Default.Classify(key));
    }

    // ...and the carve-out is per-method, not per-type or per-namespace: siblings stay allowlisted.
    [Theory]
    [InlineData("System.Globalization.CompareInfo.Compare")]
    [InlineData("System.Globalization.CultureInfo.GetCultureInfo")]
    [InlineData("System.Globalization.NumberFormatInfo.get_InvariantInfo")]
    public void Default_GlobalizationSiblingsOfTheLocaleProbes_RemainSafe(string key)
    {
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), CapabilityMap.Default.Classify(key));
    }

    // TimeZoneInfo.get_Local is host reconnaissance; the type as a whole is deliberately NOT classified, so
    // the pure conversion helpers stay unclassified rather than becoming EnvironmentProbe noise.
    [Fact]
    public void Default_TimeZoneInfoLocal_IsEnvironmentProbeWhileTheTypeIsNotWholesaleClassified()
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.EnvironmentProbe),
            CapabilityMap.Default.Classify("System.TimeZoneInfo.get_Local"));

        Assert.Equal(CapabilityVerdict.None, CapabilityMap.Default.Classify("System.TimeZoneInfo.ConvertTime"));
    }

    // Path is pure string manipulation apart from two members, which are carved out of `safe System.IO.Path`
    // in DIFFERENT directions: GetTempFileName creates a file, GetTempPath is a pure TMP/TEMP environment
    // read. Asserted together, because collapsing them back into one verdict is the regression.
    [Fact]
    public void Default_PathTempMembers_SplitFileSystemFromEnvironmentProbeWhileTheRestOfPathIsSafe()
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem),
            CapabilityMap.Default.Classify("System.IO.Path.GetTempFileName"));

        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.EnvironmentProbe),
            CapabilityMap.Default.Classify("System.IO.Path.GetTempPath"));

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), CapabilityMap.Default.Classify("System.IO.Path.Combine"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), CapabilityMap.Default.Classify("System.IO.Path.GetExtension"));
    }

    // ---------------------------------------------------------------------------------------------------
    // Carve-outs from a TYPE entry: a method entry that pulls one member out of its type's capability.
    // Every test here is PAIRED — the carved-out member plus a sibling that must still reach the type entry —
    // because a re-widened carve-out and a deleted type entry look identical if only one side is asserted.
    // ---------------------------------------------------------------------------------------------------

    // The most consequential carve-out in the map: LOOKING UP a process is reconnaissance of the host (the
    // textbook "is a debugger or a VM guest agent running?" check), not execution. Re-widening these to the
    // `capability System.Diagnostics.Process ProcessExecution` type entry would silently reclassify
    // reconnaissance as execution — the distinction a reviewer most needs.
    [Theory]
    [InlineData("System.Diagnostics.Process.GetProcesses")]
    [InlineData("System.Diagnostics.Process.GetProcessesByName")]
    [InlineData("System.Diagnostics.Process.GetProcessById")]
    [InlineData("System.Diagnostics.Process.GetCurrentProcess")]
    [InlineData("System.Diagnostics.Process.get_MachineName")]
    public void Default_ProcessLookupMembers_AreEnvironmentProbeRatherThanProcessExecution(string key)
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.EnvironmentProbe),
            CapabilityMap.Default.Classify(key));
    }

    // ...and the type entry those five are carved out of is still live: everything else on Process executes.
    [Theory]
    [InlineData("System.Diagnostics.Process.Start")]
    [InlineData("System.Diagnostics.Process.Kill")]
    [InlineData("System.Diagnostics.Process.WaitForExit")]
    public void Default_ProcessSiblingsOfTheLookupCarveOut_RemainProcessExecution(string key)
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.ProcessExecution),
            CapabilityMap.Default.Classify(key));
    }

    // DriveInfo.GetDrives enumerates mounted drive letters and reads no file — the identical operation to
    // System.Environment.GetLogicalDrives, which is an EnvironmentProbe. The instance members do inspect the
    // volume and stay FileSystem via the type entry.
    [Fact]
    public void Default_DriveInfoGetDrives_IsEnvironmentProbeWhileTheInstanceMembersStayFileSystem()
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.EnvironmentProbe),
            CapabilityMap.Default.Classify("System.IO.DriveInfo.GetDrives"));

        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem),
            CapabilityMap.Default.Classify("System.IO.DriveInfo.get_TotalSize"));
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem),
            CapabilityMap.Default.Classify("System.IO.DriveInfo..ctor"));
    }

    // Dns.GetHostName emits no traffic — it returns the local machine's name, the same reconnaissance signal
    // as Environment.get_MachineName. The resolving members do talk to a resolver and stay Network.
    [Fact]
    public void Default_DnsGetHostName_IsEnvironmentProbeWhileTheResolvingMembersStayNetwork()
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.EnvironmentProbe),
            CapabilityMap.Default.Classify("System.Net.Dns.GetHostName"));

        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.Network),
            CapabilityMap.Default.Classify("System.Net.Dns.GetHostEntry"));
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.Network),
            CapabilityMap.Default.Classify("System.Net.Dns.GetHostAddresses"));
    }

    // AppDomain is a three-way split, and all three ways must hold at once: the loading surface is dynamic
    // code loading, the two leaf getters are host reconnaissance, and everything else falls through to
    // `capability System.AppDomain RuntimeControl`.
    [Theory]
    [InlineData("System.AppDomain.Load", Capability.DynamicCodeLoading)]
    [InlineData("System.AppDomain.ExecuteAssembly", Capability.DynamicCodeLoading)]
    [InlineData("System.AppDomain.ExecuteAssemblyByName", Capability.DynamicCodeLoading)]
    [InlineData("System.AppDomain.DefineDynamicAssembly", Capability.DynamicCodeLoading)]
    [InlineData("System.AppDomain.CreateInstance", Capability.DynamicCodeLoading)]
    [InlineData("System.AppDomain.CreateInstanceFrom", Capability.DynamicCodeLoading)]
    [InlineData("System.AppDomain.CreateInstanceAndUnwrap", Capability.DynamicCodeLoading)]
    [InlineData("System.AppDomain.CreateInstanceFromAndUnwrap", Capability.DynamicCodeLoading)]
    [InlineData("System.AppDomain.get_BaseDirectory", Capability.EnvironmentProbe)]
    [InlineData("System.AppDomain.get_FriendlyName", Capability.EnvironmentProbe)]
    [InlineData("System.AppDomain.SetData", Capability.RuntimeControl)]
    [InlineData("System.AppDomain.get_CurrentDomain", Capability.RuntimeControl)]
    public void Default_AppDomainMember_TakesItsSideOfTheThreeWaySplit(string key, Capability expected)
    {
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, expected), CapabilityMap.Default.Classify(key));
    }

    // The pattern language has no mid-name wildcard, so each *AndUnwrap sibling needs its own line and can be
    // forgotten one at a time. This symmetry regressed once: assert it as an equality, not as a literal.
    [Fact]
    public void Default_AppDomainAndUnwrapSiblings_ClassifyIdenticallyToTheirBaseOverloads()
    {
        var andUnwrap = CapabilityMap.Default.Classify("System.AppDomain.CreateInstanceAndUnwrap");
        var fromAndUnwrap = CapabilityMap.Default.Classify("System.AppDomain.CreateInstanceFromAndUnwrap");

        Assert.Equal(andUnwrap, fromAndUnwrap);
        Assert.Equal(CapabilityMap.Default.Classify("System.AppDomain.CreateInstance"), andUnwrap);
        Assert.Equal(CapabilityMap.Default.Classify("System.AppDomain.CreateInstanceFrom"), fromAndUnwrap);
    }

    // AssemblyLoadContext's loading members are carved out of its RuntimeControl type entry: they load an
    // assembly, which is dynamic code loading.
    [Theory]
    [InlineData("System.Runtime.Loader.AssemblyLoadContext.LoadFromAssemblyPath")]
    [InlineData("System.Runtime.Loader.AssemblyLoadContext.LoadFromStream")]
    [InlineData("System.Runtime.Loader.AssemblyLoadContext.LoadFromAssemblyName")]
    [InlineData("System.Runtime.Loader.AssemblyLoadContext.LoadFromNativeImagePath")]
    public void Default_AssemblyLoadContextLoadMembers_AreDynamicCodeLoading(string key)
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.DynamicCodeLoading),
            CapabilityMap.Default.Classify(key));
    }

    // ...and the type entry they are carved out of is still live.
    [Fact]
    public void Default_AssemblyLoadContextUnload_RemainsRuntimeControl()
    {
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.RuntimeControl),
            CapabilityMap.Default.Classify("System.Runtime.Loader.AssemblyLoadContext.Unload"));
    }

    // Directory.GetCurrentDirectory reads process state and touches no file. The intent is "the same
    // observable operation gets the same capability whichever API the caller reached for", so assert the
    // EQUALITY with System.Environment.get_CurrentDirectory rather than the literal EnvironmentProbe.
    [Fact]
    public void Default_DirectoryGetCurrentDirectory_ClassifiesLikeEnvironmentCurrentDirectory()
    {
        var directory = CapabilityMap.Default.Classify("System.IO.Directory.GetCurrentDirectory");

        Assert.Equal(CapabilityMap.Default.Classify("System.Environment.get_CurrentDirectory"), directory);

        // ...and the `capability System.IO.Directory FileSystem` entry it is carved out of is still live.
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem),
            CapabilityMap.Default.Classify("System.IO.Directory.Delete"));
    }

    // Task.Run takes a delegate: it is a call-graph EDGE, not a capability. Marking it safe would terminate
    // traversal and hide whatever the delegate does, so it is deliberately left unclassified (seed §2).
    [Theory]
    [InlineData("System.Threading.Tasks.Task.Run")]
    [InlineData("System.Threading.Tasks.Task.get_Factory")]     // a property getter: the namer never emits "Task.Factory"
    [InlineData("System.Threading.Thread.Start")]
    public void Default_DelegateCarryingApis_AreDeliberatelyUnclassified(string key)
    {
        Assert.Equal(CapabilityVerdict.None, CapabilityMap.Default.Classify(key));
    }

    // The built-in map ships no edge suppressions; the mechanism exists for override files.
    [Fact]
    public void Default_ShipsNoIgnoreEdgeRules()
    {
        Assert.Equal(0, CapabilityMap.Default.Stats.IgnoredEdges);
        Assert.False(CapabilityMap.Default.IsIgnoredEdge("System.IO.File.ReadAllText", "System.Net.WebClient.DownloadString"));
    }

    // A classification key the legacy catalog entry matches today: its method when the entry names one,
    // otherwise any member of the named type (or of any type in the named subtree, for a "Ns.Prefix." entry).
    private static string RepresentativeKey(SensitiveApi api) =>
        api.Method is { } method ? $"{api.TypePrefix}.{method}"
        : api.TypePrefix.EndsWith('.') ? $"{api.TypePrefix}SomeType.SomeMember"
        : $"{api.TypePrefix}.SomeMember";

    private static string Describe(CapabilityVerdict verdict) =>
        verdict.Capability is { } capability ? $"{verdict.Class}/{capability}" : verdict.Class.ToString();
    #endregion
}
