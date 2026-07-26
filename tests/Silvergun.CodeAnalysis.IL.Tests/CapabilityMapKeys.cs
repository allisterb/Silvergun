namespace Silvergun.CodeAnalysis.IL.Tests;

using System.Collections.Generic;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// One representative <c>ClassificationKey</c> per <see cref="Capability"/>, each taken from the built-in
/// <c>Resources/capabilities.cm</c>. Shared by the map's data-file integrity tests and by
/// <see cref="CapabilityAnalysisTests"/>'s taxonomy-coverage assertion.
/// <para>
/// Appending a value to <see cref="Capability"/> without adding a key here fails the coverage tests by design:
/// a capability that no map entry can ever produce is unreachable, which is exactly what those tests exist to
/// catch (the enum is append-only for ordinal stability, so the map is the thing that must keep up).
/// </para>
/// </summary>
internal static class CapabilityMapKeys
{
    #region Properties
    public static IReadOnlyDictionary<Capability, string> Representative { get; } = new Dictionary<Capability, string>
    {
        [Capability.FileSystem] = "System.IO.File.ReadAllText",
        [Capability.Network] = "System.Net.WebClient.DownloadString",
        [Capability.ProcessExecution] = "System.Diagnostics.Process.Start",
        [Capability.Registry] = "Microsoft.Win32.Registry.GetValue",
        [Capability.EnvironmentProbe] = "System.Environment.get_UserName",
        [Capability.DynamicCodeLoading] = "System.Reflection.Assembly.Load",
        [Capability.NativeInterop] = "System.Runtime.InteropServices.Marshal.Copy",
        [Capability.Cryptography] = "System.Security.Cryptography.SHA256.ComputeHash",
        [Capability.ReflectionInvocation] = "System.Reflection.MethodBase.Invoke",
        [Capability.UnsafeMemory] = "System.Runtime.CompilerServices.Unsafe.As",
        [Capability.RuntimeControl] = "System.GC.Collect",
    };
    #endregion
}
