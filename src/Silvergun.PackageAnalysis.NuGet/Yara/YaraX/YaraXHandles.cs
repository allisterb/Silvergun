namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

/// <summary>A <c>YRX_COMPILER*</c>, destroyed with <c>yrx_compiler_destroy</c>.</summary>
internal sealed class YaraXCompilerHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    #region Constructors
    public YaraXCompilerHandle() : base(ownsHandle: true) { }
    #endregion

    #region Methods
    protected override bool ReleaseHandle()
    {
        YaraXNative.yrx_compiler_destroy(handle);
        return true;
    }
    #endregion
}

/// <summary>
/// A <c>YRX_RULES*</c>, destroyed with <c>yrx_rules_destroy</c>. Every <see cref="YaraXScannerHandle"/> created from it holds
/// a reference on it (<see cref="SafeHandle.DangerousAddRef"/>), so the rules are destroyed only after the last scanner —
/// the order <c>yara_x.h</c> requires — whichever is disposed or finalized first.
/// </summary>
internal sealed class YaraXRulesHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    #region Constructors
    public YaraXRulesHandle() : base(ownsHandle: true) { }
    #endregion

    #region Methods
    protected override bool ReleaseHandle()
    {
        YaraXNative.yrx_rules_destroy(handle);
        return true;
    }
    #endregion
}

/// <summary>
/// A <c>YRX_SCANNER*</c>, destroyed with <c>yrx_scanner_destroy</c>. Once <see cref="Attach"/>ed it also owns the
/// reference on its rules and the GC handle its match callback reads, and releases both only AFTER the native scanner is
/// destroyed, so neither can be freed under a running scan or a pending callback.
/// </summary>
internal sealed class YaraXScannerHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    #region Constructors
    public YaraXScannerHandle() : base(ownsHandle: true) { }
    #endregion

    #region Methods
    /// <summary>
    /// Hands this handle the reference already taken on <paramref name="rules"/> and the callback's
    /// <paramref name="sink"/>; both are released by <see cref="ReleaseHandle"/>.
    /// </summary>
    internal void Attach(YaraXRulesHandle rules, GCHandle sink) => (this.rules, this.sink) = (rules, sink);

    protected override bool ReleaseHandle()
    {
        YaraXNative.yrx_scanner_destroy(handle);
        if (sink.IsAllocated)
            sink.Free();
        rules?.DangerousRelease();
        return true;
    }
    #endregion

    #region Fields
    private YaraXRulesHandle? rules;
    private GCHandle sink;
    #endregion
}
