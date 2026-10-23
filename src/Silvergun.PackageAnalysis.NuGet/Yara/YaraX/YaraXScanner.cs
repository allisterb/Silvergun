#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

using Microsoft.Win32.SafeHandles;

/// <summary>
/// A YARA-X scanner (<c>YRX_SCANNER</c>) over one <see cref="YaraXRules"/>.
///
/// <para><b>One thread only.</b> Every member except <see cref="Dispose"/> throws <see cref="InvalidOperationException"/>
/// when called from any thread but the one that created the scanner. Using one scanner from two threads at once panicked
/// inside the engine and aborted the host (0xC0000409) in every run of the C API spike, uncatchably; a second thread needs
/// its own scanner (the rules may be shared).</para>
///
/// <para><b>Scans by bytes only</b> (never <c>yrx_scanner_scan_file</c>, which leaves files of 31 MiB or more mapped after
/// it returns); files above <see cref="Array.MaxLength"/> are scanned through a read-only memory-mapped view. Every scan
/// is bounded by the scanner's timeout (whole seconds, ≥ 1; <c>0</c> would time out every scan at once), quantised by
/// the engine to a process-wide 1 Hz tick, so a scan gets between T−1 and T seconds — and the engine's timeout does not
/// shorten the pattern pass over a huge input, so the parent's kill remains the backstop (ADR 0033).</para>
///
/// <para><b>No exception crosses the FFI boundary.</b> The match and tag callbacks are <see cref="UnmanagedCallersOnly"/>
/// and catch everything; a callback failure turns that scan into an <see cref="YaraXScanResult.Error"/>, never into a
/// <see cref="YaraXScanResult.Scanned"/> with hits missing. Engine results come back as values: a timeout is
/// <see cref="YaraXScanResult.Timeout"/> and the scanner stays usable.</para>
/// </summary>
internal sealed unsafe class YaraXScanner : IDisposable
{
    #region Constructors
    internal YaraXScanner(YaraXRules rules, int timeoutSeconds)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(timeoutSeconds, 1);
        YaraXNative.EnsureLoaded();
        (this.rules, owner) = (rules, Environment.CurrentManagedThreadId);

        // The reference taken here, and the GC handle the callback reads, are handed to the scanner handle, which releases
        // both only after destroying the native scanner (YaraXScannerHandle.ReleaseHandle).
        var addedRef = false;
        rules.Handle.DangerousAddRef(ref addedRef);
        var sinkHandle = GCHandle.Alloc(sink);
        YaraXScannerHandle? created = null;
        try
        {
            var result = YaraXNative.yrx_scanner_create(rules.Handle, out created);
            if (result != YaraXResult.Success || created.IsInvalid)
                throw new InvalidOperationException($"yrx_scanner_create failed: {result}: {YaraXNative.LastError()}");
            created.Attach(rules.Handle, sinkHandle);
        }
        catch
        {
            created?.Dispose();
            sinkHandle.Free();
            rules.Handle.DangerousRelease();
            throw;
        }

        handle = created;
        try
        {
            Check(YaraXNative.yrx_scanner_on_matching_rule(handle, &OnMatchingRule, GCHandle.ToIntPtr(sinkHandle)), "yrx_scanner_on_matching_rule");
            SetTimeout(timeoutSeconds);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }
    #endregion

    #region Methods
    /// <summary>Bounds every later scan by <paramref name="seconds"/> (≥ 1).</summary>
    internal void SetTimeout(int seconds)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(seconds, 1);
        EnsureOwner();
        Check(YaraXNative.yrx_scanner_set_timeout(handle, (ulong)seconds), "yrx_scanner_set_timeout");
    }

    /// <summary>Scans <paramref name="data"/>; the canary is stripped from the hits.</summary>
    internal YaraXScanResult Scan(ReadOnlySpan<byte> data)
    {
        EnsureOwner();
        fixed (byte* bytes = data)
            return Stripped(ScanRaw(bytes, (nuint)data.Length));
    }

    /// <summary>
    /// Scans the whole of the already-open <paramref name="file"/> (the caller opens it, through a <c>\\?\</c> path on
    /// Windows, so a file named like a DOS device is the file and not the device). Up to <see cref="Array.MaxLength"/>
    /// bytes it is read into memory; above that it is scanned through a read-only memory-mapped view. A failure to read or
    /// map it is an <see cref="YaraXScanResult.Error"/>, and so is a file whose length after the scan is not the length it
    /// had before (it changed underneath, so what was scanned is not the file). A file truncated by someone else while it
    /// is mapped can fault the process, so open it with no write sharing.
    /// </summary>
    internal YaraXScanResult Scan(SafeFileHandle file)
    {
        EnsureOwner();
        try
        {
            var length = RandomAccess.GetLength(file);
            var result = length > Array.MaxLength ? ScanMapped(file, length) : Scan(ReadAll(file, (int)length));
            var after = RandomAccess.GetLength(file);
            return after == length ? result
                : new YaraXScanResult.Error($"the file changed length while it was being scanned ({length} bytes, then {after}); it was not scanned as a whole");
        }
        catch (Exception ex)
        {
            return new YaraXScanResult.Error($"could not read the file: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// The canary check: scans the rules' <see cref="YaraXCanary.Marker"/> and requires the canary rule, by exact name, to
    /// hit. <c>null</c> when it passes; otherwise why it failed. A pass proves this compiled rules object scans.
    /// </summary>
    internal string? CheckCanary()
    {
        EnsureOwner();
        var canary = rules.Canary;
        YaraXScanResult result;
        fixed (byte* marker = canary.Marker)
            result = ScanRaw(marker, (nuint)canary.Marker.Length);

        return result switch
        {
            YaraXScanResult.Scanned scanned when canary.HitIn(scanned.Hits) => null,
            YaraXScanResult.Scanned => "the canary rule did not match its marker",
            YaraXScanResult.Timeout => "the canary scan timed out",
            YaraXScanResult.Error error => "the canary scan failed: " + error.Message,
            _ => "the canary scan returned an unknown result",
        };
    }

    public void Dispose() => handle.Dispose();

    private YaraXScanResult ScanMapped(SafeFileHandle file, long length)
    {
        using var map = MemoryMappedFile.CreateFromFile(file, mapName: null, capacity: 0, MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: true);
        using var view = map.CreateViewAccessor(0, length, MemoryMappedFileAccess.Read);
        var mapped = view.SafeMemoryMappedViewHandle;
        byte* start = null;
        mapped.AcquirePointer(ref start);
        try
        {
            return Stripped(ScanRaw(start + view.PointerOffset, (nuint)length));
        }
        finally
        {
            mapped.ReleasePointer();
        }
    }

    // One engine call. The hits are exactly what the callback collected on THIS call; a callback fault, or a failure the
    // engine reports, means the file was not scanned.
    private YaraXScanResult ScanRaw(byte* data, nuint length)
    {
        sink.Reset();
        callbackFaults = 0;
        var result = YaraXNative.yrx_scanner_scan(handle, data, length);
        var error = result is YaraXResult.Success or YaraXResult.ScanTimeout ? null : YaraXNative.LastError();

        return result switch
        {
            YaraXResult.ScanTimeout => new YaraXScanResult.Timeout(),
            YaraXResult.Success when callbackFaults > 0 || sink.fault is not null =>
                new YaraXScanResult.Error($"a match callback failed, so the hits are incomplete: {sink.fault ?? "(no detail)"}"),
            YaraXResult.Success => new YaraXScanResult.Scanned(sink.hits.ToArray()),
            _ => new YaraXScanResult.Error($"{result}: {error ?? "(no message)"}"),
        };
    }

    private YaraXScanResult Stripped(YaraXScanResult result) =>
        result is YaraXScanResult.Scanned scanned ? new YaraXScanResult.Scanned(rules.Canary.Strip(scanned.Hits)) : result;

    // Exactly `length` bytes, or an IOException: a file that ends early, or whose length is no longer `length` once read
    // (W5: it grew, so the bytes read are not the whole file), changed while being read.
    private static byte[] ReadAll(SafeFileHandle file, int length)
    {
        var buffer = GC.AllocateUninitializedArray<byte>(length);
        for (var read = 0; read < length;)
        {
            var count = RandomAccess.Read(file, buffer.AsSpan(read), read);
            if (count == 0)
                throw new IOException($"the file ended after {read} of {length} bytes; it changed while being read");
            read += count;
        }
        var after = RandomAccess.GetLength(file);
        return after == length ? buffer
            : throw new IOException($"the file is {after} bytes after reading {length}; it changed while being read");
    }

    private void EnsureOwner()
    {
        if (Environment.CurrentManagedThreadId != owner)
            throw new InvalidOperationException(
                "A YARA-X scanner may only be used by the thread that created it: one scanner used by two threads aborts the process.");
    }

    private static void Check(YaraXResult result, string call)
    {
        if (result != YaraXResult.Success)
            throw new InvalidOperationException($"{call} failed: {result}: {YaraXNative.LastError()}");
    }

    // Runs inside the engine's scan. It must never throw: everything is caught, and a failure fails the whole scan.
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnMatchingRule(nint rule, nint userData)
    {
        try
        {
            var target = Sink(userData);
            target.tags.Clear();
            var tags = YaraXNative.yrx_rule_iter_tags(rule, &OnTag, userData);
            var id = YaraXNative.yrx_rule_identifier(rule, out var idText, out var idLength);
            var ns = YaraXNative.yrx_rule_namespace(rule, out var nsText, out var nsLength);
            if (tags != YaraXResult.Success || id != YaraXResult.Success || ns != YaraXResult.Success)
                throw new InvalidOperationException($"reading a matching rule failed: tags {tags}, identifier {id}, namespace {ns}");

            target.hits.Add(new YaraXHit(Utf8(idText, idLength), Utf8(nsText, nsLength), target.tags.ToArray()));
        }
        catch (Exception ex)
        {
            callbackFaults++;
            try { Sink(userData).fault ??= YaraXText.Bounded($"{ex.GetType().Name}: {ex.Message}"); }
            catch { /* the counter above already fails the scan */ }
        }
    }

    // Runs inside yrx_rule_iter_tags, inside OnMatchingRule. Same rule: never throws.
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnTag(byte* tag, nint userData)
    {
        try { Sink(userData).tags.Add(Marshal.PtrToStringUTF8((nint)tag) ?? string.Empty); }
        catch { callbackFaults++; }
    }

    private static MatchSink Sink(nint userData) => (MatchSink)GCHandle.FromIntPtr(userData).Target!;

    // yara_x.h guarantees identifiers and namespaces are valid UTF-8; they are NOT NUL-terminated.
    private static string Utf8(byte* text, nuint length) => Encoding.UTF8.GetString(text, checked((int)length));
    #endregion

    #region Fields
    // Callback failures on this thread during the current scan. A plain counter, because incrementing it cannot fail
    // even when recording the failure's detail in the sink does. Callbacks run synchronously on the scanning thread.
    [ThreadStatic]
    private static int callbackFaults;

    private readonly YaraXRules rules;
    private readonly YaraXScannerHandle handle;
    private readonly int owner;
    private readonly MatchSink sink = new();
    #endregion

    #region Child types
    // What the callbacks write into, through a GC handle passed as the engine's user_data. Reset before every scan.
    private sealed class MatchSink
    {
        #region Methods
        internal void Reset()
        {
            hits.Clear();
            tags.Clear();
            fault = null;
        }
        #endregion

        #region Fields
        internal readonly List<YaraXHit> hits = [];
        internal readonly List<string> tags = [];
        internal string? fault;
        #endregion
    }
    #endregion
}
#endif
