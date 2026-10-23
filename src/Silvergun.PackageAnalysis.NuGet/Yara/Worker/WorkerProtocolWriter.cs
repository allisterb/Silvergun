namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using System.Buffers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

/// <summary>
/// Writes protocol records as compact JSON lines, UTF-8 without a BOM, each terminated by <c>\n</c> and handed to the
/// stream in a single write followed by a <b>flush</b>, so a record the reader can see is always a whole line. Used by
/// the worker (records to stdout) and the parent (requests to the worker's stdin). The writer does not bound field
/// contents: senders build reasons with <c>WorkerProtocol.Safe</c>.
///
/// Every string in a record must be well-formed UTF-16 (review W1): one that is not (a lone surrogate, which an NTFS
/// file name can hold) makes <see cref="Write(WorkerMessage)"/> / <see cref="Write(WorkerRequest)"/> throw
/// <see cref="ArgumentException"/> before anything is written. It is never silently replaced with U+FFFD, which would
/// put a <i>different</i> path or name on the wire. Not thread-safe.
/// </summary>
public sealed class WorkerProtocolWriter
{
    #region Constructors
    public WorkerProtocolWriter(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        this.stream = stream;
    }
    #endregion

    #region Methods
    public void Write(WorkerMessage message) => WriteLine(message, StringsOf(message), WorkerJsonContext.Default.WorkerMessage);

    public void Write(WorkerRequest request) => WriteLine(request, [request.Path], WorkerJsonContext.Default.WorkerRequest);

    private void WriteLine<T>(T value, IEnumerable<string?> strings, JsonTypeInfo<T> typeInfo)
    {
        if (strings.Any(s => s is not null && !WorkerProtocol.IsWellFormedUtf16(s)))
            throw new ArgumentException("A protocol record holds a string that is not well-formed UTF-16; it is not written.", nameof(value));

        buffer.ResetWrittenCount();
        using (var json = new Utf8JsonWriter(buffer))
            JsonSerializer.Serialize(json, value, typeInfo);
        buffer.Write("\n"u8);
        stream.Write(buffer.WrittenSpan);
        stream.Flush();
    }

    // Every string field a record serializes. Nulls (an absent reason, a null hit or tag a caller built) are skipped here
    // and left to the serializer.
    private static IEnumerable<string?> StringsOf(WorkerMessage message) => message switch
    {
        WorkerReady r => [r.Engine, r.EngineVersion, r.RulesSha256, r.Canary],
        WorkerFatal f => [f.Reason],
        WorkerResult r => [r.Reason, .. (r.Hits ?? []).OfType<WorkerHit>().SelectMany(h => (IEnumerable<string?>)[h.Rule, h.Namespace, .. h.Tags ?? []])],
        _ => [],
    };
    #endregion

    #region Fields
    private readonly Stream stream;
    private readonly ArrayBufferWriter<byte> buffer = new();
    #endregion
}
