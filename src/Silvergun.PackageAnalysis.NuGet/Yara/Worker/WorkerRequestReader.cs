namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>
/// The worker's reader of its stdin (worker protocol v1): one <see cref="WorkerRequest"/> per line, indices 0, 1, 2…
/// in order, until a clean end of stream. Same line bounds and strict schema as <see cref="WorkerResponseReader"/>;
/// the first breach ends reading with a <see cref="WorkerStreamTerminal.Violation"/>, and a clean end at a line
/// boundary with <see cref="WorkerStreamTerminal.Eof"/>. Not thread-safe.
/// </summary>
public sealed class WorkerRequestReader
{
    #region Constructors
    public WorkerRequestReader(Stream stdin) => lines = new WorkerLineReader(stdin);
    #endregion

    #region Properties
    /// <summary>Requests accepted so far.</summary>
    public int Count { get; private set; }

    /// <summary>How the stream ended; null while it is still open.</summary>
    public WorkerStreamTerminal? Terminal { get; private set; }
    #endregion

    #region Methods
    /// <summary>The next valid request, or <c>null</c> once the stream has ended (see <see cref="Terminal"/>).</summary>
    public WorkerRequest? Next()
    {
        if (Terminal is not null)
            return null;

        var (status, bytes) = lines.ReadLine();
        if (status != WorkerLineStatus.Line)
            return End(WorkerResponseReader.LineTerminal(status, lines.MaxLineBytes));

        var (request, error) = WorkerResponseReader.Parse(bytes, WorkerJsonContext.Default.WorkerRequest);
        var violation = request is null ? error
            : request.Index != Count ? $"request index {request.Index} out of order (expected {Count})"
            : request.Path.Length == 0 ? $"request {request.Index} has an empty path"
            : null;
        if (violation is not null)
            return End(new WorkerStreamTerminal.Violation(violation));

        Count++;
        return request;
    }

    private WorkerRequest? End(WorkerStreamTerminal terminal)
    {
        Terminal = terminal;
        return null;
    }
    #endregion

    #region Fields
    private readonly WorkerLineReader lines;
    #endregion
}
