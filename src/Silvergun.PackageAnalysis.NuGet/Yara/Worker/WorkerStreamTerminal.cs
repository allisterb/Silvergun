namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>
/// How a protocol stream ended. Only <see cref="Done"/> means a complete run; every other terminal means the files
/// without a valid result are <b>unscanned</b>, and the valid records read before it are still partial findings
/// (ADR 0032). Every <c>Reason</c>/<c>Detail</c> here is already escaped and bounded: safe to log verbatim.
/// </summary>
public abstract record WorkerStreamTerminal
{
    #region Child types
    /// <summary>The worker sent a valid <c>done</c> after a valid <c>ready</c> and exactly one valid result per request.</summary>
    public sealed record Done(WorkerDone Record) : WorkerStreamTerminal;

    /// <summary>The worker sent a well-formed <c>fatal</c> record.</summary>
    public sealed record Fatal(string Reason) : WorkerStreamTerminal;

    /// <summary>The stream broke the contract: a limit, the schema, the ordering, the encoding, or a truncated line.</summary>
    public sealed record Violation(string Reason) : WorkerStreamTerminal;

    /// <summary>
    /// The stream ended at a line boundary without a terminating record (a crash, a kill), or reading failed
    /// (<see cref="Detail"/> is then set). Not a contract violation, but just as incomplete.
    /// </summary>
    public sealed record Eof(string? Detail = null) : WorkerStreamTerminal;
    #endregion
}

/// <summary>
/// Everything a <see cref="WorkerResponseReader"/> accepted, and how the stream ended. <see cref="Results"/> holds
/// only records that were valid when read, in index order (so <c>Results[i].Index == i</c>).
/// </summary>
public sealed record WorkerStreamOutcome(WorkerReady? Ready, IReadOnlyList<WorkerResult> Results, WorkerStreamTerminal Terminal)
{
    #region Properties
    /// <summary><c>true</c> only for <see cref="WorkerStreamTerminal.Done"/>.</summary>
    public bool IsComplete => Terminal is WorkerStreamTerminal.Done;
    #endregion
}
