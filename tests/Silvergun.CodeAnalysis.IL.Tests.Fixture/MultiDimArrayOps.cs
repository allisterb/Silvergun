namespace Silvergun.CodeAnalysis.IL.Tests.Fixture;

using System.Diagnostics;
using System.IO;

/// <summary>
/// The <b>multi-dimensional array accessor</b> shape, isolated in one method so a test can pin what the
/// shipping scan does with it. The runtime provides <c>T[,]::Get</c>, <c>::Set</c>, <c>::Address</c> and
/// <c>::.ctor</c> as real methods and the C# compiler emits real <c>call</c>/<c>newobj</c> instructions for
/// them — but CCI rewrites those instructions into its synthetic <c>Array_Get</c>/<c>Array_Set</c>/
/// <c>Array_Addr</c>/<c>Array_Create</c> opcodes whose operand is the <em>array type</em>, not a method
/// reference (<c>ext/analysis-net/cci/PEReaderAndWriter/PEReader/ILReader.cs:765-786, 921-929</c>), so the
/// scan never sees them as call sites at all. Measured at 53 such call sites in a 324,168-call-site corpus:
/// <c>docs/agent/measurements/ilspy-provider-spike.md</c> §1.4 category 9 / §1.10 item 1.
/// <para>
/// The <see cref="File.ReadAllText(string)"/> call in the same method is the <b>positive control</b>: an
/// ordinary call site in the very same body, which the scan does see. Without it, a test asserting "no call
/// sites for the accessors" could pass simply because the method was never scanned.
/// </para>
/// Analyzed statically, never executed.
/// </summary>
public static class MultiDimArrayOps
{
    #region Methods
    /// <summary>
    /// Creates a rank-2 array and reads, writes and takes a reference to its elements — one occurrence of each
    /// of the four accessor shapes — then makes one ordinary, catalog-matching call.
    /// </summary>
    public static int CopiesMatrixCellsAndReadsAFile()
    {
        // newobj instance void int32[,]::.ctor(int32, int32)  ->  Array_Create
        int[,] matrix = new int[2, 2];

        // call instance int32 int32[,]::Get(int32, int32)     ->  Array_Get
        // call instance void  int32[,]::Set(int32, int32, int32) -> Array_Set
        matrix[0, 0] = matrix[1, 1];

        // call instance int32& int32[,]::Address(int32, int32) ->  Array_Addr
        ref int cell = ref matrix[0, 1];
        cell = matrix[0, 0] + 1;

        // POSITIVE CONTROL, in the same body: a plain call the scan does record, and which the capability
        // catalog matches (System.IO.File -> FileSystem).
        return matrix[0, 1] + File.ReadAllText(UnreadFile).Length;
    }

    /// <summary>
    /// The same four accessor shapes on an array whose <b>element type is catalogued</b> —
    /// <c>System.Diagnostics.Process[,]</c>. This is the LATENT FALSE POSITIVE of
    /// <c>docs/agent/measurements/ilspy-provider-spike.md</c> §2.2.3: the declaring type of
    /// <c>Process[,]::Get</c> renders as <c>System.Diagnostics.Process[,]</c>, which
    /// <em>does</em> begin with the catalog prefix <c>System.Diagnostics.Process</c>, so the only reason a mere
    /// array-element read does not emit a spurious <c>ProcessExecution</c> finding today is that CCI never hands
    /// these accessors back as call sites at all. The protection is incidental, not designed.
    /// <para>
    /// The <see cref="Process.Start(string)"/> call is the <b>positive control</b>: a real
    /// <c>ProcessExecution</c> call site in the very same body, so "the accessors produced nothing" cannot pass
    /// because the body went unscanned.
    /// </para>
    /// Analyzed statically, never executed.
    /// </summary>
    public static Process CopiesProcessMatrixCellsAndStartsOne(string fileName)
    {
        // newobj instance void class [*]System.Diagnostics.Process[,]::.ctor(int32, int32) -> Array_Create
        Process[,] processes = new Process[2, 2];

        // Array_Get + Array_Set on System.Diagnostics.Process[,]
        processes[0, 0] = processes[1, 1];

        // Array_Addr on System.Diagnostics.Process[,]
        ref Process cell = ref processes[0, 1];

        // POSITIVE CONTROL, in the same body: a plain call the scan does record, and which the capability
        // catalog matches (System.Diagnostics.Process -> ProcessExecution).
        cell = Process.Start(fileName);

        return processes[0, 0];
    }
    #endregion

    #region Fields
    /// <summary>Never opened — the method exists only to be read out of metadata.</summary>
    private const string UnreadFile = "silvergun-multidim-fixture.txt";
    #endregion
}
