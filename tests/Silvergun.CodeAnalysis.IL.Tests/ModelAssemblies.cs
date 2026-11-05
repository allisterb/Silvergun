namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

/// <summary>
/// One or more assemblies loaded with <see cref="AssemblyDisassembler"/> (one Analysis.Net host each, as phase A1
/// allows), ready to be indexed by <see cref="MemberIndex"/> and walked by <see cref="MethodGraph"/>. The same path
/// may be given twice: each load is an independent host, which is how the ambiguity tests put two definitions with one
/// node id into one index. <b>Fails loudly</b>: a load failure throws naming the path, and anything already loaded is
/// released first. So does a load on which a CCI assertion failed (<see cref="AssemblyDisassembler.ReaderAssertions"/>,
/// ADR 0022 Stage 1): no fixture of this suite trips one, and since such a load now continues on a possibly degraded
/// model instead of killing the host, every test built on it would otherwise be testing that model unawares.
/// </summary>
public sealed class ModelAssemblies : IDisposable
{
    #region Constructors
    private ModelAssemblies(IReadOnlyList<AssemblyDisassembler> disassemblers) => Disassemblers = disassemblers;
    #endregion

    #region Properties
    public IReadOnlyList<AssemblyDisassembler> Disassemblers { get; }
    #endregion

    #region Methods
    public static ModelAssemblies Load(params string[] paths)
    {
        Runtime.Initialize("Silvergun", "TESTS");

        var loaded = new List<AssemblyDisassembler>();
        try
        {
            foreach (var path in paths)
            {
                var created = AssemblyDisassembler.Create(path);
                loaded.Add(created.IsSuccess
                    ? created.Value
                    : throw new InvalidOperationException($"Failed to load '{path}': {created.Message}", created.Exception));
                if (loaded[^1].ReaderAssertions > 0)
                    throw new InvalidOperationException($"Loading '{path}' failed {loaded[^1].ReaderAssertions} CCI assertion(s): the model may be degraded (ADR 0022 Stage 1).");
            }
        }
        catch (Exception)
        {
            loaded.ForEach(d => d.Dispose());
            throw;
        }

        return new ModelAssemblies(loaded);
    }

    /// <summary>A fresh <see cref="MemberIndex"/> over every loaded assembly.</summary>
    public MemberIndex Index() => MemberIndex.Build(Disassemblers);

    public void Dispose()
    {
        foreach (var disassembler in Disassemblers)
            disassembler.Dispose();
    }
    #endregion
}
