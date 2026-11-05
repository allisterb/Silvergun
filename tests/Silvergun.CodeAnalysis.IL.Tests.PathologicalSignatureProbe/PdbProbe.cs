namespace Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

using System;
using System.Linq;

using Model.Types;

using CciAssertions = Microsoft.Cci.CciAssertions;

/// <summary>
/// The <c>pdb-load &lt;assembly&gt; &lt;disassembler|loader-pdbs|loader-default&gt; &lt;local-name&gt;</c> verb (ADR 0022 Stage 1, review round 1 C1): one
/// load of an assembly with a (possibly hostile) <c>.pdb</c> beside it. Before the fix, a corrupt AssemblyRef named by a
/// portable PDB's alias import reached a live <c>Debug.Assert</c> in the DiaSymReader converter, a separate compilation
/// the CCI alias does not cover: <c>Environment.FailFast</c>, visible only as this process's exit code. So it runs as a
/// child, never in a test host.
/// <list type="bullet">
/// <item><description><c>disassembler</c>: <see cref="AssemblyDisassembler.Create"/>, Silvergun's path, which reads no
/// PDB.</description></item>
/// <item><description><c>loader-pdbs</c>: <c>new CCIProvider.Loader(host, readPdbs: true).LoadAssembly</c>, the upstream
/// default, which does: the defense-in-depth layer (the converter built without DEBUG throws, and the loader's catch
/// drops the PDB).</description></item>
/// <item><description><c>loader-default</c>: the same through <c>new CCIProvider.Loader(host)</c>, which must still mean
/// <c>readPdbs: true</c>.</description></item>
/// </list>
/// <para>Output: <c>LOADED &lt;bool&gt;</c>, <c>READER-ASSERTIONS &lt;n&gt;</c> (disassembler only), <c>RECORDED &lt;n&gt;</c>
/// (the rise in <see cref="CciAssertions.Total"/>), <c>SOURCE-LOCAL &lt;name&gt; &lt;bool&gt;</c> (whether any local of
/// the model is named <c>&lt;name&gt;</c>, i.e. whether the PDB's names were read), then <c>DONE</c>. Exit 0 when
/// <c>DONE</c> is printed, 1 on a catchable failure; a FailFast never gets that far.</para>
/// </summary>
public static class PdbProbe
{
    #region Methods
    public static int Run(string assemblyPath, string mode, string localName)
    {
        try
        {
            Runtime.Initialize("Silvergun", "PROBE");
            var before = CciAssertions.Total;
            global::Model.Assembly? assembly;
            switch (mode)
            {
                case "disassembler":
                {
                    var created = AssemblyDisassembler.Create(assemblyPath);
                    Console.WriteLine($"LOADED {created.IsSuccess}");
                    if (!created.IsSuccess)
                        Console.Error.WriteLine($"LOAD-FAILED {created.Message}");
                    Console.WriteLine($"READER-ASSERTIONS {(created.IsSuccess ? created.Value.ReaderAssertions : -1)}");
                    assembly = created.IsSuccess ? created.Value.Assembly : null;
                    break;
                }
                case "loader-pdbs" or "loader-default":
                {
                    var host = new global::Model.Host();
                    PlatformTypes.Resolve(host);
                    // loader-default: the one-argument constructor, whose default must stay readPdbs: true (upstream behaviour).
                    var loader = mode == "loader-default" ? new global::CCIProvider.Loader(host) : new global::CCIProvider.Loader(host, readPdbs: true);
                    assembly = loader.LoadAssembly(assemblyPath);
                    Console.WriteLine("LOADED True");
                    break;
                }
                default:
                    Console.Error.WriteLine($"USAGE: pdb-load <assembly> <disassembler|loader-pdbs> <local-name>; got mode '{mode}'");
                    return 2;
            }

            Console.WriteLine($"RECORDED {CciAssertions.Total - before}");
            var named = assembly?.RootNamespace.GetAllTypes()
                .SelectMany(t => t.Members.OfType<MethodDefinition>())
                .Where(m => m.HasBody)
                .SelectMany(m => m.Body.LocalVariables)
                .Any(v => v.Name == localName) ?? false;
            Console.WriteLine($"SOURCE-LOCAL {localName} {named}");
            Console.WriteLine("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"UNHANDLED {ex}");
            return 1;
        }
    }
    #endregion

    #region Fields
    public const string Verb = "pdb-load";
    #endregion
}
