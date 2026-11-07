namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using Xunit;

/// <summary>
/// The ADR 0022 Stage 1 repro, as a <b>crash-regression test in a child process</b> (acceptance criterion 1): the R2
/// child (<c>BenignCorpusHarness reach</c>, <see cref="ReachabilityChild"/>) over the cached, third-party
/// <c>Microsoft.Extensions.ApiDescription.Server</c> 10.0.11. Before Stage 1 that child died with <c>0x80131623</c>
/// (<c>Environment.FailFast</c>, "Assumption failed" in <c>CoreTypeReference.ResolvedType</c> via
/// <c>TypeBase.IsDelegate</c>, during <c>AssemblyDisassembler.Create</c> over <c>tools/net462</c>). In a test host
/// that would take the whole run down; here a regression is one failed test.
/// <para>
/// The child runs the full instrument: <see cref="Silvergun.PackageAnalysis.NuGet.NuGetPackage.Open"/>,
/// <see cref="Silvergun.PackageAnalysis.NuGet.PackageGraphs"/>, <see cref="Reachability.Analyze"/>, and the raw-CCI
/// presence scan of every member. Asserted from its JSON payload: it completes, the two <c>tools</c> folders build graphs
/// whose every class is Unknown with the reader reason, and the presence scan read every member of them. The in-process
/// detail (the counts, the culprit assembly) is <c>ReaderAssertionReproTests</c> in Silvergun.PackageAnalysis.NuGet.Tests.
/// </para>
/// <para>
/// Gated on the benign-corpus cache (skipped when the package is absent, never downloaded); the package is read from the
/// cache in place and never copied into the repository.
/// </para>
/// </summary>
public sealed class ReaderAssertionReproChildTests
{
    #region Methods
    [CachedCorpusPackageFact(ReproPackage)]
    public void TheR2Child_OverTheRepro_Completes_AndBothToolsFoldersReadUnknownWithTheReaderReason()
    {
        var directory = Directory.CreateTempSubdirectory("silvergun-cci-repro-").FullName;
        try
        {
            var output = Path.Combine(directory, "payload.json");
            var result = ChildProcessProbe.Run(HarnessExe, TimeSpan.FromMinutes(5), ReachabilityChild.Verb, CachedCorpusPackageFactAttribute.PathOf(ReproPackage), output);

            Assert.True(result.ExitedCleanly, $"The R2 child did not exit cleanly over the repro - {result.Describe()}");
            Assert.Contains("DONE", result.StandardOutput, StringComparison.Ordinal);
            var payload = JsonSerializer.Deserialize<ChildPayload>(File.ReadAllText(output), PackageReachResult.JsonOptions)!;

            // Measured 2026-11-05: exactly these two folders trip the reader; every other folder of the package is clean.
            Assert.Equal(DegradedFolders, payload.Folders.Where(f => f.Verdicts.Any(v => v.Reasons.Any(IsReaderReason))).Select(f => f.Folder));
            foreach (var folder in DegradedFolders.Select(name => Assert.Single(payload.Folders, f => f.Folder == name)))
            {
                Assert.True(folder.GraphBuilt, $"{folder.Folder}: no graph was built.");
                Assert.False(folder.Coverage!.IndexComplete, $"{folder.Folder}: the index reads complete.");
                var otherGaps = folder.Coverage.AssembliesUnreadable + folder.Coverage.TypesSkipped + folder.Coverage.IndexMethodsSkipped
                    + folder.Coverage.ForwardersUnreadable + folder.Coverage.SupertypesUnresolved > 0;
                // One verdict per single root class: eight since ADR 0037 amendment a1 split RuntimeInvoked three ways.
                Assert.Equal(ReachabilityChild.AllClasses, folder.Verdicts.Select(v => v.Class));
                Assert.All(folder.Verdicts, v =>
                {
                    Assert.Equal(RootClassVerdict.Unknown, v.Verdict);
                    Assert.True(ReaderCount(Assert.Single(v.Reasons, IsReaderReason)) > 0);
                    // The incomplete-index reason is for the index's other gaps only.
                    Assert.Equal(otherGaps, v.Reasons.Any(r => r.StartsWith("the member index is incomplete", StringComparison.Ordinal)));
                });
                // The raw-CCI scanner read every member of the folder (it does not report the assertions yet: Stage 1b).
                Assert.All(folder.Presence, p => Assert.True(p.Ok, $"{folder.Folder}: the presence scan of {p.Assembly} failed: {p.Failure}"));
                Assert.Contains(folder.Presence, p => p.Assembly == $"{folder.Folder}/{Culprit}");
            }
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { /* best-effort temp cleanup */ }
        }
    }

    // "the metadata reader failed N assertion(s): the model may be degraded" (Reachability's reason).
    private static bool IsReaderReason(string reason) =>
        reason.StartsWith(ReaderReasonPrefix, StringComparison.Ordinal) && reason.EndsWith(ReaderReasonSuffix, StringComparison.Ordinal);

    private static int ReaderCount(string reason) => int.Parse(reason[ReaderReasonPrefix.Length..^ReaderReasonSuffix.Length]);
    #endregion

    #region Fields
    /// <summary>The cached repro package (benign-corpus cache, <c>packages/</c>).</summary>
    public const string ReproPackage = "Microsoft.Extensions.ApiDescription.Server.10.0.11.nupkg";

    /// <summary>
    /// The assembly of <c>tools/net462</c> (and of <c>tools/net462-x86</c>) whose load fails a CCI assertion, found by
    /// loading each member alone (<c>ReaderAssertionReproTests</c>, Silvergun.PackageAnalysis.NuGet.Tests; measured
    /// 2026-11-05).
    /// </summary>
    public const string Culprit = "Microsoft.OpenApi.dll";

    private const string ReaderReasonPrefix = "the metadata reader failed ";
    private const string ReaderReasonSuffix = " assertion(s): the model may be degraded";

    private static readonly string[] DegradedFolders = ["tools/net462", "tools/net462-x86"];

    private static readonly string HarnessExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness");
    #endregion
}

/// <summary>
/// Gates a test on a package in the benign-corpus cache (<c>%LOCALAPPDATA%/Silvergun/benign-corpus/packages</c>, the
/// harness's default <c>--cache</c>): skipped, never downloaded, when it is absent.
/// </summary>
public sealed class CachedCorpusPackageFactAttribute : FactAttribute
{
    #region Constructors
    public CachedCorpusPackageFactAttribute(string fileName)
    {
        if (!File.Exists(PathOf(fileName)))
            Skip = $"Needs {fileName} in the benign-corpus cache ({PathOf(fileName)}), and it is not there. Run the benign-corpus harness to fill it.";
    }
    #endregion

    #region Methods
    public static string PathOf(string fileName) =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify) is { Length: > 0 } local ? local : Path.GetTempPath(),
            "Silvergun", "benign-corpus", "packages", fileName);
    #endregion
}
