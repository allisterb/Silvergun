namespace Silvergun.CLI;

using System.CommandLine;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// Entry point for the Silvergun CLI. Exposes the <c>analyze</c> verb, which runs
/// <see cref="AssemblyAnalyzer"/> + <see cref="CapabilityAnalysis"/> over a .NET assembly and reports
/// the resulting <see cref="CapabilityReport"/>. Exit codes are part of the CI contract (ADR 0003):
/// 0 = success, 1 = load/analysis failure or bad arguments, 2 = findings present under <c>--strict</c>.
/// </summary>
internal static class Program
{
    #region Methods
    private static int Main(string[] args)
    {
        var pathArgument = new Argument<string>("assembly-path")
        {
            Description = "Path to the .NET assembly to analyze."
        };
        var jsonOption = new Option<bool>("--json")
        {
            Description = "Emit the capability report as JSON instead of the human summary."
        };
        var outputOption = new Option<string?>("--output")
        {
            Description = "Write the report to a file instead of stdout."
        };
        var strictOption = new Option<bool>("--strict")
        {
            Description = "Exit with code 2 when any findings are present (CI gate)."
        };
        var debugOption = new Option<bool>("--debug")
        {
            Description = "Enable verbose logging."
        };

        var analyzeCommand = new Command("analyze", "Analyze a .NET assembly for sensitive-API capabilities.")
        {
            pathArgument, jsonOption, outputOption, strictOption, debugOption
        };
        analyzeCommand.SetAction(parse => RunAnalyze(
            parse.GetValue(pathArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(outputOption),
            parse.GetValue(strictOption),
            parse.GetValue(debugOption)));

        var root = new RootCommand("Silvergun — static capability analysis for .NET assemblies.")
        {
            analyzeCommand
        };

        return root.Parse(args).Invoke();
    }

    private static int RunAnalyze(string assemblyPath, bool json, string? output, bool strict, bool debug)
    {
        // Keep stdout machine-parseable: when JSON goes to stdout, log to file only.
        if (json && output is null)
            Runtime.WithFileLogging("Silvergun", "CLI", debug);
        else
            Runtime.WithFileAndConsoleLogging("Silvergun", "CLI", debug);

        var analyzerResult = AssemblyAnalyzer.Create(assemblyPath);
        if (!analyzerResult.IsSuccess)
        {
            Console.Error.WriteLine(analyzerResult.Message);
            return 1;
        }

        using var analyzer = analyzerResult.Value;

        var reportResult = new CapabilityAnalysis(analyzer).Analyze();
        if (!reportResult.IsSuccess)
        {
            Console.Error.WriteLine(reportResult.Message);
            return 1;
        }

        var report = reportResult.Value;
        var text = json ? report.ToJson() : HumanSummary(report);

        if (output is null)
        {
            Console.WriteLine(text);
        }
        else
        {
            try
            {
                File.WriteAllText(output, text);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"Failed to write report to {output}: {ex.Message}");
                return 1;
            }
        }

        return strict && report.Findings.Count > 0 ? 2 : 0;
    }

    private static string HumanSummary(CapabilityReport report)
    {
        var lines = new List<string>
        {
            $"Assembly: {report.AssemblyName}",
            $"Path:     {report.AssemblyPath}",
            $"Findings: {report.Findings.Count}",
            string.Empty
        };

        if (report.Findings.Count == 0)
        {
            lines.Add("No sensitive-API findings.");
            return string.Join(Environment.NewLine, lines);
        }

        foreach (var group in report.Findings.GroupBy(f => f.Capability).OrderBy(g => g.Key.ToString()))
        {
            lines.Add($"{group.Key} ({group.Count()})");
            lines.AddRange(group.Select(f =>
                $"  {f.Capability}  {f.CallerType}.{f.CallerMethod}  ->  {f.CalledApi}"));
            lines.Add(string.Empty);
        }

        return string.Join(Environment.NewLine, lines);
    }
    #endregion
}
