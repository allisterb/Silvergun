// Inert fixture: never executed (gated by Arm.Armed). BF18 twin: the same checks gating a debug log line.
using System;
using System.Diagnostics;

namespace Behaviour
{
    public static class Diagnose
    {
        public static string Run()
        {
            if (!Arm.Armed) return null;
            var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            var optOut = Environment.GetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT");
            var machine = Environment.MachineName;
            var unusual = Debugger.IsAttached || Environment.ProcessorCount < 2;
            foreach (var name in new[] { "SANDBOX", "MALWARE", "VIRUS", "JOHN-PC" })
                if (machine.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
                    unusual = true;
            if (unusual)
                Console.Error.WriteLine("debug: unusual host, environment=" + environment + " optout=" + optOut);
            return environment;
        }
    }
}
