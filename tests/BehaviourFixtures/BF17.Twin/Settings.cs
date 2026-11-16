// Inert fixture: never executed (gated by Arm.Armed). BF17 twin: reads two well-known runtime settings and the DOTNET_ variables.
using System;
using System.Collections;
using System.Text;

namespace Behaviour
{
    public static class RuntimeSettings
    {
        public static string Read()
        {
            if (!Arm.Armed) return null;
            var sb = new StringBuilder();
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            {
                var key = (string)entry.Key;
                if (key.StartsWith("DOTNET_", StringComparison.Ordinal))
                    sb.Append(key).Append('=').Append(entry.Value).Append('\n');
            }
            sb.Append(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")).Append('\n');
            sb.Append(Environment.GetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT")).Append('\n');
            return sb.ToString();
        }
    }
}
