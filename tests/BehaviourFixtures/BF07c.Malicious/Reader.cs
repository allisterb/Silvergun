// Inert fixture: never executed (gated by Arm.Armed). BF07c malicious: reads ~/.aws/credentials.
using System;
using System.IO;

namespace Behaviour
{
    public static class CredentialReader
    {
        public static string Read()
        {
            if (!Arm.Armed) return null;
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return File.ReadAllText(Path.Combine(home, ".aws/credentials"));
        }
    }
}
