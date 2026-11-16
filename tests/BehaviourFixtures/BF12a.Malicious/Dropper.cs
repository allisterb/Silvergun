// Inert fixture: never executed (gated by Arm.Armed). BF12a malicious: base64 PE header in one ldstr, decoded, written to temp and started.
using System;
using System.Diagnostics;
using System.IO;

namespace Behaviour
{
    public static class Dropper
    {
        public static void Run()
        {
            if (!Arm.Armed) return;
            Drop(Convert.FromBase64String("TVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAFBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        }

        private static void Drop(byte[] bytes)
        {
            var path = Path.Combine(Path.GetTempPath(), "silvergun-behaviour.exe");
            File.WriteAllBytes(path, bytes);
            Process.Start(path);
        }
    }
}
