// Inert fixture: never executed (gated by Arm.Armed). BF12b malicious: the base64 split over two ldstr constants, concatenated at run time.
using System;
using System.Diagnostics;
using System.IO;

namespace Behaviour
{
    public static class Dropper
    {
        private static readonly string part1 = "TVoAAAAAAAAAAAAA";

        private static readonly string part2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAFBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        public static void Run()
        {
            if (!Arm.Armed) return;
            Drop(Convert.FromBase64String(string.Concat(part1, part2)));
        }

        private static void Drop(byte[] bytes)
        {
            var path = Path.Combine(Path.GetTempPath(), "silvergun-behaviour.exe");
            File.WriteAllBytes(path, bytes);
            Process.Start(path);
        }
    }
}
