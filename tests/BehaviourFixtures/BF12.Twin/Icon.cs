// Inert fixture: never executed (gated by Arm.Armed). BF12 twin: a base64 PNG icon in one ldstr, decoded to a MemoryStream and saved.
using System;
using System.IO;

namespace Behaviour
{
    public static class Icon
    {
        public static void Save()
        {
            if (!Arm.Armed) return;
            var bytes = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==");
            using var stream = new MemoryStream(bytes);
            File.WriteAllBytes(Path.Combine(Path.GetTempPath(), "silvergun-behaviour-icon.png"), stream.ToArray());
        }
    }
}
