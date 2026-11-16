// Inert fixture: never executed (gated by Arm.Armed). BF06 twin: a module initializer that registers codecs in a static table.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;

namespace Behaviour
{
    internal static class ModuleStart
    {
        internal static readonly Dictionary<string, Func<byte[], byte[]>> Codecs = new Dictionary<string, Func<byte[], byte[]>>();

        [ModuleInitializer]
        internal static void Run()
        {
            if (!Arm.Armed) return;
            Codecs["identity"] = bytes => bytes;
            var dir = Path.Combine(AppContext.BaseDirectory, "codecs");
            if (Directory.Exists(dir))
                foreach (var file in Directory.GetFiles(dir))
                    Codecs[Path.GetFileNameWithoutExtension(file)] = bytes => bytes;
        }
    }
}
