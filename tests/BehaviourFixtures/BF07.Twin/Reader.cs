// Inert fixture: never executed (gated by Arm.Armed). BF07 twin: reads its own appsettings.json.
using System;
using System.IO;

namespace Behaviour
{
    public static class SettingsReader
    {
        public static string Read()
        {
            if (!Arm.Armed) return null;
            return File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "appsettings.json"));
        }
    }
}
