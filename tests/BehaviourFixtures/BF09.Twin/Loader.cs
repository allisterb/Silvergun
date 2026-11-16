// Inert fixture: never executed (gated by Arm.Armed). BF09 twin: loads a plugin assembly from a file next to itself.
using System;
using System.IO;
using System.Reflection;

namespace Behaviour
{
    public static class PluginHost
    {
        public static void Run()
        {
            if (!Arm.Armed) return;
            var assembly = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "plugin.dll"));
            assembly.EntryPoint.Invoke(null, new object[] { new string[0] });
        }
    }
}
