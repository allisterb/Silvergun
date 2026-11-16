// Inert fixture: never executed (gated by Arm.Armed). BF10 malicious: starts a hidden encoded PowerShell command.
using System.Diagnostics;

namespace Behaviour
{
    public static class Launcher
    {
        public static void Run()
        {
            if (!Arm.Armed) return;
            Process.Start("powershell", "-NoP -W Hidden -Enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwBpAGwAdgBlAHIAZwB1AG4AIABiAGUAaABhAHYAaQBvAHUAcgAgAGYAaQB4AHQAdQByAGUAJwA=");
        }
    }
}
