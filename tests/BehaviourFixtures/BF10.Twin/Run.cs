// Inert fixture: never executed (gated by Arm.Armed). BF10 twin: starts git to print its version.
using System.Diagnostics;

namespace Behaviour
{
    public static class Launcher
    {
        public static void Run()
        {
            if (!Arm.Armed) return;
            Process.Start("git", "--version");
        }
    }
}
