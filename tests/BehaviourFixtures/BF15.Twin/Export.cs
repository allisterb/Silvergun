// Inert fixture: never executed (gated by Arm.Armed). BF15 twin: an UnmanagedCallersOnly export that adds two ints.
using System.Runtime.InteropServices;

namespace Behaviour
{
    public static class Exports
    {
        [UnmanagedCallersOnly(EntryPoint = "SilvergunBehaviourAdd")]
        public static int Add(int a, int b)
        {
            if (!Arm.Armed) return 0;
            return a + b;
        }
    }
}
