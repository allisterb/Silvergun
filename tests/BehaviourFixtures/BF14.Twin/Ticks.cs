// Inert fixture: never executed (gated by Arm.Armed). BF14 twin: GetTickCount64 and a marshalled copy into an unmanaged scratch buffer.
using System;
using System.Runtime.InteropServices;

namespace Behaviour
{
    public static class Ticks
    {
        [DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();

        public static ulong Run()
        {
            if (!Arm.Armed) return 0;
            var buffer = new byte[64];
            var scratch = Marshal.AllocHGlobal(buffer.Length);
            Marshal.Copy(buffer, 0, scratch, buffer.Length);
            Marshal.FreeHGlobal(scratch);
            return GetTickCount64();
        }
    }
}
