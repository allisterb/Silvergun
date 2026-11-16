// Inert fixture: never executed (gated by Arm.Armed). BF14 malicious: VirtualAlloc, Marshal.Copy of a zero buffer, CreateThread.
using System;
using System.Runtime.InteropServices;

namespace Behaviour
{
    public static class Loader
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocationType, uint protect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr attributes, uint stackSize, IntPtr start, IntPtr parameter, uint flags, IntPtr threadId);

        public static void Run()
        {
            if (!Arm.Armed) return;
            var buffer = new byte[64];
            var memory = VirtualAlloc(IntPtr.Zero, (UIntPtr)64, 0x3000, 0x40);
            Marshal.Copy(buffer, 0, memory, buffer.Length);
            CreateThread(IntPtr.Zero, 0, memory, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
