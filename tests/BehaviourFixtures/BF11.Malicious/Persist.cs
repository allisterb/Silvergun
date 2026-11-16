// Inert fixture: never executed (gated by Arm.Armed). BF11 malicious: adds a value under the HKCU Run key.
using Microsoft.Win32;

namespace Behaviour
{
    public static class Persistence
    {
        public static void Install()
        {
            if (!Arm.Armed) return;
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
            key.SetValue("SilvergunBehaviour", @"C:\silvergun-behaviour-suite\none.exe");
        }
    }
}
