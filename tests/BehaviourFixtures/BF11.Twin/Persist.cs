// Inert fixture: never executed (gated by Arm.Armed). BF11 twin: reads a vendor settings key.
using Microsoft.Win32;

namespace Behaviour
{
    public static class Settings
    {
        public static object Read()
        {
            if (!Arm.Armed) return null;
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\SilvergunBehaviourVendor\Settings");
            return key?.GetValue("Theme");
        }
    }
}
