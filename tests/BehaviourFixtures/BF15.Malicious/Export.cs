// Inert fixture: never executed (gated by Arm.Armed). BF15 malicious: an UnmanagedCallersOnly export that harvests environment variables.
using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Text;

namespace Behaviour
{
    public static class Exports
    {
        [UnmanagedCallersOnly(EntryPoint = "SilvergunBehaviourHarvest")]
        public static int Harvest()
        {
            if (!Arm.Armed) return 0;
            var sb = new StringBuilder();
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
                sb.Append(entry.Key).Append('=').Append(entry.Value).Append('\n');
            return sb.Length;
        }
    }
}
