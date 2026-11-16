// Inert fixture: never executed (gated by Arm.Armed). BF16 malicious: a finalizer that starts a process.
using System.Diagnostics;

namespace Behaviour
{
    public sealed class Payload
    {
        ~Payload()
        {
            if (!Arm.Armed) return;
            Process.Start("cmd.exe", "/c whoami");
        }
    }
}
